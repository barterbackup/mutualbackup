//! Retained flat-to-paged conversion. Production heads/checkpoints stay flat
//! until capture, packing, replay and recovery have migrated together.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mb_core::{
    CatalogScope, CatalogSection, CatalogSectorBuilder, CatalogSectorRecord, KeyMaterial,
    PAGED_USER_REVISION_VERSION, PagedUserRevision, SectorId, SignedRecord, UserRevision,
    V1_CIPHER_PROFILE, WriterFence, canonical_bytes_bounded, decode_canonical, merkle_commit,
};
use mb_store::{CatalogBundleState, CatalogIntent, CatalogIntentState, ControlStore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{PagedCatalogIntents, PagedLegacyDataAuthority, PagedPrivateMetadata};

const JOURNAL: &str = "paged-legacy-migration-v1";
const JOURNAL_BYTES: usize = 512;
const SOURCE_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MigrationRecord {
    version: u16,
    id: Uuid,
    scope: CatalogScope,
    legacy_hash: [u8; 32],
    legacy_id: Uuid,
    writer: WriterFence,
    sequence: u64,
    cancelled: bool,
}

/// Immutable operation identity, including the original signed body and new
/// certified writer. Keep the chosen ID across retry; cancelled IDs stay fenced.
pub struct RetainedLegacyMigration(MigrationRecord);

impl RetainedLegacyMigration {
    pub fn new(
        keys: &KeyMaterial,
        guild: [u8; 32],
        legacy: &SignedRecord<UserRevision>,
        writer: WriterFence,
        id: Uuid,
    ) -> Result<Self> {
        let (scope, _) = crate::paged_data::legacy_revision_scope(keys, guild, legacy)?;
        ensure!(
            !id.is_nil()
                && id != legacy.value.revision_id
                && writer.owner == keys.node_id()
                && writer.epoch > 0,
            "invalid retained migration identity or writer"
        );
        Ok(Self(MigrationRecord {
            version: 1,
            id,
            scope,
            legacy_hash: legacy.value.hash()?,
            legacy_id: legacy.value.revision_id,
            writer,
            sequence: legacy
                .value
                .sequence
                .checked_add(1)
                .context("migration sequence exhausted")?,
            cancelled: false,
        }))
    }

    pub fn load(control: &ControlStore, keys: &KeyMaterial, id: Uuid) -> Result<Option<Self>> {
        let Some(bytes) = control.get_record_bounded(JOURNAL, id.as_bytes(), JOURNAL_BYTES)? else {
            return Ok(None);
        };
        let record: MigrationRecord = decode_canonical(&bytes)?;
        ensure!(
            record.version == 1
                && record.id == id
                && !id.is_nil()
                && record.legacy_id != id
                && !record.legacy_id.is_nil()
                && record.sequence > 1
                && record.writer.epoch > 0
                && matches!(record.scope, CatalogScope::Dataset { owner, .. } if owner == keys.node_id())
                && record.writer.owner == keys.node_id()
                && canonical_bytes_bounded(&record, JOURNAL_BYTES)? == bytes,
            "invalid retained migration journal"
        );
        Ok(Some(Self(record)))
    }

    fn source_kind(&self) -> String {
        format!("paged-legacy-migration-source-v1/{}", self.0.id.simple())
    }

    fn roles(&self) -> [CatalogIntent; 6] {
        std::array::from_fn(|index| {
            let mut hash =
                blake3::Hasher::new_derive_key("mutualbackup retained migration intent v1");
            hash.update(self.0.id.as_bytes());
            hash.update(&[index as u8]);
            let mut id = [0; 16];
            id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
            CatalogIntent {
                id: Uuid::from_bytes(id),
                scope: self.0.scope,
                section: match index {
                    0 | 1 => CatalogSection::FileMetadata,
                    2 => CatalogSection::SectorReferences,
                    _ => CatalogSection::GitGraph,
                },
            }
        })
    }

    fn intents(&self, git: bool) -> PagedCatalogIntents {
        let roles = self.roles();
        PagedCatalogIntents {
            native: [roles[0], roles[1]],
            sources: roles[2],
            git: git.then(|| [roles[3], roles[4], roles[5]]),
        }
    }

    fn require_active(&self, control: &ControlStore) -> Result<()> {
        ensure!(!self.0.cancelled, "retained migration is cancelled");
        let bytes = canonical_bytes_bounded(&self.0, JOURNAL_BYTES)?;
        ensure!(
            control.get_record_bounded(JOURNAL, self.0.id.as_bytes(), JOURNAL_BYTES)?
                == Some(bytes),
            "retained migration changed or was cancelled"
        );
        Ok(())
    }

    fn enqueue(&self, control: &ControlStore, source: &CatalogSectorRecord) -> Result<()> {
        source.validate()?;
        let bytes = canonical_bytes_bounded(source, SOURCE_BYTES)?;
        let kind = self.source_kind();
        control.put_record_if_absent(&kind, &source.sector.id, &bytes)?;
        ensure!(
            control.get_record_bounded(&kind, &source.sector.id, SOURCE_BYTES)? == Some(bytes),
            "conflicting retained migration source"
        );
        Ok(())
    }

    fn check_publication(&self, revision: &PagedUserRevision) -> Result<()> {
        ensure!(
            revision.revision_id == self.0.id
                && revision.scope() == self.0.scope
                && revision.parent == Some(self.0.legacy_hash)
                && revision.sequence == self.0.sequence
                && revision.writer_epoch == self.0.writer.epoch
                && revision.writer_public_key == self.0.writer.public_key,
            "retained migration publication differs from its journal"
        );
        Ok(())
    }

    /// Verify the complete legacy schema/bytes, stage typed streams and publish
    /// all roots and stable sources together. No original head, recipe, signed
    /// record or protection claim is replaced. The caller supplies certified
    /// authority and serializes this operation with cancellation and retention.
    pub fn retain(
        &self,
        control: &ControlStore,
        keys: &KeyMaterial,
        legacy: &SignedRecord<UserRevision>,
        writer: &SigningKey,
        load: &mut impl FnMut(&SectorId) -> Result<Vec<u8>>,
    ) -> Result<SignedRecord<PagedUserRevision>> {
        let CatalogScope::Dataset { guild_id, .. } = self.0.scope else {
            anyhow::bail!("migration requires dataset scope");
        };
        ensure!(
            Self::new(keys, guild_id, legacy, self.0.writer.clone(), self.0.id)?.0 == self.0
                && writer.verifying_key().to_bytes() == self.0.writer.public_key,
            "retained migration identity or writer changed"
        );
        let journal = canonical_bytes_bounded(&self.0, JOURNAL_BYTES)?;
        if control
            .get_record_bounded(JOURNAL, self.0.id.as_bytes(), JOURNAL_BYTES)?
            .is_none()
        {
            ensure!(
                control.catalog_bundle(self.0.id)?.is_none()
                    && control.native_file_catalog_validation(self.0.id)?.is_none(),
                "migration ID is already owned by another catalog"
            );
        }
        control.put_record_if_absent(JOURNAL, self.0.id.as_bytes(), &journal)?;
        self.require_active(control)?;
        if let Some(snapshot) =
            PagedPrivateMetadata::load_local_catalog(control, keys, self.0.id, self.0.scope)?
        {
            let revision = snapshot.revision;
            ensure!(
                snapshot.state == CatalogBundleState::Published && snapshot.private.is_some(),
                "retained migration publication is cancelled"
            );
            self.check_publication(&revision.value)?;
            self.drain_sources(control)?;
            return Ok(revision);
        }
        let authority = PagedLegacyDataAuthority::new(keys, guild_id, legacy)?;
        // Retries rebuild this disposable ordering index from authenticated
        // inputs. Durable page ownership survives; stale queue tails do not.
        self.drain_sources(control)?;
        let roles = self.roles();
        let private = PagedPrivateMetadata::convert_legacy_revision(
            keys,
            guild_id,
            legacy,
            load,
            &mut |stream, page, bytes| {
                self.require_active(control)?;
                let index = stream.index();
                let intent = roles[if index < 2 { index } else { index + 1 }];
                ensure!(
                    control.begin_catalog(intent)? == CatalogIntentState::Building,
                    "migration stream already published"
                );
                control.stage_catalog_page(intent, page, &bytes)?;
                let (sector, ciphertext) = page.seal_private_page(
                    &keys.guild_content_id_key(&guild_id),
                    &keys.guild_data_key(&guild_id),
                    self.0.scope,
                    intent.section,
                    &bytes,
                )?;
                self.enqueue(
                    control,
                    &CatalogSectorRecord {
                        format_version: 1,
                        sector,
                        commitment: merkle_commit(&ciphertext)?,
                    },
                )
            },
        )?;
        for reference in &legacy.value.data_sectors {
            let source = CatalogSectorRecord {
                format_version: 1,
                sector: reference.clone(),
                commitment: merkle_commit(&load(&reference.id)?)?,
            };
            let anchor =
                crate::snapshot::stable_source_for_catalog_migration(control, guild_id, reference)?;
            // Check every original data recipe before new authority is signed.
            authority
                .bind(anchor, &source)?
                .render(keys, self.0.scope, &source)?;
            self.enqueue(control, &source)?;
        }
        let (metadata, _) = private.seal(keys, self.0.scope)?;
        self.enqueue(control, &metadata)?;
        let intents = self.intents(private.git.is_some());
        ensure!(
            control.begin_catalog(intents.sources)? == CatalogIntentState::Building,
            "migration source stream already published"
        );
        let mut builder = CatalogSectorBuilder::new(self.0.scope)?;
        let mut sink =
            |page, bytes: Vec<u8>| control.stage_catalog_page(intents.sources, page, &bytes);
        let mut after = None;
        while let Some((id, bytes)) =
            control.next_record_bounded(&self.source_kind(), after.as_deref(), 32, SOURCE_BYTES)?
        {
            self.require_active(control)?;
            let source: CatalogSectorRecord = decode_canonical(&bytes)?;
            ensure!(
                id == source.sector.id && canonical_bytes_bounded(&source, SOURCE_BYTES)? == bytes,
                "invalid migration source queue row"
            );
            builder.push(&source, &mut sink)?;
            after = Some(id);
        }
        let revision = PagedUserRevision {
            format_version: PAGED_USER_REVISION_VERSION,
            guild_id,
            protected_root_id: legacy.value.protected_root_id,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: self.0.id,
            owner: keys.node_id(),
            writer_epoch: self.0.writer.epoch,
            writer_public_key: self.0.writer.public_key,
            writer_signature: vec![],
            sequence: self.0.sequence,
            parent: Some(self.0.legacy_hash),
            metadata,
            sources: builder.finish(&mut sink)?,
        }
        .sign(writer, keys)?;
        self.require_active(control)?;
        private.publish_local_catalog_with_authenticated_sources(
            control,
            keys,
            &revision,
            &self.0.writer,
            intents,
            |source| {
                if authority.contains_data(source.sector.id) {
                    authority
                        .bind(
                            crate::snapshot::stable_source_for_catalog_migration(
                                control,
                                guild_id,
                                &source.sector,
                            )?,
                            source,
                        )
                        .map(Some)
                } else {
                    Ok(None)
                }
            },
        )?;
        self.drain_sources(control)?;
        Ok(revision)
    }

    fn drain_sources(&self, control: &ControlStore) -> Result<()> {
        let kind = self.source_kind();
        while let Some((id, bytes)) = control.next_record_bounded(&kind, None, 32, SOURCE_BYTES)? {
            control.delete_record_if_value(&kind, &id, &bytes)?;
        }
        Ok(())
    }

    /// Persist the cancellation fence first. Interrupted cancellation can be
    /// repeated; typed root cancellation fences serving and releases ownership
    /// through the existing bounded cleanup APIs.
    pub fn cancel(&self, control: &ControlStore) -> Result<()> {
        let mut cancelled = self.0.clone();
        cancelled.cancelled = true;
        let old = canonical_bytes_bounded(&self.0, JOURNAL_BYTES)?;
        let new = canonical_bytes_bounded(&cancelled, JOURNAL_BYTES)?;
        let bytes = control.get_record_bounded(JOURNAL, self.0.id.as_bytes(), JOURNAL_BYTES)?;
        if bytes.as_ref() != Some(&new) {
            ensure!(
                bytes == Some(old.clone()),
                "migration cancellation identity differs"
            );
            control.replace_record_if_value(JOURNAL, self.0.id.as_bytes(), &old, &new)?;
        }
        if let Some(snapshot) = control.paged_revision_catalog(self.0.id)? {
            self.check_publication(
                &PagedUserRevision::decode_signed(&snapshot.bundle.descriptor)?.value,
            )?;
            control.cancel_paged_revision_catalog(self.0.id)?;
        } else if control.native_file_catalog_validation(self.0.id)?.is_some() {
            control.cancel_native_file_catalog_validation(self.0.id)?;
        }
        for intent in self.roles() {
            // Cancellation also fences roles not reached before interruption.
            match control.begin_catalog(intent) {
                Ok(_) => control.cancel_catalog(intent)?,
                Err(_)
                    if control.catalog_intent_state(intent).ok()
                        == Some(CatalogIntentState::Cancelled) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.drain_sources(control)
    }

    /// Release at most one cancelled pin/index row. Page reclamation remains
    /// in ControlStore's shared catalog GC, which preserves other owners.
    pub fn cleanup_step(&self, control: &ControlStore) -> Result<bool> {
        let mut cancelled = self.0.clone();
        cancelled.cancelled = true;
        ensure!(
            control.get_record_bounded(JOURNAL, self.0.id.as_bytes(), JOURNAL_BYTES)?
                == Some(canonical_bytes_bounded(&cancelled, JOURNAL_BYTES)?),
            "migration must be cancelled before cleanup"
        );
        if let Some(snapshot) = control.paged_revision_catalog(self.0.id)? {
            self.check_publication(
                &PagedUserRevision::decode_signed(&snapshot.bundle.descriptor)?.value,
            )?;
            if control.release_paged_revision_data_source(self.0.id)?
                || control.release_paged_revision_page_source(self.0.id)?
            {
                return Ok(true);
            }
        }
        for intent in self.roles() {
            if control.release_catalog_pin(intent)? {
                return Ok(true);
            }
        }
        if control.native_file_catalog_validation(self.0.id)?.is_some() {
            return Ok(control.release_native_file_validation_record(self.0.id)?);
        }
        Ok(false)
    }
}

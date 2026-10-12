//! Durable native paged capture candidates. Normal backup/checkpoint switching
//! remains separate; this owner does not advertise distributed protection.

use crate::{
    NativeCatalogAdmission, PagedAnchorSectorSource, PagedCatalogIntents, PagedPrivateMetadata,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mb_core::{
    CatalogCapacityPolicy, CatalogPageRef, CatalogScope, CatalogSection, CatalogSectorBuilder,
    CatalogSectorRecord, KeyMaterial, PagedUserRevision, SignedRecord, WriterFence,
    canonical_bytes_bounded, decode_canonical, merkle_commit,
};
use mb_store::{
    CatalogBundleState, CatalogIntent, CatalogIntentState, CatalogPageReservation,
    CatalogStoreError, ControlStore, DatabaseError, SourceCapturePlan,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, path::Path};
use uuid::Uuid;

pub(crate) const JOURNAL: &str = "paged-native-capture-v1";
pub(crate) const JOURNAL_BYTES: usize = 32 * 1024;
const SOURCE_BYTES: usize = mb_store::PAGED_DATA_RECIPE_BYTES + 512;
const SOURCE_BATCH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CaptureRequest {
    pub scope: CatalogScope,
    pub id: Uuid,
    pub writer: WriterFence,
    pub sequence: u64,
    pub parent: Option<[u8; 32]>,
    pub captured_change_sequence: Option<u64>,
    #[serde(with = "mb_store::raw_path_bytes")]
    pub requested_source: std::path::PathBuf,
    pub registration_hash: [u8; 32],
    pub backend_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CaptureRecord {
    version: u16,
    request: CaptureRequest,
    policy: CatalogCapacityPolicy,
    plan: SourceCapturePlan,
    manifest_hash: Option<[u8; 32]>,
    published_hash: Option<[u8; 32]>,
    cancelled: bool,
    released: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingSource {
    version: u16,
    source: CatalogSectorRecord,
    anchor: Option<PagedAnchorSectorSource>,
}

pub(crate) struct PagedNativeCapture(CaptureRecord);

fn source_kind(id: Uuid) -> String {
    format!("paged-native-capture-source-v1/{}", id.simple())
}
fn decode_source(key: &[u8], bytes: &[u8]) -> Result<PendingSource, CatalogStoreError> {
    let source: PendingSource = decode_canonical(bytes)?;
    source.source.validate()?;
    if source.version != 1
        || source.source.sector.id != key
        || canonical_bytes_bounded(&source, SOURCE_BYTES)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(source)
}

struct Sources<'a> {
    control: &'a ControlStore,
    kind: String,
    after: Option<Vec<u8>>,
    data_only: bool,
    done: bool,
}
impl Iterator for Sources<'_> {
    type Item = Result<CatalogSectorRecord, CatalogStoreError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let result = self
                .control
                .next_record_bounded(&self.kind, self.after.as_deref(), 32, SOURCE_BYTES)
                .map_err(CatalogStoreError::from)
                .and_then(|row| {
                    row.map(|(key, bytes)| {
                        let value = decode_source(&key, &bytes)?;
                        Ok((key, value))
                    })
                    .transpose()
                });
            match result {
                Ok(Some((key, value))) => {
                    self.after = Some(key);
                    if !self.data_only || value.anchor.is_some() {
                        return Some(Ok(value.source));
                    }
                }
                Ok(None) => {
                    self.done = true;
                    return None;
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl PagedNativeCapture {
    pub(crate) fn request(&self) -> &CaptureRequest {
        &self.0.request
    }
    pub(crate) fn has_capture(&self) -> bool {
        self.0.manifest_hash.is_some()
    }
    pub(crate) fn source_root(&self) -> &Path {
        self.0.plan.source_root()
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_bytes_bounded(&self.0, JOURNAL_BYTES)?)
    }
    fn anchor_id(&self) -> Uuid {
        match &self.0.plan {
            SourceCapturePlan::ReflinkV1(plan) => plan.anchor_id(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn decode(key: &[u8], bytes: &[u8]) -> Result<Self> {
        let record: CaptureRecord = decode_canonical(bytes)?;
        let value = Self(record);
        let request = value.request();
        use std::os::unix::ffi::OsStrExt;
        ensure!(
            !request.requested_source.as_os_str().is_empty()
                && !request.requested_source.as_os_str().as_bytes().contains(&0)
                && !value.source_root().as_os_str().is_empty(),
            "invalid native capture source path"
        );
        request.scope.validate(CatalogSection::FileMetadata)?;
        let CatalogScope::Dataset { owner, .. } = request.scope else {
            anyhow::bail!("native capture requires dataset scope")
        };
        ensure!(
            value.0.version == 1
                && request.id.as_bytes() == key
                && !request.id.is_nil()
                && request.writer.owner == owner
                && request.writer.epoch > 0
                && request.sequence > 0
                && (!value.0.released || value.0.cancelled)
                && (value.0.published_hash.is_none() || value.0.manifest_hash.is_some())
                && value.bytes()? == bytes,
            "invalid native capture journal"
        );
        ensure!(
            matches!(value.0.plan, SourceCapturePlan::ReflinkV1(_)),
            "{}",
            mb_store::WITHDRAWN_GUARDED_BACKEND
        );
        value.0.plan.preserved_ownership()?;
        value.0.policy.plan()?;
        Ok(value)
    }

    pub(crate) fn load(control: &ControlStore, id: Uuid) -> Result<Option<Self>> {
        control
            .get_record_bounded(JOURNAL, id.as_bytes(), JOURNAL_BYTES)?
            .map(|bytes| Self::decode(id.as_bytes(), &bytes))
            .transpose()
    }

    pub(crate) fn admit_configuration(
        control: &ControlStore,
        scope: CatalogScope,
    ) -> Result<CatalogCapacityPolicy> {
        let CatalogScope::Dataset { guild_id, .. } = scope else {
            anyhow::bail!("native capture requires dataset scope")
        };
        let policy = control
            .catalog_capacity_policy()?
            .context("native paged capture requires an explicit capacity contract")?;
        ensure!(
            control
                .record_quota_usage()?
                .is_some_and(|usage| usage.state == mb_store::DatabaseRecordQuotaState::Active)
                && control.page_quota_usage()?.is_some()
                && control.journal_quota_usage()?.is_some()
                && control.catalog_storage_usage()?.is_some()
                && control.catalog_dataset_storage_usage(scope)?.is_some()
                && control.catalog_guild_storage_usage(guild_id)?.is_some(),
            "native paged capture requires active database and scoped page admission"
        );
        Ok(policy)
    }

    pub(crate) fn begin(
        control: &ControlStore,
        request: CaptureRequest,
        plan: SourceCapturePlan,
    ) -> Result<Self> {
        let policy = Self::admit_configuration(control, request.scope)?;
        let value = Self(CaptureRecord {
            version: 1,
            request,
            policy,
            plan,
            manifest_hash: None,
            published_hash: None,
            cancelled: false,
            released: false,
        });
        let bytes = value.bytes()?;
        Self::decode(value.request().id.as_bytes(), &bytes)?;
        ensure!(
            Self::load(control, value.request().id)?.is_none()
                && control.catalog_bundle(value.request().id)?.is_none()
                && control
                    .native_file_catalog_validation(value.request().id)?
                    .is_none()
                && control
                    .get_record_bounded(
                        "user-revision",
                        value.request().id.as_bytes(),
                        mb_core::V1_MAX_CATALOG_BYTES
                    )?
                    .is_none()
                && control
                    .get_record_bounded(
                        "paged-legacy-migration-v1",
                        value.request().id.as_bytes(),
                        512
                    )?
                    .is_none(),
            "capture ID already belongs to another operation"
        );
        control.with_record_transaction(|| -> Result<()> {
            control.put_record_if_absent(JOURNAL, value.request().id.as_bytes(), &bytes)?;
            value.require_active(control)
        })?;
        Ok(value)
    }

    fn require_record(&self, control: &ControlStore) -> Result<()> {
        ensure!(
            control.get_record_bounded(JOURNAL, self.request().id.as_bytes(), JOURNAL_BYTES)?
                == Some(self.bytes()?),
            "native capture journal changed"
        );
        Ok(())
    }
    fn require_active(&self, control: &ControlStore) -> Result<()> {
        ensure!(
            !self.0.cancelled && !self.0.released,
            "native capture is cancelled"
        );
        self.require_record(control)?;
        control.check_catalog_capacity_policy(self.0.policy)?;
        Ok(())
    }
    fn roles(&self) -> [CatalogIntent; 3] {
        std::array::from_fn(|index| {
            let mut hash =
                blake3::Hasher::new_derive_key("mutualbackup native paged capture intent v1");
            hash.update(self.request().id.as_bytes());
            hash.update(&[index as u8]);
            let mut id = [0; 16];
            id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
            CatalogIntent {
                id: Uuid::from_bytes(id),
                scope: self.request().scope,
                section: if index == 2 {
                    CatalogSection::SectorReferences
                } else {
                    CatalogSection::FileMetadata
                },
            }
        })
    }
    fn sources<'a>(&self, control: &'a ControlStore, data_only: bool) -> Sources<'a> {
        Sources {
            control,
            kind: source_kind(self.request().id),
            after: None,
            data_only,
            done: false,
        }
    }
    fn enqueue(&self, control: &ControlStore, source: &PendingSource) -> Result<()> {
        let kind = source_kind(self.request().id);
        let key = source.source.sector.id;
        let bytes = canonical_bytes_bounded(source, SOURCE_BYTES)?;
        if let Some(old) = control.get_record_bounded(&kind, &key, SOURCE_BYTES)? {
            let old = decode_source(&key, &old)?;
            ensure!(
                old.source == source.source && old.anchor.is_some() == source.anchor.is_some(),
                "conflicting captured source identity"
            );
            self.check_source_anchor(&old)?;
            return Ok(());
        }
        self.check_source_anchor(source)?;
        control.put_record_if_absent(&kind, &key, &bytes)?;
        ensure!(
            control.get_record_bounded(&kind, &key, SOURCE_BYTES)? == Some(bytes),
            "captured source write was ignored"
        );
        Ok(())
    }
    fn check_source_anchor(&self, source: &PendingSource) -> Result<()> {
        if let Some(anchor) = &source.anchor {
            let SourceCapturePlan::ReflinkV1(plan) = &self.0.plan else {
                unreachable!()
            };
            ensure!(
                anchor.locator.anchor_id == plan.anchor_id()
                    && &anchor.locator.area == plan.preserved_ownership()?.area,
                "captured source belongs to another native owner"
            );
        }
        Ok(())
    }
    fn flush(&self, control: &ControlStore, buffer: &RefCell<Vec<PendingSource>>) -> Result<()> {
        let mut values = buffer.borrow_mut();
        if values.is_empty() {
            return Ok(());
        }
        control.with_record_transaction(|| -> Result<()> {
            self.require_active(control)?;
            for value in values.iter() {
                self.enqueue(control, value)?;
            }
            self.require_active(control)
        })?;
        values.clear();
        Ok(())
    }

    pub(crate) fn completed(
        &self,
        control: &ControlStore,
        keys: &KeyMaterial,
    ) -> Result<Option<SignedRecord<PagedUserRevision>>> {
        self.require_record(control)?;
        ensure!(!self.0.cancelled, "native capture is cancelled");
        let Some(hash) = self.0.published_hash else {
            return Ok(None);
        };
        let snapshot = PagedPrivateMetadata::load_local_catalog(
            control,
            keys,
            self.request().id,
            self.request().scope,
        )?
        .context("published native capture lost its catalog")?;
        ensure!(
            snapshot.state == CatalogBundleState::Published
                && snapshot.revision.value.hash()? == hash,
            "native capture publication identity differs"
        );
        self.check_revision(&snapshot.revision.value)?;
        Ok(Some(snapshot.revision))
    }
    fn check_revision(&self, revision: &PagedUserRevision) -> Result<()> {
        let request = self.request();
        ensure!(
            revision.revision_id == request.id
                && revision.scope() == request.scope
                && revision.writer_epoch == request.writer.epoch
                && revision.writer_public_key == request.writer.public_key
                && revision.sequence == request.sequence
                && revision.parent == request.parent,
            "native capture revision differs from its journal"
        );
        Ok(())
    }

    pub(crate) fn produce(
        &mut self,
        control: &ControlStore,
        keys: &KeyMaterial,
        signing: &SigningKey,
        mut guard: impl FnMut() -> Result<()>,
    ) -> Result<SignedRecord<PagedUserRevision>> {
        if let Some(signed) = self.completed(control, keys)? {
            return Ok(signed);
        }
        self.require_active(control)?;
        guard()?;
        ensure!(
            self.request().writer.public_key == signing.verifying_key().to_bytes(),
            "native capture writer differs"
        );
        let manifest = if self.0.manifest_hash.is_some() {
            self.0.plan.captured_manifest(control)?
        } else {
            self.0.plan.capture(control)?
        };
        let manifest_hash = *blake3::hash(&canonical_bytes_bounded(
            &manifest,
            mb_core::V1_MAX_CATALOG_BYTES,
        )?)
        .as_bytes();
        if let Some(expected) = self.0.manifest_hash {
            ensure!(
                manifest_hash == expected,
                "captured native manifest changed"
            );
        } else {
            let old = self.bytes()?;
            let mut captured = self.0.clone();
            captured.manifest_hash = Some(manifest_hash);
            control.with_record_transaction(|| -> Result<()> {
                self.require_active(control)?;
                let bytes = canonical_bytes_bounded(&captured, JOURNAL_BYTES)?;
                control.replace_record_if_value(
                    JOURNAL,
                    self.request().id.as_bytes(),
                    &old,
                    &bytes,
                )?;
                ensure!(
                    control.get_record_bounded(
                        JOURNAL,
                        self.request().id.as_bytes(),
                        JOURNAL_BYTES
                    )? == Some(bytes),
                    "capture manifest ownership write was ignored"
                );
                guard()
            })?;
            self.0 = captured;
        }
        let admission =
            NativeCatalogAdmission::for_anchor(&manifest, self.request().scope, self.0.policy)?;
        let roles = self.roles();
        let requests: Vec<_> = roles
            .iter()
            .enumerate()
            .map(|(index, role)| {
                let pages = if index == 2 {
                    self.0.policy.source_pages_per_revision
                } else {
                    admission.private_roots[index].page_occurrences
                };
                (
                    *role,
                    CatalogPageReservation {
                        page_bytes: pages * mb_core::CATALOG_PAGE_BYTES as u64,
                        pages,
                    },
                )
            })
            .collect();
        control.with_catalog_page_reservations(&requests, |states| -> Result<()> {
            self.require_active(control)?;
            guard()?;
            ensure!(
                states.iter().all(|s| *s == CatalogIntentState::Building),
                "native capture stream is already published"
            );
            Ok(())
        })?;
        let buffer = RefCell::new(Vec::with_capacity(SOURCE_BATCH));
        let CatalogScope::Dataset {
            guild_id,
            owner,
            protected_root_id,
        } = self.request().scope
        else {
            unreachable!()
        };
        let native = PagedPrivateMetadata::write_native_anchor_catalog(
            control,
            keys,
            self.request().scope,
            self.0.policy,
            &manifest,
            &mut |stream, page: CatalogPageRef, bytes| {
                self.flush(control, &buffer)?;
                self.require_active(control)?;
                control.stage_catalog_page(roles[stream.index()], page, &bytes)?;
                let (sector, ciphertext) = page.seal_private_page(
                    &keys.guild_content_id_key(&guild_id),
                    &keys.guild_data_key(&guild_id),
                    self.request().scope,
                    CatalogSection::FileMetadata,
                    &bytes,
                )?;
                buffer.borrow_mut().push(PendingSource {
                    version: 1,
                    source: CatalogSectorRecord {
                        format_version: 1,
                        sector,
                        commitment: merkle_commit(&ciphertext)?,
                    },
                    anchor: None,
                });
                self.flush(control, &buffer)
            },
            &mut |source, anchor| {
                ensure!(
                    anchor.locator.anchor_id == self.anchor_id(),
                    "captured source belongs to another anchor"
                );
                buffer.borrow_mut().push(PendingSource {
                    version: 1,
                    source,
                    anchor: Some(anchor),
                });
                if buffer.borrow().len() == SOURCE_BATCH {
                    self.flush(control, &buffer)?;
                }
                Ok(())
            },
        )?;
        self.flush(control, &buffer)?;
        let private = PagedPrivateMetadata {
            format_version: mb_core::PAGED_USER_REVISION_VERSION,
            native,
            git: None,
        };
        let (metadata, _) = private.seal(keys, self.request().scope)?;
        buffer.borrow_mut().push(PendingSource {
            version: 1,
            source: metadata.clone(),
            anchor: None,
        });
        self.flush(control, &buffer)?;
        let mut builder = CatalogSectorBuilder::new(self.request().scope)?;
        let mut sink = |page, bytes: Vec<u8>| {
            self.require_active(control)
                .map_err(|_| CatalogStoreError::from(DatabaseError::Conflict))?;
            control.stage_catalog_page(roles[2], page, &bytes)
        };
        for source in self.sources(control, false) {
            builder.push(&source?, &mut sink)?;
        }
        let sources = builder.finish(&mut sink)?;
        let signed = PagedUserRevision {
            format_version: mb_core::PAGED_USER_REVISION_VERSION,
            guild_id,
            owner,
            protected_root_id,
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: self.request().id,
            writer_epoch: self.request().writer.epoch,
            writer_public_key: self.request().writer.public_key,
            writer_signature: vec![],
            sequence: self.request().sequence,
            parent: self.request().parent,
            metadata,
            sources,
        }
        .sign(signing, keys)?;
        self.require_active(control)?;
        guard()?;
        control.with_record_transaction(|| -> Result<()> {
            self.require_active(control)?;
            guard()?;
            control.reserve_catalog_retained_sources_with_dependencies_in_transaction(
                self.request().id,
                self.request().scope,
                || self.sources(control, true),
            )?;
            self.require_active(control)?;
            guard()
        })?;
        let old = self.bytes()?;
        let mut published = self.0.clone();
        published.published_hash = Some(signed.value.hash()?);
        let ready = canonical_bytes_bounded(&published, JOURNAL_BYTES)?;
        private.publish_local_catalog_with_operation(
            control,
            keys,
            &signed,
            &self.request().writer,
            PagedCatalogIntents {
                native: [roles[0], roles[1]],
                sources: roles[2],
                git: None,
            },
            (
                |record: &CatalogSectorRecord| {
                    let row = control
                        .get_record_bounded(
                            &source_kind(self.request().id),
                            &record.sector.id,
                            SOURCE_BYTES,
                        )?
                        .context("captured source queue is incomplete")?;
                    let row = decode_source(&record.sector.id, &row)?;
                    self.check_source_anchor(&row)?;
                    ensure!(
                        row.source == *record,
                        "captured source differs from signed source tree"
                    );
                    Ok(row.anchor.map(crate::PagedDataSource::from))
                },
                || {
                    self.require_active(control)?;
                    control.replace_record_if_value(
                        JOURNAL,
                        self.request().id.as_bytes(),
                        &old,
                        &ready,
                    )?;
                    Ok(())
                },
                || {
                    ensure!(
                        control.get_record_bounded(
                            JOURNAL,
                            self.request().id.as_bytes(),
                            JOURNAL_BYTES
                        )? == Some(ready.clone()),
                        "native capture final ownership write was ignored"
                    );
                    guard()
                },
            ),
        )?;
        self.0 = published;
        Ok(signed)
    }

    pub(crate) fn cancel(&mut self, control: &ControlStore) -> Result<()> {
        let old = self.bytes()?;
        let mut cancelled = self.0.clone();
        cancelled.cancelled = true;
        let bytes = canonical_bytes_bounded(&cancelled, JOURNAL_BYTES)?;
        control.with_unretained_paged_revision_record_transaction(
            self.request().id,
            || -> Result<()> {
                self.require_record(control)?;
                if !self.0.cancelled {
                    control.replace_record_if_value(
                        JOURNAL,
                        self.request().id.as_bytes(),
                        &old,
                        &bytes,
                    )?;
                }
                ensure!(
                    control.get_record_bounded(
                        JOURNAL,
                        self.request().id.as_bytes(),
                        JOURNAL_BYTES
                    )? == Some(bytes.clone()),
                    "native cancellation write was ignored"
                );
                Ok(())
            },
        )?;
        self.0 = cancelled;
        if control.paged_revision_catalog(self.request().id)?.is_some() {
            control.cancel_paged_revision_catalog(self.request().id)?;
        } else if control
            .native_file_catalog_validation(self.request().id)?
            .is_some()
        {
            control.cancel_native_file_catalog_validation(self.request().id)?;
        }
        for role in self.roles() {
            control.fence_catalog(role)?;
        }
        control
            .cancel_catalog_retained_source_reservation(self.request().id, self.request().scope)?;
        Ok(())
    }

    pub(crate) fn cleanup_step(&mut self, control: &ControlStore) -> Result<bool> {
        self.require_record(control)?;
        ensure!(
            self.0.cancelled || self.0.published_hash.is_some(),
            "capture must finish or cancel before cleanup"
        );
        if let Some((key, bytes)) =
            control.next_record_bounded(&source_kind(self.request().id), None, 32, SOURCE_BYTES)?
        {
            decode_source(&key, &bytes)?;
            control.delete_record_if_value(&source_kind(self.request().id), &key, &bytes)?;
            return Ok(true);
        }
        if !self.0.cancelled || self.0.released {
            return Ok(false);
        }
        if control
            .release_catalog_retained_source_dependency(self.request().id, self.request().scope)?
        {
            return Ok(true);
        }
        if control.paged_revision_catalog(self.request().id)?.is_some()
            && (control.release_paged_revision_data_source(self.request().id)?
                || control.release_paged_revision_page_source(self.request().id)?)
        {
            return Ok(true);
        }
        for role in self.roles() {
            if control.release_catalog_pin(role)? {
                return Ok(true);
            }
        }
        if control
            .native_file_catalog_validation(self.request().id)?
            .is_some()
            && control.release_native_file_validation_record(self.request().id)?
        {
            return Ok(true);
        }
        self.0.plan.discard(control)?;
        let old = self.bytes()?;
        let mut released = self.0.clone();
        released.released = true;
        let bytes = canonical_bytes_bounded(&released, JOURNAL_BYTES)?;
        control.replace_record_if_value(JOURNAL, self.request().id.as_bytes(), &old, &bytes)?;
        ensure!(
            control.get_record_bounded(JOURNAL, self.request().id.as_bytes(), JOURNAL_BYTES)?
                == Some(bytes),
            "capture release write was ignored"
        );
        self.0 = released;
        Ok(true)
    }

    pub(crate) fn preserved(&self) -> crate::snapshot::preserved::PreservedCaptureIntent {
        crate::snapshot::preserved::PreservedCaptureIntent {
            record_format: 1,
            guild_id: match self.request().scope {
                CatalogScope::Dataset { guild_id, .. } => guild_id,
                _ => unreachable!(),
            },
            revision_id: self.request().id,
            sequence: Some(self.request().sequence),
            parent: self.request().parent,
            captured_change_sequence: self.request().captured_change_sequence,
            requested_source: self.request().requested_source.clone(),
            plan: self.0.plan.clone(),
            replaced_anchor: None,
        }
    }
}

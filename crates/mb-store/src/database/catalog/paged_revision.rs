//! Atomic local ownership of signed paged roots and their bootstrap ciphertext.
//! This is a migration journal, not checkpoint protection or current head state.

use mb_core::{
    CATALOG_MAX_STREAM_BYTES, CatalogSectorRecord, PAGED_USER_REVISION_BYTES, PagedUserRevision,
    SignedRecord, V1_SECTOR_SIZE, merkle_commit, sector_root,
};

use super::*;

const REVISION: &str = "paged-user-revision-v1";
const BOOTSTRAP: &str = "paged-revision-bootstrap-v1";
const PUBLICATION: &str = "catalog-paged-publication-v1";

fn bootstrap_pins(id: [u8; 32]) -> String {
    format!("catalog-paged-bootstrap-owner-v1/{}", hex::encode(id))
}

fn page_sources(id: Uuid) -> String {
    format!("catalog-paged-page-source-v1/{}", id.simple())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PageSourceRecord {
    format_version: u16,
    intent: CatalogIntent,
    page: CatalogPageRef,
    source: CatalogSectorRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedCatalogPageSource {
    pub catalog: PagedCatalogSnapshot,
    pub intent: CatalogIntent,
    pub page: CatalogPageRef,
    pub source: CatalogSectorRecord,
}

/// Reads and source bindings use the publication transaction's exact snapshot
/// and cannot start a nested transaction. The caller verifies typed private
/// roots, signed source joins and current writer authority before publication.
pub struct CatalogPublicationView<'a> {
    connection: &'a Connection,
    manifest: CatalogNativeValidation,
    bundle: &'a CatalogBundle,
}

impl CatalogPublicationView<'_> {
    pub fn catalog_page(
        &self,
        section: CatalogSection,
        page: CatalogPageRef,
    ) -> Result<Vec<u8>, CatalogStoreError> {
        read_page(
            self.connection,
            PageMetadata {
                format_version: 1,
                scope: self.manifest.scope,
                section,
                reference: page,
            },
        )
    }

    pub fn source(
        &self,
        sector: [u8; 32],
    ) -> Result<Option<CatalogSectorRecord>, CatalogStoreError> {
        native_validation::source_record(self.connection, self.manifest.id, sector)
    }

    /// Bind a caller-authenticated stable native/Git data recipe and retain
    /// its physical anchor in the root publication's writer transaction.
    pub fn bind_data_source(
        &self,
        source: &CatalogSectorRecord,
        anchor: Uuid,
        recipe: &[u8],
    ) -> Result<(), CatalogStoreError> {
        paged_data::bind(self.connection, self.bundle, source, anchor, recipe)
    }

    /// Bind a verified private page while traversing the typed root. This
    /// immutable index publishes or rolls back with every revision root.
    pub fn bind_private_page_source(
        &self,
        intent: CatalogIntent,
        page: CatalogPageRef,
        source: &CatalogSectorRecord,
    ) -> Result<(), CatalogStoreError> {
        require_page_owner(self.connection, self.bundle, intent, page)?;
        read_page(
            self.connection,
            PageMetadata {
                format_version: 1,
                scope: intent.scope,
                section: intent.section,
                reference: page,
            },
        )?;
        if self.source(source.sector.id)?.as_ref() != Some(source) {
            return Err(DatabaseError::Conflict.into());
        }
        let kind = page_sources(self.bundle.id);
        if let Some(bytes) = bounded_record(
            self.connection,
            &kind,
            &source.sector.id,
            CATALOG_SECTOR_RECIPE_BYTES,
        )? {
            let previous: PageSourceRecord = decode_canonical(&bytes)?;
            if previous.format_version != 1
                || previous.page != page
                || previous.source != *source
                || canonical_bytes(&previous)? != bytes
            {
                return Err(DatabaseError::Conflict.into());
            }
            // Identical pages may occur under several member roots. Retain
            // one verified member owner rather than duplicate sector rows.
            require_page_owner(self.connection, self.bundle, previous.intent, previous.page)?;
            return Ok(());
        }
        insert_exact(
            self.connection,
            &page_sources(self.bundle.id),
            &source.sector.id,
            &canonical_bytes(&PageSourceRecord {
                format_version: 1,
                intent,
                page,
                source: source.clone(),
            })?,
        )
    }
}

fn require_page_owner(
    connection: &Connection,
    bundle: &CatalogBundle,
    intent: CatalogIntent,
    page: CatalogPageRef,
) -> Result<(), CatalogStoreError> {
    if !intent.section.is_private()
        || !bundle.roots.iter().any(|member| member.intent == intent)
        || metadata(connection, page.hash)?
            != (PageMetadata {
                format_version: 1,
                scope: intent.scope,
                section: intent.section,
                reference: page,
            })
        || bounded_record(connection, &owners(intent), &page.hash, 0)?.as_deref() != Some(&[])
        || bounded_record(connection, &pins(page.hash), intent.id.as_bytes(), 0)?.as_deref()
            != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn page_source(
    connection: &Connection,
    id: Uuid,
    sector: [u8; 32],
) -> Result<Option<PagedCatalogPageSource>, CatalogStoreError> {
    let Some(catalog) = snapshot(connection, id)? else {
        return Ok(None);
    };
    if catalog.state == CatalogBundleState::Cancelled {
        return Ok(None);
    }
    let Some(bytes) = bounded_record(
        connection,
        &page_sources(id),
        &sector,
        CATALOG_SECTOR_RECIPE_BYTES,
    )?
    else {
        return Ok(None);
    };
    let record: PageSourceRecord = decode_canonical(&bytes)?;
    if record.format_version != 1
        || record.source.sector.id != sector
        || canonical_bytes(&record)? != bytes
        || native_validation::source_record(connection, id, sector)?.as_ref()
            != Some(&record.source)
    {
        return Err(DatabaseError::Integrity.into());
    }
    require_page_owner(connection, &catalog.bundle, record.intent, record.page)?;
    Ok(Some(PagedCatalogPageSource {
        catalog,
        intent: record.intent,
        page: record.page,
        source: record.source,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedCatalogSnapshot {
    pub bundle: CatalogBundle,
    pub state: CatalogBundleState,
    /// Present for published roots. Cancelled journals retain identity/fences,
    /// while the last owner releases the shared ciphertext.
    pub bootstrap: Option<Vec<u8>>,
}

fn revision(bundle: &CatalogBundle) -> Result<SignedRecord<PagedUserRevision>, CatalogStoreError> {
    bundle.validate()?;
    let signed = PagedUserRevision::decode_signed(&bundle.descriptor)?;
    let sections = [
        CatalogSection::FileMetadata,
        CatalogSection::FileMetadata,
        CatalogSection::SectorReferences,
    ];
    if bundle.id != signed.value.revision_id
        || bundle.scope != signed.value.scope()
        || !matches!(bundle.roots.len(), 3 | 6)
        || bundle.roots[..3]
            .iter()
            .zip(sections)
            .any(|(member, section)| member.intent.section != section)
        || bundle.roots[2].root != signed.value.sources.records.page
        || bundle.roots[3..]
            .iter()
            .any(|member| member.intent.section != CatalogSection::GitGraph)
    {
        return Err(DatabaseError::Conflict.into());
    }
    if bundle
        .roots
        .iter()
        .map(|member| member.root.byte_len)
        .sum::<u64>()
        > CATALOG_MAX_STREAM_BYTES
        || bundle
            .roots
            .iter()
            .map(|member| member.root.page_occurrences)
            .sum::<u64>()
            > CATALOG_MAX_PAGE_OCCURRENCES
    {
        return Err(CatalogError::Bounds.into());
    }
    Ok(signed)
}

fn check_bootstrap(
    signed: &SignedRecord<PagedUserRevision>,
    bytes: &[u8],
) -> Result<(), CatalogStoreError> {
    let metadata = &signed.value.metadata;
    if bytes.len() != V1_SECTOR_SIZE
        || sector_root(bytes) != metadata.sector.root
        || merkle_commit(bytes).map_err(ModelError::from)? != metadata.commitment
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn matches_manifest(
    bundle: &CatalogBundle,
    manifest: CatalogNativeValidation,
    signed: &SignedRecord<PagedUserRevision>,
) -> bool {
    manifest.id == bundle.id
        && manifest.scope == bundle.scope
        && manifest.sources == signed.value.sources
        && manifest.files.namespace.records.page == bundle.roots[0].root
        && manifest.files.recipes.records.page == bundle.roots[1].root
}

fn marker(signed: &SignedRecord<PagedUserRevision>) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(canonical_bytes(&(1_u16, signed.value.hash()?))?)
}

pub(super) fn snapshot(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
    let Some((bundle, state)) = bundle::bundle_snapshot(connection, id)? else {
        if bounded_record(connection, PUBLICATION, id.as_bytes(), 64)?.is_some()
            || bounded_record(
                connection,
                REVISION,
                id.as_bytes(),
                PAGED_USER_REVISION_BYTES,
            )?
            .is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let signed = revision(&bundle)?;
    if bounded_record(connection, PUBLICATION, id.as_bytes(), 64)?.as_deref()
        != Some(marker(&signed)?.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    let (manifest, validation_state) =
        native_validation::validation_snapshot(connection, id)?.ok_or(DatabaseError::Integrity)?;
    if !matches_manifest(&bundle, manifest, &signed) {
        return Err(DatabaseError::Integrity.into());
    }
    let sector_id = signed.value.metadata.sector.id;
    let pins = bootstrap_pins(sector_id);
    let bootstrap = match state {
        CatalogBundleState::Published => {
            native_validation::require_publication_link(connection, id)?;
            if validation_state != CatalogNativeValidationState::Verified
                || bounded_record(
                    connection,
                    REVISION,
                    id.as_bytes(),
                    PAGED_USER_REVISION_BYTES,
                )?
                .as_deref()
                    != Some(bundle.descriptor.as_slice())
                || bounded_record(connection, &pins, id.as_bytes(), 0)?.as_deref() != Some(&[])
            {
                return Err(DatabaseError::Integrity.into());
            }
            let bytes = bounded_record(connection, BOOTSTRAP, &sector_id, V1_SECTOR_SIZE)?
                .ok_or(DatabaseError::Integrity)?;
            check_bootstrap(&signed, &bytes)?;
            Some(bytes)
        }
        CatalogBundleState::Cancelled => {
            native_validation::require_unpublished_validation(connection, id)?;
            if validation_state != CatalogNativeValidationState::Cancelled
                || bounded_record(
                    connection,
                    REVISION,
                    id.as_bytes(),
                    PAGED_USER_REVISION_BYTES,
                )?
                .is_some()
                || bounded_record(connection, &pins, id.as_bytes(), 0)?.is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
            None
        }
    };
    Ok(Some(PagedCatalogSnapshot {
        bundle,
        state,
        bootstrap,
    }))
}

impl ControlStore {
    /// Bind all typed roots, completed native validation, signed migration
    /// record and shared bootstrap ciphertext in one writer transaction.
    /// The check may use only the supplied read view; publication/cancellation
    /// from another connection cannot race its checks. It must authenticate
    /// the private descriptor and joins; this does not advance a backup head.
    pub fn publish_paged_revision_catalog_checked<E: From<CatalogStoreError>>(
        &self,
        bundle: &CatalogBundle,
        bootstrap: &[u8],
        check: impl FnOnce(&CatalogPublicationView<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let signed = revision(bundle)?;
        check_bootstrap(&signed, bootstrap)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(CatalogStoreError::from)?;
        let manifest = native_validation::verified_manifest(&transaction, bundle.id)?;
        if !matches_manifest(bundle, manifest, &signed) {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        check(&CatalogPublicationView {
            connection: &transaction,
            manifest,
            bundle,
        })?;
        bundle::publish_bundle(&transaction, bundle)?;
        retained_source_quota::close(&transaction, bundle.id, bundle.scope, false)?;
        native_validation::link_publication(&transaction, bundle.id)?;
        insert_exact(
            &transaction,
            REVISION,
            bundle.id.as_bytes(),
            &bundle.descriptor,
        )?;
        insert_exact(
            &transaction,
            BOOTSTRAP,
            &signed.value.metadata.sector.id,
            bootstrap,
        )?;
        insert_exact(
            &transaction,
            &bootstrap_pins(signed.value.metadata.sector.id),
            bundle.id.as_bytes(),
            &[],
        )?;
        insert_exact(
            &transaction,
            PUBLICATION,
            bundle.id.as_bytes(),
            &marker(&signed)?,
        )?;
        transaction.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    pub fn paged_revision_catalog(
        &self,
        id: Uuid,
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        let transaction = self.read_snapshot()?;
        let result = snapshot(&transaction, id)?;
        transaction.commit()?;
        Ok(result)
    }

    /// Inspect a page source without requiring its payload, so recovery can
    /// repair missing bytes. Cancellation fences the source immediately.
    pub fn paged_revision_page_source(
        &self,
        id: Uuid,
        sector: [u8; 32],
    ) -> Result<Option<PagedCatalogPageSource>, CatalogStoreError> {
        let transaction = self.read_snapshot()?;
        let result = page_source(&transaction, id, sector)?;
        transaction.commit()?;
        Ok(result)
    }

    /// Return the source and authenticated page bytes in the same snapshot.
    pub fn read_paged_revision_page(
        &self,
        id: Uuid,
        sector: [u8; 32],
    ) -> Result<Option<(PagedCatalogPageSource, Vec<u8>)>, CatalogStoreError> {
        let transaction = self.read_snapshot()?;
        let result = if let Some(source) = page_source(&transaction, id, sector)? {
            let encoded = read_page(
                &transaction,
                PageMetadata {
                    format_version: 1,
                    scope: source.intent.scope,
                    section: source.intent.section,
                    reference: source.page,
                },
            )?;
            Some((source, encoded))
        } else {
            None
        };
        transaction.commit()?;
        Ok(result)
    }

    /// Recheck live revision ownership and exact source identity under the
    /// writer before repairing only the authenticated immutable page payload.
    pub fn repair_paged_revision_page(
        &self,
        expected: &PagedCatalogPageSource,
        encoded: &[u8],
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if page_source(
            &transaction,
            expected.catalog.bundle.id,
            expected.source.sector.id,
        )?
        .as_ref()
            != Some(expected)
        {
            return Err(DatabaseError::Conflict.into());
        }
        source::repair_payload(
            &transaction,
            PageMetadata {
                format_version: 1,
                scope: expected.intent.scope,
                section: expected.intent.section,
                reference: expected.page,
            },
            encoded,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Release one cancelled revision's source-index row. Root/page pins have
    /// their own existing bounded cleanup; cancellation journals remain.
    pub fn release_paged_revision_page_source(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if snapshot(&transaction, id)?
            .ok_or(DatabaseError::NotReady)?
            .state
            != CatalogBundleState::Cancelled
        {
            return Err(DatabaseError::Conflict.into());
        }
        let kind = page_sources(id);
        let key: Option<Option<Vec<u8>>> = transaction
            .query_row(
                "SELECT CASE WHEN length(record_id) = 32 THEN record_id END
             FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
                params![kind],
                |row| row.get(0),
            )
            .optional()?;
        let removed = if let Some(key) = key {
            let key = key.ok_or(DatabaseError::Integrity)?;
            if transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![kind, key],
            )? != 1
            {
                return Err(DatabaseError::Conflict.into());
            }
            true
        } else {
            false
        };
        transaction.commit()?;
        Ok(removed)
    }

    /// Resolve one live bootstrap owner by its indexed sector namespace. The
    /// pin, signed identity, root ownership and ciphertext are checked in one
    /// read snapshot. No history scan or caller-supplied revision is needed.
    pub fn paged_revision_bootstrap_catalog(
        &self,
        sector_id: [u8; 32],
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        let transaction = self.read_snapshot()?;
        let owner: Option<Option<Vec<u8>>> = transaction
            .query_row(
                "SELECT CASE WHEN length(record_id) = 16 AND length(bytes) = 0
                 THEN record_id END FROM protocol_records WHERE kind = ?1
                 ORDER BY record_id LIMIT 1",
                params![bootstrap_pins(sector_id)],
                |row| row.get(0),
            )
            .optional()?;
        let result = match owner {
            Some(Some(owner)) => {
                let id = Uuid::from_slice(&owner).map_err(|_| DatabaseError::Integrity)?;
                let current = snapshot(&transaction, id)?.ok_or(DatabaseError::Integrity)?;
                if current.state != CatalogBundleState::Published
                    || revision(&current.bundle)?.value.metadata.sector.id != sector_id
                {
                    return Err(DatabaseError::Integrity.into());
                }
                Some(current)
            }
            Some(None) => return Err(DatabaseError::Integrity.into()),
            None => {
                if bounded_record(&transaction, BOOTSTRAP, &sector_id, V1_SECTOR_SIZE)?.is_some() {
                    return Err(DatabaseError::Integrity.into());
                }
                None
            }
        };
        transaction.commit()?;
        Ok(result)
    }

    /// Cancel validation and every root together, then remove this revision's
    /// bootstrap pin. Shared ciphertext is deleted only after its last owner.
    /// Existing cancellation journals fence replay until generation-floor GC.
    pub fn cancel_paged_revision_catalog(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let current = snapshot(&transaction, id)?.ok_or(DatabaseError::NotReady)?;
        paged_checkpoint_revision::require_unretained(&transaction, id)?;
        if current.state == CatalogBundleState::Cancelled {
            return Ok(());
        }
        let signed = revision(&current.bundle)?;
        native_validation::cancel_linked_publication(&transaction, id)?;
        bundle::cancel_bundle(&transaction, id)?;
        retained_source_quota::close(&transaction, id, current.bundle.scope, true)?;
        for kind in [
            REVISION.to_owned(),
            bootstrap_pins(signed.value.metadata.sector.id),
        ] {
            if transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![kind, id.as_bytes()],
            )? != 1
            {
                return Err(DatabaseError::Conflict.into());
            }
        }
        let pins = bootstrap_pins(signed.value.metadata.sector.id);
        let retained: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
            params![pins],
            |row| row.get(0),
        )?;
        if !retained
            && transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![BOOTSTRAP, signed.value.metadata.sector.id],
            )? != 1
        {
            return Err(DatabaseError::Conflict.into());
        }
        paged_checkpoint_revision::require_unretained(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use mb_core::{
        CatalogFileBuilder, CatalogFileRecipeBuilder, CatalogFileStat, CatalogNativeFileRoot,
        CatalogSectorBuilder, KeyMaterial, PAGED_USER_REVISION_VERSION, PagedRevisionSourceReader,
        SectorPurpose, Seed, V1_CIPHER_PROFILE, WriterFence, encrypted_sector,
        make_content_sector_id,
    };

    use super::*;

    fn keys() -> KeyMaterial {
        KeyMaterial::from_seed(&Seed::from_bytes([71; 32]))
    }
    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [73; 32],
            owner: keys().node_id(),
            protected_root_id: Uuid::from_bytes([74; 16]),
        }
    }

    pub(crate) fn fixture(
        store: &ControlStore,
        sequence: u64,
        parent: Option<[u8; 32]>,
    ) -> (CatalogBundle, Vec<u8>) {
        fixture_with_context(
            store,
            sequence,
            parent,
            &keys(),
            &SigningKey::from_bytes(&[72; 32]),
            scope(),
        )
    }

    pub(crate) fn fixture_with_context(
        store: &ControlStore,
        sequence: u64,
        parent: Option<[u8; 32]>,
        keys: &KeyMaterial,
        writer: &SigningKey,
        scope: CatalogScope,
    ) -> (CatalogBundle, Vec<u8>) {
        let CatalogScope::Dataset {
            guild_id,
            protected_root_id,
            ..
        } = scope
        else {
            panic!("test dataset scope")
        };
        let intents = [
            CatalogSection::FileMetadata,
            CatalogSection::FileMetadata,
            CatalogSection::SectorReferences,
        ]
        .map(|section| CatalogIntent {
            id: Uuid::new_v4(),
            scope,
            section,
        });
        for intent in intents {
            store.begin_catalog(intent).unwrap();
        }
        let mut private_pages = BTreeMap::new();
        let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| {
            private_pages.insert(page.hash, (page, bytes.clone()));
            store.stage_catalog_page(intents[0], page, &bytes)
        };
        let namespace = CatalogFileBuilder::new(
            scope,
            CatalogFileStat {
                mode: 0o700,
                modified_secs: 123,
                modified_nanos: 456,
            },
        )
        .unwrap()
        .finish(&mut sink)
        .unwrap();
        let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| {
            private_pages.insert(page.hash, (page, bytes.clone()));
            store.stage_catalog_page(intents[1], page, &bytes)
        };
        let recipes = CatalogFileRecipeBuilder::new(scope)
            .unwrap()
            .finish(&mut sink)
            .unwrap();
        let files = CatalogNativeFileRoot {
            format_version: 1,
            namespace,
            recipes,
        };
        // The no-Git wire layout is identical to Node's typed descriptor.
        let plaintext = canonical_bytes(&(PAGED_USER_REVISION_VERSION, files, None::<()>)).unwrap();
        let id = make_content_sector_id(
            &keys.guild_content_id_key(&guild_id),
            keys.node_id(),
            guild_id,
            protected_root_id,
            SectorPurpose::Metadata,
            &plaintext,
        )
        .unwrap();
        let (sector, bootstrap) =
            encrypted_sector(&keys.guild_data_key(&guild_id), id, &plaintext).unwrap();
        let metadata = CatalogSectorRecord {
            format_version: 1,
            sector,
            commitment: merkle_commit(&bootstrap).unwrap(),
        };
        let mut records = BTreeMap::new();
        records.insert(metadata.sector.id, metadata.clone());
        for (_, (page, bytes)) in private_pages {
            let (sector, bytes) = page
                .seal_private_page(
                    &keys.guild_content_id_key(&guild_id),
                    &keys.guild_data_key(&guild_id),
                    scope,
                    CatalogSection::FileMetadata,
                    &bytes,
                )
                .unwrap();
            records.insert(
                sector.id,
                CatalogSectorRecord {
                    format_version: 1,
                    sector,
                    commitment: merkle_commit(&bytes).unwrap(),
                },
            );
        }
        let mut sources = CatalogSectorBuilder::new(scope).unwrap();
        let mut sink = |page, bytes: Vec<u8>| store.stage_catalog_page(intents[2], page, &bytes);
        for record in records.values() {
            sources.push(record, &mut sink).unwrap();
        }
        let sources = sources.finish(&mut sink).unwrap();
        let id = Uuid::new_v4();
        let signed = PagedUserRevision {
            format_version: PAGED_USER_REVISION_VERSION,
            guild_id,
            protected_root_id,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: id,
            owner: keys.node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: vec![],
            sequence,
            parent,
            metadata,
            sources,
        }
        .sign(writer, keys)
        .unwrap();
        store
            .validate_native_file_catalog(CatalogNativeValidation {
                id,
                scope,
                files,
                sources,
            })
            .unwrap();
        let roots = [
            files.namespace.records.page,
            files.recipes.records.page,
            sources.records.page,
        ];
        let bundle = CatalogBundle {
            id,
            scope,
            roots: intents
                .into_iter()
                .zip(roots)
                .map(|(intent, root)| CatalogBundleRoot { intent, root })
                .collect(),
            descriptor: canonical_bytes(&signed).unwrap(),
        };
        (bundle, bootstrap)
    }

    fn publish(
        store: &ControlStore,
        bundle: &CatalogBundle,
        bootstrap: &[u8],
    ) -> Result<(), CatalogStoreError> {
        let signed = revision(bundle)?;
        let fence = WriterFence {
            owner: signed.value.owner,
            epoch: signed.value.writer_epoch,
            public_key: signed.value.writer_public_key,
        };
        store.publish_paged_revision_catalog_checked(bundle, bootstrap, |view| {
            let mut reader =
                PagedRevisionSourceReader::new(&signed, [73; 32], keys().node_id(), &fence)?;
            while let Some(record) = reader
                .next_sector(&mut |page| view.catalog_page(CatalogSection::SectorReferences, page))
                .map_err(|error| match error {
                    mb_core::CatalogStreamError::Catalog(error) => CatalogStoreError::from(error),
                    mb_core::CatalogStreamError::Storage(error) => error,
                })?
            {
                if view.source(record.sector.id)?.as_ref() != Some(&record) {
                    return Err(DatabaseError::Integrity.into());
                }
            }
            assert!(reader.is_complete());
            for member in bundle
                .roots
                .iter()
                .filter(|member| member.intent.section.is_private())
            {
                let mut reader =
                    mb_core::CatalogReader::new(bundle.scope, member.intent.section, member.root)?;
                while reader
                    .next_leaf(&mut |page| -> Result<Vec<u8>, CatalogStoreError> {
                        let encoded = view.catalog_page(member.intent.section, page)?;
                        let (sector, ciphertext) = page.seal_private_page(
                            &keys().guild_content_id_key(&[73; 32]),
                            &keys().guild_data_key(&[73; 32]),
                            bundle.scope,
                            member.intent.section,
                            &encoded,
                        )?;
                        view.bind_private_page_source(
                            member.intent,
                            page,
                            &CatalogSectorRecord {
                                format_version: 1,
                                sector,
                                commitment: merkle_commit(&ciphertext).map_err(ModelError::from)?,
                            },
                        )?;
                        Ok(encoded)
                    })
                    .map_err(|error| match error {
                        mb_core::CatalogStreamError::Catalog(error) => {
                            CatalogStoreError::from(error)
                        }
                        mb_core::CatalogStreamError::Storage(error) => error,
                    })?
                    .is_some()
                {}
            }
            Ok(())
        })
    }

    #[test]
    fn paged_sector_lookup_migrates_v9_bindings_without_mutating_read_only_history() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (bundle, bootstrap) = fixture(&store, 1, None);
        publish(&store, &bundle, &bootstrap).unwrap();
        let rows = store.records(&page_sources(bundle.id)).unwrap();
        let sector = rows[0].0.as_slice().try_into().unwrap();
        let expected = store
            .paged_revision_page_source(bundle.id, sector)
            .unwrap()
            .unwrap();
        store
            .connection
            .execute_batch("DROP INDEX protocol_records_paged_sector_sources;")
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                [9_u32.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(store);
        let original = std::fs::read(&path).unwrap();
        let reader = ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(
            reader
                .paged_revision_page_source(bundle.id, sector)
                .unwrap(),
            Some(expected.clone())
        );
        assert!(reader.paged_sector_source(sector).unwrap().is_none());
        drop(reader);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(store.records(&page_sources(bundle.id)).unwrap(), rows);
        assert_eq!(
            store.paged_sector_source(sector).unwrap(),
            Some(PagedCatalogSectorSource::Page(expected))
        );
        let details: String = store.connection.query_row(
            "EXPLAIN QUERY PLAN SELECT kind FROM protocol_records
             INDEXED BY protocol_records_paged_sector_sources
             WHERE record_id = ?1 AND kind > ''
               AND (kind GLOB 'catalog-paged-data-source-v1/*' OR kind GLOB 'catalog-paged-page-source-v1/*')
             ORDER BY kind LIMIT 1", params![sector], |row| row.get(3)).unwrap();
        assert!(
            details.contains("SEARCH")
                && details.contains("protocol_records_paged_sector_sources")
                && details.contains("record_id=?"),
            "{details}"
        );
        drop(store);
        ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).unwrap();
    }

    #[test]
    fn paged_sector_index_migration_rolls_back_rejected_metadata_and_checks_index_schema() {
        for key in ["database_kind", "schema_version"] {
            for fault in ["ABORT", "IGNORE"] {
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("control.db");
                let mut store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
                store.put_record("preserved", b"id", b"original").unwrap();
                store
                    .connection
                    .execute_batch("DROP INDEX protocol_records_paged_sector_sources;")
                    .unwrap();
                store
                    .connection
                    .execute(
                        "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                        [9_u32.to_be_bytes().as_slice()],
                    )
                    .unwrap();
                // TEMP triggers do not alter the persistent schema that is
                // validated before migration, but fault its writer transaction.
                let raise = if fault == "IGNORE" {
                    "RAISE(IGNORE)"
                } else {
                    "RAISE(ABORT, 'injected')"
                };
                store.connection.execute_batch(&format!("CREATE TEMP TRIGGER reject_migration BEFORE UPDATE ON main.meta WHEN OLD.key = '{key}' BEGIN SELECT {raise}; END;")).unwrap();
                assert!(super::super::super::migrate_control(&mut store.connection).is_err());
                assert_eq!(
                    super::super::super::stored_schema_version(&store.connection).unwrap(),
                    9
                );
                assert!(!store.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'protocol_records_paged_sector_sources')", [], |row| row.get::<_, bool>(0)).unwrap());
                drop(store);
                let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
                assert_eq!(
                    store.get_record("preserved", b"id").unwrap(),
                    Some(b"original".to_vec())
                );
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        store.connection.execute_batch("DROP INDEX protocol_records_paged_sector_sources;
            CREATE INDEX protocol_records_paged_sector_sources ON protocol_records(kind, record_id);").unwrap();
        drop(store);
        assert!(ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).is_err());
        assert!(ControlStore::open_existing_with_key(&path, &[7; 32]).is_err());
    }

    #[test]
    fn paged_sector_lookup_tracks_shared_live_owners_and_rejects_damaged_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (first, bootstrap) = fixture(&store, 1, None);
        let (next, next_bootstrap) = fixture(
            &store,
            2,
            Some(revision(&first).unwrap().value.hash().unwrap()),
        );
        publish(&store, &first, &bootstrap).unwrap();
        publish(&store, &next, &next_bootstrap).unwrap();
        let sector = store.records(&page_sources(first.id)).unwrap()[0]
            .0
            .as_slice()
            .try_into()
            .unwrap();
        assert!(store.paged_sector_source([0; 32]).unwrap().is_none());
        let selected = store.paged_sector_source(sector).unwrap().unwrap();
        let selected_id = selected.catalog().bundle.id;
        let remaining_id = if selected_id == first.id {
            next.id
        } else {
            first.id
        };
        let kind = page_sources(selected_id);
        let original = store.get_record(&kind, &sector).unwrap().unwrap();
        for bytes in [b"bad".to_vec(), vec![0; CATALOG_SECTOR_RECIPE_BYTES + 1]] {
            store.put_record(&kind, &sector, &bytes).unwrap();
            assert!(store.paged_sector_source(sector).is_err());
        }
        store.put_record(&kind, &sector, &original).unwrap();
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        store.cancel_paged_revision_catalog(selected_id).unwrap();
        assert_eq!(
            store
                .paged_sector_source(sector)
                .unwrap()
                .unwrap()
                .catalog()
                .bundle
                .id,
            remaining_id
        );
        store.cancel_paged_revision_catalog(remaining_id).unwrap();
        assert!(store.paged_sector_source(sector).unwrap().is_none());
        for id in [selected_id, remaining_id] {
            while store.release_paged_revision_page_source(id).unwrap() {}
        }
        assert!(store.paged_sector_source(sector).unwrap().is_none());
        for suffix in [
            "bogus".to_string(),
            "f".repeat(4096),
            Uuid::nil().simple().to_string(),
            Uuid::new_v4().simple().to_string(),
        ] {
            let kind = format!("catalog-paged-page-source-v1/{suffix}");
            store.put_record(&kind, &sector, b"orphaned").unwrap();
            assert!(store.paged_sector_source(sector).is_err());
            store.delete_record(&kind, &sector).unwrap();
        }
        let (live, bootstrap) = fixture(&store, 1, None);
        publish(&store, &live, &bootstrap).unwrap();
        assert!(store.paged_sector_source(sector).unwrap().is_some());
        store
            .connection
            .execute_batch("DROP INDEX protocol_records_paged_sector_sources;")
            .unwrap();
        assert!(store.paged_sector_source(sector).is_err());
    }

    #[test]
    fn paged_sector_lookup_bounds_retired_owner_work_until_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let mut ids = Vec::new();
        let mut sector = None;
        for _ in 0..65 {
            let (bundle, bootstrap) = fixture(&store, 1, None);
            publish(&store, &bundle, &bootstrap).unwrap();
            sector = Some(
                store.records(&page_sources(bundle.id)).unwrap()[0]
                    .0
                    .as_slice()
                    .try_into()
                    .unwrap(),
            );
            store.cancel_paged_revision_catalog(bundle.id).unwrap();
            ids.push(bundle.id);
        }
        let sector = sector.unwrap();
        assert!(matches!(
            store.paged_sector_source(sector),
            Err(CatalogStoreError::PagedSourceLookupLimit)
        ));
        assert!(store.release_paged_revision_page_source(ids[0]).unwrap());
        // Exactly 64 retired owners reach authenticated absence, without an
        // extra false budget error on the final indexed EOF query.
        assert!(store.paged_sector_source(sector).unwrap().is_none());
        assert!(store.release_paged_revision_page_source(ids[1]).unwrap());
        let (live, bootstrap) = fixture(&store, 1, None);
        publish(&store, &live, &bootstrap).unwrap();
        assert_eq!(
            store
                .paged_sector_source(sector)
                .unwrap()
                .unwrap()
                .catalog()
                .bundle
                .id,
            live.id
        );
    }

    #[test]
    fn paged_data_owner_cursor_reopens_and_visits_cancelled_pins_without_scanning_history() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let anchor = Uuid::new_v4();
        let owners = [
            data_fixture(&store, anchor),
            data_fixture(&store, anchor),
            data_fixture(&store, anchor),
        ];
        let sector = owners[0].source.sector.id;
        store
            .cancel_paged_revision_catalog(owners[1].catalog.bundle.id)
            .unwrap();
        let mut expected = owners
            .iter()
            .map(|owner| owner.catalog.bundle.id)
            .collect::<Vec<_>>();
        expected.sort();
        drop(store);
        let mut after = None;
        let mut visited = Vec::new();
        loop {
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            let Some((id, source)) = store
                .next_paged_revision_data_source(sector, after)
                .unwrap()
            else {
                break;
            };
            assert_eq!(source.is_none(), id == owners[1].catalog.bundle.id);
            if let Some(source) = source {
                assert_eq!(
                    source,
                    *owners
                        .iter()
                        .find(|owner| owner.catalog.bundle.id == id)
                        .unwrap()
                );
            }
            visited.push(id);
            after = Some(id);
        }
        assert_eq!(visited, expected);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
        assert!(
            store
                .next_paged_revision_data_source([0; 32], None)
                .unwrap()
                .is_none()
        );
        store
            .put_record("catalog-paged-data-source-v1/invalid", &sector, b"invalid")
            .unwrap();
        assert!(
            store
                .next_paged_revision_data_source(sector, after)
                .is_err()
        );
        store
            .put_record("catalog-paged-data-source-v1/", &[1; 32], b"invalid")
            .unwrap();
        assert!(
            store
                .next_paged_revision_data_source([1; 32], None)
                .is_err()
        );
    }

    #[test]
    fn paged_data_source_replacement_fences_stale_attempts_and_transfers_shared_pins() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let first = data_fixture(&store, a);
        let other = data_fixture(&store, a);
        let denied: Result<_, CatalogStoreError> = store
            .replace_paged_revision_data_source_checked(&first, b, b"source-b", |_| {
                Err(DatabaseError::Conflict.into())
            });
        assert!(denied.is_err());
        assert_eq!(
            store
                .paged_revision_data_source(first.catalog.bundle.id, first.source.sector.id)
                .unwrap(),
            Some(first.clone())
        );
        assert!(!store.paged_data_anchor_is_pinned(b).unwrap());
        let next = store
            .replace_paged_revision_data_source_checked(
                &first,
                b,
                b"source-b",
                |current| -> Result<(), CatalogStoreError> {
                    assert_eq!(current, &first);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(next.generation, 1);
        assert!(store.paged_data_anchor_is_pinned(a).unwrap());
        assert!(store.paged_data_anchor_is_pinned(b).unwrap());
        assert_eq!(
            store
                .replace_paged_revision_data_source_checked(&first, b, b"source-b", |_| Ok::<
                    _,
                    CatalogStoreError,
                >(
                    ()
                ))
                .unwrap(),
            next
        );
        assert!(
            store
                .replace_paged_revision_data_source_checked(
                    &first,
                    c,
                    b"source-c",
                    |_| -> Result<(), CatalogStoreError> { panic!("stale source reached check") }
                )
                .is_err()
        );
        let moved_other = store
            .replace_paged_revision_data_source_checked(&other, b, b"source-b", |_| {
                Ok::<_, CatalogStoreError>(())
            })
            .unwrap();
        assert!(!store.paged_data_anchor_is_pinned(a).unwrap());
        let changed_range = store
            .replace_paged_revision_data_source_checked(&next, b, b"source-b-range-2", |_| {
                Ok::<_, CatalogStoreError>(())
            })
            .unwrap();
        assert_eq!(changed_range.generation, 2);
        let back = store
            .replace_paged_revision_data_source_checked(&changed_range, a, b"source-a", |_| {
                Ok::<_, CatalogStoreError>(())
            })
            .unwrap();
        assert_eq!(back.generation, 3);
        // Returning to identical recipe bytes must not resurrect an old fence.
        assert!(
            store
                .replace_paged_revision_data_source_checked(&first, c, b"source-c", |_| Ok::<
                    _,
                    CatalogStoreError,
                >(
                    ()
                ))
                .is_err()
        );
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(
            store
                .paged_revision_data_source(first.catalog.bundle.id, first.source.sector.id)
                .unwrap(),
            Some(back)
        );
        for source in [&first, &moved_other] {
            store
                .cancel_paged_revision_catalog(source.catalog.bundle.id)
                .unwrap();
            assert!(
                store
                    .replace_paged_revision_data_source_checked(source, c, b"source-c", |_| Ok::<
                        _,
                        CatalogStoreError,
                    >(
                        ()
                    ))
                    .is_err()
            );
            assert!(
                store
                    .release_paged_revision_data_source(source.catalog.bundle.id)
                    .unwrap()
            );
        }
        assert!(store.paged_data_anchor_ids().unwrap().is_empty());
    }

    fn data_fixture(store: &ControlStore, anchor: Uuid) -> super::super::PagedCatalogDataSource {
        let (bundle, bytes) = fixture(store, 1, None);
        let member = &bundle.roots[0];
        let page = member.root;
        let encoded = store
            .catalog_page(bundle.scope, member.intent.section, page)
            .unwrap();
        let (sector, ciphertext) = page
            .seal_private_page(
                &keys().guild_content_id_key(&[73; 32]),
                &keys().guild_data_key(&[73; 32]),
                bundle.scope,
                member.intent.section,
                &encoded,
            )
            .unwrap();
        let source = CatalogSectorRecord {
            format_version: 1,
            sector,
            commitment: merkle_commit(&ciphertext).unwrap(),
        };
        store
            .publish_paged_revision_catalog_checked(&bundle, &bytes, |view| {
                view.bind_data_source(&source, anchor, b"source-a")
            })
            .unwrap();
        let result = store
            .paged_revision_data_source(bundle.id, source.sector.id)
            .unwrap()
            .unwrap();
        paged_data::make_inline_for_test(store, &result);
        result
    }

    #[test]
    fn paged_data_source_replacement_preserves_competing_connection_and_legacy_generation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let original = data_fixture(&store, a);
        let id = original.catalog.bundle.id;
        let sector = original.source.sector.id;
        let kind = format!("catalog-paged-data-source-v1/{}", id.simple());
        let legacy =
            canonical_bytes(&(1_u16, &original.source, a, original.recipe.clone())).unwrap();
        store.put_record(&kind, &sector, &legacy).unwrap();
        assert_eq!(
            store.paged_revision_data_source(id, sector).unwrap(),
            Some(original.clone())
        );
        store
            .publish_paged_revision_catalog_checked(
                &original.catalog.bundle,
                original.catalog.bootstrap.as_ref().unwrap(),
                |view| view.bind_data_source(&original.source, a, &original.recipe),
            )
            .unwrap();
        assert_eq!(store.get_record(&kind, &sector).unwrap(), Some(legacy));
        let other = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        let moved = other
            .replace_paged_revision_data_source_checked(&original, b, b"source-b", |_| {
                Ok::<_, CatalogStoreError>(())
            })
            .unwrap();
        assert_eq!(moved.generation, 1);
        assert!(
            store
                .replace_paged_revision_data_source_checked(
                    &original,
                    Uuid::new_v4(),
                    b"competing",
                    |_| Ok::<_, CatalogStoreError>(())
                )
                .is_err()
        );
        assert_eq!(
            store.paged_revision_data_source(id, sector).unwrap(),
            Some(moved.clone())
        );
        paged_data::make_inline_for_test(&store, &moved);
        let exhausted =
            canonical_bytes(&(2_u16, &moved.source, b, moved.recipe.clone(), u64::MAX)).unwrap();
        store.put_record(&kind, &sector, &exhausted).unwrap();
        let last = store
            .paged_revision_data_source(id, sector)
            .unwrap()
            .unwrap();
        assert!(
            store
                .replace_paged_revision_data_source_checked(&last, a, b"source-a", |_| Ok::<
                    _,
                    CatalogStoreError,
                >(
                    ()
                ))
                .is_err()
        );
        assert_eq!(store.get_record(&kind, &sector).unwrap(), Some(exhausted));
        assert!(!store.paged_data_anchor_is_pinned(a).unwrap());
        other.cancel_paged_revision_catalog(id).unwrap();
        assert!(
            store
                .replace_paged_revision_data_source_checked(&last, a, b"source-a", |_| Ok::<
                    _,
                    CatalogStoreError,
                >(
                    ()
                ))
                .is_err()
        );
    }

    #[test]
    fn paged_data_source_replacement_rolls_back_source_and_every_pin_boundary() {
        for boundary in 0..5 {
            for fault in ["ABORT", "IGNORE"] {
                let temp = tempfile::tempdir().unwrap();
                let store =
                    ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
                let a = Uuid::new_v4();
                let b = Uuid::new_v4();
                let original = data_fixture(&store, a);
                if boundary == 3 {
                    data_fixture(&store, a);
                }
                if boundary == 2 {
                    data_fixture(&store, b);
                }
                let before = store.records(paged_data::ANCHOR).unwrap();
                let (operation, predicate) = match boundary {
                    0 => (
                        "UPDATE",
                        "NEW.kind LIKE 'catalog-paged-data-source-v1/%'".to_owned(),
                    ),
                    1 => (
                        "INSERT",
                        format!(
                            "NEW.kind = '{}' AND NEW.record_id = X'{}'",
                            paged_data::ANCHOR,
                            b.simple()
                        ),
                    ),
                    2 => (
                        "UPDATE",
                        format!(
                            "NEW.kind = '{}' AND NEW.record_id = X'{}'",
                            paged_data::ANCHOR,
                            b.simple()
                        ),
                    ),
                    3 => (
                        "UPDATE",
                        format!(
                            "NEW.kind = '{}' AND NEW.record_id = X'{}'",
                            paged_data::ANCHOR,
                            a.simple()
                        ),
                    ),
                    4 => (
                        "DELETE",
                        format!(
                            "OLD.kind = '{}' AND OLD.record_id = X'{}'",
                            paged_data::ANCHOR,
                            a.simple()
                        ),
                    ),
                    _ => unreachable!(),
                };
                let raise = if fault == "ABORT" {
                    "RAISE(ABORT, 'injected')"
                } else {
                    "RAISE(IGNORE)"
                };
                store.connection.execute_batch(&format!("CREATE TRIGGER reject_replacement BEFORE {operation} ON protocol_records WHEN {predicate} BEGIN SELECT {raise}; END;")).unwrap();
                assert!(
                    store
                        .replace_paged_revision_data_source_checked(
                            &original,
                            b,
                            b"source-b",
                            |_| Ok::<_, CatalogStoreError>(())
                        )
                        .is_err(),
                    "boundary {boundary} {fault}"
                );
                assert_eq!(store.records(paged_data::ANCHOR).unwrap(), before);
                assert_eq!(
                    store
                        .paged_revision_data_source(
                            original.catalog.bundle.id,
                            original.source.sector.id
                        )
                        .unwrap(),
                    Some(original.clone())
                );
                store
                    .connection
                    .execute_batch("DROP TRIGGER reject_replacement")
                    .unwrap();
                assert_eq!(
                    store
                        .replace_paged_revision_data_source_checked(
                            &original,
                            b,
                            b"source-b",
                            |_| Ok::<_, CatalogStoreError>(())
                        )
                        .unwrap()
                        .generation,
                    1
                );
            }
        }
    }

    #[test]
    fn paged_stable_data_bindings_reopen_and_pin_shared_anchors_until_bounded_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (first, bytes) = fixture(&store, 1, None);
        let (next, next_bytes) = fixture(
            &store,
            2,
            Some(revision(&first).unwrap().value.hash().unwrap()),
        );
        let anchor = Uuid::new_v4();
        let page = first.roots[0].root;
        let encoded = store
            .catalog_page(first.scope, first.roots[0].intent.section, page)
            .unwrap();
        let (sector, ciphertext) = page
            .seal_private_page(
                &keys().guild_content_id_key(&[73; 32]),
                &keys().guild_data_key(&[73; 32]),
                first.scope,
                first.roots[0].intent.section,
                &encoded,
            )
            .unwrap();
        let source = CatalogSectorRecord {
            format_version: 1,
            sector,
            commitment: merkle_commit(&ciphertext).unwrap(),
        };
        for (bundle, bytes) in [(&first, &bytes), (&next, &next_bytes)] {
            for _ in 0..2 {
                store
                    .publish_paged_revision_catalog_checked(bundle, bytes, |view| {
                        view.bind_data_source(&source, anchor, b"bounded opaque recipe")
                    })
                    .unwrap();
            }
        }
        assert_eq!(store.paged_data_anchor_ids().unwrap(), [anchor]);
        assert!(store.release_paged_revision_data_source(first.id).is_err());
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(
            store
                .paged_revision_data_source(first.id, source.sector.id)
                .unwrap()
                .unwrap()
                .recipe,
            b"bounded opaque recipe"
        );
        store.cancel_paged_revision_catalog(first.id).unwrap();
        assert!(
            store
                .paged_revision_data_source(first.id, source.sector.id)
                .unwrap()
                .is_none()
        );
        assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
        assert!(store.release_paged_revision_data_source(first.id).unwrap());
        assert!(!store.release_paged_revision_data_source(first.id).unwrap());
        assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
        assert!(
            store
                .paged_revision_data_source(next.id, source.sector.id)
                .unwrap()
                .is_some()
        );
        store.cancel_paged_revision_catalog(next.id).unwrap();
        assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
        assert!(store.release_paged_revision_data_source(next.id).unwrap());
        assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
        assert!(store.paged_data_anchor_ids().unwrap().is_empty());
    }

    #[test]
    fn paged_stable_data_source_and_anchor_pin_writes_roll_back_together() {
        for kind in ["catalog-paged-data-source-v1/%", paged_data::ANCHOR] {
            for fault in ["ABORT", "IGNORE"] {
                let temp = tempfile::tempdir().unwrap();
                let store =
                    ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
                let (bundle, bytes) = fixture(&store, 1, None);
                let anchor = Uuid::new_v4();
                let page = bundle.roots[0].root;
                let encoded = store
                    .catalog_page(bundle.scope, bundle.roots[0].intent.section, page)
                    .unwrap();
                let (sector, ciphertext) = page
                    .seal_private_page(
                        &keys().guild_content_id_key(&[73; 32]),
                        &keys().guild_data_key(&[73; 32]),
                        bundle.scope,
                        bundle.roots[0].intent.section,
                        &encoded,
                    )
                    .unwrap();
                let source = CatalogSectorRecord {
                    format_version: 1,
                    sector,
                    commitment: merkle_commit(&ciphertext).unwrap(),
                };
                let raise = if fault == "ABORT" {
                    "RAISE(ABORT, 'injected')"
                } else {
                    "RAISE(IGNORE)"
                };
                store.connection.execute_batch(&format!("CREATE TRIGGER reject_data BEFORE INSERT ON protocol_records WHEN NEW.kind LIKE '{kind}' BEGIN SELECT {raise}; END;")).unwrap();
                assert!(
                    store
                        .publish_paged_revision_catalog_checked(&bundle, &bytes, |view| view
                            .bind_data_source(&source, anchor, b"recipe"))
                        .is_err()
                );
                assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
                assert!(store.paged_revision_catalog(bundle.id).unwrap().is_none());
                store
                    .connection
                    .execute_batch("DROP TRIGGER reject_data")
                    .unwrap();
                store
                    .publish_paged_revision_catalog_checked(&bundle, &bytes, |view| {
                        view.bind_data_source(&source, anchor, b"recipe")
                    })
                    .unwrap();
                store.cancel_paged_revision_catalog(bundle.id).unwrap();
                store.connection.execute_batch(&format!("CREATE TRIGGER reject_cleanup BEFORE DELETE ON protocol_records WHEN OLD.kind LIKE '{kind}' BEGIN SELECT {raise}; END;")).unwrap();
                assert!(store.release_paged_revision_data_source(bundle.id).is_err());
                assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
                store
                    .connection
                    .execute_batch("DROP TRIGGER reject_cleanup")
                    .unwrap();
                assert!(store.release_paged_revision_data_source(bundle.id).unwrap());
                assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
            }
        }
    }

    #[test]
    fn paged_page_sources_reopen_repair_and_retire_with_their_revision() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (first, bootstrap) = fixture(&store, 1, None);
        publish(&store, &first, &bootstrap).unwrap();
        publish(&store, &first, &bootstrap).unwrap();
        let rows = store.records(&page_sources(first.id)).unwrap();
        // Empty namespace and recipe share the same page under distinct intents.
        assert_eq!(rows.len(), 1);
        let sector: [u8; 32] = rows[0].0.as_slice().try_into().unwrap();
        let (source, encoded) = store
            .read_paged_revision_page(first.id, sector)
            .unwrap()
            .unwrap();
        assert!(store.release_paged_revision_page_source(first.id).is_err());
        let (next, next_bootstrap) = fixture(
            &store,
            2,
            Some(revision(&first).unwrap().value.hash().unwrap()),
        );
        publish(&store, &next, &next_bootstrap).unwrap();
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(
            store.read_paged_revision_page(first.id, sector).unwrap(),
            Some((source.clone(), encoded.clone()))
        );
        store
            .connection
            .execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![PAGE, source.page.hash],
            )
            .unwrap();
        assert!(store.read_paged_revision_page(first.id, sector).is_err());
        assert_eq!(
            store.paged_revision_page_source(first.id, sector).unwrap(),
            Some(source.clone())
        );
        assert!(
            store
                .repair_paged_revision_page(&source, b"damaged")
                .is_err()
        );
        store.repair_paged_revision_page(&source, &encoded).unwrap();
        store.cancel_paged_revision_catalog(first.id).unwrap();
        assert!(
            store
                .paged_revision_page_source(first.id, sector)
                .unwrap()
                .is_none()
        );
        assert!(store.repair_paged_revision_page(&source, &encoded).is_err());
        assert_eq!(
            store
                .read_paged_revision_page(next.id, sector)
                .unwrap()
                .unwrap()
                .1,
            encoded
        );
        assert!(store.release_paged_revision_page_source(first.id).unwrap());
        assert!(!store.release_paged_revision_page_source(first.id).unwrap());
        store.cancel_paged_revision_catalog(next.id).unwrap();
        assert!(store.release_paged_revision_page_source(next.id).unwrap());
        for bundle in [&first, &next] {
            while store
                .release_native_file_validation_record(bundle.id)
                .unwrap()
            {}
            for member in &bundle.roots {
                while store.release_catalog_pin(member.intent).unwrap() {}
            }
        }
        while store.collect_catalog_page().unwrap() {}
        assert!(store.records(&page_sources(first.id)).unwrap().is_empty());
        assert!(store.records(&page_sources(next.id)).unwrap().is_empty());
    }

    #[test]
    fn paged_page_source_writes_fail_atomically_and_reads_bound_damaged_rows() {
        for action in ["ABORT", "IGNORE"] {
            let rejection = if action == "ABORT" {
                "RAISE(ABORT, 'injected')"
            } else {
                "RAISE(IGNORE)"
            };
            let temp = tempfile::tempdir().unwrap();
            let store =
                ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
            let (bundle, bootstrap) = fixture(&store, 1, None);
            store
                .connection
                .execute_batch(&format!(
                    "CREATE TRIGGER reject_source BEFORE INSERT ON protocol_records
                WHEN NEW.kind LIKE 'catalog-paged-page-source-v1/%' BEGIN SELECT {rejection}; END;"
                ))
                .unwrap();
            assert!(publish(&store, &bundle, &bootstrap).is_err());
            assert!(store.records(&page_sources(bundle.id)).unwrap().is_empty());
            assert!(store.paged_revision_catalog(bundle.id).unwrap().is_none());
            store
                .connection
                .execute_batch("DROP TRIGGER reject_source")
                .unwrap();
            publish(&store, &bundle, &bootstrap).unwrap();
            let rows = store.records(&page_sources(bundle.id)).unwrap();
            let sector: [u8; 32] = rows[0].0.as_slice().try_into().unwrap();
            store
                .put_record(&page_sources(bundle.id), &sector, &[0; 4096])
                .unwrap();
            assert!(store.paged_revision_page_source(bundle.id, sector).is_err());
            store
                .put_record(&page_sources(bundle.id), &sector, &rows[0].1)
                .unwrap();
            store.cancel_paged_revision_catalog(bundle.id).unwrap();
            store
                .connection
                .execute_batch(&format!(
                    "CREATE TRIGGER reject_source_delete BEFORE DELETE ON protocol_records
                WHEN OLD.kind LIKE 'catalog-paged-page-source-v1/%' BEGIN SELECT {rejection}; END;"
                ))
                .unwrap();
            assert!(store.release_paged_revision_page_source(bundle.id).is_err());
            assert_eq!(store.records(&page_sources(bundle.id)).unwrap(), rows);
            store
                .connection
                .execute_batch("DROP TRIGGER reject_source_delete")
                .unwrap();
            assert!(store.release_paged_revision_page_source(bundle.id).unwrap());
        }
    }

    #[test]
    fn paged_bootstrap_lookup_follows_shared_live_owners_across_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        assert!(
            store
                .paged_revision_bootstrap_catalog([0; 32])
                .unwrap()
                .is_none()
        );
        let (first, bytes) = fixture(&store, 1, None);
        let signed = revision(&first).unwrap();
        let sector = signed.value.metadata.sector.id;
        // Staged catalog pages do not establish bootstrap ownership.
        assert!(
            store
                .paged_revision_bootstrap_catalog(sector)
                .unwrap()
                .is_none()
        );
        publish(&store, &first, &bytes).unwrap();
        let (next, shared) = fixture(&store, 2, Some(signed.value.hash().unwrap()));
        publish(&store, &next, &shared).unwrap();
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(
            store
                .paged_revision_bootstrap_catalog(sector)
                .unwrap()
                .unwrap()
                .bootstrap,
            Some(bytes.clone())
        );
        // Retire the owner actually selected by the indexed lookup.
        let selected = store
            .paged_revision_bootstrap_catalog(sector)
            .unwrap()
            .unwrap()
            .bundle
            .id;
        store.cancel_paged_revision_catalog(selected).unwrap();
        let remaining = store
            .paged_revision_bootstrap_catalog(sector)
            .unwrap()
            .unwrap();
        assert_ne!(selected, remaining.bundle.id);
        assert_eq!(remaining.bootstrap, Some(bytes));
        store
            .cancel_paged_revision_catalog(remaining.bundle.id)
            .unwrap();
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert!(
            store
                .paged_revision_bootstrap_catalog(sector)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn paged_bootstrap_lookup_rejects_corrupt_or_unowned_sources() {
        for damage in 0..7 {
            let temp = tempfile::tempdir().unwrap();
            let store =
                ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
            let (bundle, mut bytes) = fixture(&store, 1, None);
            let sector = revision(&bundle).unwrap().value.metadata.sector.id;
            publish(&store, &bundle, &bytes).unwrap();
            let pins = bootstrap_pins(sector);
            match damage {
                0 => {
                    bytes[0] ^= 1;
                    store.put_record(BOOTSTRAP, &sector, &bytes).unwrap();
                }
                1 => {
                    store
                        .connection
                        .execute(
                            "DELETE FROM protocol_records WHERE kind = ?1",
                            params![pins],
                        )
                        .unwrap();
                }
                2 => {
                    store
                        .put_record(&pins, bundle.id.as_bytes(), &[0; 4096])
                        .unwrap();
                }
                3 => {
                    store
                        .connection
                        .execute(
                            "DELETE FROM protocol_records WHERE kind = ?1",
                            params![pins],
                        )
                        .unwrap();
                    store.put_record(&pins, &[0; 4096], &[]).unwrap();
                }
                4 => {
                    store
                        .connection
                        .execute(
                            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                            params![REVISION, bundle.id.as_bytes()],
                        )
                        .unwrap();
                }
                5 => {
                    store.cancel_paged_revision_catalog(bundle.id).unwrap();
                    store.put_record(&pins, bundle.id.as_bytes(), &[]).unwrap();
                }
                6 => {
                    store
                        .put_record(&bootstrap_pins([0; 32]), bundle.id.as_bytes(), &[])
                        .unwrap();
                    assert!(store.paged_revision_bootstrap_catalog([0; 32]).is_err());
                    continue;
                }
                _ => unreachable!(),
            }
            assert!(
                store.paged_revision_bootstrap_catalog(sector).is_err(),
                "damage {damage}"
            );
        }
    }

    #[test]
    fn paged_catalog_publication_reopens_and_retires_shared_bootstrap_only_after_last_owner() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (first, bytes) = fixture(&store, 1, None);
        publish(&store, &first, &bytes).unwrap();
        publish(&store, &first, &bytes).unwrap();
        let first_signed = revision(&first).unwrap();
        let (next, same_bytes) = fixture(&store, 2, Some(first_signed.value.hash().unwrap()));
        assert_eq!(bytes, same_bytes);
        publish(&store, &next, &same_bytes).unwrap();
        for bundle in [&first, &next] {
            let snapshot = store.paged_revision_catalog(bundle.id).unwrap().unwrap();
            assert_eq!(snapshot.bundle, *bundle);
            assert_eq!(snapshot.state, CatalogBundleState::Published);
            assert_eq!(snapshot.bootstrap.as_deref(), Some(bytes.as_slice()));
            assert!(store.cancel_catalog_bundle(bundle.id).is_err());
            assert!(
                store
                    .cancel_native_file_catalog_validation(bundle.id)
                    .is_err()
            );
            for member in &bundle.roots {
                assert!(store.cancel_catalog(member.intent).is_err());
            }
        }
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        store.cancel_paged_revision_catalog(first.id).unwrap();
        store.cancel_paged_revision_catalog(first.id).unwrap();
        assert_eq!(
            store
                .paged_revision_catalog(first.id)
                .unwrap()
                .unwrap()
                .state,
            CatalogBundleState::Cancelled
        );
        assert!(
            store
                .get_record(REVISION, first.id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .paged_revision_catalog(next.id)
                .unwrap()
                .unwrap()
                .bootstrap,
            Some(bytes)
        );
        assert!(publish(&store, &first, &same_bytes).is_err());
        store.cancel_paged_revision_catalog(next.id).unwrap();
        assert!(
            store
                .get_record(BOOTSTRAP, &first_signed.value.metadata.sector.id)
                .unwrap()
                .is_none()
        );
        for bundle in [&first, &next] {
            while store
                .release_native_file_validation_record(bundle.id)
                .unwrap()
            {}
            for member in &bundle.roots {
                while store.release_catalog_pin(member.intent).unwrap() {}
            }
        }
        while store.collect_catalog_page().unwrap() {}
        assert!(
            store
                .catalog_page(
                    first.scope,
                    CatalogSection::FileMetadata,
                    first.roots[0].root
                )
                .is_err()
        );
        assert!(
            store
                .paged_revision_catalog(first.id)
                .unwrap()
                .unwrap()
                .bootstrap
                .is_none()
        );
    }

    #[test]
    fn paged_catalog_publication_rolls_back_every_insert_boundary_and_rejected_check() {
        for kind in [
            "catalog-intent-bundle-v1",
            "catalog-bundle-v1",
            "catalog-native-bundle-v1",
            REVISION,
            BOOTSTRAP,
            "catalog-paged-bootstrap-owner-v1/%",
            PUBLICATION,
        ] {
            for fault in ["ABORT", "IGNORE"] {
                let temp = tempfile::tempdir().unwrap();
                let store =
                    ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
                let (bundle, bytes) = fixture(&store, 1, None);
                let denied: Result<(), CatalogStoreError> = store
                    .publish_paged_revision_catalog_checked(&bundle, &bytes, |_| {
                        Err(DatabaseError::Conflict.into())
                    });
                assert!(denied.is_err());
                let raise = if fault == "ABORT" {
                    "RAISE(ABORT, 'injected')"
                } else {
                    "RAISE(IGNORE)"
                };
                store.connection.execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON protocol_records WHEN NEW.kind LIKE '{kind}' BEGIN SELECT {raise}; END;")).unwrap();
                assert!(publish(&store, &bundle, &bytes).is_err(), "{kind} {fault}");
                assert!(store.paged_revision_catalog(bundle.id).unwrap().is_none());
                assert!(
                    store
                        .get_record(REVISION, bundle.id.as_bytes())
                        .unwrap()
                        .is_none()
                );
                assert!(
                    store
                        .get_record(
                            BOOTSTRAP,
                            &revision(&bundle).unwrap().value.metadata.sector.id
                        )
                        .unwrap()
                        .is_none()
                );
                for member in &bundle.roots {
                    assert_eq!(
                        store.catalog_intent_state(member.intent).unwrap(),
                        CatalogIntentState::Building
                    );
                }
                assert_eq!(
                    store
                        .native_file_catalog_validation(bundle.id)
                        .unwrap()
                        .unwrap()
                        .1,
                    CatalogNativeValidationState::Verified
                );
                store
                    .connection
                    .execute_batch("DROP TRIGGER injected")
                    .unwrap();
                publish(&store, &bundle, &bytes).unwrap();
            }
        }
    }

    #[test]
    fn paged_catalog_cancellation_rolls_back_every_retirement_boundary() {
        for (operation, kind) in [
            ("UPDATE", "catalog-intent-v1"),
            ("UPDATE", "catalog-bundle-v1"),
            ("UPDATE", "catalog-native-validation-v1"),
            ("DELETE", "catalog-native-bundle-v1"),
            ("DELETE", REVISION),
            ("DELETE", "catalog-paged-bootstrap-owner-v1/%"),
            ("DELETE", BOOTSTRAP),
        ] {
            for fault in ["ABORT", "IGNORE"] {
                let temp = tempfile::tempdir().unwrap();
                let store =
                    ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
                let (bundle, bytes) = fixture(&store, 1, None);
                publish(&store, &bundle, &bytes).unwrap();
                let before = store.paged_revision_catalog(bundle.id).unwrap();
                let raise = if fault == "ABORT" {
                    "RAISE(ABORT, 'injected')"
                } else {
                    "RAISE(IGNORE)"
                };
                store.connection.execute_batch(&format!("CREATE TRIGGER injected BEFORE {operation} ON protocol_records WHEN OLD.kind LIKE '{kind}' BEGIN SELECT {raise}; END;")).unwrap();
                assert!(
                    store.cancel_paged_revision_catalog(bundle.id).is_err(),
                    "{operation} {kind} {fault}"
                );
                assert_eq!(store.paged_revision_catalog(bundle.id).unwrap(), before);
                store
                    .connection
                    .execute_batch("DROP TRIGGER injected")
                    .unwrap();
                store.cancel_paged_revision_catalog(bundle.id).unwrap();
            }
        }
    }
}

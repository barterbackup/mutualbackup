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

/// Reads use the publication transaction's exact snapshot and cannot start a
/// nested transaction or mutate the catalog. The caller verifies typed private
/// roots, signed source joins and current writer authority before publication.
pub struct CatalogPublicationView<'a> {
    connection: &'a Connection,
    manifest: CatalogNativeValidation,
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

fn snapshot(
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
        })?;
        bundle::publish_bundle(&transaction, bundle)?;
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
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let result = snapshot(&transaction, id)?;
        transaction.commit()?;
        Ok(result)
    }

    /// Resolve one live bootstrap owner by its indexed sector namespace. The
    /// pin, signed identity, root ownership and ciphertext are checked in one
    /// read snapshot. No history scan or caller-supplied revision is needed.
    pub fn paged_revision_bootstrap_catalog(
        &self,
        sector_id: [u8; 32],
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
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
        if current.state == CatalogBundleState::Cancelled {
            return Ok(());
        }
        let signed = revision(&current.bundle)?;
        native_validation::cancel_linked_publication(&transaction, id)?;
        bundle::cancel_bundle(&transaction, id)?;
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
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    fn fixture(
        store: &ControlStore,
        sequence: u64,
        parent: Option<[u8; 32]>,
    ) -> (CatalogBundle, Vec<u8>) {
        let intents = [
            CatalogSection::FileMetadata,
            CatalogSection::FileMetadata,
            CatalogSection::SectorReferences,
        ]
        .map(|section| CatalogIntent {
            id: Uuid::new_v4(),
            scope: scope(),
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
            scope(),
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
        let recipes = CatalogFileRecipeBuilder::new(scope())
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
            &keys().guild_content_id_key(&[73; 32]),
            keys().node_id(),
            [73; 32],
            Uuid::from_bytes([74; 16]),
            SectorPurpose::Metadata,
            &plaintext,
        )
        .unwrap();
        let (sector, bootstrap) =
            encrypted_sector(&keys().guild_data_key(&[73; 32]), id, &plaintext).unwrap();
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
                    &keys().guild_content_id_key(&[73; 32]),
                    &keys().guild_data_key(&[73; 32]),
                    scope(),
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
        let mut sources = CatalogSectorBuilder::new(scope()).unwrap();
        let mut sink = |page, bytes: Vec<u8>| store.stage_catalog_page(intents[2], page, &bytes);
        for record in records.values() {
            sources.push(record, &mut sink).unwrap();
        }
        let sources = sources.finish(&mut sink).unwrap();
        let id = Uuid::new_v4();
        let writer = SigningKey::from_bytes(&[72; 32]);
        let signed = PagedUserRevision {
            format_version: PAGED_USER_REVISION_VERSION,
            guild_id: [73; 32],
            protected_root_id: Uuid::from_bytes([74; 16]),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: id,
            owner: keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: vec![],
            sequence,
            parent,
            metadata,
            sources,
        }
        .sign(&writer, &keys())
        .unwrap();
        store
            .validate_native_file_catalog(CatalogNativeValidation {
                id,
                scope: scope(),
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
            scope: scope(),
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
            Ok(())
        })
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

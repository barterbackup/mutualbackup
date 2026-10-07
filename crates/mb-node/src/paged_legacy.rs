//! Authenticated conversion of bounded legacy native/Git private metadata.
//! The original signed revision remains authoritative until consumer migration.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use mb_core::{
    CatalogPageRef, KeyMaterial, MerkleCommitment, PAGED_USER_REVISION_VERSION, SectorId,
    SectorRef, SignedRecord, UserRevision, V1_SECTOR_SIZE, crypt_sector, merkle_commit,
    sector_root,
};
use mb_git::GitCatalogStream;

use crate::{NativeCatalogStream, PagedPrivateMetadata, PrivateEntry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagedPrivateStream {
    Native(NativeCatalogStream),
    Git(GitCatalogStream),
}

impl PagedPrivateStream {
    /// Namespace, recipes, Git refs, Git objects, Git blobs. Public sources
    /// are built separately when the converted roots receive new authority.
    pub const fn index(self) -> usize {
        match self {
            Self::Native(stream) => stream.index(),
            Self::Git(stream) => 2 + stream.index(),
        }
    }
}

fn ciphertext(
    reference: &SectorRef,
    commitment: Option<&MerkleCommitment>,
    load: &mut impl FnMut(&SectorId) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let bytes = load(&reference.id)?;
    ensure!(
        bytes.len() == V1_SECTOR_SIZE && sector_root(&bytes) == reference.root,
        "legacy source differs from its signed ciphertext root"
    );
    if let Some(expected) = commitment {
        ensure!(
            merkle_commit(&bytes)? == *expected,
            "legacy source differs from its signed Merkle commitment"
        );
    }
    Ok(bytes)
}

impl PagedPrivateMetadata {
    /// Convert every supported legacy private role without replacing heads,
    /// signatures or data addresses. No sink writes occur until source and
    /// complete private-schema checks pass. Sink errors leave staged pages for
    /// the caller's existing intent cancellation/retry; no root is published.
    pub fn convert_legacy_revision(
        keys: &KeyMaterial,
        guild_id: [u8; 32],
        revision: &SignedRecord<UserRevision>,
        load: &mut impl FnMut(&SectorId) -> Result<Vec<u8>>,
        sink: &mut impl FnMut(PagedPrivateStream, CatalogPageRef, Vec<u8>) -> Result<()>,
    ) -> Result<Self> {
        let (scope, length) = crate::paged_data::legacy_revision_scope(keys, guild_id, revision)?;
        let commitments = revision.value.sector_commitments.as_deref();
        if let Some(values) = commitments {
            ensure!(
                values.len()
                    == revision.value.metadata_sectors.len() + revision.value.data_sectors.len()
                    && values
                        .iter()
                        .all(|value| value.byte_len as usize == V1_SECTOR_SIZE
                            && value.validate().is_ok()),
                "legacy revision has malformed source commitments"
            );
        }
        let mut data = BTreeMap::new();
        for (index, reference) in revision.value.data_sectors.iter().enumerate() {
            ensure!(
                reference.logical_len > 0 && reference.logical_len as usize <= V1_SECTOR_SIZE,
                "invalid signed legacy data geometry"
            );
            let commitment =
                commitments.map(|values| &values[revision.value.metadata_sectors.len() + index]);
            if let Some(previous) = data.insert(reference.id, (reference, commitment)) {
                ensure!(
                    previous == (reference, commitment),
                    "conflicting signed legacy data references"
                );
            }
        }
        let encryption_key = keys.guild_data_key(&guild_id);
        let mut plaintext = Vec::with_capacity(length);
        for (index, reference) in revision.value.metadata_sectors.iter().enumerate() {
            ensure!(
                !data.contains_key(&reference.id),
                "legacy metadata/data IDs overlap"
            );
            let mut bytes = ciphertext(reference, commitments.map(|values| &values[index]), load)?;
            crypt_sector(&encryption_key, reference.id, &mut bytes)?;
            let len = reference.logical_len as usize;
            ensure!(
                bytes[len..].iter().all(|byte| *byte == 0),
                "legacy metadata padding is not canonical"
            );
            plaintext.extend_from_slice(&bytes[..len]);
        }
        let (native, git) = crate::snapshot::decode_private_metadata_for_catalog(&plaintext)?;
        let join = |reference: &SectorRef| -> Result<()> {
            ensure!(
                data.get(&reference.id)
                    .is_some_and(|(signed, _)| **signed == *reference),
                "private recipe differs from signed legacy data"
            );
            Ok(())
        };
        for entry in &native.entries {
            match entry {
                PrivateEntry::File { sectors, .. } => {
                    for reference in sectors {
                        join(reference)?;
                    }
                }
                PrivateEntry::FileV2 { data_extents, .. } => {
                    for extent in data_extents {
                        for reference in &extent.sectors {
                            join(reference)?;
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(git) = &git {
            ensure!(
                git.repository_id == revision.value.protected_root_id,
                "legacy Git belongs to another dataset"
            );
            for blob in &git.blobs {
                for extent in &blob.data_extents {
                    for reference in &extent.sectors {
                        join(reference)?;
                    }
                }
            }
        }
        // Validate all signed data, including any unused retained references.
        for (reference, commitment) in data.values() {
            ciphertext(reference, *commitment, load)?;
        }
        let mut checked_load = |id: &SectorId| -> Result<Vec<u8>> {
            let (reference, commitment) = data
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("Git source lacks signed legacy data"))?;
            ciphertext(reference, *commitment, load)
        };
        if let Some(git) = &git {
            for blob in &git.blobs {
                blob.verify_plaintext(&mut crate::snapshot::RecoveredGitBlobReader::new(
                    blob,
                    &encryption_key,
                    &mut checked_load,
                ))?;
            }
        }
        // Dry-run both typed adapters before any external page staging, so a
        // malformed later role cannot leave an apparently complete first role.
        let preview_native =
            native.write_paged_native_entries(scope, &mut |_, _, _| Ok::<_, anyhow::Error>(()))?;
        let preview_git = git
            .as_ref()
            .map(|git| {
                git.write_paged_catalog_streams(scope, &mut |_, _, _| Ok::<_, anyhow::Error>(()))
            })
            .transpose()?;
        Self {
            format_version: PAGED_USER_REVISION_VERSION,
            native: preview_native,
            git: preview_git,
        }
        .validate()?;
        let native = native.write_paged_native_entries(scope, &mut |stream, page, bytes| {
            sink(PagedPrivateStream::Native(stream), page, bytes)
        })?;
        let git = git
            .map(|git| {
                git.write_paged_catalog_streams(scope, &mut |stream, page, bytes| {
                    sink(PagedPrivateStream::Git(stream), page, bytes)
                })
            })
            .transpose()?;
        let converted = Self {
            format_version: PAGED_USER_REVISION_VERSION,
            native,
            git,
        };
        converted.validate()?;
        Ok(converted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrivateDataExtent, PrivateMetadata};
    use ed25519_dalek::SigningKey;
    use mb_core::{
        CatalogFileEvent, CatalogFileRecipeRecord, CatalogNativeFileReader, CatalogScope,
        CatalogSection, CatalogSectorBuilder, CatalogSectorRecord, Seed, USER_REVISION_DOMAIN,
        V1_CIPHER_PROFILE, canonical_bytes, encrypted_sector,
    };
    use mb_git::{
        GitBackupBlob, GitBackupDescriptor, GitBlobCatalogReader, GitBlobRecord, GitDataExtent,
        GitGraphObject, GitGraphRef, GitObjectCatalogReader, GitRefCatalogReader,
    };
    use mb_store::{CatalogIntent, CatalogNativeValidation, ControlStore};
    use uuid::Uuid;

    const PAYLOAD: &[u8] = b"raw\r\nbytes\0";

    fn keys() -> KeyMaterial {
        KeyMaterial::from_seed(&Seed::from_bytes([71; 32]))
    }
    fn root_id() -> Uuid {
        Uuid::from_bytes([74; 16])
    }
    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [73; 32],
            owner: keys().node_id(),
            protected_root_id: root_id(),
        }
    }

    fn native(version: u16, data: SectorRef) -> PrivateMetadata {
        let dense = PrivateEntry::File {
            path: "payload".into(),
            mode: 0o640,
            logical_len: PAYLOAD.len() as u64,
            modified_secs: -7,
            modified_nanos: 12,
            sectors: vec![data.clone()],
        };
        let entries = if version == 1 {
            vec![dense]
        } else {
            vec![
                PrivateEntry::FileV2 {
                    path: "z-primary".into(),
                    mode: 0o640,
                    logical_len: 4096 + PAYLOAD.len() as u64,
                    modified_secs: -7,
                    modified_nanos: 12,
                    link_group: 8,
                    data_extents: vec![PrivateDataExtent {
                        offset: 4096,
                        logical_len: PAYLOAD.len() as u64,
                        sectors: vec![data],
                    }],
                },
                PrivateEntry::HardLinkV3 {
                    path: "a-alias".into(),
                    mode: 0o640,
                    logical_len: 4096 + PAYLOAD.len() as u64,
                    modified_secs: -7,
                    modified_nanos: 12,
                    link_group: 8,
                },
            ]
        };
        PrivateMetadata {
            format_version: version,
            root_mode: 0o750,
            root_modified_secs: -1,
            root_modified_nanos: 123,
            entries,
        }
    }

    fn git_descriptor(version: u16, data: SectorRef, contents: &[u8]) -> GitBackupDescriptor {
        let temp = tempfile::tempdir().unwrap();
        let repository = git2::Repository::init_bare(temp.path()).unwrap();
        let mut blob = vec![0; 4096];
        blob.extend_from_slice(contents);
        let oid = repository.blob(&blob).unwrap();
        let mut tree = repository.treebuilder(None).unwrap();
        tree.insert("payload", oid, 0o100644).unwrap();
        let tree_oid = tree.write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature =
            git2::Signature::new("Example", "example@example.test", &git2::Time::new(1, 0))
                .unwrap();
        let commit = repository
            .commit(None, &signature, &signature, "raw commit\r\n", &tree, &[])
            .unwrap();
        let odb = repository.odb().unwrap();
        let mut objects = vec![(commit, 1), (tree_oid, 2)];
        let mut refs = vec![GitGraphRef {
            name: b"refs/heads/main".to_vec(),
            oid: commit.as_bytes().try_into().unwrap(),
        }];
        if version >= 3 {
            let object = repository
                .find_object(commit, Some(git2::ObjectType::Commit))
                .unwrap();
            let tag = repository
                .tag("release", &object, &signature, "raw tag\r\n", false)
                .unwrap();
            objects.push((tag, 3));
            refs.push(GitGraphRef {
                name: b"refs/tags/release".to_vec(),
                oid: tag.as_bytes().try_into().unwrap(),
            });
        }
        let git = GitBackupDescriptor {
            format_version: version,
            repository_id: root_id(),
            refs,
            objects: objects
                .into_iter()
                .map(|(oid, kind)| GitGraphObject {
                    oid: oid.as_bytes().try_into().unwrap(),
                    kind,
                    bytes: odb.read(oid).unwrap().data().to_vec(),
                })
                .collect(),
            blobs: vec![GitBackupBlob {
                oid: oid.as_bytes().try_into().unwrap(),
                logical_len: blob.len() as u64,
                data_extents: vec![GitDataExtent {
                    offset: 4096,
                    logical_len: contents.len() as u64,
                    sectors: vec![data],
                }],
            }],
            head_branch: "main".into(),
        };
        git.validate().unwrap();
        git
    }

    fn signed(
        plaintext: &[u8],
        data: Vec<SectorRef>,
        outer: u16,
        mut sources: BTreeMap<SectorId, Vec<u8>>,
    ) -> (SignedRecord<UserRevision>, BTreeMap<SectorId, Vec<u8>>) {
        let mut metadata = Vec::new();
        for (index, bytes) in plaintext.chunks(V1_SECTOR_SIZE).enumerate() {
            let mut id = [90; 32];
            id[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let (reference, ciphertext) =
                encrypted_sector(&keys().guild_data_key(&[73; 32]), id, bytes).unwrap();
            sources.insert(id, ciphertext);
            metadata.push(reference);
        }
        let writer = SigningKey::from_bytes(&[72; 32]);
        let commitments = (outer >= 4).then(|| {
            metadata
                .iter()
                .chain(&data)
                .map(|reference| merkle_commit(&sources[&reference.id]).unwrap())
                .collect()
        });
        let mut value = UserRevision {
            format_version: outer,
            guild_id: [73; 32],
            protected_root_id: root_id(),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: Uuid::new_v4(),
            owner: keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: metadata,
            data_sectors: data,
            sector_commitments: commitments,
        };
        value.sign_writer(&writer).unwrap();
        (
            SignedRecord::sign(USER_REVISION_DOMAIN, value, &keys()).unwrap(),
            sources,
        )
    }

    fn fixture(
        version: u16,
        git_version: u16,
        git_bytes: &[u8],
    ) -> (
        SignedRecord<UserRevision>,
        BTreeMap<SectorId, Vec<u8>>,
        Option<GitBackupDescriptor>,
    ) {
        // Preserve an authenticated historical address, including non-content IDs.
        let (data, ciphertext) =
            encrypted_sector(&keys().guild_data_key(&[73; 32]), [82; 32], PAYLOAD).unwrap();
        let native = native(version, data.clone());
        let git = (version >= 4).then(|| git_descriptor(git_version, data.clone(), git_bytes));
        let plaintext = match (&git, version) {
            (Some(git), 4) => canonical_bytes(&(
                4_u16,
                native.root_mode,
                native.root_modified_secs,
                native.root_modified_nanos,
                &native.entries,
                (
                    1_u16,
                    git.repository_id,
                    &git.refs,
                    &git.objects,
                    &git.blobs,
                ),
            ))
            .unwrap(),
            (Some(git), 5) => canonical_bytes(&(
                5_u16,
                native.root_mode,
                native.root_modified_secs,
                native.root_modified_nanos,
                &native.entries,
                git,
            ))
            .unwrap(),
            _ => canonical_bytes(&native).unwrap(),
        };
        let (revision, sources) = signed(
            &plaintext,
            vec![data],
            if version >= 4 { version } else { 3 },
            BTreeMap::from([([82; 32], ciphertext)]),
        );
        (revision, sources, git)
    }

    #[test]
    fn paged_legacy_data_authority_rejects_substitution_and_unsigned_or_unbounded_history() {
        let (revision, sources, _) = fixture(5, 3, PAYLOAD);
        let reference = revision.value.data_sectors[0].clone();
        let data = CatalogSectorRecord {
            format_version: 1,
            sector: reference,
            commitment: merkle_commit(&sources[&[82; 32]]).unwrap(),
        };
        let anchor = crate::PagedAnchorSectorSource {
            locator: mb_store::StableAnchorFileLocator {
                area: mb_store::StableAnchorAreaLocator {
                    area_id: Uuid::new_v4(),
                    path_hint: "/absent".into(),
                    filesystem_id: 1,
                    volume_root_hint: "/".into(),
                },
                anchor_id: Uuid::new_v4(),
                relative_path: "payload".into(),
            },
            offset: 0,
        };
        let authority = crate::PagedLegacyDataAuthority::new(&keys(), [73; 32], &revision).unwrap();
        let bound = authority.bind(anchor.clone(), &data).unwrap();
        for case in 0..5 {
            let mut changed = data.clone();
            match case {
                0 => changed.sector.id[0] ^= 1,
                1 => changed.sector.root[0] ^= 1,
                2 => changed.sector.logical_len += 1,
                3 => changed.commitment.root[0] ^= 1,
                _ => changed.format_version += 1,
            }
            assert!(authority.bind(anchor.clone(), &changed).is_err());
            assert!(bound.render(&keys(), scope(), &changed).is_err());
        }
        let metadata = &revision.value.metadata_sectors[0];
        assert!(
            authority
                .bind(
                    anchor.clone(),
                    &CatalogSectorRecord {
                        format_version: 1,
                        sector: metadata.clone(),
                        commitment: merkle_commit(&sources[&metadata.id]).unwrap(),
                    }
                )
                .is_err()
        );
        assert!(
            bound
                .render(
                    &keys(),
                    CatalogScope::Dataset {
                        guild_id: [73; 32],
                        owner: keys().node_id(),
                        protected_root_id: Uuid::new_v4()
                    },
                    &data
                )
                .is_err()
        );
        assert!(crate::PagedLegacyDataAuthority::new(&keys(), [1; 32], &revision).is_err());
        assert!(
            crate::PagedLegacyDataAuthority::new(
                &KeyMaterial::from_seed(&Seed::from_bytes([1; 32])),
                [73; 32],
                &revision
            )
            .is_err()
        );
        for case in 0..11 {
            let mut changed = revision.clone();
            match case {
                0 => changed.signature[0] ^= 1,
                1 => changed.value.writer_signature[0] ^= 1,
                2 => changed.value.data_sectors[0].logical_len = 0,
                3 => changed.value.protected_root_id = Uuid::nil(),
                4 => changed.value.sequence = 2,
                5 => {
                    changed.value.sector_commitments.as_mut().unwrap().pop();
                }
                6 => {
                    let mut conflict = changed.value.data_sectors[0].clone();
                    conflict.root[0] ^= 1;
                    changed.value.data_sectors.push(conflict);
                    let commitment = changed
                        .value
                        .sector_commitments
                        .as_ref()
                        .unwrap()
                        .last()
                        .unwrap()
                        .clone();
                    changed
                        .value
                        .sector_commitments
                        .as_mut()
                        .unwrap()
                        .push(commitment);
                }
                7 => changed.value.data_sectors[0].id = changed.value.metadata_sectors[0].id,
                8 => changed
                    .signature
                    .resize(mb_core::V1_MAX_CATALOG_BYTES + 1, 0),
                9 => changed
                    .value
                    .metadata_sectors
                    .resize(513, changed.value.metadata_sectors[0].clone()),
                _ => changed.value.format_version = 6,
            }
            if matches!(case, 2..=7 | 9) {
                changed
                    .value
                    .sign_writer(&SigningKey::from_bytes(&[72; 32]))
                    .unwrap();
                changed = SignedRecord::sign(USER_REVISION_DOMAIN, changed.value, &keys()).unwrap();
            } else if case == 1 {
                changed = SignedRecord::sign(USER_REVISION_DOMAIN, changed.value, &keys()).unwrap();
            }
            assert!(
                crate::PagedLegacyDataAuthority::new(&keys(), [73; 32], &changed).is_err(),
                "case {case}"
            );
        }
    }

    fn retained_migration_source(
        store: &ControlStore,
        root: &std::path::Path,
        reference: &SectorRef,
    ) -> crate::PagedAnchorSectorSource {
        std::fs::create_dir(root).unwrap();
        let area = mb_store::StableAnchorAreaLocator::prepare_for_root(root).unwrap();
        let anchor_id = Uuid::new_v4();
        let directory = area.path_hint.join(anchor_id.to_string());
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("payload"), PAYLOAD).unwrap();
        let source = crate::PagedAnchorSectorSource {
            locator: mb_store::StableAnchorFileLocator {
                area,
                anchor_id,
                relative_path: "payload".into(),
            },
            offset: 0,
        };
        // Literal historical LocalSectorRecipe layout, stable-file variant 2.
        store
            .put_record(
                "local-sector",
                &reference.id,
                &canonical_bytes(&(
                    [73_u8; 32],
                    reference,
                    (2_u8, &source.locator, source.offset),
                ))
                .unwrap(),
            )
            .unwrap();
        source
    }

    #[test]
    fn paged_retained_legacy_migration_publishes_all_roles_and_preserves_shared_sources_after_reopen()
     {
        for version in [1, 3, 4, 5] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (legacy, sources, _) = fixture(version, if version == 4 { 1 } else { 3 }, PAYLOAD);
            let original = canonical_bytes(&legacy).unwrap();
            store
                .put_record(
                    "user-revision",
                    legacy.value.revision_id.as_bytes(),
                    &original,
                )
                .unwrap();
            store
                .put_record("user-revision-head", b"sentinel", b"preserved")
                .unwrap();
            let anchor = retained_migration_source(
                &store,
                &temp.path().join("protected"),
                &legacy.value.data_sectors[0],
            );
            let writer = SigningKey::from_bytes(&[72; 32]);
            let fence = mb_core::WriterFence {
                owner: keys().node_id(),
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            };
            let id = Uuid::new_v4();
            let migration =
                crate::RetainedLegacyMigration::new(&keys(), [73; 32], &legacy, fence.clone(), id)
                    .unwrap();
            let migrated = migration
                .retain(&store, &keys(), &legacy, &writer, &mut |id| {
                    Ok(sources[id].clone())
                })
                .unwrap();
            assert_eq!(migrated.value.parent, Some(legacy.value.hash().unwrap()));
            assert_eq!(migrated.value.sequence, legacy.value.sequence + 1);
            assert!(
                store
                    .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                    .unwrap()
            );
            assert!(
                store
                    .next_record_bounded(
                        &format!("paged-legacy-migration-source-v1/{}", id.simple()),
                        None,
                        32,
                        256
                    )
                    .unwrap()
                    .is_none()
            );
            let shared = crate::RetainedLegacyMigration::new(
                &keys(),
                [73; 32],
                &legacy,
                fence,
                Uuid::new_v4(),
            )
            .unwrap();
            let retained = shared
                .retain(&store, &keys(), &legacy, &writer, &mut |id| {
                    Ok(sources[id].clone())
                })
                .unwrap();
            drop(store);
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let migration = crate::RetainedLegacyMigration::load(&store, &keys(), id)
                .unwrap()
                .unwrap();
            assert_eq!(
                migration
                    .retain(&store, &keys(), &legacy, &writer, &mut |_| anyhow::bail!(
                        "completed retry must not reopen old metadata"
                    ))
                    .unwrap(),
                migrated
            );
            let opened = PagedPrivateMetadata::load_local_catalog(&store, &keys(), id, scope())
                .unwrap()
                .unwrap();
            assert_eq!(opened.private.unwrap().git.is_some(), version >= 4);
            assert_eq!(
                crate::snapshot::render_sector(
                    &store,
                    &keys(),
                    &legacy.value.data_sectors[0].id,
                    Some(&[73; 32])
                )
                .unwrap(),
                sources[&legacy.value.data_sectors[0].id]
            );
            migration.cancel(&store).unwrap();
            while migration.cleanup_step(&store).unwrap() {}
            assert!(
                store
                    .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                    .unwrap()
            );
            assert!(
                migration
                    .retain(&store, &keys(), &legacy, &writer, &mut |id| Ok(
                        sources[id].clone()
                    ))
                    .is_err()
            );
            assert_eq!(
                PagedPrivateMetadata::load_local_catalog(
                    &store,
                    &keys(),
                    retained.value.revision_id,
                    scope()
                )
                .unwrap()
                .unwrap()
                .state,
                mb_store::CatalogBundleState::Published
            );
            shared.cancel(&store).unwrap();
            while shared.cleanup_step(&store).unwrap() {}
            assert!(
                !store
                    .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                    .unwrap()
            );
            while store.collect_catalog_page().unwrap() {}
            assert_eq!(
                store
                    .get_record("user-revision", legacy.value.revision_id.as_bytes())
                    .unwrap()
                    .unwrap(),
                original
            );
            assert_eq!(
                store
                    .get_record("user-revision-head", b"sentinel")
                    .unwrap()
                    .unwrap(),
                b"preserved"
            );
            assert!(anchor.locator.open().is_ok());
        }
    }

    #[test]
    fn paged_retained_migration_retries_failed_publication_and_fences_interrupted_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (legacy, sources, _) = fixture(5, 3, PAYLOAD);
        let original = canonical_bytes(&legacy).unwrap();
        store
            .put_record(
                "user-revision",
                legacy.value.revision_id.as_bytes(),
                &original,
            )
            .unwrap();
        let anchor = retained_migration_source(
            &store,
            &temp.path().join("protected"),
            &legacy.value.data_sectors[0],
        );
        let writer = SigningKey::from_bytes(&[72; 32]);
        let fence = mb_core::WriterFence {
            owner: keys().node_id(),
            epoch: 1,
            public_key: writer.verifying_key().to_bytes(),
        };
        let id = Uuid::new_v4();
        let migration =
            crate::RetainedLegacyMigration::new(&keys(), [73; 32], &legacy, fence.clone(), id)
                .unwrap();
        assert!(
            migration
                .retain(
                    &store,
                    &keys(),
                    &legacy,
                    &SigningKey::from_bytes(&[99; 32]),
                    &mut |id| Ok(sources[id].clone())
                )
                .is_err()
        );
        assert!(
            crate::RetainedLegacyMigration::load(&store, &keys(), id)
                .unwrap()
                .is_none()
        );
        let reference = &legacy.value.data_sectors[0];
        let original_recipe = store
            .get_record("local-sector", &reference.id)
            .unwrap()
            .unwrap();
        store.delete_record("local-sector", &reference.id).unwrap();
        assert!(
            migration
                .retain(&store, &keys(), &legacy, &writer, &mut |id| Ok(
                    sources[id].clone()
                ))
                .is_err()
        );
        assert!(store.paged_revision_catalog(id).unwrap().is_none());
        assert!(
            !store
                .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                .unwrap()
        );
        migration.cancel(&store).unwrap();
        drop(store);
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let cancelled = crate::RetainedLegacyMigration::load(&store, &keys(), id)
            .unwrap()
            .unwrap();
        while cancelled.cleanup_step(&store).unwrap() {}
        assert!(
            migration
                .retain(&store, &keys(), &legacy, &writer, &mut |id| Ok(
                    sources[id].clone()
                ))
                .is_err()
        );
        assert!(store.paged_revision_catalog(id).unwrap().is_none());
        assert!(anchor.locator.open().is_ok());
        let id = Uuid::new_v4();
        let migration =
            crate::RetainedLegacyMigration::new(&keys(), [73; 32], &legacy, fence, id).unwrap();
        store
            .put_record("local-sector", &reference.id, &original_recipe)
            .unwrap();
        store.database_shell_statement("CREATE TEMP TRIGGER ignore_migration BEFORE INSERT ON protocol_records WHEN NEW.kind = 'paged-user-revision-v1' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
        assert!(
            migration
                .retain(&store, &keys(), &legacy, &writer, &mut |id| Ok(
                    sources[id].clone()
                ))
                .is_err()
        );
        assert!(store.paged_revision_catalog(id).unwrap().is_none());
        assert!(
            !store
                .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                .unwrap()
        );
        drop(store);
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        store
            .database_shell_statement("DROP TRIGGER IF EXISTS ignore_migration", false)
            .unwrap();
        let migration = crate::RetainedLegacyMigration::load(&store, &keys(), id)
            .unwrap()
            .unwrap();
        let mut altered = legacy.clone();
        altered.value.sequence = 2;
        altered.value.parent = Some(legacy.value.hash().unwrap());
        altered.value.sign_writer(&writer).unwrap();
        altered = SignedRecord::sign(USER_REVISION_DOMAIN, altered.value, &keys()).unwrap();
        assert!(
            migration
                .retain(&store, &keys(), &altered, &writer, &mut |id| Ok(sources
                    [id]
                    .clone()))
                .is_err()
        );
        let migrated = migration
            .retain(&store, &keys(), &legacy, &writer, &mut |id| {
                Ok(sources[id].clone())
            })
            .unwrap();
        // An existing unrelated catalog ID cannot be adopted by first claiming
        // a migration journal, nor then cancelled through that claim.
        let journal = store
            .get_record("paged-legacy-migration-v1", id.as_bytes())
            .unwrap()
            .unwrap();
        store
            .delete_record("paged-legacy-migration-v1", id.as_bytes())
            .unwrap();
        assert!(
            migration
                .retain(&store, &keys(), &legacy, &writer, &mut |id| Ok(
                    sources[id].clone()
                ))
                .is_err()
        );
        assert!(
            crate::RetainedLegacyMigration::load(&store, &keys(), id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.paged_revision_catalog(id).unwrap().unwrap().state,
            mb_store::CatalogBundleState::Published
        );
        store
            .put_record("paged-legacy-migration-v1", id.as_bytes(), &journal)
            .unwrap();
        store.database_shell_statement("CREATE TEMP TRIGGER ignore_cancel BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-intent-v1' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
        assert!(migration.cancel(&store).is_err());
        assert!(
            migration
                .retain(&store, &keys(), &legacy, &writer, &mut |id| Ok(
                    sources[id].clone()
                ))
                .is_err()
        );
        drop(store);
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        store
            .database_shell_statement("DROP TRIGGER IF EXISTS ignore_cancel", false)
            .unwrap();
        let migration = crate::RetainedLegacyMigration::load(&store, &keys(), id)
            .unwrap()
            .unwrap();
        migration.cancel(&store).unwrap();
        while migration.cleanup_step(&store).unwrap() {}
        assert!(
            !store
                .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                .unwrap()
        );
        assert_eq!(
            store
                .paged_revision_catalog(migrated.value.revision_id)
                .unwrap()
                .unwrap()
                .state,
            mb_store::CatalogBundleState::Cancelled
        );
        assert_eq!(
            store
                .get_record("user-revision", legacy.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
            original
        );
    }

    #[test]
    fn paged_legacy_sources_publish_reopen_replace_and_release_without_address_rewrite() {
        for version in [1, 4, 5] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("protected");
            std::fs::create_dir(&root).unwrap();
            let area = mb_store::StableAnchorAreaLocator::prepare_for_root(&root).unwrap();
            let make_anchor = |prefix: &[u8]| {
                let anchor_id = Uuid::new_v4();
                let directory = area.path_hint.join(anchor_id.to_string());
                std::fs::create_dir(&directory).unwrap();
                let file = directory.join("payload");
                let mut bytes = prefix.to_vec();
                bytes.extend_from_slice(PAYLOAD);
                std::fs::write(&file, &bytes).unwrap();
                (
                    crate::PagedAnchorSectorSource {
                        locator: mb_store::StableAnchorFileLocator {
                            area: area.clone(),
                            anchor_id,
                            relative_path: "payload".into(),
                        },
                        offset: prefix.len() as u64,
                    },
                    file,
                    bytes,
                )
            };
            let (anchor, file, correct) = make_anchor(b"original");
            let (replacement, replacement_file, replacement_bytes) = make_anchor(b"replacement");
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (legacy, sources, git) =
                fixture(version, if version == 4 { 1 } else { 3 }, PAYLOAD);
            let original = canonical_bytes(&legacy).unwrap();
            store
                .put_record(
                    "user-revision",
                    legacy.value.revision_id.as_bytes(),
                    &original,
                )
                .unwrap();
            store
                .put_record("user-revision-head", b"sentinel", b"unchanged")
                .unwrap();
            let authority =
                crate::PagedLegacyDataAuthority::new(&keys(), [73; 32], &legacy).unwrap();
            let new_intent = |section| CatalogIntent {
                id: Uuid::new_v4(),
                scope: scope(),
                section,
            };
            let intents = crate::PagedCatalogIntents {
                native: [
                    new_intent(CatalogSection::FileMetadata),
                    new_intent(CatalogSection::FileMetadata),
                ],
                sources: new_intent(CatalogSection::SectorReferences),
                git: git.map(|_| {
                    [
                        new_intent(CatalogSection::GitGraph),
                        new_intent(CatalogSection::GitGraph),
                        new_intent(CatalogSection::GitGraph),
                    ]
                }),
            };
            let roles: Vec<_> = intents
                .native
                .into_iter()
                .chain(intents.git.into_iter().flatten())
                .collect();
            for intent in roles.iter().chain([&intents.sources]) {
                store.begin_catalog(*intent).unwrap();
            }
            let mut pages = BTreeMap::new();
            let private = PagedPrivateMetadata::convert_legacy_revision(
                &keys(),
                [73; 32],
                &legacy,
                &mut |id| Ok(sources[id].clone()),
                &mut |stream, page, bytes| {
                    let intent = roles[stream.index()];
                    store.stage_catalog_page(intent, page, &bytes)?;
                    pages.insert(page.hash, (intent.section, page, bytes));
                    Ok(())
                },
            )
            .unwrap();
            let (metadata, _) = private.seal(&keys(), scope()).unwrap();
            let data = CatalogSectorRecord {
                format_version: 1,
                sector: legacy.value.data_sectors[0].clone(),
                commitment: merkle_commit(&sources[&[82; 32]]).unwrap(),
            };
            let mut records = BTreeMap::from([
                (data.sector.id, data.clone()),
                (metadata.sector.id, metadata.clone()),
            ]);
            for (section, page, bytes) in pages.values() {
                let (sector, ciphertext) = page
                    .seal_private_page(
                        &keys().guild_content_id_key(&[73; 32]),
                        &keys().guild_data_key(&[73; 32]),
                        scope(),
                        *section,
                        bytes,
                    )
                    .unwrap();
                records.insert(
                    sector.id,
                    CatalogSectorRecord {
                        format_version: 1,
                        sector,
                        commitment: merkle_commit(&ciphertext).unwrap(),
                    },
                );
            }
            let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
            let mut sink =
                |page, bytes: Vec<u8>| store.stage_catalog_page(intents.sources, page, &bytes);
            for record in records.values() {
                builder.push(record, &mut sink).unwrap();
            }
            let public_sources = builder.finish(&mut sink).unwrap();
            let writer = SigningKey::from_bytes(&[72; 32]);
            let signed = mb_core::PagedUserRevision {
                format_version: PAGED_USER_REVISION_VERSION,
                guild_id: [73; 32],
                protected_root_id: root_id(),
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::new_v4(),
                owner: keys().node_id(),
                writer_epoch: 1,
                writer_public_key: writer.verifying_key().to_bytes(),
                writer_signature: vec![],
                sequence: 1,
                parent: None,
                metadata,
                sources: public_sources,
            }
            .sign(&writer, &keys())
            .unwrap();
            let fence = mb_core::WriterFence {
                owner: keys().node_id(),
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            };
            let id = signed.value.revision_id;
            // The ordinary capture API must not silently accept historical IDs.
            assert!(
                private
                    .publish_local_catalog_with_data_sources(
                        &store,
                        &keys(),
                        &signed,
                        &fence,
                        intents,
                        |record| Ok((record == &data).then(|| anchor.clone())),
                    )
                    .is_err()
            );
            assert!(store.paged_revision_catalog(id).unwrap().is_none());
            assert!(
                !store
                    .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                    .unwrap()
            );
            std::fs::write(&file, b"wrong historical source bytes").unwrap();
            assert!(
                private
                    .publish_local_catalog_with_authenticated_sources(
                        &store,
                        &keys(),
                        &signed,
                        &fence,
                        intents,
                        |record| if record == &data {
                            authority.bind(anchor.clone(), record).map(Some)
                        } else {
                            Ok(None)
                        },
                    )
                    .is_err()
            );
            assert!(store.paged_revision_catalog(id).unwrap().is_none());
            assert!(
                !store
                    .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                    .unwrap()
            );
            std::fs::write(&file, correct).unwrap();
            private
                .publish_local_catalog_with_authenticated_sources(
                    &store,
                    &keys(),
                    &signed,
                    &fence,
                    intents,
                    |record| {
                        if record == &data {
                            authority.bind(anchor.clone(), record).map(Some)
                        } else {
                            Ok(None)
                        }
                    },
                )
                .unwrap();
            // Exact publication retry preserves the canonical source binding.
            private
                .publish_local_catalog_with_authenticated_sources(
                    &store,
                    &keys(),
                    &signed,
                    &fence,
                    intents,
                    |record| {
                        if record == &data {
                            authority.bind(anchor.clone(), record).map(Some)
                        } else {
                            Ok(None)
                        }
                    },
                )
                .unwrap();
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            let read = || {
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    id,
                    data.sector.id,
                    scope(),
                )
            };
            assert_eq!(read().unwrap(), Some(sources[&data.sector.id].clone()));
            assert_eq!(
                crate::snapshot::render_sector(&store, &keys(), &data.sector.id, Some(&[73; 32]))
                    .unwrap(),
                sources[&data.sector.id]
            );
            assert!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &KeyMaterial::from_seed(&Seed::from_bytes([1; 32])),
                    id,
                    data.sector.id,
                    scope()
                )
                .is_err()
            );
            assert!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    id,
                    data.sector.id,
                    CatalogScope::Dataset {
                        guild_id: [73; 32],
                        owner: keys().node_id(),
                        protected_root_id: Uuid::new_v4()
                    }
                )
                .is_err()
            );
            let expected = store
                .paged_revision_data_source(id, data.sector.id)
                .unwrap()
                .unwrap();
            std::fs::remove_file(&file).unwrap();
            assert!(read().is_err());
            std::fs::write(&replacement_file, b"incorrect replacement").unwrap();
            assert!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &keys(),
                    &expected,
                    scope(),
                    &replacement
                )
                .is_err()
            );
            assert!(
                !store
                    .paged_data_anchor_is_pinned(replacement.locator.anchor_id)
                    .unwrap()
            );
            std::fs::write(&replacement_file, replacement_bytes).unwrap();
            let updated = PagedPrivateMetadata::replace_local_data_source(
                &store,
                &keys(),
                &expected,
                scope(),
                &replacement,
            )
            .unwrap();
            assert_eq!(updated.generation, 1);
            assert_eq!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &keys(),
                    &expected,
                    scope(),
                    &replacement
                )
                .unwrap(),
                updated
            );
            assert!(
                !store
                    .paged_data_anchor_is_pinned(anchor.locator.anchor_id)
                    .unwrap()
            );
            assert_eq!(read().unwrap(), Some(sources[&data.sector.id].clone()));
            let mut forged = updated.clone();
            forged.recipe = canonical_bytes(&replacement).unwrap();
            assert!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &keys(),
                    &forged,
                    scope(),
                    &anchor
                )
                .is_err()
            );
            assert_eq!(
                store
                    .get_record("user-revision", legacy.value.revision_id.as_bytes())
                    .unwrap(),
                Some(original)
            );
            assert_eq!(
                store.get_record("user-revision-head", b"sentinel").unwrap(),
                Some(b"unchanged".to_vec())
            );
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    id,
                    data.sector.id,
                    scope()
                )
                .unwrap(),
                Some(sources[&data.sector.id].clone())
            );
            store.cancel_paged_revision_catalog(id).unwrap();
            assert!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    id,
                    data.sector.id,
                    scope()
                )
                .unwrap()
                .is_none()
            );
            assert!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &keys(),
                    &updated,
                    scope(),
                    &replacement
                )
                .is_err()
            );
            assert!(
                store
                    .paged_data_anchor_is_pinned(replacement.locator.anchor_id)
                    .unwrap()
            );
            assert!(store.release_paged_revision_data_source(id).unwrap());
            assert!(!store.release_paged_revision_data_source(id).unwrap());
            assert!(store.paged_data_anchor_ids().unwrap().is_empty());
        }
    }

    #[test]
    fn paged_legacy_conversion_preserves_native_git_bytes_sources_and_reopen_ownership() {
        for (version, git_version) in [(1, 1), (3, 1), (4, 1), (5, 2), (5, 3), (5, 4)] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (revision, sources, git) = fixture(version, git_version, PAYLOAD);
            let original = canonical_bytes(&revision).unwrap();
            store
                .put_record(
                    "user-revision",
                    revision.value.revision_id.as_bytes(),
                    &original,
                )
                .unwrap();
            store
                .put_record("user-revision-head", b"sentinel", b"unchanged")
                .unwrap();
            let intents: Vec<_> = (0..if git.is_some() { 5 } else { 2 })
                .map(|index| CatalogIntent {
                    id: Uuid::new_v4(),
                    scope: scope(),
                    section: if index < 2 {
                        CatalogSection::FileMetadata
                    } else {
                        CatalogSection::GitGraph
                    },
                })
                .collect();
            for intent in &intents {
                store.begin_catalog(*intent).unwrap();
            }
            let converted = PagedPrivateMetadata::convert_legacy_revision(
                &keys(),
                [73; 32],
                &revision,
                &mut |id| Ok(sources[id].clone()),
                &mut |stream, page, bytes| {
                    store.stage_catalog_page(intents[stream.index()], page, &bytes)?;
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(canonical_bytes(&revision).unwrap(), original);
            assert_eq!(
                store
                    .get_record("user-revision", revision.value.revision_id.as_bytes())
                    .unwrap(),
                Some(original)
            );
            assert_eq!(
                store.get_record("user-revision-head", b"sentinel").unwrap(),
                Some(b"unchanged".to_vec())
            );
            let source_intent = CatalogIntent {
                id: Uuid::new_v4(),
                scope: scope(),
                section: CatalogSection::SectorReferences,
            };
            store.begin_catalog(source_intent).unwrap();
            let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
            let mut sink =
                |page, bytes: Vec<u8>| store.stage_catalog_page(source_intent, page, &bytes);
            for reference in &revision.value.data_sectors {
                builder
                    .push(
                        &CatalogSectorRecord {
                            format_version: 1,
                            sector: reference.clone(),
                            commitment: merkle_commit(&sources[&reference.id]).unwrap(),
                        },
                        &mut sink,
                    )
                    .unwrap();
            }
            let public_sources = builder.finish(&mut sink).unwrap();
            store
                .validate_native_file_catalog(CatalogNativeValidation {
                    id: Uuid::new_v4(),
                    scope: scope(),
                    files: converted.native,
                    sources: public_sources,
                })
                .unwrap();
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            let mut native = CatalogNativeFileReader::new(scope(), converted.native).unwrap();
            let mut entries = Vec::new();
            let mut references = Vec::new();
            while let Some(event) = native
                .next_event(&mut |page| {
                    store.catalog_page(scope(), CatalogSection::FileMetadata, page)
                })
                .unwrap()
            {
                match event {
                    CatalogFileEvent::Entry(entry) => entries.push(entry),
                    CatalogFileEvent::Recipe(CatalogFileRecipeRecord::Sectors {
                        references: refs,
                        ..
                    }) => references.extend(refs),
                    _ => {}
                }
            }
            assert_eq!(references, revision.value.data_sectors);
            if version != 1 {
                assert_eq!(entries[0].path, b"a-alias");
            }
            if let Some(original) = git {
                let root = converted.git.unwrap();
                let mut refs = GitRefCatalogReader::new(scope(), root.refs).unwrap();
                let mut restored_refs = BTreeMap::new();
                while let Some(reference) = refs
                    .next_ref(&mut |page| {
                        store.catalog_page(scope(), CatalogSection::GitGraph, page)
                    })
                    .unwrap()
                {
                    restored_refs.insert(reference.name, reference.oid);
                }
                assert_eq!(
                    restored_refs,
                    original
                        .refs
                        .iter()
                        .map(|reference| (reference.name.clone(), reference.oid))
                        .collect()
                );
                let mut objects = GitObjectCatalogReader::new(scope(), root.objects).unwrap();
                let mut restored_objects = BTreeMap::new();
                while let Some(record) = objects
                    .next_record(&mut |page| {
                        store.catalog_page(scope(), CatalogSection::GitGraph, page)
                    })
                    .unwrap()
                {
                    match record {
                        mb_git::GitObjectRecord::Header {
                            oid,
                            kind,
                            byte_len,
                            ..
                        } => {
                            restored_objects.insert(oid, (kind, byte_len));
                        }
                        mb_git::GitObjectRecord::Fragment { bytes, .. } => {
                            assert!(original.objects.iter().any(|object| object.bytes == bytes));
                        }
                    }
                }
                assert_eq!(
                    restored_objects,
                    original
                        .objects
                        .iter()
                        .map(|object| (object.oid, (object.kind, object.bytes.len() as u64)))
                        .collect()
                );
                let mut blobs = GitBlobCatalogReader::new(scope(), root.blobs).unwrap();
                let mut refs = Vec::new();
                while let Some(record) = blobs
                    .next_record(&mut |page| {
                        store.catalog_page(scope(), CatalogSection::GitGraph, page)
                    })
                    .unwrap()
                {
                    if let GitBlobRecord::Sectors { references, .. } = record {
                        refs.extend(references);
                    }
                }
                assert_eq!(refs, revision.value.data_sectors);
            }
        }
    }

    #[test]
    fn paged_legacy_conversion_accepts_both_frozen_v2_layouts_and_rejects_withdrawn_formats() {
        let fixtures: [&[u8]; 2] = [
            &[
                2, 237, 3, 1, 123, 2, 2, 1, 97, 164, 3, 0, 3, 200, 3, 7, 9, 0, 2, 1, 98, 164, 3, 0,
                3, 200, 3, 7, 9, 0,
            ],
            &[
                2, 237, 3, 1, 123, 2, 2, 1, 97, 164, 3, 0, 3, 200, 3, 0, 0, 2, 1, 98, 164, 3, 0, 3,
                200, 3, 0, 0,
            ],
        ];
        for bytes in fixtures {
            let (revision, sources) = signed(bytes, Vec::new(), 3, BTreeMap::new());
            let mut staged = 0;
            let root = PagedPrivateMetadata::convert_legacy_revision(
                &keys(),
                [73; 32],
                &revision,
                &mut |id| Ok(sources[id].clone()),
                &mut |_, _, _| {
                    staged += 1;
                    Ok(())
                },
            )
            .unwrap();
            assert!(staged > 0);
            assert!(root.git.is_none());
        }
        for version in [6_u16, 7] {
            let (revision, sources) = signed(
                &canonical_bytes(&version).unwrap(),
                Vec::new(),
                3,
                BTreeMap::new(),
            );
            assert!(
                PagedPrivateMetadata::convert_legacy_revision(
                    &keys(),
                    [73; 32],
                    &revision,
                    &mut |id| Ok(sources[id].clone()),
                    &mut |_, _, _| -> Result<()> { panic!("withdrawn format reached sink") }
                )
                .is_err()
            );
        }
    }

    #[test]
    fn paged_legacy_conversion_rejects_bad_authority_sources_and_later_roles_before_staging() {
        for damage in 0..11 {
            let (mut revision, mut sources, _) = fixture(
                5,
                4,
                if damage == 5 {
                    b"bad\r\nbytes\0"
                } else {
                    PAYLOAD
                },
            );
            match damage {
                0 => revision.signature[0] ^= 1,
                1 => {
                    sources
                        .get_mut(&revision.value.metadata_sectors[0].id)
                        .unwrap()[0] ^= 1
                }
                2 => sources.get_mut(&[82; 32]).unwrap()[0] ^= 1,
                3 => {
                    revision.value.sector_commitments.as_mut().unwrap()[0].root[0] ^= 1;
                    revision
                        .value
                        .sign_writer(&SigningKey::from_bytes(&[72; 32]))
                        .unwrap();
                    revision =
                        SignedRecord::sign(USER_REVISION_DOMAIN, revision.value, &keys()).unwrap();
                }
                4 | 6 | 7 | 9 | 10 => {
                    let mut metadata = native(3, revision.value.data_sectors[0].clone());
                    if damage == 4
                        && let PrivateEntry::FileV2 { data_extents, .. } = &mut metadata.entries[0]
                    {
                        data_extents[0].sectors[0].root[0] ^= 1;
                    }
                    if damage == 9
                        && let PrivateEntry::FileV2 { path, .. } = &mut metadata.entries[0]
                    {
                        *path = "../unsafe".into();
                    }
                    let mut git =
                        git_descriptor(4, revision.value.data_sectors[0].clone(), PAYLOAD);
                    if damage == 7 {
                        git.repository_id = Uuid::new_v4();
                    }
                    if damage == 10 {
                        git.objects[0].bytes[0] ^= 1;
                    }
                    let mut bytes = if matches!(damage, 7 | 10) {
                        canonical_bytes(&(
                            5_u16,
                            metadata.root_mode,
                            metadata.root_modified_secs,
                            metadata.root_modified_nanos,
                            &metadata.entries,
                            git,
                        ))
                        .unwrap()
                    } else {
                        canonical_bytes(&metadata).unwrap()
                    };
                    if damage == 6 {
                        bytes.push(0);
                    }
                    (revision, sources) = signed(
                        &bytes,
                        revision.value.data_sectors.clone(),
                        5,
                        BTreeMap::from([([82; 32], sources[&[82; 32]].clone())]),
                    );
                }
                5 | 8 => {}
                _ => unreachable!(),
            }
            let mut writes = 0;
            assert!(
                PagedPrivateMetadata::convert_legacy_revision(
                    &keys(),
                    [73; 32],
                    &revision,
                    &mut |id| {
                        if damage == 8 {
                            anyhow::bail!("offline");
                        }
                        Ok(sources[id].clone())
                    },
                    &mut |_, _, _| {
                        writes += 1;
                        Ok(())
                    }
                )
                .is_err(),
                "damage {damage}"
            );
            assert_eq!(writes, 0, "damage {damage}");
        }
        let (revision, _, _) = fixture(1, 1, PAYLOAD);
        let wrong_keys = KeyMaterial::from_seed(&Seed::from_bytes([1; 32]));
        for (keys, guild) in [(&wrong_keys, [73; 32]), (&keys(), [1; 32])] {
            assert!(
                PagedPrivateMetadata::convert_legacy_revision(
                    keys,
                    guild,
                    &revision,
                    &mut |_| -> Result<Vec<u8>> { panic!("bad authority loaded source") },
                    &mut |_, _, _| -> Result<()> { panic!("bad authority staged pages") }
                )
                .is_err()
            );
        }
    }

    #[test]
    fn paged_legacy_conversion_sink_failure_keeps_original_and_releases_staged_intents() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let (revision, sources, _) = fixture(5, 4, PAYLOAD);
        let original = canonical_bytes(&revision).unwrap();
        store
            .put_record(
                "user-revision",
                revision.value.revision_id.as_bytes(),
                &original,
            )
            .unwrap();
        let intents: Vec<_> = (0..5)
            .map(|index| CatalogIntent {
                id: Uuid::new_v4(),
                scope: scope(),
                section: if index < 2 {
                    CatalogSection::FileMetadata
                } else {
                    CatalogSection::GitGraph
                },
            })
            .collect();
        for intent in &intents {
            store.begin_catalog(*intent).unwrap();
        }
        let mut writes = 0;
        assert!(
            PagedPrivateMetadata::convert_legacy_revision(
                &keys(),
                [73; 32],
                &revision,
                &mut |id| Ok(sources[id].clone()),
                &mut |stream, page, bytes| {
                    store.stage_catalog_page(intents[stream.index()], page, &bytes)?;
                    writes += 1;
                    if writes == 3 {
                        anyhow::bail!("sink offline after staging");
                    }
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(writes, 3);
        for intent in &intents {
            assert_eq!(
                store.catalog_intent_state(*intent).unwrap(),
                mb_store::CatalogIntentState::Building
            );
            store.cancel_catalog(*intent).unwrap();
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        assert!(store.records("catalog-page-v1").unwrap().is_empty());
        assert!(store.records("paged-user-revision-v1").unwrap().is_empty());
        assert_eq!(
            store
                .get_record("user-revision", revision.value.revision_id.as_bytes())
                .unwrap(),
            Some(original)
        );
    }
}

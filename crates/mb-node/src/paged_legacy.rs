//! Authenticated conversion of bounded legacy native/Git private metadata.
//! The original signed revision remains authoritative until consumer migration.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use mb_core::{
    CatalogPageRef, CatalogScope, KeyMaterial, MerkleCommitment, PAGED_USER_REVISION_VERSION,
    SectorId, SectorRef, SignedRecord, UserRevision, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE,
    canonical_size_bounded, crypt_sector, merkle_commit, sector_root,
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
        let length = crate::snapshot::checked_metadata_length(revision)?;
        ensure!(
            revision.signature.len() == 64 && revision.value.writer_signature.len() == 64,
            "legacy revision exceeds bounded conversion geometry"
        );
        canonical_size_bounded(revision, V1_MAX_CATALOG_BYTES)?;
        crate::snapshot::validate_restore_revision(keys, guild_id, revision)?;
        ensure!(
            !revision.value.revision_id.is_nil()
                && !revision.value.protected_root_id.is_nil()
                && revision.value.sequence > 0
                && (revision.value.sequence == 1) == revision.value.parent.is_none(),
            "legacy revision has no protected dataset identity"
        );
        let scope = CatalogScope::Dataset {
            guild_id,
            owner: keys.node_id(),
            protected_root_id: revision.value.protected_root_id,
        };
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
        CatalogFileEvent, CatalogFileRecipeRecord, CatalogNativeFileReader, CatalogSection,
        CatalogSectorBuilder, CatalogSectorRecord, Seed, USER_REVISION_DOMAIN, V1_CIPHER_PROFILE,
        canonical_bytes, encrypted_sector,
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

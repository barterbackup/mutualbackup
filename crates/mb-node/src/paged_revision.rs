//! Owner-encrypted root descriptor for the paged revision migration.
//! Ordinary capture/replay remain on existing formats until all consumers move.

use anyhow::{Result, ensure};
use mb_core::{
    CATALOG_MAX_PAGE_OCCURRENCES, CATALOG_MAX_STREAM_BYTES, CatalogNativeFileRoot, CatalogScope,
    CatalogSectorRecord, KeyMaterial, PAGED_USER_REVISION_VERSION, PagedUserRevision,
    SectorPurpose, SignedRecord, V1_SECTOR_SIZE, canonical_bytes_bounded, crypt_sector,
    decode_canonical, encrypted_sector, make_content_sector_id, merkle_commit, sector_root,
};
use mb_git::GitCatalogRoot;
use mb_store::{
    CatalogBundle, CatalogBundleRoot, CatalogBundleState, CatalogIntent, CatalogNativeValidation,
    ControlStore,
};
use serde::{Deserialize, Serialize};

pub const PAGED_PRIVATE_METADATA_BYTES: usize = mb_core::PAGED_PRIVATE_METADATA_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagedCatalogIntents {
    pub native: [CatalogIntent; 2],
    pub sources: CatalogIntent,
    pub git: Option<[CatalogIntent; 3]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedRevisionCatalogSnapshot {
    pub revision: SignedRecord<PagedUserRevision>,
    pub state: CatalogBundleState,
    pub private: Option<PagedPrivateMetadata>,
}

/// Private native namespace/recipe roots and optional exact Git history roots.
/// Plaintext page hashes belong only inside this encrypted descriptor. Every
/// referenced stream also needs durable ownership and a verified source join.
/// Historical withdrawn private formats 6/7 keep their original interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PagedPrivateMetadata {
    pub format_version: u16,
    pub native: CatalogNativeFileRoot,
    pub git: Option<GitCatalogRoot>,
}

impl PagedPrivateMetadata {
    fn local_bundle(
        &self,
        signed: &SignedRecord<PagedUserRevision>,
        intents: PagedCatalogIntents,
    ) -> Result<CatalogBundle> {
        self.validate()?;
        PagedUserRevision::verify_signed(signed)?;
        ensure!(
            self.git.is_some() == intents.git.is_some(),
            "paged Git root/intents disagree"
        );
        let scope = signed.value.scope();
        let mut roots: Vec<_> = intents
            .native
            .into_iter()
            .zip(self.native.page_roots())
            .map(|(intent, root)| CatalogBundleRoot { intent, root })
            .collect();
        roots.push(CatalogBundleRoot {
            intent: intents.sources,
            root: signed.value.sources.records.page,
        });
        if let (Some(git), Some(intents)) = (&self.git, intents.git) {
            roots.extend(
                intents
                    .into_iter()
                    .zip(git.page_roots())
                    .map(|(intent, root)| CatalogBundleRoot { intent, root }),
            );
        }
        let sections = [
            mb_core::CatalogSection::FileMetadata,
            mb_core::CatalogSection::FileMetadata,
            mb_core::CatalogSection::SectorReferences,
            mb_core::CatalogSection::GitGraph,
            mb_core::CatalogSection::GitGraph,
            mb_core::CatalogSection::GitGraph,
        ];
        ensure!(
            roots
                .iter()
                .zip(sections)
                .all(|(member, section)| member.intent.scope == scope
                    && member.intent.section == section),
            "paged catalog scope or role differs"
        );
        let bundle = CatalogBundle {
            id: signed.value.revision_id,
            scope,
            roots,
            descriptor: canonical_bytes_bounded(signed, mb_core::PAGED_USER_REVISION_BYTES)?,
        };
        bundle.validate()?;
        ensure!(
            bundle
                .roots
                .iter()
                .map(|member| member.root.byte_len)
                .sum::<u64>()
                <= CATALOG_MAX_STREAM_BYTES
                && bundle
                    .roots
                    .iter()
                    .map(|member| member.root.page_occurrences)
                    .sum::<u64>()
                    <= CATALOG_MAX_PAGE_OCCURRENCES,
            "paged revision roots exceed the aggregate catalog geometry"
        );
        Ok(bundle)
    }

    /// Retain every owned stream, signed migration record and encrypted
    /// bootstrap atomically. Current writer authority is supplied from the
    /// certified checkpoint. This does not advance a production backup head.
    pub fn publish_local_catalog(
        &self,
        control: &ControlStore,
        keys: &KeyMaterial,
        signed: &SignedRecord<PagedUserRevision>,
        fence: &mb_core::WriterFence,
        intents: PagedCatalogIntents,
    ) -> Result<()> {
        let bundle = self.local_bundle(signed, intents)?;
        let (record, bootstrap) = self.seal(keys, bundle.scope)?;
        ensure!(
            record == signed.value.metadata,
            "signed bootstrap does not bind these private roots"
        );
        // Reject a mismatched certified fence before creating any pending
        // validation rows, then check it again in the publication snapshot.
        mb_core::PagedRevisionSourceReader::new(
            signed,
            signed.value.guild_id,
            keys.node_id(),
            fence,
        )?;
        // Full native/source validation is durable but remains a pending index
        // if later publication fails; callers can retry or cancel that index.
        let manifest = CatalogNativeValidation {
            id: bundle.id,
            scope: bundle.scope,
            files: self.native,
            sources: signed.value.sources,
        };
        control.validate_native_file_catalog(manifest)?;
        control.publish_paged_revision_catalog_checked(
            &bundle,
            &bootstrap,
            |view| -> Result<()> {
                let mut sources = mb_core::PagedRevisionSourceReader::new(
                    signed,
                    signed.value.guild_id,
                    keys.node_id(),
                    fence,
                )?;
                while let Some(record) = sources.next_sector(&mut |page| {
                    view.catalog_page(mb_core::CatalogSection::SectorReferences, page)
                })? {
                    ensure!(
                        view.source(record.sector.id)?.as_ref() == Some(&record),
                        "native source index differs from signed source catalog"
                    );
                }
                ensure!(
                    sources.is_complete(),
                    "signed source traversal is incomplete"
                );
                for member in bundle
                    .roots
                    .iter()
                    .filter(|member| member.intent.section.is_private())
                {
                    let section = member.intent.section;
                    let mut pages =
                        mb_core::CatalogReader::new(bundle.scope, section, member.root)?;
                    while pages
                        .next_leaf(&mut |page| -> Result<Vec<u8>> {
                            let encoded = view.catalog_page(section, page)?;
                            let (sector, ciphertext) = page.seal_private_page(
                                &keys.guild_content_id_key(&signed.value.guild_id),
                                &keys.guild_data_key(&signed.value.guild_id),
                                bundle.scope,
                                section,
                                &encoded,
                            )?;
                            let expected = CatalogSectorRecord {
                                format_version: 1,
                                sector,
                                commitment: merkle_commit(&ciphertext)?,
                            };
                            ensure!(
                                view.source(expected.sector.id)?.as_ref() == Some(&expected),
                                "private page lacks its exact signed source commitment"
                            );
                            Ok(encoded)
                        })?
                        .is_some()
                    {}
                }
                if let Some(git) = &self.git {
                    let mut refs =
                        mb_git::GitRefCatalogReader::new(bundle.scope, git.refs.clone())?;
                    while refs
                        .next_ref(&mut |page| {
                            view.catalog_page(mb_core::CatalogSection::GitGraph, page)
                        })?
                        .is_some()
                    {}
                    let mut objects =
                        mb_git::GitObjectCatalogReader::new(bundle.scope, git.objects)?;
                    while objects
                        .next_record(&mut |page| {
                            view.catalog_page(mb_core::CatalogSection::GitGraph, page)
                        })?
                        .is_some()
                    {}
                    let mut blobs = mb_git::GitBlobCatalogReader::new(bundle.scope, git.blobs)?;
                    while let Some(record) = blobs.next_record(&mut |page| {
                        view.catalog_page(mb_core::CatalogSection::GitGraph, page)
                    })? {
                        if let mb_git::GitBlobRecord::Sectors { references, .. } = record {
                            for reference in references {
                                ensure!(
                                    view.source(reference.id)?
                                        .is_some_and(|source| source.sector == reference),
                                    "Git blob recipe differs from signed sources"
                                );
                            }
                        }
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Reopen a consistent local ownership snapshot. Every later traversal
    /// still verifies page/payload bytes; this is not a remote protection claim.
    pub fn load_local_catalog(
        control: &ControlStore,
        keys: &KeyMaterial,
        id: uuid::Uuid,
        expected_scope: CatalogScope,
    ) -> Result<Option<PagedRevisionCatalogSnapshot>> {
        let Some(snapshot) = control.paged_revision_catalog(id)? else {
            return Ok(None);
        };
        let signed = PagedUserRevision::decode_signed(&snapshot.bundle.descriptor)?;
        ensure!(
            signed.value.scope() == expected_scope && signed.value.owner == keys.node_id(),
            "paged revision scope differs on reopen"
        );
        let private = if let Some(bootstrap) = &snapshot.bootstrap {
            let private = Self::open(keys, signed.value.guild_id, &signed, bootstrap)?;
            let roots = &snapshot.bundle.roots;
            let intents = PagedCatalogIntents {
                native: [roots[0].intent, roots[1].intent],
                sources: roots[2].intent,
                git: (roots.len() == 6)
                    .then(|| [roots[3].intent, roots[4].intent, roots[5].intent]),
            };
            ensure!(
                private.local_bundle(&signed, intents)? == snapshot.bundle,
                "paged root manifest differs from its encrypted descriptor"
            );
            Some(private)
        } else {
            None
        };
        Ok(Some(PagedRevisionCatalogSnapshot {
            revision: signed,
            state: snapshot.state,
            private,
        }))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == PAGED_USER_REVISION_VERSION,
            "unsupported paged private metadata version"
        );
        self.native.validate()?;
        let mut bytes = 0_u64;
        let mut pages = 0_u64;
        for root in self.native.page_roots() {
            bytes += root.byte_len;
            pages += root.page_occurrences;
        }
        if let Some(git) = &self.git {
            git.validate()?;
            for root in git.page_roots() {
                bytes += root.byte_len;
                pages += root.page_occurrences;
            }
        }
        ensure!(
            bytes <= CATALOG_MAX_STREAM_BYTES && pages <= CATALOG_MAX_PAGE_OCCURRENCES,
            "paged private roots exceed the aggregate catalog geometry"
        );
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= PAGED_PRIVATE_METADATA_BYTES,
            "paged private descriptor exceeds its bounded metadata budget"
        );
        let descriptor: Self = decode_canonical(bytes)?;
        descriptor.validate()?;
        ensure!(
            canonical_bytes_bounded(&descriptor, PAGED_PRIVATE_METADATA_BYTES)? == bytes,
            "paged private descriptor is not canonical"
        );
        Ok(descriptor)
    }

    /// Produces the exact bootstrap source record to bind in the signed
    /// revision AND its streamed source catalog before either is activated.
    pub fn seal(
        &self,
        keys: &KeyMaterial,
        scope: CatalogScope,
    ) -> Result<(CatalogSectorRecord, Vec<u8>)> {
        self.validate()?;
        scope.validate(mb_core::CatalogSection::FileMetadata)?;
        let CatalogScope::Dataset {
            guild_id,
            owner,
            protected_root_id,
        } = scope
        else {
            anyhow::bail!("private descriptor requires a dataset scope");
        };
        ensure!(
            owner == keys.node_id(),
            "private descriptor belongs to another owner"
        );
        let plaintext = canonical_bytes_bounded(self, PAGED_PRIVATE_METADATA_BYTES)?;
        let id = make_content_sector_id(
            &keys.guild_content_id_key(&guild_id),
            owner,
            guild_id,
            protected_root_id,
            SectorPurpose::Metadata,
            &plaintext,
        )?;
        let (sector, ciphertext) =
            encrypted_sector(&keys.guild_data_key(&guild_id), id, &plaintext)?;
        let record = CatalogSectorRecord {
            format_version: 1,
            sector,
            commitment: merkle_commit(&ciphertext)?,
        };
        record.validate()?;
        Ok((record, ciphertext))
    }

    /// Verify owner/writer signatures and both ciphertext commitments before
    /// decrypting. This opens root authority, not complete private/source joins,
    /// checkpoint writer authorization or a protection/restore success claim.
    pub fn open(
        keys: &KeyMaterial,
        guild_id: [u8; 32],
        signed: &SignedRecord<PagedUserRevision>,
        ciphertext: &[u8],
    ) -> Result<Self> {
        PagedUserRevision::verify_signed(signed)?;
        let revision = &signed.value;
        ensure!(
            revision.owner == keys.node_id() && revision.guild_id == guild_id,
            "paged revision does not belong to the recovering seed and guild"
        );
        let source = &revision.metadata;
        let length = source.sector.logical_len as usize;
        ensure!(
            length <= PAGED_PRIVATE_METADATA_BYTES
                && ciphertext.len() == V1_SECTOR_SIZE
                && source.sector.root == sector_root(ciphertext)
                && source.commitment == merkle_commit(ciphertext)?,
            "paged private metadata ciphertext does not match its signed source"
        );
        let mut plaintext = ciphertext.to_vec();
        crypt_sector(
            &keys.guild_data_key(&guild_id),
            source.sector.id,
            &mut plaintext,
        )?;
        ensure!(
            plaintext[length..].iter().all(|byte| *byte == 0),
            "paged private metadata padding is not canonical"
        );
        let descriptor = Self::decode(&plaintext[..length])?;
        let id = make_content_sector_id(
            &keys.guild_content_id_key(&guild_id),
            revision.owner,
            guild_id,
            revision.protected_root_id,
            SectorPurpose::Metadata,
            &plaintext[..length],
        )?;
        ensure!(
            id == source.sector.id,
            "paged private metadata has a conflicting scope address"
        );
        Ok(descriptor)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ed25519_dalek::SigningKey;
    use mb_core::{
        CatalogFileBuilder, CatalogFileRecipeBuilder, CatalogFileStat, CatalogPageRef,
        CatalogSectorBuilder, PAGED_USER_REVISION_DOMAIN, PagedRevisionSourceReader, Seed,
        V1_CIPHER_PROFILE, WriterFence, canonical_bytes,
    };
    use mb_git::{GitBlobCatalogBuilder, GitObjectCatalogBuilder, GitRefCatalogBuilder};
    use uuid::Uuid;

    use super::*;

    type OwnedPages =
        std::collections::BTreeMap<[u8; 32], (mb_core::CatalogSection, CatalogPageRef, Vec<u8>)>;

    fn stage_page(
        store: &ControlStore,
        intent: CatalogIntent,
        pages: &mut OwnedPages,
        page: CatalogPageRef,
        bytes: Vec<u8>,
    ) -> Result<(), mb_store::CatalogStoreError> {
        pages.insert(page.hash, (intent.section, page, bytes.clone()));
        store.stage_catalog_page(intent, page, &bytes)
    }

    fn owned_fixture(
        store: &ControlStore,
        with_git: bool,
        damage: u8,
    ) -> (
        PagedPrivateMetadata,
        SignedRecord<PagedUserRevision>,
        PagedCatalogIntents,
    ) {
        let new_intent = |section| CatalogIntent {
            id: Uuid::new_v4(),
            scope: scope(),
            section,
        };
        let intents = PagedCatalogIntents {
            native: [
                new_intent(mb_core::CatalogSection::FileMetadata),
                new_intent(mb_core::CatalogSection::FileMetadata),
            ],
            sources: new_intent(mb_core::CatalogSection::SectorReferences),
            git: with_git.then(|| {
                [
                    new_intent(mb_core::CatalogSection::GitGraph),
                    new_intent(mb_core::CatalogSection::GitGraph),
                    new_intent(mb_core::CatalogSection::GitGraph),
                ]
            }),
        };
        for intent in intents
            .native
            .into_iter()
            .chain([intents.sources])
            .chain(intents.git.into_iter().flatten())
        {
            store.begin_catalog(intent).unwrap();
        }
        let payload = b"raw\r\nbytes\0";
        let (sector, data) =
            encrypted_sector(&keys().guild_data_key(&[73; 32]), [82; 32], payload).unwrap();
        let data_source = CatalogSectorRecord {
            format_version: 1,
            sector: sector.clone(),
            commitment: merkle_commit(&data).unwrap(),
        };
        let stat = CatalogFileStat {
            mode: 0o640,
            modified_secs: 123,
            modified_nanos: 456,
        };
        let logical_len = 4096 + payload.len() as u64;
        let mut pages = OwnedPages::new();
        let mut namespace = CatalogFileBuilder::new(scope(), stat).unwrap();
        let mut sink = |page, bytes| stage_page(store, intents.native[0], &mut pages, page, bytes);
        for (path, kind) in [
            (
                b"alias".as_slice(),
                mb_core::CatalogFileKind::HardLink {
                    logical_len,
                    link_group: 7,
                },
            ),
            (
                b"payload-\xff".as_slice(),
                mb_core::CatalogFileKind::File {
                    file_key: 1,
                    logical_len,
                    link_group: Some(7),
                },
            ),
        ] {
            namespace
                .push(
                    &mb_core::CatalogFileRecord {
                        format_version: 1,
                        path: path.to_vec(),
                        stat,
                        kind,
                    },
                    &mut sink,
                )
                .unwrap();
        }
        let namespace = namespace.finish(&mut sink).unwrap();
        let mut recipes = CatalogFileRecipeBuilder::new(scope()).unwrap();
        let mut sink = |page, bytes| stage_page(store, intents.native[1], &mut pages, page, bytes);
        let references = [sector.clone()];
        recipes
            .push_file(
                1,
                logical_len,
                std::iter::once(mb_core::CatalogFileExtent {
                    offset: 4096,
                    logical_len: payload.len() as u64,
                    sectors: &references,
                }),
                &mut sink,
            )
            .unwrap();
        let native = CatalogNativeFileRoot {
            format_version: 1,
            namespace,
            recipes: recipes.finish(&mut sink).unwrap(),
        };
        let git = intents.git.map(|git_intents| {
            let mut sink = |page, bytes| stage_page(store, git_intents[0], &mut pages, page, bytes);
            let refs = GitRefCatalogBuilder::new(scope(), b"unborn")
                .unwrap()
                .finish(&mut sink)
                .unwrap();
            let mut sink = |page, bytes| stage_page(store, git_intents[1], &mut pages, page, bytes);
            let objects = GitObjectCatalogBuilder::new(scope())
                .unwrap()
                .finish(&mut sink)
                .unwrap();
            let mut sink = |page, bytes| stage_page(store, git_intents[2], &mut pages, page, bytes);
            let mut blobs = GitBlobCatalogBuilder::new(scope()).unwrap();
            let mut reference = sector.clone();
            if damage == 3 {
                reference.root[0] ^= 1;
            }
            for record in [
                mb_git::GitBlobRecord::Blob {
                    format_version: 1,
                    oid: git2::Oid::hash_object(git2::ObjectType::Blob, payload)
                        .unwrap()
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    logical_len: payload.len() as u64,
                    extents: 1,
                    sectors: 1,
                },
                mb_git::GitBlobRecord::Extent {
                    offset: 0,
                    logical_len: payload.len() as u64,
                    sectors: 1,
                },
                mb_git::GitBlobRecord::Sectors {
                    first_sector: 0,
                    references: vec![reference],
                },
            ] {
                blobs.push_record(&record, &mut sink).unwrap();
            }
            GitCatalogRoot {
                format_version: 1,
                repository_id: Uuid::from_bytes([77; 16]),
                refs,
                objects,
                blobs: blobs.finish(&mut sink).unwrap(),
            }
        });
        let private = PagedPrivateMetadata {
            format_version: PAGED_USER_REVISION_VERSION,
            native,
            git,
        };
        let (metadata, _) = private.seal(&keys(), scope()).unwrap();
        let mut records = std::collections::BTreeMap::new();
        records.insert(data_source.sector.id, data_source);
        if damage != 4 {
            records.insert(metadata.sector.id, metadata.clone());
        }
        for (_, (section, page, bytes)) in pages {
            if damage == 1 {
                continue;
            }
            let (sector, ciphertext) = page
                .seal_private_page(
                    &keys().guild_content_id_key(&[73; 32]),
                    &keys().guild_data_key(&[73; 32]),
                    scope(),
                    section,
                    &bytes,
                )
                .unwrap();
            let mut commitment = merkle_commit(&ciphertext).unwrap();
            if damage == 2 {
                commitment.root[0] ^= 1;
            }
            records.insert(
                sector.id,
                CatalogSectorRecord {
                    format_version: 1,
                    sector,
                    commitment,
                },
            );
        }
        let mut sources = CatalogSectorBuilder::new(scope()).unwrap();
        let mut sink =
            |page, bytes: Vec<u8>| store.stage_catalog_page(intents.sources, page, &bytes);
        for record in records.values() {
            sources.push(record, &mut sink).unwrap();
        }
        let sources = sources.finish(&mut sink).unwrap();
        let writer = SigningKey::from_bytes(&[72; 32]);
        let body = PagedUserRevision {
            format_version: PAGED_USER_REVISION_VERSION,
            guild_id: [73; 32],
            protected_root_id: Uuid::from_bytes([74; 16]),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: Uuid::new_v4(),
            owner: keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: vec![],
            sequence: 1,
            parent: None,
            metadata,
            sources,
        };
        (private, body.sign(&writer, &keys()).unwrap(), intents)
    }

    fn writer_fence(signed: &SignedRecord<PagedUserRevision>) -> WriterFence {
        WriterFence {
            owner: signed.value.owner,
            epoch: signed.value.writer_epoch,
            public_key: signed.value.writer_public_key,
        }
    }

    #[test]
    fn paged_revision_catalog_publishes_reopens_and_cancels_all_native_and_git_root_roles() {
        for with_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, with_git, 0);
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .unwrap();
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .unwrap();
            let id = signed.value.revision_id;
            assert!(
                store
                    .get_record("user-revision", id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(store.records("user-revision-head").unwrap().is_empty());
            let link = store.native_file_catalog_link(id, 7).unwrap().unwrap();
            assert_eq!(link.primary_file_key, Some(1));
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            let loaded = PagedPrivateMetadata::load_local_catalog(&store, &keys(), id, scope())
                .unwrap()
                .unwrap();
            assert_eq!(loaded.revision, signed);
            assert_eq!(loaded.private, Some(private.clone()));
            assert_eq!(loaded.state, CatalogBundleState::Published);
            assert_eq!(
                store
                    .paged_revision_catalog(id)
                    .unwrap()
                    .unwrap()
                    .bundle
                    .roots
                    .len(),
                if with_git { 6 } else { 3 }
            );
            assert!(store.cancel_catalog_bundle(id).is_err());
            assert!(store.cancel_native_file_catalog_validation(id).is_err());
            let mut wrong_scope = scope();
            if let CatalogScope::Dataset {
                protected_root_id, ..
            } = &mut wrong_scope
            {
                *protected_root_id = Uuid::new_v4();
            }
            assert!(
                PagedPrivateMetadata::load_local_catalog(&store, &keys(), id, wrong_scope).is_err()
            );
            store.cancel_paged_revision_catalog(id).unwrap();
            let cancelled = PagedPrivateMetadata::load_local_catalog(&store, &keys(), id, scope())
                .unwrap()
                .unwrap();
            assert_eq!(cancelled.state, CatalogBundleState::Cancelled);
            assert!(cancelled.private.is_none());
            assert!(
                private
                    .publish_local_catalog(
                        &store,
                        &keys(),
                        &signed,
                        &writer_fence(&signed),
                        intents
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn paged_revision_catalog_rejects_missing_substituted_sources_and_writer_without_publication() {
        for damage in 0..=4 {
            let temp = tempfile::tempdir().unwrap();
            let store =
                ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, true, damage);
            let mut fence = writer_fence(&signed);
            if damage == 0 {
                fence.epoch += 1;
            }
            assert!(
                private
                    .publish_local_catalog(&store, &keys(), &signed, &fence, intents)
                    .is_err(),
                "damage {damage}"
            );
            assert!(
                store
                    .paged_revision_catalog(signed.value.revision_id)
                    .unwrap()
                    .is_none()
            );
            assert!(store.records("paged-user-revision-v1").unwrap().is_empty());
            assert!(
                store
                    .records("paged-revision-bootstrap-v1")
                    .unwrap()
                    .is_empty()
            );
            if damage == 0 {
                assert!(
                    store
                        .native_file_catalog_validation(signed.value.revision_id)
                        .unwrap()
                        .is_none()
                );
            }
            for intent in intents
                .native
                .into_iter()
                .chain([intents.sources])
                .chain(intents.git.into_iter().flatten())
            {
                assert_eq!(
                    store.catalog_intent_state(intent).unwrap(),
                    mb_store::CatalogIntentState::Building
                );
            }
        }
    }

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

    fn descriptor(with_git: bool) -> PagedPrivateMetadata {
        let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, &'static str>(());
        let native = CatalogNativeFileRoot {
            format_version: 1,
            namespace: CatalogFileBuilder::new(
                scope(),
                CatalogFileStat {
                    mode: 0o700,
                    modified_secs: 123,
                    modified_nanos: 456,
                },
            )
            .unwrap()
            .finish(&mut sink)
            .unwrap(),
            recipes: CatalogFileRecipeBuilder::new(scope())
                .unwrap()
                .finish(&mut sink)
                .unwrap(),
        };
        let git = with_git.then(|| GitCatalogRoot {
            format_version: 1,
            repository_id: Uuid::from_bytes([77; 16]),
            refs: GitRefCatalogBuilder::new(scope(), b"unborn")
                .unwrap()
                .finish(&mut sink)
                .unwrap(),
            objects: GitObjectCatalogBuilder::new(scope())
                .unwrap()
                .finish(&mut sink)
                .unwrap(),
            blobs: GitBlobCatalogBuilder::new(scope())
                .unwrap()
                .finish(&mut sink)
                .unwrap(),
        });
        PagedPrivateMetadata {
            format_version: PAGED_USER_REVISION_VERSION,
            native,
            git,
        }
    }

    fn signed(
        record: CatalogSectorRecord,
    ) -> (SignedRecord<PagedUserRevision>, HashMap<[u8; 32], Vec<u8>>) {
        let mut pages = HashMap::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
        builder.push(&record, &mut sink).unwrap();
        let writer = SigningKey::from_bytes(&[72; 32]);
        let body = PagedUserRevision {
            format_version: PAGED_USER_REVISION_VERSION,
            guild_id: [73; 32],
            protected_root_id: Uuid::from_bytes([74; 16]),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([75; 16]),
            owner: keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: vec![],
            sequence: 1,
            parent: None,
            metadata: record,
            sources: builder.finish(&mut sink).unwrap(),
        };
        (body.sign(&writer, &keys()).unwrap(), pages)
    }

    #[test]
    fn paged_private_revision_seals_native_and_git_roots_without_public_plaintext_hashes() {
        for with_git in [false, true] {
            let original = descriptor(with_git);
            let (record, ciphertext) = original.seal(&keys(), scope()).unwrap();
            let regenerated = original.seal(&keys(), scope()).unwrap();
            assert_eq!(regenerated, (record.clone(), ciphertext.clone()));
            assert_eq!(ciphertext.len(), V1_SECTOR_SIZE);
            let (signed, pages) = signed(record);
            let encoded = canonical_bytes(&signed).unwrap();
            for page in original
                .native
                .page_roots()
                .into_iter()
                .chain(original.git.iter().flat_map(|git| git.page_roots()))
            {
                assert!(!encoded.windows(32).any(|bytes| bytes == page.hash));
            }
            let signed = PagedUserRevision::decode_signed(&encoded).unwrap();
            assert_eq!(
                PagedPrivateMetadata::open(&keys(), [73; 32], &signed, &ciphertext).unwrap(),
                original
            );
            let fence = WriterFence {
                owner: signed.value.owner,
                epoch: 1,
                public_key: signed.value.writer_public_key,
            };
            let mut reader =
                PagedRevisionSourceReader::new(&signed, [73; 32], keys().node_id(), &fence)
                    .unwrap();
            let mut fetch = |page: CatalogPageRef| Ok::<_, &'static str>(pages[&page.hash].clone());
            assert_eq!(
                reader.next_sector(&mut fetch).unwrap(),
                Some(signed.value.metadata.clone())
            );
            assert!(!reader.is_complete());
            assert!(reader.next_sector(&mut fetch).unwrap().is_none());
            assert!(reader.is_complete());
        }
    }

    #[test]
    fn paged_private_revision_rejects_ciphertext_commitment_address_and_scope_substitution() {
        let original = descriptor(true);
        let (record, ciphertext) = original.seal(&keys(), scope()).unwrap();
        let (revision, _) = signed(record);
        assert!(
            PagedPrivateMetadata::open(
                &KeyMaterial::from_seed(&Seed::from_bytes([99; 32])),
                [73; 32],
                &revision,
                &ciphertext
            )
            .is_err()
        );
        assert!(PagedPrivateMetadata::open(&keys(), [99; 32], &revision, &ciphertext).is_err());
        for case in 0..6 {
            let mut record = revision.value.metadata.clone();
            let mut bytes = ciphertext.clone();
            match case {
                0 => bytes[0] ^= 1,
                1 => {
                    bytes.pop();
                }
                2 => record.commitment.root[0] ^= 1,
                3 => record.sector.id[0] ^= 1,
                4 => {
                    crypt_sector(
                        &keys().guild_data_key(&[73; 32]),
                        record.sector.id,
                        &mut bytes,
                    )
                    .unwrap();
                    bytes[V1_SECTOR_SIZE - 1] = 1;
                    crypt_sector(
                        &keys().guild_data_key(&[73; 32]),
                        record.sector.id,
                        &mut bytes,
                    )
                    .unwrap();
                    record.sector.root = sector_root(&bytes);
                    record.commitment = merkle_commit(&bytes).unwrap();
                }
                _ => record.sector.logical_len += 1,
            }
            let (resigned, _) = signed(record);
            assert!(
                PagedPrivateMetadata::open(&keys(), [73; 32], &resigned, &bytes).is_err(),
                "case {case}"
            );
        }
        let mut moved = revision.value.clone();
        moved.protected_root_id = Uuid::from_bytes([99; 16]);
        let moved = moved
            .sign(&SigningKey::from_bytes(&[72; 32]), &keys())
            .unwrap();
        assert!(PagedPrivateMetadata::open(&keys(), [73; 32], &moved, &ciphertext).is_err());
        let mut writer_tamper = revision.value;
        writer_tamper.writer_signature[0] ^= 1;
        let writer_tamper =
            SignedRecord::sign(PAGED_USER_REVISION_DOMAIN, writer_tamper, &keys()).unwrap();
        assert!(
            PagedPrivateMetadata::open(&keys(), [73; 32], &writer_tamper, &ciphertext).is_err()
        );
        assert!(
            original
                .seal(&keys(), CatalogScope::Guild { guild_id: [73; 32] })
                .is_err()
        );
        assert!(
            original
                .seal(
                    &KeyMaterial::from_seed(&Seed::from_bytes([99; 32])),
                    scope()
                )
                .is_err()
        );
    }

    #[test]
    fn paged_private_descriptor_rejects_withdrawn_versions_and_aggregate_forest_overflow() {
        let original = descriptor(true);
        assert_eq!(
            PagedPrivateMetadata::decode(&canonical_bytes(&original).unwrap()).unwrap(),
            original
        );
        for version in [1, 3, 5, 6, 7, 9] {
            let mut wrong = original.clone();
            wrong.format_version = version;
            assert!(PagedPrivateMetadata::decode(&canonical_bytes(&wrong).unwrap()).is_err());
        }
        let mut wrong = original.clone();
        wrong.native.namespace.files += 1;
        assert!(wrong.validate().is_err());
        let mut wrong = original.clone();
        wrong.git.as_mut().unwrap().repository_id = Uuid::nil();
        assert!(wrong.validate().is_err());
        // Root summaries can be individually bounded but collectively too big.
        // No pages/payloads are materialized by this structural admission test.
        let inflate = |root: &mut mb_core::CatalogRecordRoot, bytes: u64| {
            root.page = CatalogPageRef {
                hash: [90; 32],
                encoded_len: 8192,
                height: 3,
                byte_len: bytes,
                page_occurrences: 150_000,
            };
            root.records = bytes.div_ceil(mb_core::CATALOG_RECORD_BYTES as u64);
        };
        let mut wrong = original.clone();
        inflate(&mut wrong.native.namespace.records, 5 << 30);
        inflate(&mut wrong.native.recipes.records, 5 << 30);
        wrong.native.namespace.files = 1;
        wrong.native.namespace.directories = wrong.native.namespace.records.records - 1;
        wrong.native.recipes.files = 1;
        inflate(&mut wrong.git.as_mut().unwrap().refs.records, 8 << 30);
        wrong.native.validate().unwrap();
        wrong.git.as_ref().unwrap().validate().unwrap();
        assert!(wrong.validate().is_err());
        assert!(PagedPrivateMetadata::decode(&vec![0; PAGED_PRIVATE_METADATA_BYTES + 1]).is_err());
    }
}

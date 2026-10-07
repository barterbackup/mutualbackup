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
        ensure!(
            self.git
                .as_ref()
                .is_none_or(|git| git.repository_id == signed.value.protected_root_id),
            "paged Git repository differs from protected root"
        );
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
        self.publish_local_catalog_with_data_sources(control, keys, signed, fence, intents, |_| {
            Ok(None)
        })
    }

    /// Supply stable native/Git data sources one signed sector at a time. Every
    /// supplied source is authenticated before binding it to the revision.
    pub fn publish_local_catalog_with_data_sources(
        &self,
        control: &ControlStore,
        keys: &KeyMaterial,
        signed: &SignedRecord<PagedUserRevision>,
        fence: &mb_core::WriterFence,
        intents: PagedCatalogIntents,
        mut source_for: impl FnMut(
            &CatalogSectorRecord,
        ) -> Result<Option<crate::PagedAnchorSectorSource>>,
    ) -> Result<()> {
        self.publish_local_catalog_with_authenticated_sources(
            control,
            keys,
            signed,
            fence,
            intents,
            |record| Ok(source_for(record)?.map(crate::PagedDataSource::from)),
        )
    }

    /// Publish scoped sources or historical sources authorized by an original
    /// signed legacy revision. The certified new source root remains the
    /// authority for serving after reopen; local recipes preserve address mode.
    pub fn publish_local_catalog_with_authenticated_sources(
        &self,
        control: &ControlStore,
        keys: &KeyMaterial,
        signed: &SignedRecord<PagedUserRevision>,
        fence: &mb_core::WriterFence,
        intents: PagedCatalogIntents,
        mut source_for: impl FnMut(&CatalogSectorRecord) -> Result<Option<crate::PagedDataSource>>,
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
        if let Some(git) = &self.git {
            git.validate_graph(bundle.scope, |page| {
                Ok(control.catalog_page(bundle.scope, mb_core::CatalogSection::GitGraph, page)?)
            })?;
        }
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
                    if let Some(source) = source_for(&record)? {
                        let recipe = source.encode()?;
                        source.render(keys, bundle.scope, &record)?;
                        view.bind_data_source(&record, source.anchor_id(), &recipe)?;
                    }
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
                            view.bind_private_page_source(member.intent, page, &expected)?;
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
        Ok(Some(Self::open_local_snapshot(
            keys,
            &snapshot,
            expected_scope,
        )?))
    }

    pub(super) fn open_local_snapshot(
        keys: &KeyMaterial,
        snapshot: &mb_store::PagedCatalogSnapshot,
        expected_scope: CatalogScope,
    ) -> Result<PagedRevisionCatalogSnapshot> {
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
        Ok(PagedRevisionCatalogSnapshot {
            revision: signed,
            state: snapshot.state,
            private,
        })
    }

    /// Route ordinary sector requests through authenticated retained ownership.
    /// A damaged live source is an error, never a reason to use a legacy copy.
    pub(crate) fn render_local_sector(
        control: &ControlStore,
        keys: &KeyMaterial,
        sector_id: [u8; 32],
        expected_guild: Option<&[u8; 32]>,
        update_area_hint: bool,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(bytes) = Self::render_local_bootstrap(control, keys, sector_id, expected_guild)?
        {
            return Ok(Some(bytes));
        }
        let Some(source) = control.paged_sector_source(sector_id)? else {
            return Ok(None);
        };
        let scope = source.catalog().bundle.scope;
        let opened = Self::open_local_snapshot(keys, source.catalog(), scope)?;
        ensure!(
            expected_guild.is_none_or(|guild| *guild == opened.revision.value.guild_id),
            "paged sector does not belong to the requested guild"
        );
        let bytes = match source {
            mb_store::PagedCatalogSectorSource::Data(source) => {
                Self::render_data_source(control, keys, &source, scope, update_area_hint)?
            }
            mb_store::PagedCatalogSectorSource::Page(source) => {
                // The second read rechecks this exact immutable owner together
                // with its page payload; cancellation between reads fails closed.
                Self::render_local_catalog_page(
                    control,
                    keys,
                    source.catalog.bundle.id,
                    sector_id,
                    scope,
                )?
                .ok_or_else(|| anyhow::anyhow!("paged page owner retired during serving"))?
            }
        };
        Ok(Some(bytes))
    }

    /// Serve retained bootstrap ciphertext through its live paged root owner;
    /// never copy it into an independently collected legacy Inline recipe.
    pub(crate) fn render_local_bootstrap(
        control: &ControlStore,
        keys: &KeyMaterial,
        sector_id: [u8; 32],
        expected_guild: Option<&[u8; 32]>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(snapshot) = control.paged_revision_bootstrap_catalog(sector_id)? else {
            return Ok(None);
        };
        let opened = Self::open_local_snapshot(keys, &snapshot, snapshot.bundle.scope)?;
        ensure!(
            expected_guild.is_none_or(|guild| *guild == opened.revision.value.guild_id),
            "paged bootstrap does not belong to the requested guild"
        );
        ensure!(
            opened.private.is_some(),
            "paged bootstrap owner is cancelled"
        );
        Ok(snapshot.bootstrap)
    }

    /// Regenerate a private catalog page using the exact retained revision.
    /// Data/file/blob sectors require their own stable source adapters.
    pub fn render_local_catalog_page(
        control: &ControlStore,
        keys: &KeyMaterial,
        id: uuid::Uuid,
        sector_id: [u8; 32],
        expected_scope: CatalogScope,
    ) -> Result<Option<Vec<u8>>> {
        let Some((source, encoded)) = control.read_paged_revision_page(id, sector_id)? else {
            return Ok(None);
        };
        Self::open_local_snapshot(keys, &source.catalog, expected_scope)?;
        let signed = PagedUserRevision::decode_signed(&source.catalog.bundle.descriptor)?;
        let guild = signed.value.guild_id;
        let (reference, ciphertext) = source.page.seal_private_page(
            &keys.guild_content_id_key(&guild),
            &keys.guild_data_key(&guild),
            source.intent.scope,
            source.intent.section,
            &encoded,
        )?;
        ensure!(
            reference == source.source.sector
                && merkle_commit(&ciphertext)? == source.source.commitment,
            "regenerated catalog page differs from its signed source"
        );
        Ok(Some(ciphertext))
    }

    /// Authenticate recovered page ciphertext, then repair its payload only
    /// if the owning revision and immutable binding remain live under the writer.
    pub fn repair_local_catalog_page(
        control: &ControlStore,
        keys: &KeyMaterial,
        id: uuid::Uuid,
        sector_id: [u8; 32],
        expected_scope: CatalogScope,
        ciphertext: &[u8],
    ) -> Result<()> {
        let source = control
            .paged_revision_page_source(id, sector_id)?
            .ok_or_else(|| anyhow::anyhow!("paged catalog source is unavailable"))?;
        Self::repair_catalog_source(control, keys, &source, expected_scope, ciphertext)
    }

    pub(super) fn repair_catalog_source(
        control: &ControlStore,
        keys: &KeyMaterial,
        source: &mb_store::PagedCatalogPageSource,
        expected_scope: CatalogScope,
        ciphertext: &[u8],
    ) -> Result<()> {
        Self::open_local_snapshot(keys, &source.catalog, expected_scope)?;
        let signed = PagedUserRevision::decode_signed(&source.catalog.bundle.descriptor)?;
        let guild = signed.value.guild_id;
        ensure!(
            merkle_commit(ciphertext)? == source.source.commitment,
            "recovered page differs from its signed Merkle commitment"
        );
        let encoded = source.page.open_private_page(
            &keys.guild_content_id_key(&guild),
            &keys.guild_data_key(&guild),
            source.intent.scope,
            source.intent.section,
            &source.source.sector,
            ciphertext,
        )?;
        control.repair_paged_revision_page(source, &encoded)?;
        Ok(())
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
        ensure!(
            self.git
                .as_ref()
                .is_none_or(|git| git.repository_id == protected_root_id),
            "paged Git repository differs from protected root"
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
        ensure!(
            descriptor
                .git
                .as_ref()
                .is_none_or(|git| git.repository_id == revision.protected_root_id),
            "paged Git repository differs from protected root"
        );
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

    #[cfg(target_os = "linux")]
    use anyhow::Context;
    use ed25519_dalek::SigningKey;
    use mb_core::{
        CatalogFileBuilder, CatalogFileRecipeBuilder, CatalogFileStat, CatalogPageRef,
        CatalogSection, CatalogSectorBuilder, PAGED_USER_REVISION_DOMAIN,
        PagedRevisionSourceReader, Seed, V1_CIPHER_PROFILE, WriterFence, canonical_bytes,
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
        owned_fixture_with_directories(store, with_git, damage, 0)
    }

    fn owned_fixture_with_directories(
        store: &ControlStore,
        with_git: bool,
        damage: u8,
        directories: usize,
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
        let data_id = make_content_sector_id(
            &keys().guild_content_id_key(&[73; 32]),
            keys().node_id(),
            [73; 32],
            Uuid::from_bytes([74; 16]),
            SectorPurpose::Data,
            payload,
        )
        .unwrap();
        let (sector, data) =
            encrypted_sector(&keys().guild_data_key(&[73; 32]), data_id, payload).unwrap();
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
        for index in 0..directories {
            namespace
                .push(
                    &mb_core::CatalogFileRecord {
                        format_version: 1,
                        path: format!("z-{index:08}-{}", "d".repeat(128)).into_bytes(),
                        stat,
                        kind: mb_core::CatalogFileKind::Directory,
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
            let directory = tempfile::tempdir().unwrap();
            let repository = git2::Repository::init_bare(directory.path()).unwrap();
            let blob = repository.blob(payload).unwrap();
            let mut tree = repository.treebuilder(None).unwrap();
            tree.insert("payload", blob, 0o100644).unwrap();
            let tree = tree.write().unwrap();
            let signature =
                git2::Signature::new("Author", "a@example.test", &git2::Time::new(0, 0)).unwrap();
            let commit = repository
                .commit(
                    None,
                    &signature,
                    &signature,
                    "fixture",
                    &repository.find_tree(tree).unwrap(),
                    &[],
                )
                .unwrap();
            let mut sink = |page, bytes| stage_page(store, git_intents[0], &mut pages, page, bytes);
            let mut refs = GitRefCatalogBuilder::new(scope(), b"main").unwrap();
            refs.push_ref(
                &mb_git::GitRefRecord {
                    format_version: 1,
                    name: b"refs/heads/main".to_vec(),
                    oid: if damage == 5 { tree } else { commit }
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                },
                &mut sink,
            )
            .unwrap();
            let refs = refs.finish(&mut sink).unwrap();
            let mut sink = |page, bytes| stage_page(store, git_intents[1], &mut pages, page, bytes);
            let mut objects = GitObjectCatalogBuilder::new(scope()).unwrap();
            let mut entries = [(1, commit), (2, tree)];
            entries.sort_by_key(|(_, oid)| *oid);
            let odb = repository.odb().unwrap();
            for (kind, oid) in entries {
                let object = odb.read(oid).unwrap();
                objects
                    .push_object(
                        oid.as_bytes().try_into().unwrap(),
                        kind,
                        object.len() as u64,
                        &mut object.data(),
                        &mut sink,
                    )
                    .unwrap();
            }
            let objects = objects.finish(&mut sink).unwrap();
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
                repository_id: Uuid::from_bytes([74; 16]),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn paged_native_restore_streams_raw_names_sparse_files_forward_links_and_directory_metadata() {
        use std::os::unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, PermissionsExt},
        };
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let (private, signed, intents) = owned_fixture_with_directories(&store, true, 0, 450);
        private
            .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
            .unwrap();
        let target = temp.path().join("restored");
        let mut reads = 0;
        PagedPrivateMetadata::restore_retained_native_catalog(
            &store,
            &keys(),
            signed.value.revision_id,
            scope(),
            &target,
            |id| {
                reads += 1;
                Ok(encrypted_sector(&keys().guild_data_key(&[73; 32]), *id, b"raw\r\nbytes\0")?.1)
            },
        )
        .unwrap();
        assert_eq!(reads, 1);
        assert_eq!(
            target.metadata().unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(target.metadata().unwrap().mtime(), 123);
        assert_eq!(target.metadata().unwrap().mtime_nsec(), 456);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750)).unwrap();
        let raw = target.join(std::ffi::OsString::from_vec(b"payload-\xff".to_vec()));
        let mut expected = vec![0; 4096];
        expected.extend(b"raw\r\nbytes\0");
        assert_eq!(std::fs::read(&raw).unwrap(), expected);
        assert_eq!(
            raw.metadata().unwrap().ino(),
            target.join("alias").metadata().unwrap().ino()
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 452);
        let directory = target.join(format!("z-00000000-{}", "d".repeat(128)));
        let stat = directory.metadata().unwrap();
        assert_eq!(stat.permissions().mode() & 0o777, 0o640);
        assert_eq!((stat.mtime(), stat.mtime_nsec()), (123, 456));
        assert!(store.records("restore-job").unwrap().is_empty());
        assert!(
            !store
                .has_records_with_kind_prefix("paged-native-restore-")
                .unwrap()
        );
        assert!(
            PagedPrivateMetadata::restore_retained_native_catalog(
                &store,
                &keys(),
                signed.value.revision_id,
                scope(),
                &target,
                |_| anyhow::bail!("existing target must not fetch data")
            )
            .is_err()
        );
        assert_eq!(std::fs::read(raw).unwrap(), expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn paged_native_restore_reopens_failures_and_finishes_renamed_tree_after_source_retirement() {
        use std::os::unix::fs::PermissionsExt;
        for fault in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, false, 0);
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .unwrap();
            let target = temp.path().join("restored");
            if fault == 1 {
                store.database_shell_statement("CREATE TEMP TRIGGER ignore_restore_index BEFORE INSERT ON protocol_records WHEN NEW.kind LIKE 'paged-native-restore-entry-v1/%' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
            }
            if fault == 2 {
                store.database_shell_statement("CREATE TEMP TRIGGER ignore_restore_job BEFORE INSERT ON protocol_records WHEN NEW.kind = 'restore-job' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
            }
            if fault == 3 {
                crate::snapshot::interrupt_next_restore_after_rename();
            }
            let result =
                PagedPrivateMetadata::restore_retained_native_catalog(
                    &store,
                    &keys(),
                    signed.value.revision_id,
                    scope(),
                    &target,
                    |id| {
                        if fault == 0 {
                            return Ok(vec![0; V1_SECTOR_SIZE]);
                        }
                        if fault == 4 {
                            let staging = std::fs::read_dir(temp.path())?
                                .find_map(|entry| {
                                    let entry = entry.ok()?;
                                    entry
                                        .file_name()
                                        .to_str()?
                                        .starts_with(".mutualbackup-restore-")
                                        .then(|| entry.path())
                                })
                                .context("missing staged restore")?;
                            std::fs::write(staging.join("untracked"), b"must not publish")?;
                        }
                        Ok(encrypted_sector(
                            &keys().guild_data_key(&[73; 32]),
                            *id,
                            b"raw\r\nbytes\0",
                        )?
                        .1)
                    },
                );
            assert!(result.is_err(), "fault {fault}");
            assert_eq!(target.exists(), fault == 3);
            if fault == 2 {
                assert!(store.records("restore-job").unwrap().is_empty());
            }
            if fault == 3 {
                store
                    .cancel_paged_revision_catalog(signed.value.revision_id)
                    .unwrap();
            }
            drop(store);
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            PagedPrivateMetadata::restore_retained_native_catalog(
                &store,
                &keys(),
                signed.value.revision_id,
                scope(),
                &target,
                |id| {
                    ensure!(fault != 3, "publishing replay must not fetch retired data");
                    Ok(
                        encrypted_sector(
                            &keys().guild_data_key(&[73; 32]),
                            *id,
                            b"raw\r\nbytes\0",
                        )?
                        .1,
                    )
                },
            )
            .unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750)).unwrap();
            assert!(target.join("alias").is_file());
            assert!(!target.join("untracked").exists());
            assert!(store.records("restore-job").unwrap().is_empty());
            assert!(
                !store
                    .has_records_with_kind_prefix("paged-native-restore-")
                    .unwrap()
            );
        }
    }

    fn writer_fence(signed: &SignedRecord<PagedUserRevision>) -> WriterFence {
        WriterFence {
            owner: signed.value.owner,
            epoch: signed.value.writer_epoch,
            public_key: signed.value.writer_public_key,
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn paged_ordinary_sector_serving_and_recovery_use_shared_root_owned_sources() {
        for with_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("protected");
            std::fs::create_dir(&root).unwrap();
            let area = mb_store::StableAnchorAreaLocator::prepare_for_root(&root).unwrap();
            let anchor_id = Uuid::new_v4();
            let directory = area.path_hint.join(anchor_id.to_string());
            std::fs::create_dir(&directory).unwrap();
            let payload = b"raw\r\nbytes\0";
            let file = directory.join("payload");
            std::fs::write(&file, payload).unwrap();
            let recipe = crate::PagedAnchorSectorSource {
                locator: mb_store::StableAnchorFileLocator {
                    area,
                    anchor_id,
                    relative_path: "payload".into(),
                },
                offset: 0,
            };
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let mut ids = Vec::new();
            let mut expected_pages = std::collections::BTreeMap::new();
            let data_id = make_content_sector_id(
                &keys().guild_content_id_key(&[73; 32]),
                keys().node_id(),
                [73; 32],
                Uuid::from_bytes([74; 16]),
                SectorPurpose::Data,
                payload,
            )
            .unwrap();
            let (data_ref, data_ciphertext) =
                encrypted_sector(&keys().guild_data_key(&[73; 32]), data_id, payload).unwrap();
            for _ in 0..2 {
                let (private, signed, intents) =
                    owned_fixture_with_directories(&store, with_git, 0, 1000);
                private
                    .publish_local_catalog_with_data_sources(
                        &store,
                        &keys(),
                        &signed,
                        &writer_fence(&signed),
                        intents,
                        |record| Ok((record.sector.id == data_id).then(|| recipe.clone())),
                    )
                    .unwrap();
                ids.push(signed.value.revision_id);
                for (section, root) in private
                    .native
                    .page_roots()
                    .map(|root| (CatalogSection::FileMetadata, root))
                    .into_iter()
                    .chain(private.git.into_iter().flat_map(|git| {
                        git.page_roots()
                            .map(|root| (CatalogSection::GitGraph, root))
                    }))
                {
                    let mut reader = mb_core::CatalogReader::new(scope(), section, root).unwrap();
                    while reader
                        .next_leaf(&mut |page| -> Result<Vec<u8>> {
                            let encoded = store.catalog_page(scope(), section, page)?;
                            let (reference, ciphertext) = page.seal_private_page(
                                &keys().guild_content_id_key(&[73; 32]),
                                &keys().guild_data_key(&[73; 32]),
                                scope(),
                                section,
                                &encoded,
                            )?;
                            expected_pages.insert(reference.id, (reference, page, ciphertext));
                            Ok(encoded)
                        })
                        .unwrap()
                        .is_some()
                    {}
                }
            }
            drop(store);
            let mut store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[73; 32])).unwrap(),
                data_ciphertext
            );
            assert!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[1; 32])).is_err()
            );
            assert!(
                crate::snapshot::render_sector(
                    &store,
                    &KeyMaterial::from_seed(&Seed::from_bytes([1; 32])),
                    &data_id,
                    Some(&[73; 32])
                )
                .is_err()
            );
            crate::snapshot::install_recovered_sector_recipe(
                &mut store,
                &keys(),
                [73; 32],
                data_ref.clone(),
                &data_ciphertext,
            )
            .unwrap();
            for (sector, (reference, page, ciphertext)) in &expected_pages {
                assert_eq!(
                    crate::snapshot::render_sector(&store, &keys(), sector, None).unwrap(),
                    *ciphertext
                );
                assert!(
                    crate::snapshot::render_sector(&store, &keys(), sector, Some(&[1; 32]))
                        .is_err()
                );
                store.delete_record("catalog-page-v1", &page.hash).unwrap();
                assert!(
                    crate::snapshot::render_sector(&store, &keys(), sector, Some(&[73; 32]))
                        .is_err()
                );
                let mut bad = ciphertext.clone();
                bad[0] ^= 1;
                assert!(
                    crate::snapshot::install_recovered_sector_recipe(
                        &mut store,
                        &keys(),
                        [73; 32],
                        reference.clone(),
                        &bad
                    )
                    .is_err()
                );
                assert!(
                    crate::snapshot::install_recovered_sector_recipe(
                        &mut store,
                        &keys(),
                        [1; 32],
                        reference.clone(),
                        ciphertext
                    )
                    .is_err()
                );
                assert!(
                    crate::snapshot::install_recovered_sector_recipe(
                        &mut store,
                        &KeyMaterial::from_seed(&Seed::from_bytes([1; 32])),
                        [73; 32],
                        reference.clone(),
                        ciphertext
                    )
                    .is_err()
                );
                crate::snapshot::install_recovered_sector_recipe(
                    &mut store,
                    &keys(),
                    [73; 32],
                    reference.clone(),
                    ciphertext,
                )
                .unwrap();
                assert_eq!(
                    crate::snapshot::render_sector(&store, &keys(), sector, Some(&[73; 32]))
                        .unwrap(),
                    *ciphertext
                );
            }
            // An active damaged source cannot be obscured by a legacy Inline
            // copy, and its recovery requires a durable stable replacement.
            std::fs::write(&file, b"damaged stable data").unwrap();
            assert!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[73; 32])).is_err()
            );
            crate::snapshot::install_inline_recipe(
                &mut store,
                [73; 32],
                data_ref.clone(),
                payload.to_vec(),
            )
            .unwrap();
            assert!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[73; 32])).is_err()
            );
            store.delete_record("local-sector", &data_id).unwrap();
            assert!(
                crate::snapshot::install_recovered_sector_recipe(
                    &mut store,
                    &keys(),
                    [73; 32],
                    data_ref.clone(),
                    &data_ciphertext
                )
                .is_err()
            );
            assert!(store.records("local-sector").unwrap().is_empty());
            std::fs::write(&file, payload).unwrap();
            let selected = store
                .paged_sector_source(data_id)
                .unwrap()
                .unwrap()
                .catalog()
                .bundle
                .id;
            let remaining = *ids.iter().find(|id| **id != selected).unwrap();
            store.cancel_paged_revision_catalog(selected).unwrap();
            assert_eq!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[73; 32])).unwrap(),
                data_ciphertext
            );
            for (sector, (_, _, ciphertext)) in &expected_pages {
                assert_eq!(
                    crate::snapshot::render_sector(&store, &keys(), sector, Some(&[73; 32]))
                        .unwrap(),
                    *ciphertext
                );
            }
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[73; 32])).unwrap(),
                data_ciphertext
            );
            store.cancel_paged_revision_catalog(remaining).unwrap();
            assert!(
                crate::snapshot::render_sector(&store, &keys(), &data_id, Some(&[73; 32])).is_err()
            );
            for sector in expected_pages.keys() {
                assert!(
                    crate::snapshot::render_sector(&store, &keys(), sector, Some(&[73; 32]))
                        .is_err()
                );
            }
            for id in ids {
                while store.release_paged_revision_page_source(id).unwrap() {}
                while store.release_paged_revision_data_source(id).unwrap() {}
            }
            assert!(store.paged_data_anchor_ids().unwrap().is_empty());
            assert!(store.records("local-sector").unwrap().is_empty());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn paged_data_source_recovery_replacement_authenticates_bytes_and_preserves_fences() {
        for with_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("protected");
            std::fs::create_dir(&root).unwrap();
            let area = mb_store::StableAnchorAreaLocator::prepare_for_root(&root).unwrap();
            let payload = b"raw\r\nbytes\0";
            let make_source = |prefix: &[u8]| {
                let anchor_id = Uuid::new_v4();
                let directory = area.path_hint.join(anchor_id.to_string());
                std::fs::create_dir(&directory).unwrap();
                let mut bytes = prefix.to_vec();
                bytes.extend_from_slice(payload);
                let file = directory.join("payload");
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
            let (old_recipe, old_file, _) = make_source(b"old");
            let (replacement, replacement_file, correct_bytes) = make_source(b"replacement");
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, with_git, 0);
            let sector = make_content_sector_id(
                &keys().guild_content_id_key(&[73; 32]),
                keys().node_id(),
                [73; 32],
                Uuid::from_bytes([74; 16]),
                SectorPurpose::Data,
                payload,
            )
            .unwrap();
            private
                .publish_local_catalog_with_data_sources(
                    &store,
                    &keys(),
                    &signed,
                    &writer_fence(&signed),
                    intents,
                    |record| Ok((record.sector.id == sector).then(|| old_recipe.clone())),
                )
                .unwrap();
            let id = signed.value.revision_id;
            let expected = store
                .paged_revision_data_source(id, sector)
                .unwrap()
                .unwrap();
            let (_, ciphertext) =
                encrypted_sector(&keys().guild_data_key(&[73; 32]), sector, payload).unwrap();
            std::fs::remove_file(old_file).unwrap();
            assert!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    id,
                    sector,
                    scope()
                )
                .is_err()
            );
            let mut damaged = correct_bytes.clone();
            damaged[replacement.offset as usize] ^= 1;
            std::fs::write(&replacement_file, damaged).unwrap();
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
            assert_eq!(
                store.paged_revision_data_source(id, sector).unwrap(),
                Some(expected.clone())
            );
            assert!(
                !store
                    .paged_data_anchor_is_pinned(replacement.locator.anchor_id)
                    .unwrap()
            );
            std::fs::write(&replacement_file, &correct_bytes).unwrap();
            let wrong_keys = KeyMaterial::from_seed(&Seed::from_bytes([1; 32]));
            assert!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &wrong_keys,
                    &expected,
                    scope(),
                    &replacement
                )
                .is_err()
            );
            let moved = PagedPrivateMetadata::replace_local_data_source(
                &store,
                &keys(),
                &expected,
                scope(),
                &replacement,
            )
            .unwrap();
            assert_eq!(moved.generation, 1);
            assert_eq!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &keys(),
                    &expected,
                    scope(),
                    &replacement
                )
                .unwrap(),
                moved
            );
            assert!(
                !store
                    .paged_data_anchor_is_pinned(old_recipe.locator.anchor_id)
                    .unwrap()
            );
            assert!(
                crate::snapshot::git_prune_recipe_anchor_ids(&store)
                    .unwrap()
                    .contains(&replacement.locator.anchor_id)
            );
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    id,
                    sector,
                    scope()
                )
                .unwrap(),
                Some(ciphertext.clone())
            );
            // Reauthentication also applies to an otherwise exact retry.
            std::fs::write(&replacement_file, b"lost").unwrap();
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
            std::fs::write(&replacement_file, &correct_bytes).unwrap();
            let (competing, _, _) = make_source(b"competing");
            let winner = PagedPrivateMetadata::replace_local_data_source(
                &store,
                &keys(),
                &moved,
                scope(),
                &competing,
            )
            .unwrap();
            assert_eq!(winner.generation, 2);
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
            assert_eq!(
                store.paged_revision_data_source(id, sector).unwrap(),
                Some(winner.clone())
            );
            store.cancel_paged_revision_catalog(id).unwrap();
            assert!(
                PagedPrivateMetadata::replace_local_data_source(
                    &store,
                    &keys(),
                    &winner,
                    scope(),
                    &replacement
                )
                .is_err()
            );
            assert!(store.release_paged_revision_data_source(id).unwrap());
            assert!(store.paged_data_anchor_ids().unwrap().is_empty());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn paged_stable_native_and_git_data_sources_reopen_authenticate_and_pin_cleanup() {
        for with_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("protected");
            std::fs::create_dir(&root).unwrap();
            let mut area = mb_store::StableAnchorAreaLocator::prepare_for_root(&root).unwrap();
            // Keep fallback qualification within this disposable namespace.
            area.volume_root_hint = temp.path().to_path_buf();
            let original_area = area.path_hint.clone();
            let area_id = area.area_id;
            let anchor_id = Uuid::new_v4();
            let directory = area.path_hint.join(anchor_id.to_string());
            std::fs::create_dir(&directory).unwrap();
            let payload = b"raw\r\nbytes\0";
            let file = directory.join("payload");
            let mut contents = b"head".to_vec();
            contents.extend_from_slice(payload);
            std::fs::write(&file, &contents).unwrap();
            let recipe = crate::PagedAnchorSectorSource {
                locator: mb_store::StableAnchorFileLocator {
                    area,
                    anchor_id,
                    relative_path: "payload".into(),
                },
                offset: 4,
            };
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, with_git, 0);
            let sector = make_content_sector_id(
                &keys().guild_content_id_key(&[73; 32]),
                keys().node_id(),
                [73; 32],
                Uuid::from_bytes([74; 16]),
                SectorPurpose::Data,
                payload,
            )
            .unwrap();
            let (_, ciphertext) =
                encrypted_sector(&keys().guild_data_key(&[73; 32]), sector, payload).unwrap();
            for _ in 0..2 {
                private
                    .publish_local_catalog_with_data_sources(
                        &store,
                        &keys(),
                        &signed,
                        &writer_fence(&signed),
                        intents,
                        |record| Ok((record.sector.id == sector).then(|| recipe.clone())),
                    )
                    .unwrap();
            }
            assert!(store.records("local-sector").unwrap().is_empty());
            assert!(
                crate::snapshot::git_prune_recipe_anchor_ids(&store)
                    .unwrap()
                    .contains(&anchor_id)
            );
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            let render = || {
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    signed.value.revision_id,
                    sector,
                    scope(),
                )
            };
            assert_eq!(render().unwrap(), Some(ciphertext.clone()));
            assert_eq!(
                crate::snapshot::render_sector(&store, &keys(), &sector, Some(&[73; 32])).unwrap(),
                ciphertext
            );
            assert_eq!(
                crate::snapshot::anchor_area_hint(&store, area_id).unwrap(),
                Some(original_area.clone())
            );
            let saved_hint = store
                .get_record("anchor-area-location", area_id.as_bytes())
                .unwrap();
            use std::os::unix::ffi::OsStringExt;
            let moved = temp.path().join(std::ffi::OsString::from_vec(
                b".mutualbackup-anchors-moved-\xff".to_vec(),
            ));
            std::fs::rename(&original_area, &moved).unwrap();
            let readonly = ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).unwrap();
            let mut readonly_bytes = None;
            for _ in 0..100 {
                match PagedPrivateMetadata::render_local_sector(
                    &readonly,
                    &keys(),
                    sector,
                    Some(&[73; 32]),
                    false,
                ) {
                    Ok(bytes) => {
                        readonly_bytes = bytes;
                        break;
                    }
                    Err(error)
                        if matches!(
                            error.downcast_ref::<mb_store::AnchorError>(),
                            Some(mb_store::AnchorError::AnchorAreaDiscoveryPending)
                        ) => {}
                    Err(error) => panic!("{error:#}"),
                }
            }
            drop(readonly);
            assert_eq!(readonly_bytes, Some(ciphertext.clone()));
            assert_eq!(
                store
                    .get_record("anchor-area-location", area_id.as_bytes())
                    .unwrap(),
                saved_hint
            );
            assert_eq!(render().unwrap(), Some(ciphertext.clone()));
            assert_eq!(
                crate::snapshot::render_sector(&store, &keys(), &sector, Some(&[73; 32])).unwrap(),
                ciphertext
            );
            assert_eq!(
                crate::snapshot::anchor_area_hint(&store, area_id).unwrap(),
                Some(moved.clone())
            );
            // A second rename uses a durable hint outside automatic discovery's
            // name prefix. Neither the old locator nor its cached path works.
            let final_area = temp
                .path()
                .join(std::ffi::OsString::from_vec(b"relocated-\xfe".to_vec()));
            std::fs::rename(&moved, &final_area).unwrap();
            crate::snapshot::remember_anchor_area_location(&store, area_id, &final_area).unwrap();
            let readonly = ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                PagedPrivateMetadata::render_local_data_sector(
                    &readonly,
                    &keys(),
                    signed.value.revision_id,
                    sector,
                    scope(),
                )
                .unwrap(),
                Some(ciphertext.clone())
            );
            drop(readonly);
            let other = KeyMaterial::from_seed(&Seed::from_bytes([1; 32]));
            assert!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &other,
                    signed.value.revision_id,
                    sector,
                    scope()
                )
                .is_err()
            );
            let mut wrong_scope = scope();
            if let CatalogScope::Dataset {
                protected_root_id, ..
            } = &mut wrong_scope
            {
                *protected_root_id = Uuid::new_v4();
            }
            assert!(
                PagedPrivateMetadata::render_local_data_sector(
                    &store,
                    &keys(),
                    signed.value.revision_id,
                    sector,
                    wrong_scope
                )
                .is_err()
            );
            store
                .delete_record("anchor-area-location", area_id.as_bytes())
                .unwrap();
            std::fs::rename(&final_area, &original_area).unwrap();
            let file = original_area.join(anchor_id.to_string()).join("payload");
            let mut changed = contents.clone();
            changed[4] ^= 1;
            std::fs::write(&file, changed).unwrap();
            assert!(render().is_err());
            assert!(
                crate::snapshot::render_sector(&store, &keys(), &sector, Some(&[73; 32])).is_err()
            );
            assert!(
                crate::snapshot::anchor_area_hint(&store, area_id)
                    .unwrap()
                    .is_none()
            );
            std::fs::write(&file, &contents).unwrap();
            assert_eq!(render().unwrap(), Some(ciphertext));
            std::fs::remove_file(&file).unwrap();
            assert!(render().is_err());
            std::fs::write(&file, &contents).unwrap();
            store
                .cancel_paged_revision_catalog(signed.value.revision_id)
                .unwrap();
            assert!(render().unwrap().is_none());
            assert!(
                crate::snapshot::git_prune_recipe_anchor_ids(&store)
                    .unwrap()
                    .contains(&anchor_id)
            );
            assert!(
                store
                    .release_paged_revision_data_source(signed.value.revision_id)
                    .unwrap()
            );
            assert!(
                !store
                    .release_paged_revision_data_source(signed.value.revision_id)
                    .unwrap()
            );
            assert!(
                !crate::snapshot::git_prune_recipe_anchor_ids(&store)
                    .unwrap()
                    .contains(&anchor_id)
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn paged_stable_data_rejects_bad_geometry_paths_and_payload_without_publication() {
        for damage in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("protected");
            std::fs::create_dir(&root).unwrap();
            let area = mb_store::StableAnchorAreaLocator::prepare_for_root(&root).unwrap();
            let anchor_id = Uuid::new_v4();
            std::fs::create_dir(area.path_hint.join(anchor_id.to_string())).unwrap();
            std::fs::write(
                area.path_hint.join(anchor_id.to_string()).join("payload"),
                b"wrong",
            )
            .unwrap();
            let mut recipe = crate::PagedAnchorSectorSource {
                locator: mb_store::StableAnchorFileLocator {
                    area,
                    anchor_id,
                    relative_path: "payload".into(),
                },
                offset: 0,
            };
            match damage {
                0 => recipe.offset = u64::MAX,
                1 => recipe.locator.relative_path = "../payload".into(),
                2 => {
                    recipe.locator.relative_path =
                        "p".repeat(mb_store::PAGED_DATA_RECIPE_BYTES + 1).into()
                }
                3 => {}
                _ => unreachable!(),
            }
            let store =
                ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, true, 0);
            let data_id = make_content_sector_id(
                &keys().guild_content_id_key(&[73; 32]),
                keys().node_id(),
                [73; 32],
                Uuid::from_bytes([74; 16]),
                SectorPurpose::Data,
                b"raw\r\nbytes\0",
            )
            .unwrap();
            assert!(
                private
                    .publish_local_catalog_with_data_sources(
                        &store,
                        &keys(),
                        &signed,
                        &writer_fence(&signed),
                        intents,
                        |record| Ok((record.sector.id == data_id).then(|| recipe.clone()))
                    )
                    .is_err()
            );
            assert!(
                store
                    .paged_revision_catalog(signed.value.revision_id)
                    .unwrap()
                    .is_none()
            );
            assert!(!store.paged_data_anchor_is_pinned(anchor_id).unwrap());
            assert!(
                store
                    .records(&format!(
                        "catalog-paged-data-source-v1/{}",
                        signed.value.revision_id.simple()
                    ))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn paged_private_page_sources_regenerate_and_repair_all_root_roles_and_index_pages() {
        for with_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (private, signed, intents) =
                owned_fixture_with_directories(&store, with_git, 0, 1000);
            assert!(private.native.namespace.records.page.height > 0);
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .unwrap();
            let id = signed.value.revision_id;
            let bundle = store.paged_revision_catalog(id).unwrap().unwrap().bundle;
            let mut expected = std::collections::BTreeMap::new();
            for member in bundle
                .roots
                .iter()
                .filter(|member| member.intent.section.is_private())
            {
                let section = member.intent.section;
                let mut reader =
                    mb_core::CatalogReader::new(scope(), section, member.root).unwrap();
                while reader
                    .next_leaf(&mut |page| -> Result<Vec<u8>> {
                        let encoded = store.catalog_page(scope(), section, page)?;
                        let (reference, ciphertext) = page.seal_private_page(
                            &keys().guild_content_id_key(&[73; 32]),
                            &keys().guild_data_key(&[73; 32]),
                            scope(),
                            section,
                            &encoded,
                        )?;
                        expected.insert(reference.id, (page, ciphertext));
                        Ok(encoded)
                    })
                    .unwrap()
                    .is_some()
                {}
            }
            assert_eq!(
                store
                    .records(&format!("catalog-paged-page-source-v1/{}", id.simple()))
                    .unwrap()
                    .len(),
                expected.len()
            );
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            for (sector, (page, ciphertext)) in &expected {
                let render = || {
                    PagedPrivateMetadata::render_local_catalog_page(
                        &store,
                        &keys(),
                        id,
                        *sector,
                        scope(),
                    )
                };
                assert_eq!(render().unwrap(), Some(ciphertext.clone()));
                assert!(
                    PagedPrivateMetadata::render_local_catalog_page(
                        &store,
                        &KeyMaterial::from_seed(&Seed::from_bytes([1; 32])),
                        id,
                        *sector,
                        scope()
                    )
                    .is_err()
                );
                let mut wrong_scope = scope();
                if let CatalogScope::Dataset { guild_id, .. } = &mut wrong_scope {
                    *guild_id = [1; 32];
                }
                assert!(
                    PagedPrivateMetadata::render_local_catalog_page(
                        &store,
                        &keys(),
                        id,
                        *sector,
                        wrong_scope
                    )
                    .is_err()
                );
                let encoded = store
                    .get_record("catalog-page-v1", &page.hash)
                    .unwrap()
                    .unwrap();
                let mut damaged = encoded.clone();
                damaged[0] ^= 1;
                store
                    .put_record("catalog-page-v1", &page.hash, &damaged)
                    .unwrap();
                assert!(render().is_err());
                let mut bad_ciphertext = ciphertext.clone();
                bad_ciphertext[0] ^= 1;
                assert!(
                    PagedPrivateMetadata::repair_local_catalog_page(
                        &store,
                        &keys(),
                        id,
                        *sector,
                        scope(),
                        &bad_ciphertext
                    )
                    .is_err()
                );
                PagedPrivateMetadata::repair_local_catalog_page(
                    &store,
                    &keys(),
                    id,
                    *sector,
                    scope(),
                    ciphertext,
                )
                .unwrap();
                assert_eq!(render().unwrap(), Some(ciphertext.clone()));
            }
            store.cancel_paged_revision_catalog(id).unwrap();
            for (sector, (_, ciphertext)) in &expected {
                assert!(
                    PagedPrivateMetadata::render_local_catalog_page(
                        &store,
                        &keys(),
                        id,
                        *sector,
                        scope()
                    )
                    .unwrap()
                    .is_none()
                );
                assert!(
                    PagedPrivateMetadata::repair_local_catalog_page(
                        &store,
                        &keys(),
                        id,
                        *sector,
                        scope(),
                        ciphertext
                    )
                    .is_err()
                );
            }
            let mut released = 0;
            while store.release_paged_revision_page_source(id).unwrap() {
                released += 1;
            }
            assert_eq!(released, expected.len());
        }
    }

    #[test]
    fn paged_bootstrap_sector_rendering_authenticates_and_tracks_shared_ownership() {
        for with_git in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (private, signed, intents) = owned_fixture(&store, with_git, 0);
            let (source, ciphertext) = private.seal(&keys(), scope()).unwrap();
            let sector = source.sector.id;
            let render = |store: &ControlStore| {
                crate::snapshot::render_sector(store, &keys(), &sector, Some(&[73; 32]))
            };
            assert!(render(&store).is_err());
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .unwrap();
            let (next_private, next, next_intents) = owned_fixture(&store, with_git, 0);
            let mut body = next.value;
            body.sequence = 2;
            body.parent = Some(signed.value.hash().unwrap());
            let next = body
                .sign(&SigningKey::from_bytes(&[72; 32]), &keys())
                .unwrap();
            assert_eq!(next_private, private);
            assert_eq!(next.value.metadata, source);
            next_private
                .publish_local_catalog(&store, &keys(), &next, &writer_fence(&next), next_intents)
                .unwrap();
            // Legacy recipe bytes cannot replace a retained signed bootstrap.
            store
                .put_record("local-sector", &sector, b"invalid recipe")
                .unwrap();
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(render(&store).unwrap(), ciphertext);
            assert!(
                crate::snapshot::render_sector(&store, &keys(), &sector, Some(&[1; 32])).is_err()
            );
            let other_keys = KeyMaterial::from_seed(&Seed::from_bytes([1; 32]));
            assert!(crate::snapshot::render_sector(&store, &other_keys, &sector, None).is_err());
            let mut corrupt = ciphertext.clone();
            corrupt[0] ^= 1;
            store
                .put_record("paged-revision-bootstrap-v1", &sector, &corrupt)
                .unwrap();
            assert!(render(&store).is_err());
            store
                .put_record("paged-revision-bootstrap-v1", &sector, &ciphertext)
                .unwrap();
            store
                .cancel_paged_revision_catalog(signed.value.revision_id)
                .unwrap();
            assert_eq!(render(&store).unwrap(), ciphertext);
            store
                .cancel_paged_revision_catalog(next.value.revision_id)
                .unwrap();
            assert!(
                PagedPrivateMetadata::render_local_bootstrap(&store, &keys(), sector, None)
                    .unwrap()
                    .is_none()
            );
            assert!(render(&store).is_err());
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert!(render(&store).is_err());
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

    #[test]
    fn paged_git_publication_rejects_wrong_ref_target_before_validation_and_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let (private, signed, intents) = owned_fixture(&store, true, 5);
        assert!(
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .is_err()
        );
        assert!(
            store
                .paged_revision_catalog(signed.value.revision_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .native_file_catalog_validation(signed.value.revision_id)
                .unwrap()
                .is_none()
        );
        drop(store);
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        assert!(
            private
                .publish_local_catalog(&store, &keys(), &signed, &writer_fence(&signed), intents)
                .is_err()
        );
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
        let (valid, valid_signed, valid_intents) = owned_fixture(&store, true, 0);
        valid
            .publish_local_catalog(
                &store,
                &keys(),
                &valid_signed,
                &writer_fence(&valid_signed),
                valid_intents,
            )
            .unwrap();
        assert!(
            store
                .paged_revision_catalog(valid_signed.value.revision_id)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .paged_revision_catalog(signed.value.revision_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn paged_git_repository_identity_is_bound_during_seal_and_authenticated_open() {
        let mut private = descriptor(true);
        private.git.as_mut().unwrap().repository_id = Uuid::from_bytes([77; 16]);
        assert!(private.seal(&keys(), scope()).is_err());
        // Construct an otherwise authenticated descriptor as an untrusted owner
        // could, bypassing the local sealing API's admission check.
        let bytes = canonical_bytes_bounded(&private, PAGED_PRIVATE_METADATA_BYTES).unwrap();
        let id = make_content_sector_id(
            &keys().guild_content_id_key(&[73; 32]),
            keys().node_id(),
            [73; 32],
            Uuid::from_bytes([74; 16]),
            SectorPurpose::Metadata,
            &bytes,
        )
        .unwrap();
        let (sector, ciphertext) =
            encrypted_sector(&keys().guild_data_key(&[73; 32]), id, &bytes).unwrap();
        let (signed, _) = signed(CatalogSectorRecord {
            format_version: 1,
            sector,
            commitment: merkle_commit(&ciphertext).unwrap(),
        });
        PagedUserRevision::verify_signed(&signed).unwrap();
        assert!(PagedPrivateMetadata::open(&keys(), [73; 32], &signed, &ciphertext).is_err());
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
            repository_id: Uuid::from_bytes([74; 16]),
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

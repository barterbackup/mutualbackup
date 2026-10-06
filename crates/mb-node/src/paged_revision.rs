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
use serde::{Deserialize, Serialize};

pub const PAGED_PRIVATE_METADATA_BYTES: usize = mb_core::PAGED_PRIVATE_METADATA_BYTES;

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

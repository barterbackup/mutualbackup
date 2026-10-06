//! Derivable page addresses and private page sectors. A private reference must
//! be obtained from authenticated owner-encrypted metadata; publishing its
//! plaintext hash would allow metadata guesses despite the keyed storage ID.

use crate::{
    SectorId, SectorRef, V1_SECTOR_SIZE, canonical_bytes, crypt_sector, encrypted_sector,
    sector_root,
};

use super::{CatalogError, CatalogPageRef, CatalogScope, CatalogSection};

impl CatalogPageRef {
    /// Public lookup address. Authority still comes from the signed catalog
    /// root and verified parent path, never from a server's returned hash.
    pub fn public_page_id(
        self,
        scope: CatalogScope,
        section: CatalogSection,
    ) -> Result<SectorId, CatalogError> {
        self.validate()?;
        scope.validate(section)?;
        if section.is_private() {
            return Err(CatalogError::InvalidPage);
        }
        let mut hash =
            blake3::Hasher::new_derive_key("mutualbackup public catalog page address v1");
        hash.update(&canonical_bytes(&(1_u16, scope, section, self))?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Keyed lookup address can be recovered from an authenticated parent
    /// reference without fetching the child's plaintext first. Binding all
    /// reference fields also prevents malformed aliases of the same hash.
    pub fn private_sector_id(
        self,
        identity_key: &[u8; 32],
        scope: CatalogScope,
        section: CatalogSection,
    ) -> Result<SectorId, CatalogError> {
        self.validate()?;
        scope.validate(section)?;
        if !section.is_private() {
            return Err(CatalogError::InvalidPage);
        }
        let mut hash = blake3::Hasher::new_keyed(identity_key);
        hash.update(b"mutualbackup private catalog page address v1");
        hash.update(&canonical_bytes(&(1_u16, scope, section, self))?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Validate before padding/encrypting a complete bounded page. The existing
    /// sector representation supplies the same exact ciphertext, flat root and
    /// Merkle-commitment input used by coding, packing and repair.
    pub fn seal_private_page(
        self,
        identity_key: &[u8; 32],
        encryption_key: &[u8; 32],
        scope: CatalogScope,
        section: CatalogSection,
        encoded: &[u8],
    ) -> Result<(SectorRef, Vec<u8>), CatalogError> {
        let id = self.private_sector_id(identity_key, scope, section)?;
        self.verify_page(scope, section, encoded)?;
        Ok(encrypted_sector(encryption_key, id, encoded)?)
    }

    /// Check the expected address, exact sector geometry/ciphertext root,
    /// canonical padding and authenticated plaintext page before returning it.
    /// The sector reference must be bound by the signed source catalog when
    /// using its ciphertext root as authority for reconstruction or repair.
    pub fn open_private_page(
        self,
        identity_key: &[u8; 32],
        encryption_key: &[u8; 32],
        scope: CatalogScope,
        section: CatalogSection,
        sector: &SectorRef,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CatalogError> {
        let id = self.private_sector_id(identity_key, scope, section)?;
        if sector.id != id
            || sector.logical_len != self.encoded_len
            || ciphertext.len() != V1_SECTOR_SIZE
            || sector.root != sector_root(ciphertext)
        {
            return Err(CatalogError::InvalidPage);
        }
        let mut bytes = ciphertext.to_vec();
        crypt_sector(encryption_key, id, &mut bytes)?;
        let length = self.encoded_len as usize;
        if bytes[length..].iter().any(|byte| *byte != 0) {
            return Err(CatalogError::InvalidPage);
        }
        bytes.truncate(length);
        self.verify_page(scope, section, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        CATALOG_LEAF_BYTES, CatalogBuilder, CatalogPageContents, CatalogReader, KeyMaterial,
        NodeId, SectorPurpose, Seed, make_content_sector_id, merkle_commit,
    };
    use uuid::Uuid;

    use super::*;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn single(section: CatalogSection) -> (CatalogPageRef, Vec<u8>) {
        let mut page = Vec::new();
        let mut sink = |_, encoded| {
            page = encoded;
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(scope(), section).unwrap();
        builder
            .push(b"private filenames and exact Git object bytes", &mut sink)
            .unwrap();
        (builder.finish(&mut sink).unwrap(), page)
    }

    #[test]
    fn private_catalog_sector_reuses_only_exact_scoped_pages_and_regenerates_coding_bytes() {
        let (page, encoded) = single(CatalogSection::GitGraph);
        let (sector, ciphertext) = page
            .seal_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::GitGraph,
                &encoded,
            )
            .unwrap();
        assert_eq!(
            sector.id,
            page.private_sector_id(&[4; 32], scope(), CatalogSection::GitGraph)
                .unwrap()
        );
        assert_ne!(sector.id, page.hash);
        assert_eq!(ciphertext.len(), V1_SECTOR_SIZE);
        assert_eq!(sector.logical_len as usize, encoded.len());
        assert_eq!(sector.root, sector_root(&ciphertext));
        assert_ne!(&ciphertext[..encoded.len()], encoded);
        let regenerated = page
            .seal_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::GitGraph,
                &encoded,
            )
            .unwrap();
        assert_eq!(regenerated, (sector.clone(), ciphertext.clone()));
        assert_eq!(
            merkle_commit(&regenerated.1).unwrap(),
            merkle_commit(&ciphertext).unwrap()
        );
        assert_eq!(
            page.open_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::GitGraph,
                &sector,
                &ciphertext
            )
            .unwrap(),
            encoded
        );
        assert_ne!(
            sector.id,
            make_content_sector_id(
                &[4; 32],
                NodeId([2; 32]),
                [1; 32],
                Uuid::from_bytes([3; 16]),
                SectorPurpose::Metadata,
                &encoded
            )
            .unwrap()
        );
    }

    #[test]
    fn private_catalog_addresses_bind_keys_scope_section_and_reference_geometry() {
        let (reference, encoded) = single(CatalogSection::GitGraph);
        let key = [4; 32];
        let first = reference
            .private_sector_id(&key, scope(), CatalogSection::GitGraph)
            .unwrap();
        assert_ne!(
            first,
            reference
                .private_sector_id(&[5; 32], scope(), CatalogSection::GitGraph)
                .unwrap()
        );
        for alternate in [
            CatalogScope::Dataset {
                guild_id: [6; 32],
                owner: NodeId([2; 32]),
                protected_root_id: Uuid::from_bytes([3; 16]),
            },
            CatalogScope::Dataset {
                guild_id: [1; 32],
                owner: NodeId([7; 32]),
                protected_root_id: Uuid::from_bytes([3; 16]),
            },
            CatalogScope::Dataset {
                guild_id: [1; 32],
                owner: NodeId([2; 32]),
                protected_root_id: Uuid::from_bytes([8; 16]),
            },
        ] {
            assert_ne!(
                first,
                reference
                    .private_sector_id(&key, alternate, CatalogSection::GitGraph)
                    .unwrap()
            );
            assert!(
                reference
                    .seal_private_page(
                        &key,
                        &[9; 32],
                        alternate,
                        CatalogSection::GitGraph,
                        &encoded
                    )
                    .is_err()
            );
        }
        assert_ne!(
            first,
            reference
                .private_sector_id(&key, scope(), CatalogSection::FileMetadata)
                .unwrap()
        );
        assert!(
            reference
                .seal_private_page(
                    &key,
                    &[9; 32],
                    scope(),
                    CatalogSection::FileMetadata,
                    &encoded
                )
                .is_err()
        );
        let mut changed = reference;
        changed.encoded_len += 1;
        assert_ne!(
            first,
            changed
                .private_sector_id(&key, scope(), CatalogSection::GitGraph)
                .unwrap()
        );
        assert!(
            changed
                .seal_private_page(&key, &[9; 32], scope(), CatalogSection::GitGraph, &encoded)
                .is_err()
        );
    }

    #[test]
    fn private_catalog_open_rejects_corruption_wrong_keys_lengths_and_noncanonical_padding() {
        let (page, encoded) = single(CatalogSection::FileMetadata);
        let (sector, ciphertext) = page
            .seal_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::FileMetadata,
                &encoded,
            )
            .unwrap();
        assert!(
            page.open_private_page(
                &[6; 32],
                &[5; 32],
                scope(),
                CatalogSection::FileMetadata,
                &sector,
                &ciphertext
            )
            .is_err()
        );
        assert!(
            page.open_private_page(
                &[4; 32],
                &[6; 32],
                scope(),
                CatalogSection::FileMetadata,
                &sector,
                &ciphertext
            )
            .is_err()
        );
        for wrong in [
            SectorRef {
                id: [7; 32],
                ..sector.clone()
            },
            SectorRef {
                root: [7; 32],
                ..sector.clone()
            },
            SectorRef {
                logical_len: sector.logical_len - 1,
                ..sector.clone()
            },
        ] {
            assert!(
                page.open_private_page(
                    &[4; 32],
                    &[5; 32],
                    scope(),
                    CatalogSection::FileMetadata,
                    &wrong,
                    &ciphertext
                )
                .is_err()
            );
        }
        assert!(
            page.open_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::FileMetadata,
                &sector,
                &ciphertext[..ciphertext.len() - 1]
            )
            .is_err()
        );
        let mut corrupt = ciphertext.clone();
        corrupt[0] ^= 1;
        assert!(
            page.open_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::FileMetadata,
                &sector,
                &corrupt
            )
            .is_err()
        );
        // A self-reported ciphertext hash cannot replace plaintext authority.
        let rehashed = SectorRef {
            root: sector_root(&corrupt),
            ..sector.clone()
        };
        assert!(
            page.open_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::FileMetadata,
                &rehashed,
                &corrupt
            )
            .is_err()
        );
        let mut padding = ciphertext.clone();
        *padding.last_mut().unwrap() ^= 1;
        let rehashed = SectorRef {
            root: sector_root(&padding),
            ..sector
        };
        assert!(
            page.open_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::FileMetadata,
                &rehashed,
                &padding
            )
            .is_err()
        );
    }

    #[test]
    fn public_catalog_lookup_is_context_bound_and_private_sections_cannot_use_it() {
        let (page, encoded) = single(CatalogSection::SectorReferences);
        let address = page
            .public_page_id(scope(), CatalogSection::SectorReferences)
            .unwrap();
        page.verify_page(scope(), CatalogSection::SectorReferences, &encoded)
            .unwrap();
        assert_ne!(address, page.hash);
        assert!(
            page.private_sector_id(&[4; 32], scope(), CatalogSection::SectorReferences)
                .is_err()
        );
        assert!(
            page.seal_private_page(
                &[4; 32],
                &[5; 32],
                scope(),
                CatalogSection::SectorReferences,
                &encoded
            )
            .is_err()
        );
        assert!(
            page.public_page_id(scope(), CatalogSection::FileMetadata)
                .is_err()
        );
        assert_ne!(
            address,
            page.public_page_id(
                CatalogScope::Dataset {
                    guild_id: [6; 32],
                    owner: NodeId([2; 32]),
                    protected_root_id: Uuid::from_bytes([3; 16])
                },
                CatalogSection::SectorReferences
            )
            .unwrap()
        );
        for section in [CatalogSection::Packing, CatalogSection::Coding] {
            let guild = CatalogScope::Guild { guild_id: [1; 32] };
            let mut sink = |_, _| Ok::<_, &'static str>(());
            let public = CatalogBuilder::new(guild, section)
                .unwrap()
                .finish(&mut sink)
                .unwrap();
            assert!(public.public_page_id(guild, section).is_ok());
            assert!(public.private_sector_id(&[4; 32], guild, section).is_err());
        }
    }

    #[test]
    fn private_catalog_tree_recovery_derives_every_lookup_from_seed_and_authenticated_parent() {
        let seed = Seed::from_bytes([81; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        let identity_key = keys.guild_content_id_key(&[1; 32]);
        let encryption_key = keys.guild_data_key(&[1; 32]);
        let bytes = [
            vec![1; CATALOG_LEAF_BYTES],
            vec![2; CATALOG_LEAF_BYTES],
            vec![3; 17],
        ]
        .concat();
        let mut remote = HashMap::new();
        let mut sink = |reference: CatalogPageRef, encoded: Vec<u8>| {
            let (sector, ciphertext) = reference
                .seal_private_page(
                    &identity_key,
                    &encryption_key,
                    scope(),
                    CatalogSection::GitGraph,
                    &encoded,
                )
                .unwrap();
            assert!(remote.insert(sector.id, (sector, ciphertext)).is_none());
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        builder.push(&bytes, &mut sink).unwrap();
        let root = builder.finish(&mut sink).unwrap();
        drop(keys);
        let recovered = KeyMaterial::from_seed(&Seed::from_bytes([81; 32]));
        let identity_key = recovered.guild_content_id_key(&[1; 32]);
        let encryption_key = recovered.guild_data_key(&[1; 32]);
        let mut reader = CatalogReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
        let mut seen = 0;
        let mut fetch = |reference: CatalogPageRef| {
            let id =
                reference.private_sector_id(&identity_key, scope(), CatalogSection::GitGraph)?;
            let (sector, ciphertext) = remote
                .get(&id)
                .expect("parent reference must derive the child's remote address");
            let encoded = reference.open_private_page(
                &identity_key,
                &encryption_key,
                scope(),
                CatalogSection::GitGraph,
                sector,
                ciphertext,
            )?;
            match reference.verify_page(scope(), CatalogSection::GitGraph, &encoded)? {
                CatalogPageContents::Index(children) => assert!(children.iter().all(|child| {
                    remote.contains_key(
                        &child
                            .private_sector_id(&identity_key, scope(), CatalogSection::GitGraph)
                            .unwrap(),
                    )
                })),
                CatalogPageContents::Leaf(_) => seen += 1,
            }
            Ok::<_, CatalogError>(encoded)
        };
        let mut restored = Vec::new();
        while let Some(leaf) = reader.next_leaf(&mut fetch).unwrap() {
            restored.extend(leaf);
        }
        assert_eq!(restored, bytes);
        assert_eq!(seen, 3);
    }

    #[test]
    fn private_catalog_ciphertext_survives_reconstruction_of_missing_information_pages() {
        let mut pages = Vec::new();
        let mut sink = |reference: CatalogPageRef, encoded: Vec<u8>| {
            let (sector, ciphertext) = reference
                .seal_private_page(
                    &[4; 32],
                    &[5; 32],
                    scope(),
                    CatalogSection::FileMetadata,
                    &encoded,
                )
                .unwrap();
            pages.push((reference, encoded, sector, ciphertext));
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::FileMetadata).unwrap();
        builder
            .push(&vec![7; CATALOG_LEAF_BYTES + 1], &mut sink)
            .unwrap();
        builder.finish(&mut sink).unwrap();
        assert_eq!(pages.len(), 3, "two leaf pages and their index");
        let codeword =
            crate::encode_3_2([pages[0].3.clone(), pages[1].3.clone(), pages[2].3.clone()])
                .unwrap();
        let mut remaining = codeword.into_iter().map(Some).collect::<Vec<_>>();
        remaining[0] = None;
        remaining[2] = None;
        crate::reconstruct_3_2(&mut remaining).unwrap();
        for (index, (reference, encoded, sector, original)) in pages.iter().enumerate() {
            let reconstructed = remaining[index].as_ref().unwrap();
            assert_eq!(reconstructed, original);
            assert_eq!(
                merkle_commit(reconstructed).unwrap(),
                merkle_commit(original).unwrap()
            );
            assert_eq!(
                reference
                    .open_private_page(
                        &[4; 32],
                        &[5; 32],
                        scope(),
                        CatalogSection::FileMetadata,
                        sector,
                        reconstructed,
                    )
                    .unwrap(),
                *encoded
            );
        }
    }

    #[test]
    fn catalog_address_version_one_has_stable_test_vectors() {
        let reference = CatalogPageRef {
            hash: [7; 32],
            encoded_len: 256,
            height: 0,
            byte_len: 120,
            page_occurrences: 1,
        };
        assert_eq!(
            hex::encode(
                reference
                    .private_sector_id(&[4; 32], scope(), CatalogSection::GitGraph)
                    .unwrap()
            ),
            "12a9d56ee8e33fd8f5824f77a3a2ad55d65b39c3c03faae69a44becdaf4bb40a"
        );
        assert_eq!(
            hex::encode(
                reference
                    .public_page_id(scope(), CatalogSection::SectorReferences)
                    .unwrap()
            ),
            "2e68b167f5f23c3f1e2b4bf7bb5d683f19283c469ada95e25fa35d8ac0d509a2"
        );
    }
}

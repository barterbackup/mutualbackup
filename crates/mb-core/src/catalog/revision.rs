//! Signed authority for paged sources and one encrypted private root envelope.
//! Checkpoint writer-fence authorization and complete catalog joins are still
//! required before activation. Existing flat revision formats are unchanged.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::{
    CatalogError, CatalogPageRef, CatalogScope, CatalogSectorReader, CatalogSectorRecord,
    CatalogSectorRoot, CatalogStreamError,
};
use crate::{
    KeyMaterial, ModelError, NodeId, SignedRecord, V1_CIPHER_PROFILE, WriterFence,
    canonical_bytes_bounded, decode_canonical, keys::signing_payload,
};

pub const PAGED_USER_REVISION_VERSION: u16 = 8;
pub const PAGED_USER_REVISION_BYTES: usize = 2048;
pub const PAGED_PRIVATE_METADATA_BYTES: usize = 8192;
pub const PAGED_USER_REVISION_DOMAIN: &[u8] = b"mutualbackup/paged-user-revision/v1";
const WRITER_DOMAIN: &[u8] = b"mutualbackup/paged-writer-revision/v1";

/// Public source authority contains no plaintext private page hashes. The
/// encrypted metadata sector contains the typed native/Git roots; sources
/// include that sector, private page sectors and file/blob data sectors.
/// Counts are source geometry, not retained-history quota or physical usage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PagedUserRevision {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub protected_root_id: Uuid,
    pub cipher_profile: u16,
    pub revision_id: Uuid,
    pub owner: NodeId,
    pub writer_epoch: u64,
    pub writer_public_key: [u8; 32],
    #[serde(deserialize_with = "decode_signature")]
    pub writer_signature: Vec<u8>,
    pub sequence: u64,
    pub parent: Option<[u8; 32]>,
    pub metadata: CatalogSectorRecord,
    pub sources: CatalogSectorRoot,
}

fn decode_signature<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    struct BoundedSignature;
    impl<'de> Visitor<'de> for BoundedSignature {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 64 signature bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|len| len > 64) {
                return Err(serde::de::Error::custom(
                    "oversized paged revision signature",
                ));
            }
            let mut bytes = Vec::with_capacity(64);
            while let Some(byte) = seq.next_element()? {
                if bytes.len() == 64 {
                    return Err(serde::de::Error::custom(
                        "oversized paged revision signature",
                    ));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    decoder.deserialize_seq(BoundedSignature)
}

impl PagedUserRevision {
    pub fn scope(&self) -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: self.guild_id,
            owner: self.owner,
            protected_root_id: self.protected_root_id,
        }
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        self.metadata.validate()?;
        self.sources.validate()?;
        if self.format_version != PAGED_USER_REVISION_VERSION
            || self.cipher_profile != V1_CIPHER_PROFILE
            || self.protected_root_id.is_nil()
            || self.revision_id.is_nil()
            || self.writer_epoch == 0
            || self.writer_signature.len() != 64
            || self.sequence == 0
            || (self.sequence == 1) != self.parent.is_none()
            || self.sources.records.records == 0
            || self.metadata.sector.logical_len as usize > PAGED_PRIVATE_METADATA_BYTES
            || self.sources.logical_bytes < u64::from(self.metadata.sector.logical_len)
        {
            return Err(CatalogError::InvalidPage);
        }
        for bytes in [self.owner.0, self.writer_public_key] {
            let key = VerifyingKey::from_bytes(&bytes).map_err(ModelError::from)?;
            if key.is_weak() {
                return Err(ModelError::WeakPublicKey.into());
            }
        }
        Ok(())
    }

    /// Sign the exact roots with both the current writer and seed-derived owner.
    /// The certified checkpoint must separately authorize the writer fence.
    pub fn sign(
        mut self,
        writer: &SigningKey,
        owner: &KeyMaterial,
    ) -> Result<SignedRecord<Self>, CatalogError> {
        if self.owner != owner.node_id()
            || self.writer_public_key != writer.verifying_key().to_bytes()
        {
            return Err(ModelError::InvalidWriterFence.into());
        }
        self.writer_signature = vec![0; 64];
        self.validate()?;
        // Count the complete envelope with both fixed-size signatures before
        // either signing operation allocates its canonical signing payload.
        crate::canonical_size_bounded(
            &SignedRecord {
                signer: self.owner,
                value: &self,
                signature: vec![0; 64],
            },
            PAGED_USER_REVISION_BYTES,
        )?;
        self.writer_signature.clear();
        let payload = canonical_bytes_bounded(&self, PAGED_USER_REVISION_BYTES)?;
        self.writer_signature = writer
            .sign(&signing_payload(WRITER_DOMAIN, &payload))
            .to_vec();
        let signed = SignedRecord::sign(PAGED_USER_REVISION_DOMAIN, self, owner)?;
        canonical_bytes_bounded(&signed, PAGED_USER_REVISION_BYTES)?;
        Ok(signed)
    }

    pub fn verify_signed(signed: &SignedRecord<Self>) -> Result<(), CatalogError> {
        signed.value.validate()?;
        if signed.signer != signed.value.owner || signed.signature.len() != 64 {
            return Err(CatalogError::InvalidPage);
        }
        canonical_bytes_bounded(signed, PAGED_USER_REVISION_BYTES)?;
        signed.verify(PAGED_USER_REVISION_DOMAIN)?;
        let mut unsigned = signed.value.clone();
        unsigned.writer_signature.clear();
        let payload = canonical_bytes_bounded(&unsigned, PAGED_USER_REVISION_BYTES)?;
        VerifyingKey::from_bytes(&signed.value.writer_public_key)
            .map_err(ModelError::from)?
            .verify_strict(
                &signing_payload(WRITER_DOMAIN, &payload),
                &Signature::from_slice(&signed.value.writer_signature).map_err(ModelError::from)?,
            )
            .map_err(ModelError::from)?;
        Ok(())
    }

    /// Bound both signature collections before allocating from peer input.
    /// Unsupported versions and noncanonical/trailing bytes fail closed.
    pub fn decode_signed(bytes: &[u8]) -> Result<SignedRecord<Self>, CatalogError> {
        #[derive(Deserialize)]
        struct BoundedSigned {
            signer: NodeId,
            value: PagedUserRevision,
            #[serde(deserialize_with = "decode_signature")]
            signature: Vec<u8>,
        }
        if bytes.is_empty() || bytes.len() > PAGED_USER_REVISION_BYTES {
            return Err(CatalogError::Bounds);
        }
        let decoded: BoundedSigned = decode_canonical(bytes)?;
        let signed = SignedRecord {
            signer: decoded.signer,
            value: decoded.value,
            signature: decoded.signature,
        };
        Self::verify_signed(&signed)?;
        if canonical_bytes_bounded(&signed, PAGED_USER_REVISION_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(signed)
    }

    pub fn hash(&self) -> Result<[u8; 32], CatalogError> {
        self.validate()?;
        let mut hash = blake3::Hasher::new_derive_key("mutualbackup paged user revision body v1");
        hash.update(&canonical_bytes_bounded(self, PAGED_USER_REVISION_BYTES)?);
        Ok(*hash.finalize().as_bytes())
    }
}

/// Streaming signed source traversal with an exact bootstrap-sector join.
/// A valid prefix does not establish complete authority: reach authenticated
/// EOF and then verify private namespace/Git joins before activating a revision.
pub struct PagedRevisionSourceReader {
    sources: CatalogSectorReader,
    metadata: CatalogSectorRecord,
    found_metadata: bool,
    complete: bool,
    failed: bool,
}

impl PagedRevisionSourceReader {
    pub fn last_record_range(&self) -> Option<std::ops::Range<u64>> {
        if self.failed {
            None
        } else {
            self.sources.last_record_range()
        }
    }
    pub fn new(
        signed: &SignedRecord<PagedUserRevision>,
        guild_id: [u8; 32],
        owner: NodeId,
        fence: &WriterFence,
    ) -> Result<Self, CatalogError> {
        PagedUserRevision::verify_signed(signed)?;
        let revision = &signed.value;
        if revision.guild_id != guild_id
            || revision.owner != owner
            || fence.owner != owner
            || fence.epoch != revision.writer_epoch
            || fence.public_key != revision.writer_public_key
        {
            return Err(ModelError::InvalidWriterFence.into());
        }
        Ok(Self {
            sources: CatalogSectorReader::new(revision.scope(), revision.sources)?,
            metadata: revision.metadata.clone(),
            found_metadata: false,
            complete: false,
            failed: false,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn next_sector<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogSectorRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            let next = self.sources.next_sector(fetch)?;
            if let Some(record) = &next {
                if record.sector.id == self.metadata.sector.id {
                    if *record != self.metadata {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    self.found_metadata = true;
                }
            } else {
                if !self.found_metadata {
                    return Err(CatalogError::InvalidPage.into());
                }
                self.complete = true;
            }
            Ok(next)
        })();
        self.failed = result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        CatalogSectorBuilder, SectorRef, Seed, USER_REVISION_DOMAIN, UserRevision, V1_SECTOR_SIZE,
        canonical_bytes, merkle_zero_commitment,
    };

    use super::*;

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn record(index: u64) -> CatalogSectorRecord {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&index.to_be_bytes());
        CatalogSectorRecord {
            format_version: 1,
            sector: SectorRef {
                id,
                root: [11; 32],
                logical_len: 19,
            },
            commitment: merkle_zero_commitment(V1_SECTOR_SIZE as u32).unwrap(),
        }
    }

    fn fixture(records: &[CatalogSectorRecord]) -> (SignedRecord<PagedUserRevision>, Pages) {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([71; 32]));
        let writer = SigningKey::from_bytes(&[72; 32]);
        let mut body = PagedUserRevision {
            format_version: PAGED_USER_REVISION_VERSION,
            guild_id: [73; 32],
            protected_root_id: Uuid::from_bytes([74; 16]),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([75; 16]),
            owner: keys.node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: vec![],
            sequence: 1,
            parent: None,
            metadata: record(999),
            sources: CatalogSectorRoot {
                records: crate::CatalogRecordRoot {
                    format_version: 1,
                    page: CatalogPageRef {
                        hash: [0; 32],
                        encoded_len: 0,
                        height: 0,
                        byte_len: 0,
                        page_occurrences: 0,
                    },
                    records: 0,
                },
                logical_bytes: 0,
            },
        };
        let mut pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogSectorBuilder::new(body.scope()).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        body.sources = builder.finish(&mut sink).unwrap();
        (body.sign(&writer, &keys).unwrap(), pages)
    }

    fn fence(revision: &PagedUserRevision) -> WriterFence {
        WriterFence {
            owner: revision.owner,
            epoch: revision.writer_epoch,
            public_key: revision.writer_public_key,
        }
    }

    #[test]
    fn paged_revision_signatures_roundtrip_and_remain_distinct_from_flat_formats() {
        let (signed, _) = fixture(&[record(999)]);
        let encoded = canonical_bytes(&signed).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            include_str!("../../../../protocol/vectors/paged-user-revision-v8.postcard.hex").trim()
        );
        assert!(encoded.len() < 1024);
        assert_eq!(PagedUserRevision::decode_signed(&encoded).unwrap(), signed);
        assert!(decode_canonical::<SignedRecord<UserRevision>>(&encoded).is_err());
        assert!(signed.verify(USER_REVISION_DOMAIN).is_err());
        let hash = signed.value.hash().unwrap();
        let mut next = signed.value.clone();
        next.revision_id = Uuid::from_bytes([76; 16]);
        next.sequence = 2;
        next.parent = Some(hash);
        let next = next
            .sign(
                &SigningKey::from_bytes(&[72; 32]),
                &KeyMaterial::from_seed(&Seed::from_bytes([71; 32])),
            )
            .unwrap();
        assert_ne!(next.value.hash().unwrap(), hash);
        PagedUserRevision::verify_signed(&next).unwrap();
    }

    #[test]
    fn paged_revision_rejects_owner_writer_and_root_substitution() {
        let (signed, _) = fixture(&[record(999)]);
        let owner = KeyMaterial::from_seed(&Seed::from_bytes([71; 32]));
        for case in 0..12 {
            let mut candidate = signed.clone();
            match case {
                0 => candidate.signature[0] ^= 1,
                1 => candidate.value.writer_signature[0] ^= 1,
                2 => candidate.value.sources.records.page.hash[0] ^= 1,
                3 => candidate.value.metadata.sector.root[0] ^= 1,
                4 => candidate.value.metadata.commitment.root[0] ^= 1,
                5 => candidate.value.guild_id[0] ^= 1,
                6 => candidate.value.protected_root_id = Uuid::from_bytes([99; 16]),
                7 => candidate.value.revision_id = Uuid::from_bytes([99; 16]),
                8 => candidate.value.writer_epoch += 1,
                9 => candidate.value.sequence += 1,
                10 => candidate.value.parent = Some([99; 32]),
                _ => {
                    candidate.signer = KeyMaterial::from_seed(&Seed::from_bytes([99; 32])).node_id()
                }
            }
            assert!(
                PagedUserRevision::verify_signed(&candidate).is_err(),
                "case {case}"
            );
            if (1..=8).contains(&case) {
                // A new owner signature cannot hide an invalid writer signature.
                let resigned =
                    SignedRecord::sign(PAGED_USER_REVISION_DOMAIN, candidate.value, &owner)
                        .unwrap();
                assert!(
                    PagedUserRevision::verify_signed(&resigned).is_err(),
                    "writer case {case}"
                );
            }
        }
        assert!(
            signed
                .value
                .clone()
                .sign(&SigningKey::from_bytes(&[99; 32]), &owner)
                .is_err()
        );
        assert!(
            signed
                .value
                .clone()
                .sign(
                    &SigningKey::from_bytes(&[72; 32]),
                    &KeyMaterial::from_seed(&Seed::from_bytes([99; 32]))
                )
                .is_err()
        );
    }

    #[test]
    fn paged_revision_decoder_bounds_signatures_versions_and_complete_encoding() {
        let (signed, _) = fixture(&[record(999)]);
        for case in 0..7 {
            let mut candidate = signed.clone();
            match case {
                0 => candidate.signature = vec![0; 65],
                1 => candidate.value.writer_signature = vec![0; 65],
                2 => candidate.value.format_version = 6,
                3 => candidate.value.format_version = 7,
                4 => candidate.value.writer_public_key = [0; 32],
                5 => candidate.value.protected_root_id = Uuid::nil(),
                _ => candidate.value.sources.records.records = 0,
            }
            assert!(
                PagedUserRevision::decode_signed(&canonical_bytes(&candidate).unwrap()).is_err(),
                "case {case}"
            );
        }
        let mut bytes = canonical_bytes(&signed).unwrap();
        bytes.push(0);
        assert!(PagedUserRevision::decode_signed(&bytes).is_err());
        assert!(PagedUserRevision::decode_signed(&bytes[..bytes.len() - 2]).is_err());
        assert!(PagedUserRevision::decode_signed(&vec![0; PAGED_USER_REVISION_BYTES + 1]).is_err());
        let body = &signed.value;
        let mut huge_writer = canonical_bytes(&(
            signed.signer,
            body.format_version,
            body.guild_id,
            body.protected_root_id,
            body.cipher_profile,
            body.revision_id,
            body.owner,
            body.writer_epoch,
            body.writer_public_key,
        ))
        .unwrap();
        huge_writer.extend(canonical_bytes(&u64::MAX).unwrap());
        assert!(PagedUserRevision::decode_signed(&huge_writer).is_err());
        let mut huge_owner = canonical_bytes(&(signed.signer, &signed.value)).unwrap();
        huge_owner.extend(canonical_bytes(&u64::MAX).unwrap());
        assert!(PagedUserRevision::decode_signed(&huge_owner).is_err());
        for length in [
            PAGED_PRIVATE_METADATA_BYTES - 1,
            PAGED_PRIVATE_METADATA_BYTES,
            PAGED_PRIVATE_METADATA_BYTES + 1,
        ] {
            let mut measured = signed.value.clone();
            measured.metadata.sector.logical_len = length as u32;
            measured.sources.logical_bytes = length as u64;
            let result = measured.sign(
                &SigningKey::from_bytes(&[72; 32]),
                &KeyMaterial::from_seed(&Seed::from_bytes([71; 32])),
            );
            assert_eq!(result.is_ok(), length <= PAGED_PRIVATE_METADATA_BYTES);
        }
    }

    #[test]
    fn paged_revision_source_authority_requires_fence_exact_bootstrap_and_authenticated_eof() {
        let records: Vec<_> = (0..2000).map(record).collect();
        let (signed, pages) = fixture(&records);
        assert!(signed.value.sources.records.page.height > 0);
        let revision = &signed.value;
        let expected = fence(revision);
        let mut reader =
            PagedRevisionSourceReader::new(&signed, revision.guild_id, revision.owner, &expected)
                .unwrap();
        let mut fetch = |page: CatalogPageRef| Ok::<_, &'static str>(pages[&page.hash].clone());
        for record in records {
            assert!(!reader.is_complete());
            assert_eq!(reader.next_sector(&mut fetch).unwrap(), Some(record));
        }
        assert!(!reader.is_complete());
        assert!(reader.next_sector(&mut fetch).unwrap().is_none());
        assert!(reader.is_complete());
        assert!(reader.next_sector(&mut fetch).unwrap().is_none());
        for case in 0..5 {
            let mut wrong = expected.clone();
            let mut guild = revision.guild_id;
            let mut owner = revision.owner;
            match case {
                0 => wrong.epoch += 1,
                1 => wrong.public_key[0] ^= 1,
                2 => wrong.owner.0[0] ^= 1,
                3 => guild[0] ^= 1,
                _ => owner.0[0] ^= 1,
            }
            assert!(PagedRevisionSourceReader::new(&signed, guild, owner, &wrong).is_err());
        }
        for records in [
            vec![record(998)],
            vec![{
                let mut changed = record(999);
                changed.commitment.root[0] ^= 1;
                changed
            }],
        ] {
            let (signed, pages) = fixture(&records);
            let mut reader = PagedRevisionSourceReader::new(
                &signed,
                signed.value.guild_id,
                signed.value.owner,
                &fence(&signed.value),
            )
            .unwrap();
            let mut fetch = |page: CatalogPageRef| Ok::<_, &'static str>(pages[&page.hash].clone());
            let mut failed = false;
            for _ in 0..3 {
                if reader.next_sector(&mut fetch).is_err() {
                    failed = true;
                    break;
                }
            }
            assert!(failed && !reader.is_complete());
            assert!(reader.next_sector(&mut fetch).is_err());
        }
    }

    #[test]
    fn paged_revision_source_reader_fences_storage_and_corrupt_tail_failures() {
        let records: Vec<_> = (0..2000).map(record).collect();
        let (signed, pages) = fixture(&records);
        for corrupt in [false, true] {
            let mut reader = PagedRevisionSourceReader::new(
                &signed,
                signed.value.guild_id,
                signed.value.owner,
                &fence(&signed.value),
            )
            .unwrap();
            let mut fetches = 0;
            let mut fetch = |page: CatalogPageRef| {
                fetches += 1;
                if fetches >= 3 {
                    if !corrupt {
                        return Err("unavailable tail");
                    }
                    let mut bytes = pages[&page.hash].clone();
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                    return Ok(bytes);
                }
                Ok(pages[&page.hash].clone())
            };
            let mut count = 0;
            while reader
                .next_sector(&mut fetch)
                .is_ok_and(|next| next.is_some())
            {
                count += 1;
            }
            assert!(count > 0 && count < records.len());
            assert!(!reader.is_complete());
            assert!(reader.next_sector(&mut fetch).is_err());
        }
    }
}

//! Collection limits for existing packing/coding records. These preserve the
//! serialized layouts; paged catalogs still need their own aggregate budgets.
use std::marker::PhantomData;

use serde::de::{DeserializeSeed, Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

pub(crate) struct VecSeed<T> {
    limit: usize,
    marker: PhantomData<T>,
}

impl<T> VecSeed<T> {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            marker: PhantomData,
        }
    }
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for VecSeed<T> {
    type Value = Vec<T>;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        struct Values<T>(usize, PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Values<T> {
            type Value = Vec<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {} collection elements", self.0)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                if seq.size_hint().is_some_and(|size| size > self.0) {
                    return Err(A::Error::custom("collection exceeds protocol geometry"));
                }
                // A short/truncated record cannot force a huge eager allocation
                // merely by declaring an otherwise permitted count.
                let mut values =
                    Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.0).min(64));
                while values.len() < self.0 {
                    match seq.next_element()? {
                        Some(value) => values.push(value),
                        None => return Ok(values),
                    }
                }
                // Unknown-length formats must reject the extra element before
                // decoding its potentially nested payload.
                seq.next_element_seed(Extra)?;
                Ok(values)
            }
        }
        decoder.deserialize_seq(Values(self.limit, PhantomData))
    }
}

pub(crate) struct Extra;
impl<'de> DeserializeSeed<'de> for Extra {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(D::Error::custom("collection exceeds protocol geometry"))
    }
}

pub(crate) fn coding<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> Result<Vec<T>, D::Error> {
    VecSeed::new(crate::MAX_CODING_SHARDS as usize).deserialize(decoder)
}

pub(crate) fn failure_domain<'de, D: Deserializer<'de>>(decoder: D) -> Result<String, D::Error> {
    struct Domain;
    impl Visitor<'_> for Domain {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a failure domain of at most 256 UTF-8 bytes")
        }
        fn visit_str<E: Error>(self, value: &str) -> Result<String, E> {
            if value.len() > 256 {
                return Err(E::custom("oversized failure domain"));
            }
            Ok(value.to_owned())
        }
        fn visit_string<E: Error>(self, value: String) -> Result<String, E> {
            if value.len() > 256 {
                return Err(E::custom("oversized failure domain"));
            }
            Ok(value)
        }
    }
    decoder.deserialize_string(Domain)
}

// Preserve the generic SignedRecord layout while bounding signatures before
// allocating from new paged authority records. Legacy decoders stay unchanged.
pub(crate) fn signature<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    VecSeed::new(64).deserialize(decoder)
}

pub(crate) fn signed_record<'de, D, T>(decoder: D) -> Result<crate::SignedRecord<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    struct BoundedSigned<T> {
        signer: crate::NodeId,
        value: T,
        #[serde(deserialize_with = "signature")]
        signature: Vec<u8>,
    }
    let signed = BoundedSigned::<T>::deserialize(decoder)?;
    Ok(crate::SignedRecord {
        signer: signed.signer,
        value: signed.value,
        signature: signed.signature,
    })
}

pub(crate) fn signed_coding<'de, D, T>(decoder: D) -> Result<Vec<crate::SignedRecord<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    struct Bounded<T> {
        #[serde(deserialize_with = "signed_record")]
        signed: crate::SignedRecord<T>,
    }
    Ok(
        VecSeed::<Bounded<T>>::new(crate::MAX_CODING_SHARDS as usize)
            .deserialize(decoder)?
            .into_iter()
            .map(|value| value.signed)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{Error as ValueError, SeqAccessDeserializer, U8Deserializer};

    struct Sequence {
        count: usize,
        hint: Option<usize>,
        touched: std::rc::Rc<std::cell::Cell<usize>>,
    }
    impl<'de> SeqAccess<'de> for Sequence {
        type Error = ValueError;
        fn size_hint(&self) -> Option<usize> {
            self.hint
        }
        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, Self::Error> {
            if self.count == 0 {
                return Ok(None);
            }
            self.count -= 1;
            self.touched.set(self.touched.get() + 1);
            seed.deserialize(U8Deserializer::<ValueError>::new(1))
                .map(Some)
        }
    }

    #[test]
    fn real_record_declarations_reject_before_reading_nested_payloads() {
        fn declared(prefix: impl serde::Serialize, count: usize) -> Vec<u8> {
            let mut bytes = crate::canonical_bytes(&prefix).unwrap();
            bytes.extend(crate::canonical_bytes(&count).unwrap());
            // Postcard withholds its count hint if fewer bytes remain than
            // declared elements. Supply filler so rejection must happen at the
            // geometry check, before interpreting the nested record payload.
            bytes.resize(bytes.len() + count, 0);
            bytes
        }
        fn oversized<T: serde::de::DeserializeOwned>(bytes: Vec<u8>) {
            let error = crate::decode_canonical::<T>(&bytes)
                .err()
                .expect("oversized declaration accepted");
            assert!(
                matches!(
                    error,
                    crate::ModelError::Decode(postcard::Error::SerdeDeCustom)
                ),
                "{error}"
            );
        }
        let commitment = crate::merkle_zero_commitment(64).unwrap();
        oversized::<crate::PackedSectorDescriptor>(declared(
            ([1_u8; 32], 0_u32, [2_u8; 32], &commitment),
            crate::MAX_PROFILE_SHARD_SIZE as usize / crate::MERKLE_LEAF_SIZE + 1,
        ));
        let descriptor = crate::PackedSectorDescriptor {
            id: [1; 32],
            sector_index: 0,
            flat_root: [2; 32],
            commitment,
            slots: vec![],
        };
        oversized::<crate::PackedSector>(declared(
            &descriptor,
            crate::MAX_PROFILE_SHARD_SIZE as usize + 1,
        ));
        oversized::<crate::MerkleRangeProof>(declared(
            (1_u16, 0_u32),
            crate::MAX_PROFILE_SHARD_SIZE as usize / crate::MERKLE_LEAF_SIZE + 1,
        ));
        oversized::<crate::MerkleSubtreeProof>(declared((1_u16, 0_u32, 1_u32, [0_u8; 32]), 19));
        oversized::<crate::CodingGroupV2>(declared(
            (
                [1_u8; 32],
                2_u16,
                [2_u8; 32],
                crate::CodingProfile::new(3, 2, 64),
            ),
            crate::MAX_CODING_SHARDS as usize + 1,
        ));
    }

    #[test]
    fn domain_byte_bound_and_merkle_proofs_preserve_existing_encodings() {
        let mut information = crate::InformationRoleV2 {
            owner: crate::NodeId([1; 32]),
            failure_domain: "é".repeat(128),
            sector: crate::RangeSectorRef {
                id: [2; 32],
                commitment: crate::merkle_zero_commitment(64).unwrap(),
                logical_len: 64,
                virtual_zero: false,
            },
        };
        let bytes = crate::canonical_bytes(&information).unwrap();
        let decoded: crate::InformationRoleV2 = crate::decode_canonical(&bytes).unwrap();
        assert_eq!(crate::canonical_bytes(&decoded).unwrap(), bytes);
        information.failure_domain.push('x');
        assert!(
            crate::decode_canonical::<crate::InformationRoleV2>(
                &crate::canonical_bytes(&information).unwrap()
            )
            .is_err()
        );
        let bytes = vec![7; 1024];
        let commitment = crate::merkle_commit(&bytes).unwrap();
        let proof = crate::merkle_open_range(&bytes, 0, 1).unwrap();
        let encoded = crate::canonical_bytes(&proof).unwrap();
        let decoded: crate::MerkleRangeProof = crate::decode_canonical(&encoded).unwrap();
        assert_eq!(crate::canonical_bytes(&decoded).unwrap(), encoded);
        crate::merkle_verify_range(&commitment, &decoded).unwrap();
    }

    #[test]
    fn limits_reject_huge_hints_and_unknown_length_overflow_before_extra_decode() {
        let touched = std::rc::Rc::new(std::cell::Cell::new(0));
        let sequence = Sequence {
            count: usize::MAX,
            hint: Some(usize::MAX),
            touched: touched.clone(),
        };
        assert!(
            VecSeed::<u8>::new(64)
                .deserialize(SeqAccessDeserializer::new(sequence))
                .is_err()
        );
        assert_eq!(touched.get(), 0);
        for (count, succeeds) in [(2, true), (3, false)] {
            touched.set(0);
            let sequence = Sequence {
                count,
                hint: None,
                touched: touched.clone(),
            };
            assert_eq!(
                VecSeed::<u8>::new(2)
                    .deserialize(SeqAccessDeserializer::new(sequence))
                    .is_ok(),
                succeeds
            );
            assert_eq!(touched.get(), count);
        }
        let bytes = crate::canonical_bytes(&vec![1_u8; 65]).unwrap();
        let mut decoder = postcard::Deserializer::from_bytes(&bytes);
        assert!(VecSeed::<u8>::new(64).deserialize(&mut decoder).is_err());
    }
}

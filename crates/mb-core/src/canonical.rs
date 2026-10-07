//! Bounded encoding using the same Postcard wire representation as the model.

use postcard::ser_flavors::Flavor;
use serde::Serialize;

use crate::ModelError;

struct HashUpdate<'a>(&'a mut blake3::Hasher);

impl Flavor for HashUpdate<'_> {
    type Output = ();

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.try_extend(&[byte])
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.0.update(bytes);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<()> {
        Ok(())
    }
}

/// Append the exact canonical encoding without retaining an encoded copy.
/// Callers bound/validate their input independently and abandon the hash after
/// an encoding error; a failed serializer may already have appended a prefix.
pub(crate) fn update_canonical_hash<T: Serialize>(
    hasher: &mut blake3::Hasher,
    value: &T,
) -> Result<(), ModelError> {
    postcard::serialize_with_flavor(value, HashUpdate(hasher)).map_err(ModelError::Encode)
}

struct BoundedSize {
    size: usize,
    limit: usize,
}

impl Flavor for BoundedSize {
    type Output = usize;

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.try_extend(&[byte])
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.size = self
            .size
            .checked_add(bytes.len())
            .filter(|size| *size <= self.limit)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        Ok(())
    }

    fn finalize(self) -> postcard::Result<usize> {
        Ok(self.size)
    }
}

/// Count exact canonical bytes, including nested lengths and field overhead,
/// without allocating an encoding. Stop as soon as the limit is exceeded.
/// A size violation is `ModelError::EncodingTooLarge`; other encode
/// errors are preserved. This does not validate the model's semantic rules.
pub fn canonical_size_bounded<T: Serialize>(value: &T, limit: usize) -> Result<usize, ModelError> {
    postcard::serialize_with_flavor(value, BoundedSize { size: 0, limit }).map_err(|error| {
        if error == postcard::Error::SerializeBufferFull {
            ModelError::EncodingTooLarge { limit }
        } else {
            ModelError::Encode(error)
        }
    })
}

/// Encode only after a bounded count, into an exactly sized buffer. A second
/// serialization cannot grow that allocation even for a stateful serializer.
/// Deterministic inputs produce precisely the bytes of `canonical_bytes`.
pub fn canonical_bytes_bounded<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, ModelError> {
    let size = canonical_size_bounded(value, limit)?;
    let mut bytes = vec![0; size];
    let written = postcard::to_slice(value, &mut bytes)
        .map_err(ModelError::Encode)?
        .len();
    bytes.truncate(written);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde::Serializer;
    use serde::ser::SerializeSeq;

    use super::*;
    use crate::canonical_bytes;

    #[test]
    fn bounded_canonical_encoding_matches_wire_bytes_and_exact_boundaries() {
        for len in [0, 1, 127, 128, 16_383, 16_384] {
            let value = (u64::MAX, vec![0xab_u8; len], vec!["ref", "nested"]);
            let expected = canonical_bytes(&value).unwrap();
            let limit = expected.len();
            assert_eq!(canonical_size_bounded(&value, limit).unwrap(), limit);
            assert_eq!(canonical_bytes_bounded(&value, limit).unwrap(), expected);
            assert_eq!(canonical_size_bounded(&value, limit + 1).unwrap(), limit);
            for result in [
                canonical_size_bounded(&value, limit - 1).map(|_| ()),
                canonical_bytes_bounded(&value, limit - 1).map(|_| ()),
            ] {
                assert!(matches!(result, Err(ModelError::EncodingTooLarge { .. })));
            }
        }
        assert_eq!(canonical_bytes_bounded(&(), 0).unwrap(), Vec::<u8>::new());
        assert_eq!(canonical_size_bounded(&(), 0).unwrap(), 0);
        assert!(canonical_bytes_bounded(&1_u8, 0).is_err());
    }

    struct Generated<'a> {
        visits: &'a Cell<usize>,
        len: usize,
    }

    impl Serialize for Generated<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(Some(self.len))?;
            for _ in 0..self.len {
                self.visits.set(self.visits.get() + 1);
                seq.serialize_element(&0_u8)?;
            }
            seq.end()
        }
    }

    #[test]
    fn bounded_canonical_encoding_stops_without_visiting_the_whole_value() {
        let visits = Cell::new(0);
        let generated = Generated {
            visits: &visits,
            len: usize::MAX,
        };
        assert!(matches!(
            canonical_bytes_bounded(&generated, 100),
            Err(ModelError::EncodingTooLarge { limit: 100 })
        ));
        assert!(visits.get() <= 101);
        assert!(visits.get() > 0);
        let mut count = BoundedSize {
            size: usize::MAX,
            limit: usize::MAX,
        };
        assert_eq!(count.try_push(0), Err(postcard::Error::SerializeBufferFull));
    }

    #[test]
    fn bounded_canonical_encoding_preserves_errors_and_bounds_the_second_pass() {
        struct Stateful(Cell<bool>);
        impl Serialize for Stateful {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if self.0.replace(true) {
                    serializer.serialize_bytes(&[1; 128])
                } else {
                    serializer.serialize_bytes(&[])
                }
            }
        }
        assert!(matches!(
            canonical_bytes_bounded(&Stateful(Cell::new(false)), 128),
            Err(ModelError::Encode(postcard::Error::SerializeBufferFull))
        ));
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("invalid model"))
            }
        }
        assert!(matches!(
            canonical_size_bounded(&Invalid, usize::MAX),
            Err(ModelError::Encode(postcard::Error::SerdeSerCustom))
        ));
    }

    #[test]
    fn streamed_canonical_hash_matches_nested_wire_bytes_and_preserves_errors() {
        for length in [0, 1, 127, 128, 16_383, 16_384] {
            let value = (u64::MAX, vec![0xab_u8; length], Some(vec!["ref", "nested"]));
            let mut streamed = blake3::Hasher::new_derive_key("test canonical hash");
            update_canonical_hash(&mut streamed, &value).unwrap();
            let mut reference = blake3::Hasher::new_derive_key("test canonical hash");
            reference.update(&canonical_bytes(&value).unwrap());
            assert_eq!(streamed.finalize(), reference.finalize());
        }
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let _ = serializer.serialize_seq(Some(1))?;
                Err(serde::ser::Error::custom("injected encoding failure"))
            }
        }
        assert!(matches!(
            update_canonical_hash(&mut blake3::Hasher::new(), &Invalid),
            Err(ModelError::Encode(postcard::Error::SerdeSerCustom))
        ));
    }
}

//! Exact size of the dense Git recipe emitted by the current capture format.
//! Sector identities affect bytes, not encoded length; no payload is read and
//! no sector-reference collection is allocated here.

use mb_core::{ModelError, SectorRef, V1_SECTOR_SIZE, canonical_size_bounded};
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::{GitGraphObject, GitGraphRef};

#[derive(Serialize)]
struct Descriptor<'a> {
    format_version: u16,
    repository_id: Uuid,
    refs: &'a [GitGraphRef],
    objects: &'a [GitGraphObject],
    blobs: Blobs<'a>,
    head_branch: &'a str,
}

struct Blobs<'a>(&'a [([u8; 20], u64)]);
impl Serialize for Blobs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (oid, len) in self.0 {
            seq.serialize_element(&(*oid, *len, Extents(*len)))?;
        }
        seq.end()
    }
}

struct Extents(u64);
impl Serialize for Extents {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(usize::from(self.0 != 0)))?;
        if self.0 != 0 {
            seq.serialize_element(&(0_u64, self.0, Sectors(self.0)))?;
        }
        seq.end()
    }
}

struct Sectors(u64);
impl Serialize for Sectors {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = usize::try_from(self.0.div_ceil(V1_SECTOR_SIZE as u64))
            .map_err(|_| serde::ser::Error::custom("Git recipe sector count overflows usize"))?;
        let mut seq = serializer.serialize_seq(Some(count))?;
        let mut remaining = self.0;
        while remaining != 0 {
            let len = remaining.min(V1_SECTOR_SIZE as u64) as u32;
            seq.serialize_element(&SectorRef {
                id: [0; 32],
                root: [0; 32],
                logical_len: len,
            })?;
            remaining -= u64::from(len);
        }
        seq.end()
    }
}

pub(crate) fn dense_backup_size(
    repository_id: Uuid,
    refs: &[GitGraphRef],
    objects: &[GitGraphObject],
    blobs: &[([u8; 20], u64)],
    head_branch: &str,
    limit: usize,
) -> Result<usize, ModelError> {
    // Current capture selects versions 2/3/4; all have the same field shape
    // and one-byte version encoding. Keep that wire geometry explicit.
    canonical_size_bounded(
        &Descriptor {
            format_version: 4,
            repository_id,
            refs,
            objects,
            blobs: Blobs(blobs),
            head_branch,
        },
        limit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitBackupBlob, GitBackupDescriptor, GitDataExtent};

    #[test]
    fn git_admission_dense_size_matches_real_descriptor_geometry_and_boundaries() {
        let lengths = [0, 1, 127, 128, 16_383, 16_384, 65_535, 65_536, 65_537];
        let blobs: Vec<_> = lengths
            .iter()
            .enumerate()
            .map(|(index, len)| ([index as u8; 20], *len))
            .collect();
        let mut descriptor = GitBackupDescriptor {
            format_version: 4,
            repository_id: Uuid::from_bytes([1; 16]),
            refs: vec![GitGraphRef {
                name: b"refs/heads/main".to_vec(),
                oid: [2; 20],
            }],
            objects: vec![GitGraphObject {
                kind: 1,
                oid: [2; 20],
                bytes: vec![3; 128],
            }],
            blobs: blobs
                .iter()
                .map(|(oid, len)| GitBackupBlob {
                    oid: *oid,
                    logical_len: *len,
                    data_extents: if *len == 0 {
                        vec![]
                    } else {
                        let mut remaining = *len;
                        let mut sectors = vec![];
                        while remaining != 0 {
                            let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as u32;
                            sectors.push(SectorRef {
                                id: [4; 32],
                                root: [5; 32],
                                logical_len,
                            });
                            remaining -= u64::from(logical_len);
                        }
                        vec![GitDataExtent {
                            offset: 0,
                            logical_len: *len,
                            sectors,
                        }]
                    },
                })
                .collect(),
            head_branch: "main".to_owned(),
        };
        for version in 2..=4 {
            descriptor.format_version = version;
            let expected = mb_core::canonical_bytes(&descriptor).unwrap().len();
            for limit in [expected, expected + 1] {
                assert_eq!(
                    dense_backup_size(
                        descriptor.repository_id,
                        &descriptor.refs,
                        &descriptor.objects,
                        &blobs,
                        &descriptor.head_branch,
                        limit
                    )
                    .unwrap(),
                    expected
                );
            }
            assert!(matches!(
                dense_backup_size(
                    descriptor.repository_id,
                    &descriptor.refs,
                    &descriptor.objects,
                    &blobs,
                    &descriptor.head_branch,
                    expected - 1
                ),
                Err(ModelError::EncodingTooLarge { .. })
            ));
        }
        assert!(matches!(
            dense_backup_size(
                descriptor.repository_id,
                &[],
                &[],
                &[([1; 20], u64::MAX)],
                "main",
                4096
            ),
            Err(ModelError::EncodingTooLarge { .. })
        ));
    }
}

//! Lossless, portable private metadata for a guarded source revision.
//! Local inode and anchor IDs never enter these encrypted signed bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use mb_core::{V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_bytes, decode_canonical};
use mb_store::{
    FileExtent, GuardedStoppedCaptureV1, GuardedStoppedFileV1, GuardedViewEntryKind,
    GuardedViewMetadataEntry,
};
use serde::{Deserialize, Serialize};

use crate::snapshot::{PrivateDataExtent, validate_file_extents};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedPrivateStatV6 {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime_secs: i64,
    pub atime_nanos: u32,
    pub modified_secs: i64,
    pub modified_nanos: u32,
}

impl GuardedPrivateStatV6 {
    fn from_entry(entry: &GuardedViewMetadataEntry) -> Self {
        Self {
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            atime_secs: entry.atime_secs,
            atime_nanos: entry.atime_nanos,
            modified_secs: entry.modified_secs,
            modified_nanos: entry.modified_nanos,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.atime_nanos < 1_000_000_000 && self.modified_nanos < 1_000_000_000,
            "guarded private metadata has an invalid timestamp"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuardedPrivateEntryV6 {
    Directory {
        path: Vec<u8>,
        stat: GuardedPrivateStatV6,
        logical_len: u64,
    },
    File {
        path: Vec<u8>,
        stat: GuardedPrivateStatV6,
        logical_len: u64,
        link_group: u64,
        data_extents: Vec<PrivateDataExtent>,
    },
    HardLink {
        path: Vec<u8>,
        stat: GuardedPrivateStatV6,
        logical_len: u64,
        link_group: u64,
    },
}

impl GuardedPrivateEntryV6 {
    fn path(&self) -> &[u8] {
        match self {
            Self::Directory { path, .. }
            | Self::File { path, .. }
            | Self::HardLink { path, .. } => path,
        }
    }

    fn stat(&self) -> &GuardedPrivateStatV6 {
        match self {
            Self::Directory { stat, .. }
            | Self::File { stat, .. }
            | Self::HardLink { stat, .. } => stat,
        }
    }
}

/// Encrypted owner metadata. Format 6 preserves the guarded view's raw Unix
/// paths, visible ownership, modes, access/modified times and sparse layout.
/// It deliberately omits local root IDs, inode IDs and anchor locators.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedPrivateMetadataV6 {
    pub format_version: u16,
    pub root: GuardedPrivateStatV6,
    pub entries: Vec<GuardedPrivateEntryV6>,
}

impl GuardedPrivateMetadataV6 {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= V1_MAX_CATALOG_BYTES,
            "guarded private metadata exceeds the catalog bound"
        );
        let metadata: Self = decode_canonical(bytes)?;
        metadata.validate()?;
        Ok(metadata)
    }

    /// Build the portable metadata after sector encoding has produced one
    /// signed sparse recipe for each distinct captured inode. The caller must
    /// retain every captured anchor until those sector recipes are durable.
    pub fn from_capture(
        capture: &GuardedStoppedCaptureV1,
        mut encode_file: impl FnMut(&GuardedStoppedFileV1) -> Result<Vec<PrivateDataExtent>>,
    ) -> Result<Self> {
        capture.verify()?;
        let root = &capture.metadata;
        let mut files = capture.files.iter();
        let mut groups = BTreeMap::new();
        let mut entries = Vec::with_capacity(root.entries.len());
        for entry in &root.entries {
            let stat = GuardedPrivateStatV6::from_entry(entry);
            match entry.kind {
                GuardedViewEntryKind::Directory => entries.push(GuardedPrivateEntryV6::Directory {
                    path: entry.path.clone(),
                    stat,
                    logical_len: entry.logical_len,
                }),
                GuardedViewEntryKind::File => {
                    let file = files.next().context("guarded capture is missing a file")?;
                    if let Some((group, hash, extents)) = groups.get(&entry.native_id) {
                        ensure!(
                            file.content_hash == *hash && file.data_extents == *extents,
                            "guarded inode aliases have different captured bytes"
                        );
                        entries.push(GuardedPrivateEntryV6::HardLink {
                            path: entry.path.clone(),
                            stat,
                            logical_len: entry.logical_len,
                            link_group: *group,
                        });
                    } else {
                        let link_group = u64::try_from(groups.len())
                            .context("too many guarded hard-link groups")?;
                        let data_extents = encode_file(file)?;
                        ensure!(
                            matching_extents(&data_extents, &file.data_extents),
                            "guarded signed sectors differ from captured sparse extents"
                        );
                        groups.insert(
                            entry.native_id,
                            (link_group, file.content_hash, file.data_extents.clone()),
                        );
                        entries.push(GuardedPrivateEntryV6::File {
                            path: entry.path.clone(),
                            stat,
                            logical_len: entry.logical_len,
                            link_group,
                            data_extents,
                        });
                    }
                }
            }
        }
        ensure!(files.next().is_none(), "guarded capture has an extra file");
        let metadata = Self {
            format_version: 6,
            root: GuardedPrivateStatV6 {
                mode: root.root_mode,
                uid: root.root_uid,
                gid: root.root_gid,
                atime_secs: root.root_atime_secs,
                atime_nanos: root.root_atime_nanos,
                modified_secs: root.root_modified_secs,
                modified_nanos: root.root_modified_nanos,
            },
            entries,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validate decoded signed metadata before any restore creates paths.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == 6,
            "unsupported guarded private metadata"
        );
        ensure!(
            canonical_bytes(self)?.len() <= V1_MAX_CATALOG_BYTES,
            "guarded private metadata exceeds the catalog bound"
        );
        self.root.validate()?;
        let mut previous = None::<&[u8]>;
        let mut directories = BTreeSet::<&[u8]>::new();
        let mut groups = BTreeMap::<u64, (&GuardedPrivateStatV6, u64)>::new();
        for entry in &self.entries {
            let path = entry.path();
            let raw = PathBuf::from(OsString::from_vec(path.to_vec()));
            let mut normalized = PathBuf::new();
            for component in raw.components() {
                let Component::Normal(name) = component else {
                    bail!("guarded private metadata has an unsafe path")
                };
                normalized.push(name);
            }
            ensure!(
                !path.is_empty()
                    && !path.contains(&0)
                    && normalized.as_os_str().as_bytes() == path
                    && previous.is_none_or(|prior| prior < path),
                "guarded private metadata has an unsafe or unordered path"
            );
            if let Some(slash) = path.iter().rposition(|byte| *byte == b'/') {
                ensure!(
                    directories.contains(&path[..slash]),
                    "guarded private metadata has no parent directory"
                );
            }
            entry.stat().validate()?;
            match entry {
                GuardedPrivateEntryV6::Directory { .. } => {
                    directories.insert(path);
                }
                GuardedPrivateEntryV6::File {
                    stat,
                    logical_len,
                    link_group,
                    data_extents,
                    ..
                } => {
                    ensure!(
                        *link_group == u64::try_from(groups.len())?,
                        "guarded file link groups are not in primary order"
                    );
                    validate_file_extents(
                        *logical_len,
                        data_extents
                            .iter()
                            .map(|extent| (extent.offset, extent.logical_len)),
                    )?;
                    for extent in data_extents {
                        let mut length = 0_u64;
                        for sector in &extent.sectors {
                            ensure!(
                                sector.logical_len > 0
                                    && sector.logical_len as usize <= V1_SECTOR_SIZE,
                                "guarded private extent has an invalid sector length"
                            );
                            length = length
                                .checked_add(sector.logical_len as u64)
                                .context("guarded private extent length overflow")?;
                        }
                        ensure!(
                            length == extent.logical_len,
                            "guarded private extent differs from its sectors"
                        );
                    }
                    groups.insert(*link_group, (stat, *logical_len));
                }
                GuardedPrivateEntryV6::HardLink {
                    stat,
                    logical_len,
                    link_group,
                    ..
                } => {
                    let (primary_stat, primary_len) = groups
                        .get(link_group)
                        .context("guarded hard-link alias precedes its primary")?;
                    ensure!(
                        stat == *primary_stat && logical_len == primary_len,
                        "guarded hard-link alias differs from its primary"
                    );
                }
            }
            previous = Some(path);
        }
        Ok(())
    }
}

fn matching_extents(private: &[PrivateDataExtent], captured: &[FileExtent]) -> bool {
    private
        .iter()
        .map(|extent| (extent.offset, extent.logical_len))
        .eq(captured
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)))
}

#[cfg(test)]
mod tests {
    use mb_core::SectorRef;

    use super::*;

    #[test]
    fn guarded_private_metadata_roundtrips_raw_names_and_rejects_invalid_layout() {
        let stat = GuardedPrivateStatV6 {
            mode: 0o640,
            uid: 1000,
            gid: 1001,
            atime_secs: 101,
            atime_nanos: 102,
            modified_secs: 103,
            modified_nanos: 104,
        };
        let valid = GuardedPrivateMetadataV6 {
            format_version: 6,
            root: stat.clone(),
            entries: vec![
                GuardedPrivateEntryV6::Directory {
                    path: b"dir".to_vec(),
                    stat: stat.clone(),
                    logical_len: 4096,
                },
                GuardedPrivateEntryV6::File {
                    path: b"dir/\xfe".to_vec(),
                    stat: stat.clone(),
                    logical_len: 3,
                    link_group: 0,
                    data_extents: vec![PrivateDataExtent {
                        offset: 0,
                        logical_len: 3,
                        sectors: vec![SectorRef {
                            id: [1; 32],
                            root: [2; 32],
                            logical_len: 3,
                        }],
                    }],
                },
                GuardedPrivateEntryV6::HardLink {
                    path: b"dir/\xff".to_vec(),
                    stat: stat.clone(),
                    logical_len: 3,
                    link_group: 0,
                },
            ],
        };
        valid.validate().unwrap();
        let encoded = canonical_bytes(&valid).unwrap();
        assert_eq!(GuardedPrivateMetadataV6::decode(&encoded).unwrap(), valid);

        let mut invalid = valid.clone();
        invalid.entries.remove(0);
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        if let GuardedPrivateEntryV6::File { path, .. } = &mut invalid.entries[1] {
            *path = b"dir/../escape".to_vec();
        }
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        if let GuardedPrivateEntryV6::File { data_extents, .. } = &mut invalid.entries[1] {
            data_extents[0].sectors[0].logical_len = 2;
        }
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        if let GuardedPrivateEntryV6::HardLink { link_group, .. } = &mut invalid.entries[2] {
            *link_group = 1;
        }
        assert!(invalid.validate().is_err());
        let mut invalid = valid;
        invalid.root.atime_nanos = 1_000_000_000;
        assert!(invalid.validate().is_err());
    }
}

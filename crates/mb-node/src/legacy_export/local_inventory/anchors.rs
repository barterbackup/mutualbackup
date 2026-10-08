//! Original native anchor and retirement layouts, with no payload/marker reads.
use super::*;
use mb_store::{AnchorManifest, CapturedEntry, StableAnchorManifest};
use std::path::{Component, PathBuf};

pub(in crate::legacy_export) enum PreservedAnchor {
    Legacy(AnchorManifest),
    Stable(StableAnchorManifest),
}

impl PreservedAnchor {
    pub(super) fn decode(kind: &str, bytes: &[u8]) -> Result<Self> {
        let (format, _) = postcard::take_from_bytes::<u16>(bytes)?;
        let anchor = match format {
            1 if kind == "anchor-manifest" => Self::Legacy(canonical_record(bytes)?),
            2 | 3 => Self::Stable(canonical_record(bytes)?),
            _ => anyhow::bail!("unsupported preserved anchor manifest version"),
        };
        match &anchor {
            Self::Legacy(old) => {
                ensure!(
                    !old.anchor_id.is_nil()
                        && !old.area.area_id.is_nil()
                        && old.root_modified_nanos < 1_000_000_000,
                    "invalid preserved legacy anchor"
                );
                validate_hint(&old.source_root_hint)?;
                validate_hint(&old.area.path_hint)?;
                validate_entries(&old.entries, false)?;
            }
            Self::Stable(stable) => validate_stable(stable)?,
        }
        Ok(anchor)
    }

    pub(super) fn anchor_id(&self) -> Uuid {
        match self {
            Self::Legacy(old) => old.anchor_id,
            Self::Stable(stable) => stable.anchor_id,
        }
    }

    pub(super) fn for_each_input(
        &self,
        mut visit: impl FnMut(PreservedInput<'_>) -> Result<()>,
    ) -> Result<()> {
        let (source, area) = match self {
            Self::Legacy(old) => (&old.source_root_hint, &old.area.path_hint),
            Self::Stable(stable) => (&stable.source_root_hint, &stable.area.path_hint),
        };
        visit(PreservedInput::PathHint(source))?;
        visit(PreservedInput::PathHint(area))
    }

    pub(super) fn report(&self, used: &mut usize, limit: usize) -> Result<LegacyCaptureOwnership> {
        match self {
            Self::Legacy(old) => {
                let mut report = LegacyCaptureOwnership {
                    record_format: 1,
                    anchor_id: old.anchor_id,
                    source_path_hint_hex: hex::encode(old.source_root_hint.as_os_str().as_bytes()),
                    area_id: old.area.area_id,
                    recorded_area_filesystem_id: None,
                    area_path_hint_hex: hex::encode(old.area.path_hint.as_os_str().as_bytes()),
                    volume_root_hint_hex: None,
                    recorded_root_identity: None,
                    stable_root_identity: None,
                    file_pins: Vec::new(),
                };
                account(&report, used, limit)?;
                add_file_pins(&mut report, &old.entries, used, limit)?;
                Ok(report)
            }
            Self::Stable(stable) => report_stable(stable, used, limit),
        }
    }
}

pub(super) fn validate_stable(anchor: &StableAnchorManifest) -> Result<()> {
    ensure!(
        matches!(anchor.format_version, 2 | 3)
            && !anchor.anchor_id.is_nil()
            && !anchor.area.area_id.is_nil()
            && anchor.area.filesystem_id != 0
            && anchor.root_modified_nanos < 1_000_000_000,
        "invalid preserved stable anchor"
    );
    for path in [
        &anchor.source_root_hint,
        &anchor.area.path_hint,
        &anchor.area.volume_root_hint,
    ] {
        validate_hint(path)?;
    }
    validate_entries(&anchor.entries, anchor.format_version == 3)
}

fn validate_entries(entries: &[CapturedEntry], raw: bool) -> Result<()> {
    let mut paths = std::collections::BTreeSet::new();
    for entry in entries {
        let (path, nanos) = match entry {
            CapturedEntry::Directory {
                path,
                modified_nanos,
                ..
            }
            | CapturedEntry::File {
                path,
                modified_nanos,
                ..
            }
            | CapturedEntry::FileV2 {
                path,
                modified_nanos,
                ..
            } => (path, modified_nanos),
        };
        let mut normalized = PathBuf::new();
        for component in path.components() {
            let Component::Normal(name) = component else {
                anyhow::bail!("unsafe preserved anchor entry")
            };
            normalized.push(name);
        }
        let bytes = path.as_os_str().as_bytes();
        ensure!(
            !bytes.is_empty()
                && !bytes.contains(&0)
                && normalized.as_os_str().as_bytes() == bytes
                && paths.insert(bytes)
                && *nanos < 1_000_000_000
                && (raw || path.to_str().is_some()),
            "invalid preserved anchor entry"
        );
        if let CapturedEntry::FileV2 {
            native_id,
            logical_len,
            data_extents,
            ..
        } = entry
        {
            ensure!(
                native_id.filesystem_id != 0 && native_id.inode != 0,
                "invalid preserved anchor file identity"
            );
            let mut end = 0;
            for extent in data_extents {
                ensure!(
                    extent.logical_len != 0 && extent.offset >= end,
                    "invalid preserved anchor file extents"
                );
                end = extent
                    .offset
                    .checked_add(extent.logical_len)
                    .context("preserved anchor extent overflow")?;
                ensure!(end <= *logical_len, "preserved anchor extent exceeds file");
            }
        }
    }
    Ok(())
}

pub(super) fn report_stable(
    old: &StableAnchorManifest,
    used: &mut usize,
    limit: usize,
) -> Result<LegacyCaptureOwnership> {
    let mut report = ownership(
        old.format_version,
        old.anchor_id,
        &old.source_root_hint,
        &old.area,
        None,
        None,
    );
    account(&report, used, limit)?;
    add_file_pins(&mut report, &old.entries, used, limit)?;
    Ok(report)
}

fn add_file_pins(
    report: &mut LegacyCaptureOwnership,
    entries: &[CapturedEntry],
    used: &mut usize,
    limit: usize,
) -> Result<()> {
    for entry in entries {
        let (path, len, id) = match entry {
            CapturedEntry::Directory { .. } => continue,
            CapturedEntry::File {
                path, logical_len, ..
            } => (path, *logical_len, None),
            CapturedEntry::FileV2 {
                path,
                logical_len,
                native_id,
                ..
            } => (path, *logical_len, Some(*native_id)),
        };
        let pin = LegacyPendingFilePin {
            relative_path_hex: hex::encode(path.as_os_str().as_bytes()),
            capture_id: report.anchor_id,
            recorded_file_identity: id,
            logical_len: len,
        };
        account(&pin, used, limit)?;
        report.file_pins.push(pin);
    }
    Ok(())
}

//! Decode original intent layouts without migration, replay or filesystem I/O.
use super::*;
use serde::de::DeserializeOwned;

pub(crate) struct PreservedCaptureIntent {
    pub record_format: u16,
    pub guild_id: [u8; 32],
    pub revision_id: Uuid,
    pub sequence: Option<u64>,
    pub parent: Option<[u8; 32]>,
    pub captured_change_sequence: Option<u64>,
    pub requested_source: PathBuf,
    pub plan: SourceCapturePlan,
    pub replaced_anchor: Option<mb_store::StableAnchorManifest>,
}

fn original<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = decode_canonical(bytes)?;
    ensure!(
        canonical_bytes_bounded(&value, V1_MAX_CATALOG_BYTES)? == bytes,
        "preserved capture intent is not canonical in its original layout"
    );
    Ok(value)
}

pub(crate) fn decode_capture_intent(
    kind: &str,
    key: &[u8],
    bytes: &[u8],
) -> Result<PreservedCaptureIntent> {
    let (version, _) = postcard::take_from_bytes::<u16>(bytes)
        .context("preserved capture intent version is undecodable")?;
    let intent = match (kind, version) {
        ("capture-intent", 1) => {
            let old: LegacyCaptureIntentV1 = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 1,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                sequence: Some(old.sequence),
                parent: old.parent,
                captured_change_sequence: None,
                requested_source: old.requested_source,
                plan: SourceCapturePlan::ReflinkV1(old.plan),
                replaced_anchor: None,
            }
        }
        ("capture-intent", 2) => {
            let old: LegacyCaptureIntentV2 = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 2,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                sequence: Some(old.sequence),
                parent: old.parent,
                captured_change_sequence: old.captured_change_sequence,
                requested_source: old.requested_source,
                plan: SourceCapturePlan::ReflinkV1(old.plan),
                replaced_anchor: None,
            }
        }
        ("capture-intent", 3) => {
            let current: CaptureIntent = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 3,
                guild_id: current.guild_id,
                revision_id: current.revision_id,
                sequence: Some(current.sequence),
                parent: current.parent,
                captured_change_sequence: current.captured_change_sequence,
                requested_source: current.requested_source,
                plan: current.plan,
                replaced_anchor: None,
            }
        }
        (RECOVERY_ANCHOR_INTENT_KIND, 1) => {
            let old: LegacyRecoveryAnchorIntentV1 = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 1,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                sequence: None,
                parent: None,
                captured_change_sequence: None,
                requested_source: old.source_root,
                plan: SourceCapturePlan::ReflinkV1(old.plan),
                replaced_anchor: old.replaced_anchor,
            }
        }
        (RECOVERY_ANCHOR_INTENT_KIND, 2) => {
            let current: RecoveryAnchorIntent = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 2,
                guild_id: current.guild_id,
                revision_id: current.revision_id,
                sequence: None,
                parent: None,
                captured_change_sequence: None,
                requested_source: current.source_root,
                plan: current.plan,
                replaced_anchor: current.replaced_anchor,
            }
        }
        _ => bail!("unsupported preserved capture intent kind/version"),
    };
    ensure!(
        !intent.revision_id.is_nil() && key == intent.revision_id.as_bytes(),
        "preserved capture intent key differs from its revision ID"
    );
    Ok(intent)
}

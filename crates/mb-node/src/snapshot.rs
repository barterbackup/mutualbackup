use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
#[cfg(test)]
use mb_core::make_sector_id;
use mb_core::{
    KeyMaterial, MerkleCommitment, SectorId, SectorPurpose, SectorRef, SignedRecord,
    USER_REVISION_DOMAIN, UserRevision, V1_CIPHER_PROFILE, V1_MAX_CATALOG_BYTES,
    V1_MAX_CODING_GROUPS, V1_SECTOR_SIZE, canonical_bytes, crypt_sector, decode_canonical,
    encrypted_sector, make_content_sector_id, merkle_commit, sector_root,
};
use mb_git::{
    GitBackupBlob, GitBackupDescriptor, GitDataExtent, GitGraphObject, GitGraphRef, GitGraphSource,
    GitRepository,
};
#[cfg(test)]
use mb_store::ReflinkAnchor;
use mb_store::{
    AnchorFileLocator, CapturedEntry, ControlStore, FileExtent, NativeFileId, PinnedDirectory,
    ReflinkCapturePlan, SourceBackendKind, SourceCapturePlan, SourceFileCapturePlan,
    StableAnchorFileLocator, git_catalog_marker,
};
#[cfg(target_os = "linux")]
use mb_store::{
    GUARDED_REVISION_CAPTURE_KIND, GuardedRevisionCaptureV1, GuardedViewMount,
    RawFileAnchorManifestV2,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::guarded_metadata::{
    GuardedPrivateEntryV6, GuardedPrivateMetadataV6, GuardedPrivateStatV6,
};

type RecordWrite = (String, Vec<u8>, Vec<u8>);
const ANCHOR_AREA_LOCATION_KIND: &str = "anchor-area-location";
const RECOVERY_ANCHOR_INTENT_KIND: &str = "recovery-anchor-intent";
#[cfg(target_os = "linux")]
const GUARDED_RECOVERY_INTENT_KIND: &str = "guarded-recovery-reflink-intent-v1";
#[cfg(target_os = "linux")]
const GUARDED_RECOVERY_CAPTURE_KIND: &str = "guarded-recovery-reflink-capture-v1";
#[cfg(target_os = "linux")]
const GUARDED_RECOVERY_RETIRE_KIND: &str = "guarded-recovery-reflink-retirement-v1";
const ANCHOR_RETIREMENT_KIND: &str = "anchor-retirement";
const MAX_METADATA_SECTORS: usize = V1_MAX_CATALOG_BYTES.div_ceil(V1_SECTOR_SIZE);
const MAX_DATA_SECTORS: usize = V1_MAX_CODING_GROUPS - MAX_METADATA_SECTORS;
const RESTORE_JOB_KIND: &str = "restore-job";
const GIT_GRAPH_INTENT_KIND: &str = "git-graph-intent-v1";

#[cfg(test)]
type RestoreRenameHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(test)]
thread_local! {
    static INTERRUPT_RECOVERY_ANCHOR_AFTER_CAPTURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static INTERRUPT_GUARDED_RECOVERY_AFTER_CAPTURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static INTERRUPT_AFTER_LEGACY_RESTORE_RETIRE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static AFTER_RESTORE_RENAME: std::cell::RefCell<Option<RestoreRenameHook>> =
        std::cell::RefCell::new(None);
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
        data_extents: Vec<PrivateDataExtent>,
    },
    HardLinkV3 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateDataExtent {
    pub offset: u64,
    pub logical_len: u64,
    pub sectors: Vec<SectorRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateMetadata {
    pub format_version: u16,
    pub root_mode: u32,
    pub root_modified_secs: i64,
    pub root_modified_nanos: u32,
    pub entries: Vec<PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GitPrivateMetadataV4 {
    format_version: u16,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<PrivateEntry>,
    git: LegacyGitBackupDescriptorV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyGitBackupDescriptorV1 {
    format_version: u16,
    repository_id: Uuid,
    refs: Vec<GitGraphRef>,
    objects: Vec<GitGraphObject>,
    blobs: Vec<GitBackupBlob>,
}

impl LegacyGitBackupDescriptorV1 {
    fn into_current(self) -> Result<GitBackupDescriptor> {
        if self.format_version != 1 {
            bail!("historical Git backup descriptor has the wrong version");
        }
        let descriptor = GitBackupDescriptor {
            format_version: 1,
            repository_id: self.repository_id,
            refs: self.refs,
            objects: self.objects,
            blobs: self.blobs,
            head_branch: "main".to_owned(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GitPrivateMetadataV5 {
    format_version: u16,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<PrivateEntry>,
    git: GitBackupDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyGitGraphIntentV1 {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    protected_root_id: Uuid,
    graph: GitGraphSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GitGraphIntent {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    protected_root_id: Uuid,
    graph: GitGraphSource,
    head_branch: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum RestoreJobState {
    Building,
    Publishing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RestoreJob {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target: PathBuf,
    parent_identity: NativeFileId,
    staging_name: String,
    staged_identity: Option<NativeFileId>,
    state: RestoreJobState,
}

struct ReservedRestoreJob {
    record_id: [u8; 32],
    bytes: Vec<u8>,
    job: RestoreJob,
}

struct RestoreOperationGuard(File);

// Private metadata version 2 existed briefly with two different positional
// postcard layouts. Keep both wire types immutable: changing PrivateEntry
// cannot make either historical layout disappear from recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct NativeV2PrivateMetadata {
    format_version: u16,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<NativeV2PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum NativeV2PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        native_id: NativeFileId,
        data_extents: Vec<PrivateDataExtent>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LinkV2PrivateMetadata {
    format_version: u16,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<LinkV2PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LinkV2PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
        data_extents: Vec<PrivateDataExtent>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LocalSectorRecipe {
    guild_id: [u8; 32],
    reference: SectorRef,
    source: LocalPlaintextSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LocalPlaintextSource {
    AnchorFile {
        locator: AnchorFileLocator,
        offset: u64,
    },
    Inline(Vec<u8>),
    StableAnchorFile {
        locator: StableAnchorFileLocator,
        offset: u64,
    },
}

struct PendingAnchor {
    manifest: mb_store::StableAnchorManifest,
    committed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CaptureIntent {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    sequence: u64,
    parent: Option<[u8; 32]>,
    captured_change_sequence: Option<u64>,
    requested_source: PathBuf,
    plan: SourceCapturePlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyCaptureIntentV2 {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    sequence: u64,
    parent: Option<[u8; 32]>,
    captured_change_sequence: Option<u64>,
    requested_source: PathBuf,
    plan: ReflinkCapturePlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyCaptureIntentV1 {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    sequence: u64,
    parent: Option<[u8; 32]>,
    requested_source: PathBuf,
    plan: ReflinkCapturePlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RecoveryAnchorIntent {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    source_root: PathBuf,
    plan: SourceCapturePlan,
    replaced_anchor: Option<mb_store::StableAnchorManifest>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedRecoveredFilePlanV1 {
    path: Vec<u8>,
    plan: SourceFileCapturePlan,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedRecoveryIntentV1 {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    source_root: PathBuf,
    metadata_hash: [u8; 32],
    files: Vec<GuardedRecoveredFilePlanV1>,
    replaced: Option<GuardedRecoveredCaptureV1>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedRecoveredFileV1 {
    path: Vec<u8>,
    anchor: RawFileAnchorManifestV2,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedRecoveredCaptureV1 {
    format_version: u16,
    revision_id: Uuid,
    metadata_hash: [u8; 32],
    files: Vec<GuardedRecoveredFileV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyRecoveryAnchorIntentV1 {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    source_root: PathBuf,
    plan: ReflinkCapturePlan,
    replaced_anchor: Option<mb_store::StableAnchorManifest>,
}

fn decode_capture_intent(bytes: &[u8]) -> Result<(CaptureIntent, bool)> {
    if let Ok(intent) = decode_canonical::<CaptureIntent>(bytes)
        && intent.format_version == 3
    {
        return Ok((intent, false));
    }
    if let Ok(legacy) = decode_canonical::<LegacyCaptureIntentV2>(bytes)
        && legacy.format_version == 2
    {
        return Ok((
            CaptureIntent {
                format_version: 3,
                guild_id: legacy.guild_id,
                revision_id: legacy.revision_id,
                sequence: legacy.sequence,
                parent: legacy.parent,
                captured_change_sequence: legacy.captured_change_sequence,
                requested_source: legacy.requested_source,
                plan: SourceCapturePlan::ReflinkV1(legacy.plan),
            },
            true,
        ));
    }
    let legacy: LegacyCaptureIntentV1 = decode_canonical(bytes)
        .context("pending source capture is undecodable in every supported format")?;
    if legacy.format_version != 1 {
        bail!("pending source capture has an unsupported version");
    }
    Ok((
        CaptureIntent {
            format_version: 3,
            guild_id: legacy.guild_id,
            revision_id: legacy.revision_id,
            sequence: legacy.sequence,
            parent: legacy.parent,
            captured_change_sequence: None,
            requested_source: legacy.requested_source,
            plan: SourceCapturePlan::ReflinkV1(legacy.plan),
        },
        true,
    ))
}

fn prepare_git_graph_intent(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision_id: Uuid,
    protected_root_id: Uuid,
    source_root: &Path,
) -> Result<Option<GitGraphIntent>> {
    let registration = control.get_record("git-repository", protected_root_id.as_bytes())?;
    let existing = control.get_record(GIT_GRAPH_INTENT_KIND, revision_id.as_bytes())?;
    let Some(registration) = registration else {
        if existing.is_some() || git_catalog_marker(source_root)?.is_some() {
            bail!(
                "Git catalog marker or backup intent has no matching protected-root registration"
            );
        }
        return Ok(None);
    };
    let info: crate::control::GitRepositoryInfo = decode_canonical(&registration)?;
    if info.format_version != 1
        || info.repository_id != protected_root_id
        || info.path != source_root
        || git_catalog_marker(source_root)? != Some(protected_root_id)
    {
        bail!("protected Git root registration or marker changed before backup");
    }
    if let Some(encoded) = existing {
        let (intent, migrated) = decode_git_graph_intent(&encoded)?;
        if intent.guild_id != guild_id
            || intent.revision_id != revision_id
            || intent.protected_root_id != protected_root_id
            || intent.graph.repository_id != protected_root_id
            || !matches!(intent.graph.format_version, 1 | 2)
        {
            bail!("pending Git graph backup conflicts with the source revision");
        }
        if migrated {
            control.put_record(
                GIT_GRAPH_INTENT_KIND,
                revision_id.as_bytes(),
                &canonical_bytes(&intent)?,
            )?;
        }
        return Ok(Some(intent));
    }
    let catalog_key = mb_git::catalog_key(keys, protected_root_id);
    let repository = GitRepository::open(source_root, protected_root_id, &catalog_key)?;
    let graph = repository.export_graph_source()?;
    let head_branch = repository.selected_branch()?;
    let intent = GitGraphIntent {
        format_version: 2,
        guild_id,
        revision_id,
        protected_root_id,
        graph,
        head_branch,
    };
    validate_git_graph_intent(&intent)?;
    if !control.put_record_if_absent(
        GIT_GRAPH_INTENT_KIND,
        revision_id.as_bytes(),
        &canonical_bytes(&intent)?,
    )? {
        bail!("Git graph backup intent changed during source capture");
    }
    Ok(Some(intent))
}

fn validate_git_graph_intent(intent: &GitGraphIntent) -> Result<()> {
    let has_tags = intent.graph.objects.iter().any(|object| object.kind == 3);
    if intent.format_version != 2
        || !matches!(intent.graph.format_version, 1 | 2)
        || (intent.graph.format_version == 2) != has_tags
    {
        bail!("pending Git graph backup has an unsupported version");
    }
    if intent.graph.refs.is_empty() && intent.head_branch != "main" {
        bail!("unborn Git backup has an invalid selected branch");
    }
    Ok(())
}

fn decode_git_graph_intent(bytes: &[u8]) -> Result<(GitGraphIntent, bool)> {
    let (version, _) = postcard::take_from_bytes::<u16>(bytes)?;
    let (intent, migrated) = match version {
        1 => {
            let legacy: LegacyGitGraphIntentV1 = decode_canonical(bytes)?;
            (
                GitGraphIntent {
                    format_version: 2,
                    guild_id: legacy.guild_id,
                    revision_id: legacy.revision_id,
                    protected_root_id: legacy.protected_root_id,
                    graph: legacy.graph,
                    head_branch: "main".to_owned(),
                },
                true,
            )
        }
        2 => (decode_canonical(bytes)?, false),
        _ => bail!("pending Git graph backup intent has an unsupported version"),
    };
    validate_git_graph_intent(&intent)?;
    Ok((intent, migrated))
}

pub(crate) fn git_prune_capture_pending(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
) -> Result<bool> {
    for (_, bytes) in control.records("capture-intent")? {
        let (intent, _) = decode_capture_intent(&bytes)?;
        if intent.requested_source == source_root {
            return Ok(true);
        }
    }
    for (_, bytes) in control.records(GIT_GRAPH_INTENT_KIND)? {
        let (intent, _) = decode_git_graph_intent(&bytes)?;
        if intent.protected_root_id == repository_id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Local sector recipes can keep an exact Git anchor serving encrypted backup
/// data after its branch or index entry has gone away. Prune must preserve that
/// physical source until the recipe itself is retired by guild GC.
pub(crate) fn git_prune_recipe_anchor_ids(control: &ControlStore) -> Result<BTreeSet<Uuid>> {
    let mut anchors = BTreeSet::new();
    for (record_id, encoded) in control.records("local-sector")? {
        let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
        if record_id != recipe.reference.id {
            bail!("local sector recipe key does not match its reference");
        }
        if let LocalPlaintextSource::StableAnchorFile { locator, .. } = recipe.source {
            anchors.insert(locator.anchor_id);
        }
    }
    Ok(anchors)
}

fn decode_recovery_anchor_intent(bytes: &[u8]) -> Result<(RecoveryAnchorIntent, bool)> {
    if let Ok(intent) = decode_canonical::<RecoveryAnchorIntent>(bytes)
        && intent.format_version == 2
    {
        return Ok((intent, false));
    }
    let legacy: LegacyRecoveryAnchorIntentV1 =
        decode_canonical(bytes).context("pending recovered-anchor capture is undecodable")?;
    if legacy.format_version != 1 {
        bail!("pending recovered-anchor capture has an unsupported version");
    }
    Ok((
        RecoveryAnchorIntent {
            format_version: 2,
            guild_id: legacy.guild_id,
            revision_id: legacy.revision_id,
            source_root: legacy.source_root,
            plan: SourceCapturePlan::ReflinkV1(legacy.plan),
            replaced_anchor: legacy.replaced_anchor,
        },
        true,
    ))
}

pub(crate) fn reconcile_pending_captures(control: &ControlStore) -> Result<()> {
    for (record_id, bytes) in control.records("capture-intent")? {
        let (intent, migrated) = decode_capture_intent(&bytes)?;
        if record_id.as_slice() != intent.revision_id.as_bytes() {
            bail!("pending source capture is inconsistent");
        }
        if migrated {
            control.put_record("capture-intent", &record_id, &canonical_bytes(&intent)?)?;
        }
        // An offline source volume must not prevent unrelated guilds from
        // starting. The exact plan remains durable for a later explicit retry.
        let _ = intent.plan.reconcile(control);
    }
    for (record_id, bytes) in control.records(GIT_GRAPH_INTENT_KIND)? {
        let (intent, migrated) = decode_git_graph_intent(&bytes)?;
        if record_id.as_slice() != intent.revision_id.as_bytes() {
            bail!("pending Git graph backup intent is inconsistent");
        }
        if migrated {
            control.put_record(
                GIT_GRAPH_INTENT_KIND,
                &record_id,
                &canonical_bytes(&intent)?,
            )?;
        }
        if control
            .get_record("capture-intent", intent.revision_id.as_bytes())?
            .is_none()
        {
            control.delete_record(GIT_GRAPH_INTENT_KIND, &record_id)?;
        }
    }
    for (record_id, bytes) in control.records(RECOVERY_ANCHOR_INTENT_KIND)? {
        let (intent, migrated) = decode_recovery_anchor_intent(&bytes)?;
        if record_id.as_slice() != intent.revision_id.as_bytes() {
            bail!("pending recovered-anchor capture is inconsistent");
        }
        if migrated {
            control.put_record(
                RECOVERY_ANCHOR_INTENT_KIND,
                &record_id,
                &canonical_bytes(&intent)?,
            )?;
        }
        let _ = intent.plan.reconcile(control);
    }
    #[cfg(target_os = "linux")]
    for (record_id, bytes) in control.records(GUARDED_RECOVERY_INTENT_KIND)? {
        let intent: GuardedRecoveryIntentV1 = decode_canonical(&bytes)?;
        ensure!(
            intent.format_version == 1
                && record_id.as_slice() == intent.revision_id.as_bytes()
                && canonical_bytes(&intent)?.len() <= V1_MAX_CATALOG_BYTES * 2,
            "pending guarded recovery intent is invalid"
        );
        for file in &intent.files {
            let _ = file.plan.reconcile_with_control(control);
        }
    }
    reconcile_anchor_retirements(control)?;
    Ok(())
}

fn remove_revision_anchor(
    control: &ControlStore,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(plan) = mb_store::GuardedRootCapturePlan::load_for_manifest(control, manifest)? {
        return plan.discard_unreferenced(control);
    }
    manifest.remove()?;
    Ok(())
}

fn reconcile_anchor_retirements(control: &ControlStore) -> Result<()> {
    for (record_id, bytes) in control.records(ANCHOR_RETIREMENT_KIND)? {
        let manifest: mb_store::StableAnchorManifest = decode_canonical(&bytes)?;
        if record_id.as_slice() != manifest.anchor_id.as_bytes() {
            bail!("durable anchor retirement is inconsistent");
        }
        if remove_revision_anchor(control, &manifest).is_ok() {
            let _ = control.delete_record(ANCHOR_RETIREMENT_KIND, &record_id)?;
        }
    }
    #[cfg(target_os = "linux")]
    if GuardedViewMount::has_revision_capture_retirements(control)? {
        GuardedViewMount::reconcile_revision_capture_retirements(
            control,
            &git_prune_recipe_anchor_ids(control)?,
        )?;
    }
    #[cfg(target_os = "linux")]
    reconcile_guarded_recovered_retirements(control)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn guarded_recovered_capture_ids(control: &ControlStore) -> Result<BTreeSet<Uuid>> {
    let mut ids = BTreeSet::new();
    for (record_id, bytes) in control.records(GUARDED_RECOVERY_CAPTURE_KIND)? {
        let capture: GuardedRecoveredCaptureV1 = decode_canonical(&bytes)?;
        ensure!(
            capture.format_version == 1 && record_id.as_slice() == capture.revision_id.as_bytes(),
            "recovered guarded capture record is invalid"
        );
        ids.extend(capture.files.iter().map(|file| file.anchor.anchor_id));
    }
    Ok(ids)
}

#[cfg(target_os = "linux")]
fn reconcile_guarded_recovered_retirements(control: &ControlStore) -> Result<()> {
    let retirements = control.records(GUARDED_RECOVERY_RETIRE_KIND)?;
    if retirements.is_empty() {
        return Ok(());
    }
    let mut pinned = git_prune_recipe_anchor_ids(control)?;
    pinned.extend(guarded_recovered_capture_ids(control)?);
    for (id, bytes) in retirements {
        ensure!(
            id.as_slice() == blake3::hash(&bytes).as_bytes()
                && bytes.len() <= V1_MAX_CATALOG_BYTES * 2,
            "recovered guarded anchor retirement record is invalid"
        );
        let capture: GuardedRecoveredCaptureV1 = decode_canonical(&bytes)?;
        ensure!(
            capture.format_version == 1
                && capture.files.iter().all(|file| {
                    file.anchor.format_version == 2
                        && file.anchor.source_relative_path.as_os_str().as_bytes() == file.path
                }),
            "recovered guarded anchor retirement is inconsistent"
        );
        if capture
            .files
            .iter()
            .any(|file| pinned.contains(&file.anchor.anchor_id))
        {
            continue;
        }
        if capture
            .files
            .iter()
            .any(|file| file.anchor.remove().is_err())
        {
            continue;
        }
        control.delete_record_if_value(GUARDED_RECOVERY_RETIRE_KIND, &id, &bytes)?;
    }
    Ok(())
}

/// Return false while an unreachable guarded revision still has a signed
/// record or a local sector recipe. GC retries its anchor candidate after
/// those sources are released, then transfers cleanup to a durable journal.
pub(crate) fn retire_revision_anchor(
    control: &mut ControlStore,
    revision_id: Uuid,
) -> Result<bool> {
    #[cfg(target_os = "linux")]
    if control
        .get_record(GUARDED_RECOVERY_INTENT_KIND, revision_id.as_bytes())?
        .is_some()
    {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    if let Some(capture) = GuardedViewMount::load_revision_capture(revision_id, control)? {
        if control
            .get_record("user-revision", revision_id.as_bytes())?
            .is_some()
        {
            return Ok(false);
        }
        let recipe_anchors = git_prune_recipe_anchor_ids(control)?;
        if recipe_anchors.contains(&capture.capture.metadata.anchor_id)
            || capture
                .capture
                .files
                .iter()
                .any(|file| recipe_anchors.contains(&file.locator.anchor_id))
        {
            return Ok(false);
        }
        GuardedViewMount::retire_revision_capture_unreferenced(
            revision_id,
            control,
            &recipe_anchors,
        )?;
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    if let Some(bytes) =
        control.get_record(GUARDED_RECOVERY_CAPTURE_KIND, revision_id.as_bytes())?
    {
        let capture: GuardedRecoveredCaptureV1 = decode_canonical(&bytes)?;
        ensure!(
            capture.format_version == 1 && capture.revision_id == revision_id,
            "recovered guarded revision capture is inconsistent"
        );
        let recipe_anchors = git_prune_recipe_anchor_ids(control)?;
        if control
            .get_record("user-revision", revision_id.as_bytes())?
            .is_some()
            || capture
                .files
                .iter()
                .any(|file| recipe_anchors.contains(&file.anchor.anchor_id))
        {
            return Ok(false);
        }
        let retirement_id = blake3::hash(&bytes);
        ensure!(
            control
                .get_record(GUARDED_RECOVERY_RETIRE_KIND, retirement_id.as_bytes())?
                .is_none_or(|existing| existing == bytes),
            "recovered guarded retirement conflicts with its capture"
        );
        control.move_protocol_record(
            GUARDED_RECOVERY_CAPTURE_KIND,
            revision_id.as_bytes(),
            &bytes,
            GUARDED_RECOVERY_RETIRE_KIND,
            retirement_id.as_bytes(),
        )?;
        reconcile_guarded_recovered_retirements(control)?;
        return Ok(true);
    }
    let Some(bytes) = control.get_record("anchor-manifest", revision_id.as_bytes())? else {
        return Ok(true);
    };
    let manifest: mb_store::StableAnchorManifest = decode_canonical(&bytes)?;
    control.move_protocol_record(
        "anchor-manifest",
        revision_id.as_bytes(),
        &bytes,
        ANCHOR_RETIREMENT_KIND,
        manifest.anchor_id.as_bytes(),
    )?;
    if remove_revision_anchor(control, &manifest).is_ok() {
        let _ = control.delete_record(ANCHOR_RETIREMENT_KIND, manifest.anchor_id.as_bytes())?;
    }
    Ok(true)
}

pub(crate) fn abandon_recovered_anchor_capture(
    control: &ControlStore,
    guild_id: [u8; 32],
    revision_id: Uuid,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(bytes) = control.get_record(GUARDED_RECOVERY_INTENT_KIND, revision_id.as_bytes())? {
        let intent: GuardedRecoveryIntentV1 = decode_canonical(&bytes)?;
        ensure!(
            intent.format_version == 1
                && intent.guild_id == guild_id
                && intent.revision_id == revision_id,
            "pending guarded recovery conflicts with the recovery job"
        );
        for file in &intent.files {
            file.plan.discard_with_control(control)?;
        }
        control.delete_record_if_value(
            GUARDED_RECOVERY_INTENT_KIND,
            revision_id.as_bytes(),
            &bytes,
        )?;
    }
    let Some(bytes) = control.get_record(RECOVERY_ANCHOR_INTENT_KIND, revision_id.as_bytes())?
    else {
        return Ok(());
    };
    let (intent, _) = decode_recovery_anchor_intent(&bytes)?;
    if intent.guild_id != guild_id || intent.revision_id != revision_id {
        bail!("pending recovered-anchor capture conflicts with the recovery job");
    }
    intent
        .plan
        .discard(control)
        .context("discard recovered-anchor capture whose restored source was lost")?;
    if !control.delete_record(RECOVERY_ANCHOR_INTENT_KIND, revision_id.as_bytes())? {
        bail!("pending recovered-anchor capture disappeared");
    }
    Ok(())
}

impl PendingAnchor {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingAnchor {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.manifest.remove();
        }
    }
}

pub(crate) struct WriterCredentials<'a> {
    pub epoch: u64,
    pub secret: &'a [u8; 32],
    pub captured_change_sequence: Option<u64>,
}

pub(crate) fn revision_head_id(guild_id: [u8; 32], protected_root_id: Uuid) -> Vec<u8> {
    let mut id = Vec::with_capacity(48);
    id.extend_from_slice(&guild_id);
    id.extend_from_slice(protected_root_id.as_bytes());
    id
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    protected_root_id: Uuid,
    source_root: &Path,
    sequence: u64,
    revision_id: Option<Uuid>,
    source_backend: SourceBackendKind,
    writer: WriterCredentials<'_>,
) -> Result<SignedRecord<UserRevision>> {
    let writer_epoch = writer.epoch;
    let writer_secret = writer.secret;
    let captured_change_sequence = writer.captured_change_sequence;
    let revision_id = revision_id.unwrap_or_else(Uuid::new_v4);
    if let Some(bytes) = control.get_record("user-revision", revision_id.as_bytes())? {
        let existing: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        existing.verify(USER_REVISION_DOMAIN)?;
        existing.value.verify_writer()?;
        if existing.value.revision_id != revision_id
            || existing.value.owner != keys.node_id()
            || existing.value.guild_id != guild_id
            || existing.value.protected_root_id != protected_root_id
            || existing.value.sequence != sequence
            || existing.value.writer_epoch != writer_epoch
            || existing.value.writer_public_key
                != SigningKey::from_bytes(writer_secret)
                    .verifying_key()
                    .to_bytes()
        {
            bail!("persisted revision does not match the retried operation");
        }
        return Ok(existing);
    }
    let head_id = revision_head_id(guild_id, protected_root_id);
    let parent = match control.get_record("user-revision-head", &head_id)? {
        Some(bytes) => {
            let previous: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
            previous.verify(USER_REVISION_DOMAIN)?;
            previous.value.verify_writer()?;
            if previous.signer != keys.node_id()
                || previous.value.owner != keys.node_id()
                || previous.value.guild_id != guild_id
                || previous.value.protected_root_id != protected_root_id
                || !matches!(previous.value.format_version, 3..=5)
                || previous.value.cipher_profile != V1_CIPHER_PROFILE
                || previous.value.sequence.checked_add(1) != Some(sequence)
            {
                bail!("new revision does not extend the durable local revision head");
            }
            Some(previous.value.hash()?)
        }
        None if sequence == 1 => None,
        None => bail!("the first local revision must have sequence one"),
    };
    let (intent, intent_bytes) = match control
        .get_record("capture-intent", revision_id.as_bytes())?
    {
        Some(bytes) => {
            let (intent, migrated) = decode_capture_intent(&bytes)?;
            if intent.guild_id != guild_id
                || intent.revision_id != revision_id
                || intent.sequence != sequence
                || intent.parent != parent
                || intent.requested_source != source_root
            {
                bail!("pending source capture conflicts with the retried operation");
            }
            if migrated {
                let migrated_bytes = canonical_bytes(&intent)?;
                control.put_record("capture-intent", revision_id.as_bytes(), &migrated_bytes)?;
                (intent, migrated_bytes)
            } else {
                (intent, bytes)
            }
        }
        None => {
            let intent = CaptureIntent {
                format_version: 3,
                guild_id,
                revision_id,
                sequence,
                parent,
                captured_change_sequence,
                requested_source: source_root.to_path_buf(),
                plan: source_backend
                    .plan_root(source_root)
                    .context("plan source anchor")?,
            };
            let bytes = canonical_bytes(&intent)?;
            control.put_record("capture-intent", revision_id.as_bytes(), &bytes)?;
            (intent, bytes)
        }
    };
    let git_graph = prepare_git_graph_intent(
        control,
        keys,
        guild_id,
        revision_id,
        protected_root_id,
        source_root,
    )?;
    let result = (|| {
        let mut anchor = PendingAnchor {
            manifest: intent
                .plan
                .capture(control)
                .context("capture source anchor")?,
            committed: false,
        };
        if canonical_bytes(&anchor.manifest)?.len() > V1_MAX_CATALOG_BYTES / 2 {
            bail!("captured source catalog exceeds the v1 bounded-object limit");
        }
        validate_capture_sector_budget(&anchor.manifest)?;
        let encryption_key = keys.guild_data_key(&guild_id);
        let content_id_key = keys.guild_content_id_key(&guild_id);
        let mut data_references = Vec::new();
        let mut sector_commitments = BTreeMap::<SectorId, MerkleCommitment>::new();
        let mut private_entries = Vec::new();
        let mut recipe_records = Vec::with_capacity(256);
        let mut ordinal = 0_u64;
        let mut prepared_links = BTreeMap::<NativeFileId, u64>::new();
        let mut next_link_group = 0_u64;

        for entry in &anchor.manifest.entries {
            match entry {
                CapturedEntry::Directory {
                    path,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => {
                    private_entries.push(PrivateEntry::Directory {
                        path: path.clone(),
                        mode: *mode,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                    });
                }
                CapturedEntry::File {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                } => {
                    let locator = anchor.manifest.file_locator(path.clone())?;
                    let mut file = locator.open().context("open captured anchor file")?;
                    let mut remaining = *logical_len;
                    let mut offset = 0_u64;
                    let mut file_references = Vec::new();
                    while remaining > 0 {
                        let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as usize;
                        let mut plaintext = vec![0_u8; logical_len];
                        file.read_exact(&mut plaintext)?;
                        let id = make_content_sector_id(
                            &content_id_key,
                            keys.node_id(),
                            guild_id,
                            protected_root_id,
                            SectorPurpose::Data,
                            &plaintext,
                        )?;
                        ordinal += 1;
                        let (reference, ciphertext) =
                            encrypted_sector(&encryption_key, id, &plaintext)?;
                        sector_commitments.insert(id, merkle_commit(&ciphertext)?);
                        push_data_reference(&mut data_references, reference.clone())?;
                        file_references.push(reference.clone());
                        queue_recipe(
                            &mut recipe_records,
                            LocalSectorRecipe {
                                guild_id,
                                reference,
                                source: LocalPlaintextSource::StableAnchorFile {
                                    locator: locator.clone(),
                                    offset,
                                },
                            },
                        )?;
                        offset += logical_len as u64;
                        remaining -= logical_len as u64;
                    }
                    private_entries.push(PrivateEntry::File {
                        path: path.clone(),
                        mode: *mode,
                        logical_len: *logical_len,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                        sectors: file_references,
                    });
                }
                CapturedEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    native_id,
                    data_extents,
                } => {
                    if let Some(link_group) = prepared_links.get(native_id) {
                        private_entries.push(PrivateEntry::HardLinkV3 {
                            path: path.clone(),
                            mode: *mode,
                            logical_len: *logical_len,
                            modified_secs: *modified_secs,
                            modified_nanos: *modified_nanos,
                            link_group: *link_group,
                        });
                        continue;
                    }
                    let locator = anchor.manifest.file_locator(path.clone())?;
                    let private_extents = prepare_sparse_file(
                        &mut recipe_records,
                        keys,
                        guild_id,
                        protected_root_id,
                        &content_id_key,
                        &mut ordinal,
                        &mut sector_commitments,
                        &locator,
                        *logical_len,
                        data_extents,
                    )?;
                    for reference in private_extents
                        .iter()
                        .flat_map(|extent| extent.sectors.iter())
                    {
                        push_data_reference(&mut data_references, reference.clone())?;
                    }
                    let link_group = next_link_group;
                    next_link_group = next_link_group
                        .checked_add(1)
                        .context("too many hard-link groups in one revision")?;
                    prepared_links.insert(*native_id, link_group);
                    private_entries.push(PrivateEntry::FileV2 {
                        path: path.clone(),
                        mode: *mode,
                        logical_len: *logical_len,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                        link_group,
                        data_extents: private_extents,
                    });
                }
            }
        }

        let metadata_bytes = if let Some(graph) = git_graph.clone() {
            let git = prepare_git_backup_descriptor(
                &mut recipe_records,
                &mut data_references,
                keys,
                guild_id,
                protected_root_id,
                &content_id_key,
                &mut ordinal,
                &mut sector_commitments,
                graph,
            )?;
            canonical_bytes(&GitPrivateMetadataV5 {
                format_version: 5,
                root_mode: anchor.manifest.root_mode,
                root_modified_secs: anchor.manifest.root_modified_secs,
                root_modified_nanos: anchor.manifest.root_modified_nanos,
                entries: private_entries,
                git,
            })?
        } else {
            canonical_bytes(&PrivateMetadata {
                format_version: 3,
                root_mode: anchor.manifest.root_mode,
                root_modified_secs: anchor.manifest.root_modified_secs,
                root_modified_nanos: anchor.manifest.root_modified_nanos,
                entries: private_entries,
            })?
        };
        if metadata_bytes.is_empty() || metadata_bytes.len() > V1_MAX_CATALOG_BYTES {
            bail!("private metadata exceeds the v1 bounded-object limit");
        }
        let mut metadata_references = Vec::new();
        for plaintext in metadata_bytes.chunks(V1_SECTOR_SIZE) {
            let id = make_content_sector_id(
                &content_id_key,
                keys.node_id(),
                guild_id,
                protected_root_id,
                SectorPurpose::Metadata,
                plaintext,
            )?;
            let (reference, ciphertext) = encrypted_sector(&encryption_key, id, plaintext)?;
            sector_commitments.insert(id, merkle_commit(&ciphertext)?);
            metadata_references.push(reference.clone());
            queue_recipe(
                &mut recipe_records,
                LocalSectorRecipe {
                    guild_id,
                    reference,
                    source: LocalPlaintextSource::Inline(plaintext.to_vec()),
                },
            )?;
        }

        let writer = SigningKey::from_bytes(writer_secret);
        let signed_sector_commitments = metadata_references
            .iter()
            .chain(&data_references)
            .map(|reference| {
                sector_commitments
                    .get(&reference.id)
                    .cloned()
                    .context("captured sector is missing its Merkle commitment")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut revision = UserRevision {
            format_version: 5,
            guild_id,
            protected_root_id,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            writer_epoch,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence,
            parent,
            metadata_sectors: metadata_references,
            data_sectors: data_references,
            sector_commitments: Some(signed_sector_commitments),
        };
        revision.sign_writer(&writer)?;
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, keys)?;
        if canonical_bytes(&revision)?.len() > V1_MAX_CATALOG_BYTES {
            bail!("revision catalog exceeds the v1 bounded-object limit");
        }
        let mut records = recipe_records;
        records.extend([
            (
                ANCHOR_AREA_LOCATION_KIND.to_owned(),
                anchor.manifest.area.area_id.as_bytes().to_vec(),
                canonical_bytes(&anchor.manifest.area.path_hint)?,
            ),
            (
                "anchor-manifest".to_owned(),
                revision_id.as_bytes().to_vec(),
                canonical_bytes(&anchor.manifest)?,
            ),
            (
                "user-revision".to_owned(),
                revision_id.as_bytes().to_vec(),
                canonical_bytes(&revision)?,
            ),
            (
                "user-revision-head".to_owned(),
                head_id,
                canonical_bytes(&revision)?,
            ),
        ]);
        if let Some(captured_change_sequence) = intent.captured_change_sequence {
            records.push((
                "revision-root-change".to_owned(),
                revision_id.as_bytes().to_vec(),
                canonical_bytes(&captured_change_sequence)?,
            ));
        }
        control.finalize_capture_records(revision_id.as_bytes(), &records)?;
        anchor.commit();
        if git_graph.is_some() {
            // A crash here leaves a harmless intent; startup reconciliation
            // retires it after observing the committed revision.
            let _ = control.delete_record(GIT_GRAPH_INTENT_KIND, revision_id.as_bytes());
        }
        Ok(revision)
    })();
    match result {
        Ok(revision) => Ok(revision),
        Err(error) => {
            intent
                .plan
                .discard(control)
                .context("discard failed source capture")?;
            control
                .abandon_capture_intent(revision_id.as_bytes(), &intent_bytes)
                .context("retire failed source-capture intent")?;
            if git_graph.is_some() {
                let _ = control.delete_record(GIT_GRAPH_INTENT_KIND, revision_id.as_bytes());
            }
            Err(error)
        }
    }
}

/// Sign one stopped guarded-view attempt. The store's published attempt owns
/// all anchors until the final SQL transaction replaces it with a durable
/// revision capture record and sector recipes.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Guarded root enrollment must select this path after its recovery gate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_guarded_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    protected_root_id: Uuid,
    root_anchor_id: Uuid,
    sequence: u64,
    revision_id: Uuid,
    writer: WriterCredentials<'_>,
) -> Result<SignedRecord<UserRevision>> {
    let writer_key = SigningKey::from_bytes(writer.secret);
    if let Some(bytes) = control.get_record("user-revision", revision_id.as_bytes())? {
        let existing: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        existing.verify(USER_REVISION_DOMAIN)?;
        existing.value.verify_writer()?;
        if existing.signer != keys.node_id()
            || existing.value.revision_id != revision_id
            || existing.value.owner != keys.node_id()
            || existing.value.guild_id != guild_id
            || existing.value.protected_root_id != protected_root_id
            || existing.value.sequence != sequence
            || existing.value.writer_epoch != writer.epoch
            || existing.value.writer_public_key != writer_key.verifying_key().to_bytes()
        {
            bail!("guarded revision retry differs from its committed revision");
        }
        let retained = GuardedViewMount::load_revision_capture(revision_id, control)?
            .context("committed guarded revision lost its local anchor map")?;
        if retained.capture.metadata.anchor_id != root_anchor_id {
            bail!("guarded revision retry belongs to another root anchor");
        }
        return Ok(existing);
    }
    if control
        .get_record("capture-intent", revision_id.as_bytes())?
        .is_some()
        || control
            .get_record(GUARDED_REVISION_CAPTURE_KIND, revision_id.as_bytes())?
            .is_some()
    {
        bail!("guarded revision attempt conflicts with another source capture");
    }
    let head_id = revision_head_id(guild_id, protected_root_id);
    let parent = match control.get_record("user-revision-head", &head_id)? {
        Some(bytes) => {
            let previous: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
            previous.verify(USER_REVISION_DOMAIN)?;
            previous.value.verify_writer()?;
            if previous.signer != keys.node_id()
                || previous.value.owner != keys.node_id()
                || previous.value.guild_id != guild_id
                || previous.value.protected_root_id != protected_root_id
                || !matches!(previous.value.format_version, 3..=5)
                || previous.value.cipher_profile != V1_CIPHER_PROFILE
                || previous.value.sequence.checked_add(1) != Some(sequence)
            {
                bail!("guarded revision does not extend the durable local head");
            }
            Some(previous.value.hash()?)
        }
        None if sequence == 1 => None,
        None => bail!("the first guarded revision must have sequence one"),
    };
    let (attempt_bytes, capture) =
        GuardedViewMount::published_stopped_capture_attempt(root_anchor_id, revision_id, control)?;
    let content_id_key = keys.guild_content_id_key(&guild_id);
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut recipes = Vec::new();
    let mut commitments = BTreeMap::<SectorId, MerkleCommitment>::new();
    let mut ordinal = 0_u64;
    let metadata =
        crate::guarded_metadata::GuardedPrivateMetadataV6::from_capture(&capture, |file| {
            prepare_sparse_file(
                &mut recipes,
                keys,
                guild_id,
                protected_root_id,
                &content_id_key,
                &mut ordinal,
                &mut commitments,
                &file.locator,
                file.logical_len,
                &file.data_extents,
            )
        })?;
    let mut data_references = Vec::new();
    for entry in &metadata.entries {
        if let GuardedPrivateEntryV6::File { data_extents, .. } = entry {
            for reference in data_extents.iter().flat_map(|extent| extent.sectors.iter()) {
                push_data_reference(&mut data_references, reference.clone())?;
            }
        }
    }
    let metadata_bytes = canonical_bytes(&metadata)?;
    let mut metadata_references = Vec::new();
    for plaintext in metadata_bytes.chunks(V1_SECTOR_SIZE) {
        let id = make_content_sector_id(
            &content_id_key,
            keys.node_id(),
            guild_id,
            protected_root_id,
            SectorPurpose::Metadata,
            plaintext,
        )?;
        let (reference, ciphertext) = encrypted_sector(&encryption_key, id, plaintext)?;
        commitments.insert(id, merkle_commit(&ciphertext)?);
        metadata_references.push(reference.clone());
        queue_recipe(
            &mut recipes,
            LocalSectorRecipe {
                guild_id,
                reference,
                source: LocalPlaintextSource::Inline(plaintext.to_vec()),
            },
        )?;
    }
    let signed_commitments = metadata_references
        .iter()
        .chain(&data_references)
        .map(|reference| {
            commitments
                .get(&reference.id)
                .cloned()
                .context("guarded sector lacks a Merkle commitment")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut revision = UserRevision {
        format_version: 5,
        guild_id,
        protected_root_id,
        cipher_profile: V1_CIPHER_PROFILE,
        revision_id,
        owner: keys.node_id(),
        writer_epoch: writer.epoch,
        writer_public_key: writer_key.verifying_key().to_bytes(),
        writer_signature: Vec::new(),
        sequence,
        parent,
        metadata_sectors: metadata_references,
        data_sectors: data_references,
        sector_commitments: Some(signed_commitments),
    };
    revision.sign_writer(&writer_key)?;
    let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, keys)?;
    if canonical_bytes(&revision)?.len() > V1_MAX_CATALOG_BYTES {
        bail!("guarded revision catalog exceeds the bounded-object limit");
    }
    let retained = GuardedRevisionCaptureV1 {
        format_version: 1,
        revision_id,
        capture: capture.clone(),
    };
    retained.verify()?;
    let mut areas = BTreeMap::<Uuid, PathBuf>::new();
    for file in &capture.files {
        let area = &file.locator.area;
        if areas
            .insert(area.area_id, area.path_hint.clone())
            .is_some_and(|path| path != area.path_hint)
        {
            bail!("guarded capture uses conflicting anchor-area hints");
        }
    }
    for (area_id, hint) in areas {
        recipes.push((
            ANCHOR_AREA_LOCATION_KIND.to_owned(),
            area_id.as_bytes().to_vec(),
            canonical_bytes(&hint)?,
        ));
    }
    recipes.extend([
        (
            GUARDED_REVISION_CAPTURE_KIND.to_owned(),
            revision_id.as_bytes().to_vec(),
            canonical_bytes(&retained)?,
        ),
        (
            "user-revision".to_owned(),
            revision_id.as_bytes().to_vec(),
            canonical_bytes(&revision)?,
        ),
        (
            "user-revision-head".to_owned(),
            head_id,
            canonical_bytes(&revision)?,
        ),
    ]);
    if let Some(change_sequence) = writer.captured_change_sequence {
        recipes.push((
            "revision-root-change".to_owned(),
            revision_id.as_bytes().to_vec(),
            canonical_bytes(&change_sequence)?,
        ));
    }
    control.finalize_guarded_capture_records(revision_id.as_bytes(), &attempt_bytes, &recipes)?;
    Ok(revision)
}

#[allow(clippy::too_many_arguments)]
fn prepare_sparse_file(
    recipe_records: &mut Vec<RecordWrite>,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    protected_root_id: Uuid,
    content_id_key: &[u8; 32],
    ordinal: &mut u64,
    sector_commitments: &mut BTreeMap<SectorId, MerkleCommitment>,
    locator: &StableAnchorFileLocator,
    logical_len: u64,
    extents: &[FileExtent],
) -> Result<Vec<PrivateDataExtent>> {
    validate_file_extents(
        logical_len,
        extents
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)),
    )?;
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut file = locator.open().context("open captured anchor file")?;
    let mut result = Vec::with_capacity(extents.len());
    for extent in extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.logical_len;
        let mut offset = extent.offset;
        let mut sectors = Vec::new();
        while remaining > 0 {
            let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as usize;
            let mut plaintext = vec![0_u8; logical_len];
            file.read_exact(&mut plaintext)?;
            let id = make_content_sector_id(
                content_id_key,
                keys.node_id(),
                guild_id,
                protected_root_id,
                SectorPurpose::Data,
                &plaintext,
            )?;
            *ordinal = ordinal
                .checked_add(1)
                .context("too many sectors in one revision")?;
            let (reference, ciphertext) = encrypted_sector(&encryption_key, id, &plaintext)?;
            sector_commitments.insert(id, merkle_commit(&ciphertext)?);
            sectors.push(reference.clone());
            queue_recipe(
                recipe_records,
                LocalSectorRecipe {
                    guild_id,
                    reference,
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                },
            )?;
            offset += logical_len as u64;
            remaining -= logical_len as u64;
        }
        result.push(PrivateDataExtent {
            offset: extent.offset,
            logical_len: extent.logical_len,
            sectors,
        });
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn prepare_git_backup_descriptor(
    recipe_records: &mut Vec<RecordWrite>,
    data_references: &mut Vec<SectorRef>,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    protected_root_id: Uuid,
    content_id_key: &[u8; 32],
    ordinal: &mut u64,
    sector_commitments: &mut BTreeMap<SectorId, MerkleCommitment>,
    source: GitGraphIntent,
) -> Result<GitBackupDescriptor> {
    let encryption_key = keys.guild_data_key(&guild_id);
    validate_git_graph_intent(&source)?;
    let GitGraphIntent {
        graph, head_branch, ..
    } = source;
    let GitGraphSource {
        format_version,
        repository_id,
        refs,
        objects,
        blobs: source_blobs,
    } = graph;
    let mut blobs = Vec::with_capacity(source_blobs.len());
    for blob in &source_blobs {
        if mb_git::blob_oid_from_anchor(&blob.anchor)?.as_bytes() != blob.oid {
            bail!("Git backup blob ID does not match its immutable source anchor");
        }
        let mut file = blob.anchor.open_verified()?;
        let locator = blob.anchor.file_locator();
        let mut sectors = Vec::new();
        let mut offset = 0_u64;
        while offset < blob.anchor.logical_len {
            let logical_len =
                (blob.anchor.logical_len - offset).min(V1_SECTOR_SIZE as u64) as usize;
            let mut plaintext = vec![0_u8; logical_len];
            file.read_exact(&mut plaintext)?;
            let id = make_content_sector_id(
                content_id_key,
                keys.node_id(),
                guild_id,
                protected_root_id,
                SectorPurpose::Data,
                &plaintext,
            )?;
            *ordinal = ordinal
                .checked_add(1)
                .context("too many Git blob sectors")?;
            let (reference, ciphertext) = encrypted_sector(&encryption_key, id, &plaintext)?;
            sector_commitments.insert(id, merkle_commit(&ciphertext)?);
            push_data_reference(data_references, reference.clone())?;
            sectors.push(reference.clone());
            queue_recipe(
                recipe_records,
                LocalSectorRecipe {
                    guild_id,
                    reference,
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                },
            )?;
            offset += logical_len as u64;
        }
        blobs.push(GitBackupBlob {
            oid: blob.oid,
            logical_len: blob.anchor.logical_len,
            data_extents: if blob.anchor.logical_len == 0 {
                Vec::new()
            } else {
                vec![GitDataExtent {
                    offset: 0,
                    logical_len: blob.anchor.logical_len,
                    sectors,
                }]
            },
        });
    }
    let selected_ref = format!("refs/heads/{head_branch}");
    let selected_is_present = refs
        .iter()
        .any(|reference| reference.name == selected_ref.as_bytes());
    let descriptor_version = if !refs.is_empty() && !selected_is_present {
        4
    } else if format_version == 2 {
        3
    } else {
        2
    };
    let descriptor = GitBackupDescriptor {
        format_version: descriptor_version,
        repository_id,
        refs,
        objects,
        blobs,
        head_branch,
    };
    let symlink_blobs = descriptor.symlink_blob_oids()?;
    for blob in &source_blobs {
        if symlink_blobs.contains(&git2::Oid::from_bytes(&blob.oid)?) {
            let mut target = Vec::with_capacity(blob.anchor.logical_len as usize);
            blob.anchor
                .open_verified()?
                .take(4096)
                .read_to_end(&mut target)?;
            if target.len() as u64 != blob.anchor.logical_len || target.contains(&0) {
                bail!("Git backup symlink target cannot be recreated exactly");
            }
        }
    }
    Ok(descriptor)
}

pub(crate) fn validate_file_extents(
    logical_len: u64,
    extents: impl IntoIterator<Item = (u64, u64)>,
) -> Result<()> {
    let mut previous_end = 0_u64;
    for (offset, extent_len) in extents {
        let end = offset
            .checked_add(extent_len)
            .context("file extent overflows its signed range")?;
        if extent_len == 0 || offset < previous_end || end > logical_len {
            bail!("invalid or overlapping file extent");
        }
        previous_end = end;
    }
    Ok(())
}

fn queue_recipe(records: &mut Vec<RecordWrite>, recipe: LocalSectorRecipe) -> Result<()> {
    records.push((
        "local-sector".to_owned(),
        recipe.reference.id.to_vec(),
        canonical_bytes(&recipe)?,
    ));
    Ok(())
}

fn push_data_reference(references: &mut Vec<SectorRef>, reference: SectorRef) -> Result<()> {
    if references.len() >= MAX_DATA_SECTORS {
        bail!("source data exceeds the bounded v1 coding catalog");
    }
    references.push(reference);
    Ok(())
}

fn validate_capture_sector_budget(manifest: &mb_store::StableAnchorManifest) -> Result<()> {
    let mut sectors = 0_usize;
    let mut seen_files = BTreeSet::new();
    for entry in &manifest.entries {
        let additional = match entry {
            CapturedEntry::Directory { .. } => 0,
            CapturedEntry::File { logical_len, .. } => {
                usize::try_from(logical_len.div_ceil(V1_SECTOR_SIZE as u64))
                    .context("captured file is too large for this platform")?
            }
            CapturedEntry::FileV2 {
                native_id,
                data_extents,
                ..
            } if seen_files.insert(*native_id) => {
                data_extents.iter().try_fold(0_usize, |count, extent| {
                    let extent_sectors =
                        usize::try_from(extent.logical_len.div_ceil(V1_SECTOR_SIZE as u64))
                            .context("captured extent is too large for this platform")?;
                    count
                        .checked_add(extent_sectors)
                        .context("captured sector count overflow")
                })?
            }
            CapturedEntry::FileV2 { .. } => 0,
        };
        sectors = sectors
            .checked_add(additional)
            .context("captured sector count overflow")?;
        if sectors > MAX_DATA_SECTORS {
            bail!("source data exceeds the bounded v1 coding catalog");
        }
    }
    Ok(())
}

fn checked_metadata_length(revision: &SignedRecord<UserRevision>) -> Result<usize> {
    if revision.value.metadata_sectors.is_empty()
        || revision.value.metadata_sectors.len() > MAX_METADATA_SECTORS
        || revision
            .value
            .metadata_sectors
            .len()
            .saturating_add(revision.value.data_sectors.len())
            > V1_MAX_CODING_GROUPS
    {
        bail!("revision exceeds the bounded v1 metadata or coding catalog");
    }
    revision
        .value
        .metadata_sectors
        .iter()
        .try_fold(0_usize, |total, reference| {
            let length = usize::try_from(reference.logical_len)
                .context("metadata sector length does not fit memory")?;
            let total = total
                .checked_add(length)
                .context("private metadata length overflow")?;
            if length == 0 || length > V1_SECTOR_SIZE || total > V1_MAX_CATALOG_BYTES {
                bail!("private metadata exceeds the bounded v1 object limit");
            }
            Ok(total)
        })
}

pub(crate) fn install_inline_recipe(
    control: &mut ControlStore,
    guild_id: [u8; 32],
    reference: SectorRef,
    plaintext: Vec<u8>,
) -> Result<()> {
    let recipe = LocalSectorRecipe {
        guild_id,
        reference: reference.clone(),
        source: LocalPlaintextSource::Inline(plaintext),
    };
    control.put_record("local-sector", &reference.id, &canonical_bytes(&recipe)?)?;
    Ok(())
}

pub(crate) fn install_recovered_sector_recipe(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    reference: SectorRef,
    ciphertext: &[u8],
) -> Result<()> {
    if reference.logical_len as usize > V1_SECTOR_SIZE
        || ciphertext.len() != V1_SECTOR_SIZE
        || sector_root(ciphertext) != reference.root
    {
        bail!("recovered information shard does not match its descriptor");
    }
    if render_sector(control, keys, &reference.id, Some(&guild_id))
        .is_ok_and(|existing| existing == ciphertext)
    {
        return Ok(());
    }
    let mut plaintext = ciphertext.to_vec();
    crypt_sector(
        &keys.guild_data_key(&guild_id),
        reference.id,
        &mut plaintext,
    )?;
    plaintext.truncate(reference.logical_len as usize);
    install_inline_recipe(control, guild_id, reference, plaintext)
}

pub(crate) fn reanchor_recovered_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &Path,
) -> Result<()> {
    revision.verify(USER_REVISION_DOMAIN)?;
    revision.value.verify_writer()?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
    {
        bail!("recovered revision does not belong to the local seed and guild");
    }
    if revision.value.data_sectors.is_empty() {
        return Ok(());
    }
    reconcile_anchor_retirements(control)?;
    #[cfg(target_os = "linux")]
    {
        let metadata_bytes = load_private_metadata_bytes(control, keys, guild_id, revision)?;
        if private_metadata_format(&metadata_bytes)? == 6 {
            return reanchor_recovered_guarded_revision(
                control,
                keys,
                guild_id,
                revision,
                restored_root,
                &metadata_bytes,
            );
        }
    }
    let (metadata, git_backup) = load_private_metadata_with_git(control, keys, guild_id, revision)?;
    let git_repository = if let Some(descriptor) = git_backup.as_ref() {
        if descriptor.repository_id != revision.value.protected_root_id {
            bail!("recovered Git history belongs to another protected root");
        }
        let key = mb_git::catalog_key(keys, descriptor.repository_id);
        Some(GitRepository::open(
            restored_root,
            descriptor.repository_id,
            &key,
        )?)
    } else {
        None
    };
    let existing = control.get_record("anchor-manifest", revision.value.revision_id.as_bytes())?;
    let old_manifest = existing
        .as_deref()
        .and_then(|bytes| decode_canonical::<mb_store::StableAnchorManifest>(bytes).ok());
    if let Some(manifest) = old_manifest.as_ref()
        && let Ok(records) = recovered_anchor_records(
            keys,
            guild_id,
            revision,
            &metadata,
            manifest,
            git_backup.as_ref(),
            git_repository.as_ref(),
        )
    {
        if let Some(bytes) = control.get_record(
            RECOVERY_ANCHOR_INTENT_KIND,
            revision.value.revision_id.as_bytes(),
        )? {
            let (intent, _) = decode_recovery_anchor_intent(&bytes)?;
            if intent.guild_id != guild_id || intent.revision_id != revision.value.revision_id {
                bail!("pending recovered-anchor capture conflicts with the revision");
            }
            intent
                .plan
                .discard(control)
                .context("discard redundant recovered-anchor capture")?;
            if !control.delete_record(
                RECOVERY_ANCHOR_INTENT_KIND,
                revision.value.revision_id.as_bytes(),
            )? {
                bail!("pending recovered-anchor capture disappeared");
            }
        }
        control.put_records(&records)?;
        return Ok(());
    }

    let canonical_source = restored_root
        .canonicalize()
        .context("resolve recovered source before anchoring")?;
    let (intent, intent_bytes) = match control.get_record(
        RECOVERY_ANCHOR_INTENT_KIND,
        revision.value.revision_id.as_bytes(),
    )? {
        Some(bytes) => {
            let (intent, migrated) = decode_recovery_anchor_intent(&bytes)?;
            if intent.guild_id != guild_id
                || intent.revision_id != revision.value.revision_id
                || intent.source_root != canonical_source
                || intent.replaced_anchor != old_manifest
            {
                bail!("pending recovered-anchor capture conflicts with the revision");
            }
            if migrated {
                let migrated_bytes = canonical_bytes(&intent)?;
                control.put_record(
                    RECOVERY_ANCHOR_INTENT_KIND,
                    revision.value.revision_id.as_bytes(),
                    &migrated_bytes,
                )?;
                (intent, migrated_bytes)
            } else {
                (intent, bytes)
            }
        }
        None => {
            let plan = SourceCapturePlan::plan_reflink(&canonical_source)
                .context("plan recovered source anchor")?;
            let intent = RecoveryAnchorIntent {
                format_version: 2,
                guild_id,
                revision_id: revision.value.revision_id,
                source_root: canonical_source,
                plan,
                replaced_anchor: old_manifest.clone(),
            };
            let bytes = canonical_bytes(&intent)?;
            control.put_record(
                RECOVERY_ANCHOR_INTENT_KIND,
                revision.value.revision_id.as_bytes(),
                &bytes,
            )?;
            (intent, bytes)
        }
    };
    let mut anchor = PendingAnchor {
        manifest: intent
            .plan
            .capture(control)
            .context("capture recovered source anchor")?,
        committed: false,
    };
    #[cfg(test)]
    if INTERRUPT_RECOVERY_ANCHOR_AFTER_CAPTURE.with(|interrupt| interrupt.replace(false)) {
        anchor.commit();
        bail!("injected interruption after recovered-anchor capture");
    }
    let mut records = recovered_anchor_records(
        keys,
        guild_id,
        revision,
        &metadata,
        &anchor.manifest,
        git_backup.as_ref(),
        git_repository.as_ref(),
    )?;
    if let Some(old) = intent.replaced_anchor.as_ref()
        && old.anchor_id != anchor.manifest.anchor_id
    {
        records.push((
            ANCHOR_RETIREMENT_KIND.to_owned(),
            old.anchor_id.as_bytes().to_vec(),
            canonical_bytes(old)?,
        ));
    }
    // The durable intent now owns this completed anchor. Keep it for an exact
    // retry if the following SQL transaction fails or the process stops.
    anchor.commit();
    control.finalize_recovery_anchor_records(
        revision.value.revision_id.as_bytes(),
        &intent_bytes,
        &records,
    )?;
    reconcile_anchor_retirements(control)?;
    Ok(())
}

fn recovered_anchor_records(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
    git_backup: Option<&GitBackupDescriptor>,
    git_repository: Option<&GitRepository>,
) -> Result<Vec<RecordWrite>> {
    if manifest.format_version != 2 {
        bail!("unsupported recovered anchor manifest version");
    }
    validate_recovered_manifest(metadata, manifest)?;
    let mut records = recovered_anchor_recipes(
        keys,
        guild_id,
        revision,
        metadata,
        manifest,
        git_backup,
        git_repository,
    )?;
    records.push((
        ANCHOR_AREA_LOCATION_KIND.to_owned(),
        manifest.area.area_id.as_bytes().to_vec(),
        canonical_bytes(&manifest.area.path_hint)?,
    ));
    records.push((
        "anchor-manifest".to_owned(),
        revision.value.revision_id.as_bytes().to_vec(),
        canonical_bytes(manifest)?,
    ));
    Ok(records)
}

#[cfg(target_os = "linux")]
impl GuardedRecoveredCaptureV1 {
    fn validate(
        &self,
        revision_id: Uuid,
        metadata_bytes: &[u8],
        metadata: &GuardedPrivateMetadataV6,
    ) -> Result<()> {
        ensure!(
            self.format_version == 1
                && self.revision_id == revision_id
                && self.metadata_hash == *blake3::hash(metadata_bytes).as_bytes(),
            "recovered guarded anchor map differs from signed metadata"
        );
        let primary_paths = metadata.entries.iter().filter_map(|entry| match entry {
            GuardedPrivateEntryV6::File { path, .. } => Some(path.as_slice()),
            _ => None,
        });
        ensure!(
            self.files
                .iter()
                .map(|file| file.path.as_slice())
                .eq(primary_paths),
            "recovered guarded anchor paths differ from signed metadata"
        );
        let mut anchor_ids = BTreeSet::new();
        for file in &self.files {
            ensure!(
                file.anchor.format_version == 2
                    && file.anchor.source_relative_path.as_os_str().as_bytes() == file.path
                    && anchor_ids.insert(file.anchor.anchor_id),
                "recovered guarded file anchor is inconsistent"
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn verify_zero_gap(file: &mut File, start: u64, end: u64) -> Result<()> {
    ensure!(start <= end, "recovered guarded sparse extents overlap");
    file.seek(SeekFrom::Start(start))?;
    let mut remaining = end - start;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let size = usize::try_from(remaining.min(buffer.len() as u64))?;
        file.read_exact(&mut buffer[..size])?;
        ensure!(
            buffer[..size].iter().all(|byte| *byte == 0),
            "recovered guarded sparse hole contains unexpected bytes"
        );
        remaining -= size as u64;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn recovered_guarded_anchor_records(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    metadata: &GuardedPrivateMetadataV6,
    metadata_bytes: &[u8],
    capture: &GuardedRecoveredCaptureV1,
) -> Result<Vec<RecordWrite>> {
    capture.validate(revision.value.revision_id, metadata_bytes, metadata)?;
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut recipes = BTreeMap::<SectorId, LocalSectorRecipe>::new();
    let mut files = capture.files.iter();
    let mut records = Vec::new();
    for entry in &metadata.entries {
        let GuardedPrivateEntryV6::File {
            path,
            logical_len,
            data_extents,
            ..
        } = entry
        else {
            continue;
        };
        let anchored = files
            .next()
            .context("recovered guarded file anchor is missing")?;
        ensure!(
            anchored.path == *path && anchored.anchor.logical_len == *logical_len,
            "recovered guarded file length or path differs from signed metadata"
        );
        let locator = anchored.anchor.file_locator();
        let mut file = anchored.anchor.open_verified()?;
        let mut position = 0_u64;
        for extent in data_extents {
            verify_zero_gap(&mut file, position, extent.offset)?;
            let mut offset = extent.offset;
            for reference in &extent.sectors {
                file.seek(SeekFrom::Start(offset))?;
                let mut plaintext = vec![0_u8; reference.logical_len as usize];
                file.read_exact(&mut plaintext)?;
                let (actual, _) = encrypted_sector(&encryption_key, reference.id, &plaintext)?;
                ensure!(
                    actual == *reference,
                    "recovered guarded anchor content differs from a signed sector"
                );
                let recipe = LocalSectorRecipe {
                    guild_id,
                    reference: reference.clone(),
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                };
                if recipes
                    .insert(reference.id, recipe.clone())
                    .is_some_and(|previous| previous.reference != recipe.reference)
                {
                    bail!("recovered guarded sector has conflicting signed references");
                }
                offset = offset
                    .checked_add(reference.logical_len as u64)
                    .context("recovered guarded sector offset overflow")?;
            }
            position = offset;
        }
        verify_zero_gap(&mut file, position, *logical_len)?;
        records.push((
            ANCHOR_AREA_LOCATION_KIND.to_owned(),
            locator.area.area_id.as_bytes().to_vec(),
            canonical_bytes(&locator.area.path_hint)?,
        ));
    }
    ensure!(
        files.next().is_none(),
        "recovered guarded anchor has an extra file"
    );
    ensure!(
        recipes.len() == revision.value.data_sectors.len()
            && revision.value.data_sectors.iter().all(|reference| {
                recipes.get(&reference.id).map(|recipe| &recipe.reference) == Some(reference)
            }),
        "recovered guarded anchor data catalog differs from signed revision"
    );
    for recipe in recipes.into_values() {
        records.push((
            "local-sector".to_owned(),
            recipe.reference.id.to_vec(),
            canonical_bytes(&recipe)?,
        ));
    }
    Ok(records)
}

#[cfg(target_os = "linux")]
fn guarded_recovery_primary_paths(metadata: &GuardedPrivateMetadataV6) -> Vec<&[u8]> {
    metadata
        .entries
        .iter()
        .filter_map(|entry| match entry {
            GuardedPrivateEntryV6::File { path, .. } => Some(path.as_slice()),
            _ => None,
        })
        .collect()
}

#[cfg(target_os = "linux")]
impl GuardedRecoveryIntentV1 {
    fn validate(
        &self,
        revision: &SignedRecord<UserRevision>,
        guild_id: [u8; 32],
        metadata_bytes: &[u8],
        metadata: &GuardedPrivateMetadataV6,
        source_root: &Path,
        previous: Option<&GuardedRecoveredCaptureV1>,
    ) -> Result<()> {
        ensure!(
            self.format_version == 1
                && self.guild_id == guild_id
                && self.revision_id == revision.value.revision_id
                && self.source_root == source_root
                && self.metadata_hash == *blake3::hash(metadata_bytes).as_bytes()
                && self.replaced.as_ref() == previous
                && canonical_bytes(self)?.len() <= V1_MAX_CATALOG_BYTES * 2,
            "pending guarded recovery differs from its signed revision"
        );
        let paths = guarded_recovery_primary_paths(metadata);
        ensure!(
            self.files.iter().map(|file| file.path.as_slice()).eq(paths)
                && self.files.iter().all(|file| {
                    file.plan.backend_kind() == SourceBackendKind::ReflinkV1
                        && file.plan.source_root() == source_root
                        && file.plan.relative_path().as_os_str().as_bytes() == file.path
                }),
            "pending guarded recovery file plans differ from signed paths"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn reanchor_recovered_guarded_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &Path,
    metadata_bytes: &[u8],
) -> Result<()> {
    let metadata = GuardedPrivateMetadataV6::decode(metadata_bytes)?;
    let existing = control
        .get_record(
            GUARDED_RECOVERY_CAPTURE_KIND,
            revision.value.revision_id.as_bytes(),
        )?
        .map(|bytes| decode_canonical::<GuardedRecoveredCaptureV1>(&bytes))
        .transpose()?;
    let pending_intent = control.get_record(
        GUARDED_RECOVERY_INTENT_KIND,
        revision.value.revision_id.as_bytes(),
    )?;
    if let Some(capture) = existing.as_ref()
        && pending_intent.is_none()
    {
        capture.validate(revision.value.revision_id, metadata_bytes, &metadata)?;
        if let Ok(records) = recovered_guarded_anchor_records(
            keys,
            guild_id,
            revision,
            &metadata,
            metadata_bytes,
            capture,
        ) {
            control.put_records(&records)?;
            return Ok(());
        }
    }
    if control
        .get_record(
            GUARDED_REVISION_CAPTURE_KIND,
            revision.value.revision_id.as_bytes(),
        )?
        .is_some()
    {
        bail!("recovered guarded revision still has an original claimed-view capture");
    }
    let source_root = restored_root
        .canonicalize()
        .context("resolve guarded recovered source before reflink capture")?;
    let (intent, intent_bytes) = match pending_intent {
        Some(bytes) => {
            let intent: GuardedRecoveryIntentV1 = decode_canonical(&bytes)?;
            intent.validate(
                revision,
                guild_id,
                metadata_bytes,
                &metadata,
                &source_root,
                existing.as_ref(),
            )?;
            (intent, bytes)
        }
        None => {
            let mut files = Vec::new();
            for path in guarded_recovery_primary_paths(&metadata) {
                let relative = PathBuf::from(OsString::from_vec(path.to_vec()));
                files.push(GuardedRecoveredFilePlanV1 {
                    path: path.to_vec(),
                    plan: SourceFileCapturePlan::plan_reflink_raw(&source_root, relative)
                        .context("plan guarded recovered file reflink")?,
                });
            }
            let intent = GuardedRecoveryIntentV1 {
                format_version: 1,
                guild_id,
                revision_id: revision.value.revision_id,
                source_root: source_root.clone(),
                metadata_hash: *blake3::hash(metadata_bytes).as_bytes(),
                files,
                replaced: existing.clone(),
            };
            intent.validate(
                revision,
                guild_id,
                metadata_bytes,
                &metadata,
                &source_root,
                existing.as_ref(),
            )?;
            let bytes = canonical_bytes(&intent)?;
            control.put_record(
                GUARDED_RECOVERY_INTENT_KIND,
                revision.value.revision_id.as_bytes(),
                &bytes,
            )?;
            (intent, bytes)
        }
    };
    let mut files = Vec::with_capacity(intent.files.len());
    for planned in &intent.files {
        let anchor = planned.plan.capture_with_control(control)?;
        files.push(GuardedRecoveredFileV1 {
            path: planned.path.clone(),
            anchor: RawFileAnchorManifestV2::from_file_anchor(anchor),
        });
    }
    #[cfg(test)]
    if INTERRUPT_GUARDED_RECOVERY_AFTER_CAPTURE.with(|interrupt| interrupt.replace(false)) {
        bail!("injected interruption after guarded recovered file capture");
    }
    let capture = GuardedRecoveredCaptureV1 {
        format_version: 1,
        revision_id: revision.value.revision_id,
        metadata_hash: intent.metadata_hash,
        files,
    };
    let mut records = recovered_guarded_anchor_records(
        keys,
        guild_id,
        revision,
        &metadata,
        metadata_bytes,
        &capture,
    )?;
    records.push((
        GUARDED_RECOVERY_CAPTURE_KIND.to_owned(),
        revision.value.revision_id.as_bytes().to_vec(),
        canonical_bytes(&capture)?,
    ));
    if let Some(old) = &intent.replaced {
        let bytes = canonical_bytes(old)?;
        records.push((
            GUARDED_RECOVERY_RETIRE_KIND.to_owned(),
            blake3::hash(&bytes).as_bytes().to_vec(),
            bytes,
        ));
    }
    control.finalize_guarded_recovery_records(
        revision.value.revision_id.as_bytes(),
        &intent_bytes,
        &records,
    )?;
    reconcile_anchor_retirements(control)?;
    Ok(())
}

fn load_private_metadata_with_git(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<(PrivateMetadata, Option<GitBackupDescriptor>)> {
    decode_private_metadata_with_git(&load_private_metadata_bytes(
        control, keys, guild_id, revision,
    )?)
}

fn load_private_metadata_bytes(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<Vec<u8>> {
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::with_capacity(checked_metadata_length(revision)?);
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(
            &encryption_key,
            reference,
            &mut |sector_id| render_sector(control, keys, sector_id, Some(&guild_id)),
        )?);
    }
    Ok(metadata_bytes)
}

pub(crate) fn revision_git_backup(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<Option<GitBackupDescriptor>> {
    let bytes = load_private_metadata_bytes(control, keys, guild_id, revision)?;
    if private_metadata_format(&bytes)? == 6 {
        #[cfg(target_os = "linux")]
        GuardedPrivateMetadataV6::decode(&bytes)?;
        #[cfg(not(target_os = "linux"))]
        bail!("guarded private metadata cannot be decoded on this platform");
        return Ok(None);
    }
    Ok(decode_private_metadata_with_git(&bytes)?.1)
}

#[cfg(test)]
fn decode_private_metadata(bytes: &[u8]) -> Result<PrivateMetadata> {
    Ok(decode_private_metadata_with_git(bytes)?.0)
}

fn decode_private_metadata_with_git(
    bytes: &[u8],
) -> Result<(PrivateMetadata, Option<GitBackupDescriptor>)> {
    let format_version = private_metadata_format(bytes)?;
    match format_version {
        1 | 3 => {
            let metadata: PrivateMetadata = decode_canonical(bytes)?;
            if metadata.format_version != format_version {
                bail!("private metadata version changed while decoding");
            }
            if format_version == 1
                && metadata.entries.iter().any(|entry| {
                    matches!(
                        entry,
                        PrivateEntry::FileV2 { .. } | PrivateEntry::HardLinkV3 { .. }
                    )
                })
            {
                bail!("version-1 private metadata contains a later entry variant");
            }
            Ok((metadata, None))
        }
        2 => Ok((decode_v2_private_metadata(bytes)?, None)),
        4 => {
            let metadata: GitPrivateMetadataV4 = decode_canonical(bytes)?;
            if metadata.format_version != 4 {
                bail!("Git private metadata has the wrong version");
            }
            let descriptor = metadata.git.into_current()?;
            Ok((
                PrivateMetadata {
                    format_version: 4,
                    root_mode: metadata.root_mode,
                    root_modified_secs: metadata.root_modified_secs,
                    root_modified_nanos: metadata.root_modified_nanos,
                    entries: metadata.entries,
                },
                Some(descriptor),
            ))
        }
        5 => {
            let metadata: GitPrivateMetadataV5 = decode_canonical(bytes)?;
            if metadata.format_version != 5 || !matches!(metadata.git.format_version, 2..=4) {
                bail!("Git private metadata has the wrong version");
            }
            metadata.git.validate()?;
            Ok((
                PrivateMetadata {
                    format_version: 5,
                    root_mode: metadata.root_mode,
                    root_modified_secs: metadata.root_modified_secs,
                    root_modified_nanos: metadata.root_modified_nanos,
                    entries: metadata.entries,
                },
                Some(metadata.git),
            ))
        }
        _ => bail!("unsupported private metadata version"),
    }
}

fn private_metadata_format(bytes: &[u8]) -> Result<u16> {
    Ok(postcard::take_from_bytes::<u16>(bytes)
        .context("decode private metadata version")?
        .0)
}

fn decode_v2_private_metadata(bytes: &[u8]) -> Result<PrivateMetadata> {
    if let Ok(metadata) = decode_canonical::<LinkV2PrivateMetadata>(bytes)
        && validate_link_v2_layout(&metadata).is_ok()
    {
        return Ok(convert_link_v2(metadata));
    }
    let metadata: NativeV2PrivateMetadata = decode_canonical(bytes)
        .context("private metadata does not match either historical version-2 layout")?;
    convert_native_v2(metadata)
}

fn validate_link_v2_layout(metadata: &LinkV2PrivateMetadata) -> Result<()> {
    if metadata.format_version != 2 {
        bail!("historical link metadata has the wrong version");
    }
    let mut next_group = 0_u64;
    let mut groups = BTreeSet::new();
    for entry in &metadata.entries {
        if let LinkV2PrivateEntry::FileV2 { link_group, .. } = entry
            && groups.insert(*link_group)
        {
            if *link_group != next_group {
                bail!("historical link groups are not in emitted order");
            }
            next_group = next_group
                .checked_add(1)
                .context("too many historical link groups")?;
        }
    }
    Ok(())
}

fn convert_link_v2(metadata: LinkV2PrivateMetadata) -> PrivateMetadata {
    PrivateMetadata {
        format_version: metadata.format_version,
        root_mode: metadata.root_mode,
        root_modified_secs: metadata.root_modified_secs,
        root_modified_nanos: metadata.root_modified_nanos,
        entries: metadata
            .entries
            .into_iter()
            .map(|entry| match entry {
                LinkV2PrivateEntry::Directory {
                    path,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => PrivateEntry::Directory {
                    path,
                    mode,
                    modified_secs,
                    modified_nanos,
                },
                LinkV2PrivateEntry::File {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    sectors,
                } => PrivateEntry::File {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    sectors,
                },
                LinkV2PrivateEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                } => PrivateEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                },
            })
            .collect(),
    }
}

fn convert_native_v2(metadata: NativeV2PrivateMetadata) -> Result<PrivateMetadata> {
    if metadata.format_version != 2 {
        bail!("historical native-ID metadata has the wrong version");
    }
    let mut groups = BTreeMap::<NativeFileId, u64>::new();
    let mut next_group = 0_u64;
    let mut entries = Vec::with_capacity(metadata.entries.len());
    for entry in metadata.entries {
        entries.push(match entry {
            NativeV2PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            } => PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            },
            NativeV2PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            } => PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            },
            NativeV2PrivateEntry::FileV2 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                native_id,
                data_extents,
            } => {
                let link_group = match groups.get(&native_id) {
                    Some(group) => *group,
                    None => {
                        let group = next_group;
                        next_group = next_group
                            .checked_add(1)
                            .context("too many historical native file identities")?;
                        groups.insert(native_id, group);
                        group
                    }
                };
                PrivateEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                }
            }
        });
    }
    Ok(PrivateMetadata {
        format_version: metadata.format_version,
        root_mode: metadata.root_mode,
        root_modified_secs: metadata.root_modified_secs,
        root_modified_nanos: metadata.root_modified_nanos,
        entries,
    })
}

pub(crate) fn restore_signed_root_metadata_at(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &PinnedDirectory,
) -> Result<()> {
    let bytes = load_private_metadata_bytes(control, keys, guild_id, revision)?;
    if private_metadata_format(&bytes)? == 6 {
        #[cfg(target_os = "linux")]
        return set_guarded_metadata_durable(
            restored_root.as_file(),
            &GuardedPrivateMetadataV6::decode(&bytes)?.root,
        );
        #[cfg(not(target_os = "linux"))]
        bail!("guarded private metadata cannot be restored on this platform");
    }
    let (metadata, _) = decode_private_metadata_with_git(&bytes)?;
    set_metadata_durable(
        restored_root.as_file(),
        metadata.root_mode,
        metadata.root_modified_secs,
        metadata.root_modified_nanos,
    )
}

pub(crate) fn make_restore_root_private_at(restored_root: &PinnedDirectory) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        restored_root
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    restored_root.sync_all()?;
    Ok(())
}

fn validate_recovered_manifest(
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<()> {
    if metadata.root_mode != manifest.root_mode
        || metadata.root_modified_secs != manifest.root_modified_secs
        || metadata.root_modified_nanos != manifest.root_modified_nanos
        || metadata.entries.len() != manifest.entries.len()
    {
        bail!("recovered anchor root does not match signed metadata");
    }
    let captured = manifest
        .entries
        .iter()
        .map(|entry| {
            let path = match entry {
                CapturedEntry::Directory { path, .. }
                | CapturedEntry::File { path, .. }
                | CapturedEntry::FileV2 { path, .. } => path,
            };
            (path.as_str(), entry)
        })
        .collect::<BTreeMap<_, _>>();
    if captured.len() != manifest.entries.len() {
        bail!("recovered anchor contains duplicate paths");
    }
    let mut signed_to_captured = BTreeMap::<u64, NativeFileId>::new();
    let mut captured_to_signed = BTreeMap::<NativeFileId, u64>::new();
    for entry in &metadata.entries {
        let path = private_entry_path(entry);
        let actual = captured
            .get(path)
            .with_context(|| format!("recovered anchor is missing {path}"))?;
        match (entry, *actual) {
            (
                PrivateEntry::Directory {
                    mode,
                    modified_secs,
                    modified_nanos,
                    ..
                },
                CapturedEntry::Directory {
                    mode: actual_mode,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    ..
                },
            ) if mode == actual_mode
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos => {}
            (
                PrivateEntry::File {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos => {}
            (
                PrivateEntry::FileV2 {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    native_id: actual_native_id,
                    data_extents: actual_extents,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos
                && data_extents
                    .iter()
                    .map(|extent| FileExtent {
                        offset: extent.offset,
                        logical_len: extent.logical_len,
                    })
                    .eq(actual_extents.iter().cloned()) =>
            {
                if signed_to_captured
                    .insert(*link_group, *actual_native_id)
                    .is_some_and(|previous| previous != *actual_native_id)
                    || captured_to_signed
                        .insert(*actual_native_id, *link_group)
                        .is_some_and(|previous| previous != *link_group)
                {
                    bail!("recovered anchor does not preserve signed hard-link groups");
                }
            }
            (
                PrivateEntry::HardLinkV3 {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    native_id: actual_native_id,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos =>
            {
                if signed_to_captured.get(link_group) != Some(actual_native_id)
                    || captured_to_signed.get(actual_native_id) != Some(link_group)
                {
                    bail!("recovered anchor does not preserve signed hard-link aliases");
                }
            }
            _ => bail!("recovered anchor entry {path} does not match signed metadata"),
        }
    }
    Ok(())
}

fn private_entry_path(entry: &PrivateEntry) -> &str {
    match entry {
        PrivateEntry::Directory { path, .. }
        | PrivateEntry::File { path, .. }
        | PrivateEntry::FileV2 { path, .. }
        | PrivateEntry::HardLinkV3 { path, .. } => path,
    }
}

fn recovered_anchor_recipes(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
    git_backup: Option<&GitBackupDescriptor>,
    git_repository: Option<&GitRepository>,
) -> Result<Vec<RecordWrite>> {
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut by_id = BTreeMap::<SectorId, LocalSectorRecipe>::new();
    for entry in &metadata.entries {
        let (path, extents) = match entry {
            PrivateEntry::Directory { .. } => continue,
            PrivateEntry::File {
                path,
                logical_len,
                sectors,
                ..
            } => (
                path,
                vec![PrivateDataExtent {
                    offset: 0,
                    logical_len: *logical_len,
                    sectors: sectors.clone(),
                }],
            ),
            PrivateEntry::FileV2 {
                path, data_extents, ..
            } => (path, data_extents.clone()),
            PrivateEntry::HardLinkV3 { .. } => continue,
        };
        let locator = manifest.file_locator(path.clone())?;
        let mut file = locator.open().context("open recovered anchor file")?;
        for extent in extents {
            let mut offset = extent.offset;
            let mut extent_len = 0_u64;
            for reference in extent.sectors {
                file.seek(SeekFrom::Start(offset))?;
                let mut plaintext = vec![0_u8; reference.logical_len as usize];
                file.read_exact(&mut plaintext)?;
                let (actual, _) = encrypted_sector(&encryption_key, reference.id, &plaintext)?;
                if actual != reference {
                    bail!("recovered anchor content does not match a signed sector");
                }
                let recipe = LocalSectorRecipe {
                    guild_id,
                    reference: reference.clone(),
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                };
                if by_id
                    .insert(reference.id, recipe.clone())
                    .is_some_and(|previous| previous.reference != recipe.reference)
                {
                    bail!("one sector ID has conflicting signed references");
                }
                offset = offset
                    .checked_add(reference.logical_len as u64)
                    .context("signed sector range overflow")?;
                extent_len = extent_len
                    .checked_add(reference.logical_len as u64)
                    .context("signed extent length overflow")?;
            }
            if extent_len != extent.logical_len {
                bail!("signed extent does not match its sector lengths");
            }
        }
    }
    match (git_backup, git_repository) {
        (Some(descriptor), Some(repository)) => {
            for blob in &descriptor.blobs {
                let oid = git2::Oid::from_bytes(&blob.oid)?;
                let anchor = repository
                    .anchors_for_oid(oid)?
                    .into_iter()
                    .find(|anchor| anchor.logical_len == blob.logical_len)
                    .context("recovered Git blob has no matching native anchor")?;
                let locator = anchor.file_locator();
                let mut file = anchor.open_verified()?;
                for extent in &blob.data_extents {
                    let mut offset = extent.offset;
                    let mut covered = 0_u64;
                    for reference in &extent.sectors {
                        file.seek(SeekFrom::Start(offset))?;
                        let mut plaintext = vec![0_u8; reference.logical_len as usize];
                        file.read_exact(&mut plaintext)?;
                        let (actual, _) =
                            encrypted_sector(&encryption_key, reference.id, &plaintext)?;
                        if actual != *reference {
                            bail!("recovered Git blob differs from its signed data sector");
                        }
                        let recipe = LocalSectorRecipe {
                            guild_id,
                            reference: reference.clone(),
                            source: LocalPlaintextSource::StableAnchorFile {
                                locator: locator.clone(),
                                offset,
                            },
                        };
                        if by_id
                            .insert(reference.id, recipe.clone())
                            .is_some_and(|previous| previous.reference != recipe.reference)
                        {
                            bail!("one Git sector ID has conflicting signed references");
                        }
                        offset = offset
                            .checked_add(reference.logical_len as u64)
                            .context("recovered Git blob sector range overflow")?;
                        covered = covered
                            .checked_add(reference.logical_len as u64)
                            .context("recovered Git extent length overflow")?;
                    }
                    if covered != extent.logical_len {
                        bail!("recovered Git extent differs from its signed length");
                    }
                }
            }
        }
        (None, None) => {}
        _ => bail!("Git backup descriptor and recovered catalog disagree"),
    }
    let expected = revision
        .value
        .data_sectors
        .iter()
        .map(|reference| (reference.id, reference))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != by_id.len()
        || expected.iter().any(|(id, reference)| {
            by_id.get(id).map(|recipe| &recipe.reference) != Some(*reference)
        })
    {
        bail!("signed data-sector catalog does not match recovered file metadata");
    }
    by_id
        .into_values()
        .map(|recipe| {
            Ok((
                "local-sector".to_owned(),
                recipe.reference.id.to_vec(),
                canonical_bytes(&recipe)?,
            ))
        })
        .collect()
}

pub(crate) fn render_sector(
    control: &ControlStore,
    keys: &KeyMaterial,
    sector_id: &SectorId,
    expected_guild: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    render_sector_with_hint_update(control, keys, sector_id, expected_guild, true)
}

fn render_sector_with_hint_update(
    control: &ControlStore,
    keys: &KeyMaterial,
    sector_id: &SectorId,
    expected_guild: Option<&[u8; 32]>,
    update_area_hint: bool,
) -> Result<Vec<u8>> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    if expected_guild.is_some_and(|guild_id| recipe.guild_id != *guild_id) {
        bail!("local sector does not belong to the requested guild");
    }
    let plaintext = match &recipe.source {
        LocalPlaintextSource::AnchorFile { locator, offset } => {
            let mut file = locator.open().context("open source anchor")?;
            file.seek(SeekFrom::Start(*offset))?;
            let mut plaintext = vec![0_u8; recipe.reference.logical_len as usize];
            file.read_exact(&mut plaintext)?;
            plaintext
        }
        LocalPlaintextSource::StableAnchorFile { locator, offset } => {
            let area_hint = control
                .get_record(ANCHOR_AREA_LOCATION_KIND, locator.area.area_id.as_bytes())?
                .and_then(|bytes| decode_canonical::<PathBuf>(&bytes).ok());
            let (mut file, resolved_area) = locator
                .open_with_area_hint(area_hint.as_deref())
                .context("open stable source anchor")?;
            if update_area_hint && area_hint.as_ref() != Some(&resolved_area) {
                control.put_record(
                    ANCHOR_AREA_LOCATION_KIND,
                    locator.area.area_id.as_bytes(),
                    &canonical_bytes(&resolved_area)?,
                )?;
            }
            file.seek(SeekFrom::Start(*offset))?;
            let mut plaintext = vec![0_u8; recipe.reference.logical_len as usize];
            file.read_exact(&mut plaintext)?;
            plaintext
        }
        LocalPlaintextSource::Inline(bytes) => bytes.clone(),
    };
    let (actual_reference, ciphertext) = encrypted_sector(
        &keys.guild_data_key(&recipe.guild_id),
        recipe.reference.id,
        &plaintext,
    )?;
    if actual_reference != recipe.reference {
        bail!("source anchor no longer matches the committed sector root");
    }
    Ok(ciphertext)
}

#[cfg(test)]
pub(crate) fn local_recipe_is_inline(control: &ControlStore, sector_id: &SectorId) -> Result<bool> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    Ok(matches!(recipe.source, LocalPlaintextSource::Inline(_)))
}

pub(crate) fn recovered_recipe_is_stable(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    reference: &SectorRef,
) -> Result<bool> {
    let Some(encoded) = control.get_record("local-sector", &reference.id)? else {
        return Ok(false);
    };
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    if recipe.guild_id != guild_id || recipe.reference != *reference {
        bail!("local sector recipe conflicts with the recovered revision");
    }
    if !matches!(recipe.source, LocalPlaintextSource::StableAnchorFile { .. }) {
        return Ok(false);
    }
    Ok(
        render_sector_with_hint_update(control, keys, &reference.id, Some(&guild_id), false)
            .is_ok_and(|ciphertext| sector_root(&ciphertext) == reference.root),
    )
}

pub fn restore_revision(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    ciphertexts: &BTreeMap<SectorId, Vec<u8>>,
    target: &Path,
) -> Result<()> {
    restore_revision_from_source(control, keys, guild_id, revision, target, |sector_id| {
        ciphertexts
            .get(sector_id)
            .cloned()
            .with_context(|| format!("missing recovered sector {}", hex_id(sector_id)))
    })
}

pub fn restore_revision_from_source<F>(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    target: &Path,
    mut load_ciphertext: F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    validate_restore_revision(keys, guild_id, revision)?;
    let _operation = lock_restore_operations(control)?;
    let (target, target_name, parent) = pinned_restore_parent(target)?;
    let parent_identity = parent.identity()?;
    let ReservedRestoreJob {
        record_id,
        mut bytes,
        mut job,
    } = loop {
        if let Some(reserved) = reserved_restore_job(
            control,
            &target,
            &parent,
            guild_id,
            revision.value.revision_id,
        )? {
            break reserved;
        }
        if parent.entry_identity(&target_name, true)?.is_some() {
            bail!("restore target already exists: {}", target.display());
        }
        let job = RestoreJob {
            format_version: 2,
            guild_id,
            revision_id: revision.value.revision_id,
            target: target.clone(),
            parent_identity,
            staging_name: format!(".mutualbackup-restore-{}", Uuid::new_v4()),
            staged_identity: None,
            state: RestoreJobState::Building,
        };
        let record_id = restore_job_record_id(&target)?;
        let bytes = canonical_bytes(&job)?;
        if control.put_record_if_absent(RESTORE_JOB_KIND, &record_id, &bytes)? {
            break ReservedRestoreJob {
                record_id,
                bytes,
                job,
            };
        }
        // A non-cooperating writer changed the journal despite the operation
        // lock. Reload the durable owner and fail closed below.
    };
    validate_reserved_restore_job(
        &job,
        guild_id,
        revision.value.revision_id,
        &target,
        parent_identity,
    )?;

    if parent.identity()? != job.parent_identity {
        bail!("restore parent directory changed since the durable job was created");
    }
    if job.state == RestoreJobState::Publishing {
        let staging_identity = parent.entry_identity(&job.staging_name, true)?;
        let target_identity = parent.entry_identity(&target_name, true)?;
        if staging_identity.is_none() && target_identity.is_none() {
            // An older multi-job reconciliation could stop after durably
            // removing this job's staging tree but before retiring its journal
            // row. Nothing remains to publish or adopt, so return the signed
            // revision to Building and reconstruct it under a fresh name.
            job.state = RestoreJobState::Building;
            job.staged_identity = None;
            bytes = replace_restore_job(control, &record_id, &bytes, &job)?;
        } else {
            return finish_durable_restore_publication(
                control,
                &record_id,
                &bytes,
                &job,
                &parent,
                &target_name,
            );
        }
    }

    let prior_staging_identity = parent.entry_identity(&job.staging_name, true)?;
    if parent.entry_identity(&target_name, true)?.is_some() {
        if job.staged_identity.is_none() && prior_staging_identity.is_none() {
            control.delete_record_if_value(RESTORE_JOB_KIND, &record_id, &bytes)?;
        }
        bail!("restore target appeared while rebuilding an unfinished restore");
    }
    if let Some(actual) = prior_staging_identity {
        match job.staged_identity {
            Some(expected) if actual == expected => {
                parent.remove_child_directory(&job.staging_name, actual)?;
                parent.sync_all()?;
            }
            Some(_) => bail!("durable restore staging directory was replaced"),
            None => {
                // The process may have stopped between directory creation and
                // recording its inode. Never delete an unbound name; rotate to
                // a fresh staging name and leave the unknown entry untouched.
            }
        }
    }

    job.staging_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
    job.staged_identity = None;
    bytes = replace_restore_job(control, &record_id, &bytes, &job)?;
    let staging = parent.create_child_directory(&job.staging_name)?;
    parent.sync_all()?;
    let staged_identity = staging.identity()?;
    job.staged_identity = Some(staged_identity);
    match replace_restore_job(control, &record_id, &bytes, &job) {
        Ok(replacement) => bytes = replacement,
        Err(error) => {
            if parent.entry_identity(&job.staging_name, true)? == Some(staged_identity) {
                parent.remove_child_directory(&job.staging_name, staged_identity)?;
                parent.sync_all()?;
            }
            return Err(error);
        }
    }

    build_revision_restore(
        keys,
        guild_id,
        revision,
        &staging,
        &mut load_ciphertext,
        true,
    )?;
    if parent.entry_identity(&job.staging_name, true)? != Some(staged_identity) {
        bail!("restore staging directory changed during construction");
    }
    job.state = RestoreJobState::Publishing;
    bytes = replace_restore_job(control, &record_id, &bytes, &job)?;
    finish_durable_restore_publication(control, &record_id, &bytes, &job, &parent, &target_name)
}

pub(crate) fn resume_restore_publication(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    target: &Path,
) -> Result<bool> {
    validate_restore_revision(keys, guild_id, revision)?;
    let _operation = lock_restore_operations(control)?;
    let (target, target_name, parent) = pinned_restore_parent(target)?;
    let parent_identity = parent.identity()?;
    let Some(ReservedRestoreJob {
        record_id,
        bytes,
        mut job,
    }) = reserved_restore_job(
        control,
        &target,
        &parent,
        guild_id,
        revision.value.revision_id,
    )?
    else {
        return Ok(false);
    };
    validate_reserved_restore_job(
        &job,
        guild_id,
        revision.value.revision_id,
        &target,
        parent_identity,
    )?;
    if job.state != RestoreJobState::Publishing {
        return Ok(false);
    }
    if parent.entry_identity(&job.staging_name, true)?.is_none()
        && parent.entry_identity(&target_name, true)?.is_none()
    {
        job.state = RestoreJobState::Building;
        job.staged_identity = None;
        replace_restore_job(control, &record_id, &bytes, &job)?;
        return Ok(false);
    }
    finish_durable_restore_publication(control, &record_id, &bytes, &job, &parent, &target_name)?;
    Ok(true)
}

fn validate_restore_revision(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<()> {
    revision.verify(USER_REVISION_DOMAIN)?;
    revision.value.verify_writer()?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
        || !matches!(revision.value.format_version, 3..=5)
        || revision.value.cipher_profile != V1_CIPHER_PROFILE
    {
        bail!("revision does not belong to the recovering seed and guild");
    }
    Ok(())
}

fn validate_reserved_restore_job(
    job: &RestoreJob,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target: &Path,
    parent_identity: NativeFileId,
) -> Result<()> {
    if job.guild_id != guild_id
        || job.revision_id != revision_id
        || job.target != target
        || job.parent_identity != parent_identity
    {
        bail!("restore request conflicts with an unfinished durable restore job");
    }
    Ok(())
}

fn lock_restore_operations(control: &ControlStore) -> Result<RestoreOperationGuard> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(control.path())
        .context("open control database for restore serialization")?;
    FileExt::lock_exclusive(&file).context("serialize ordinary restore operations")?;
    Ok(RestoreOperationGuard(file))
}

impl Drop for RestoreOperationGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn replace_restore_job(
    control: &ControlStore,
    record_id: &[u8; 32],
    expected: &[u8],
    replacement: &RestoreJob,
) -> Result<Vec<u8>> {
    let replacement = canonical_bytes(replacement)?;
    control.replace_record_if_value(RESTORE_JOB_KIND, record_id, expected, &replacement)?;
    Ok(replacement)
}

fn restore_job_record_id(target: &Path) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup restore target reservation v1");
    hasher.update(&canonical_bytes(&target)?);
    Ok(*hasher.finalize().as_bytes())
}

fn reserved_restore_job(
    control: &ControlStore,
    target: &Path,
    parent: &PinnedDirectory,
    guild_id: [u8; 32],
    revision_id: Uuid,
) -> Result<Option<ReservedRestoreJob>> {
    let target_record_id = restore_job_record_id(target)?;
    for _ in 0..2 {
        let mut matching = Vec::new();
        for (record_id, bytes) in control.records(RESTORE_JOB_KIND)? {
            let job: RestoreJob = decode_canonical(&bytes)?;
            match job.format_version {
                1 if record_id.as_slice() == job.revision_id.as_bytes() => {}
                2 if record_id.as_slice() == restore_job_record_id(&job.target)? => {}
                _ => bail!("unfinished durable restore job is inconsistent"),
            }
            if job.target == target {
                matching.push((record_id, bytes, job));
            }
        }
        if matching.len() > 1 {
            return reconcile_legacy_restore_jobs(
                control,
                target,
                parent,
                guild_id,
                revision_id,
                target_record_id,
                matching,
            );
        }
        let Some((record_id, bytes, mut job)) = matching.pop() else {
            return Ok(None);
        };
        if job.format_version == 2 {
            return Ok(Some(ReservedRestoreJob {
                record_id: target_record_id,
                bytes,
                job,
            }));
        }

        job.format_version = 2;
        let replacement = canonical_bytes(&job)?;
        match control.move_record_if_value(
            RESTORE_JOB_KIND,
            &record_id,
            &bytes,
            &target_record_id,
            &replacement,
        ) {
            Ok(()) => {
                return Ok(Some(ReservedRestoreJob {
                    record_id: target_record_id,
                    bytes: replacement,
                    job,
                }));
            }
            Err(mb_store::DatabaseError::Conflict) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("unfinished durable restore job changed concurrently")
}

fn reconcile_legacy_restore_jobs(
    control: &ControlStore,
    target: &Path,
    parent: &PinnedDirectory,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target_record_id: [u8; 32],
    matching: Vec<(Vec<u8>, Vec<u8>, RestoreJob)>,
) -> Result<Option<ReservedRestoreJob>> {
    if matching.iter().any(|(_, _, job)| job.format_version != 1) {
        bail!("multiple unfinished durable restore jobs reserve the same target");
    }
    let selected_index = matching
        .iter()
        .position(|(_, _, job)| job.guild_id == guild_id && job.revision_id == revision_id)
        .context("restore request conflicts with multiple legacy jobs for this target")?;
    let parent_identity = parent.identity()?;
    if matching
        .iter()
        .any(|(_, _, job)| job.parent_identity != parent_identity)
    {
        bail!("legacy restore parent directory changed unexpectedly");
    }
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("legacy restore target has no UTF-8 file name")?;
    if let Some(actual_target) = parent.entry_identity(target_name, true)? {
        let owners = matching
            .iter()
            .enumerate()
            .filter(|(_, (_, _, job))| {
                job.state == RestoreJobState::Publishing
                    && job.staged_identity == Some(actual_target)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if owners.as_slice() != [selected_index] {
            bail!("existing restore target belongs to another legacy job or actor");
        }
    }
    let selected_staging = &matching[selected_index].2.staging_name;
    for (index, (_, _, job)) in matching.iter().enumerate() {
        if index == selected_index {
            continue;
        }
        if &job.staging_name == selected_staging {
            bail!("multiple legacy restore jobs share one staging name");
        }
        retire_legacy_restore_staging(parent, job)?;
    }
    let mut selected = matching[selected_index].2.clone();
    selected.format_version = 2;
    let replacement = canonical_bytes(&selected)?;
    let old_records = matching
        .iter()
        .map(|(record_id, bytes, _)| (record_id.clone(), bytes.clone()))
        .collect::<Vec<_>>();
    control.replace_records_with_one(
        RESTORE_JOB_KIND,
        &old_records,
        &target_record_id,
        &replacement,
    )?;
    Ok(Some(ReservedRestoreJob {
        record_id: target_record_id,
        bytes: replacement,
        job: selected,
    }))
}

fn retire_legacy_restore_staging(parent: &PinnedDirectory, job: &RestoreJob) -> Result<()> {
    let Some(actual) = parent.entry_identity(&job.staging_name, true)? else {
        return Ok(());
    };
    match job.staged_identity {
        Some(expected) if expected == actual => {
            parent.remove_child_directory(&job.staging_name, expected)?;
            parent.sync_all()?;
            run_after_legacy_restore_retire_hook()
        }
        Some(_) => bail!("legacy restore staging directory was replaced"),
        None => Ok(()),
    }
}

#[cfg(test)]
fn run_after_legacy_restore_retire_hook() -> Result<()> {
    INTERRUPT_AFTER_LEGACY_RESTORE_RETIRE.with(|interrupt| {
        if interrupt.replace(false) {
            bail!("injected interruption after legacy restore retirement");
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn run_after_legacy_restore_retire_hook() -> Result<()> {
    Ok(())
}

pub(crate) fn build_revision_restore<F>(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    staging: &PinnedDirectory,
    load_ciphertext: &mut F,
    apply_root_metadata: bool,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    revision.verify(USER_REVISION_DOMAIN)?;
    revision.value.verify_writer()?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
        || !matches!(revision.value.format_version, 3..=5)
        || revision.value.cipher_profile != V1_CIPHER_PROFILE
    {
        bail!("revision does not belong to the recovering seed and guild");
    }
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::with_capacity(checked_metadata_length(revision)?);
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(
            &encryption_key,
            reference,
            load_ciphertext,
        )?);
    }
    if private_metadata_format(&metadata_bytes)? == 6 {
        #[cfg(target_os = "linux")]
        return restore_guarded_entries(
            staging,
            &GuardedPrivateMetadataV6::decode(&metadata_bytes)?,
            &encryption_key,
            load_ciphertext,
            apply_root_metadata,
        );
        #[cfg(not(target_os = "linux"))]
        bail!("guarded private metadata cannot be restored on this platform");
    }
    let (metadata, git) = decode_private_metadata_with_git(&metadata_bytes)?;
    restore_entries(
        staging,
        &metadata,
        &encryption_key,
        load_ciphertext,
        apply_root_metadata && git.is_none(),
    )?;
    if let Some(descriptor) = git {
        if descriptor.repository_id != revision.value.protected_root_id {
            bail!("Git backup belongs to another protected root");
        }
        restore_git_backup_at(keys, staging, &descriptor, &encryption_key, load_ciphertext)?;
        if apply_root_metadata {
            set_metadata_durable(
                staging.as_file(),
                metadata.root_mode,
                metadata.root_modified_secs,
                metadata.root_modified_nanos,
            )?;
        } else {
            staging.sync_all()?;
        }
    }
    Ok(())
}

fn restore_git_backup_at<F>(
    keys: &KeyMaterial,
    staging: &PinnedDirectory,
    descriptor: &GitBackupDescriptor,
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    descriptor.validate()?;
    let root = staging.descriptor_path();
    let catalog_key = mb_git::catalog_key(keys, descriptor.repository_id);
    let repository = GitRepository::init(&root, descriptor.repository_id, &catalog_key)?;
    let mut anchors = Vec::with_capacity(descriptor.blobs.len());
    let result = (|| {
        for blob in &descriptor.blobs {
            let temporary_name = format!(".mutualbackup-recovered-blob-{}", Uuid::new_v4());
            let mut file = staging.create_child_file(&temporary_name)?;
            file.set_len(blob.logical_len)?;
            for extent in &blob.data_extents {
                file.seek(SeekFrom::Start(extent.offset))?;
                let mut written = 0_u64;
                for reference in &extent.sectors {
                    let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
                    file.write_all(&plaintext)?;
                    written = written
                        .checked_add(plaintext.len() as u64)
                        .context("Git recovered extent length overflow")?;
                }
                if written != extent.logical_len {
                    bail!("Git recovered extent does not match signed sector lengths");
                }
            }
            file.sync_all()?;
            drop(file);
            let plan = SourceFileCapturePlan::plan_reflink(&root, &temporary_name)?;
            let anchor = plan.capture()?;
            let actual_oid = mb_git::blob_oid_from_anchor(&anchor);
            anchors.push(anchor);
            if actual_oid?.as_bytes() != blob.oid {
                bail!("recovered Git blob bytes do not match their signed object ID");
            }
            staging.remove_child_file(&temporary_name)?;
            staging.sync_all()?;
        }
        repository.import_backup(descriptor, &anchors)?;
        Ok(())
    })();
    if result.is_err() {
        for anchor in &anchors {
            let _ = anchor.remove();
        }
    }
    result
}

fn pinned_restore_parent(target: &Path) -> Result<(PathBuf, String, PinnedDirectory)> {
    let parent_hint = containing_directory(target);
    fs::create_dir_all(parent_hint)?;
    let parent_path = parent_hint.canonicalize()?;
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("restore target needs one UTF-8 file name")?
        .to_owned();
    let relative = Path::new(&target_name);
    if relative.components().count() != 1
        || !matches!(relative.components().next(), Some(Component::Normal(_)))
    {
        bail!("restore target needs one safe file name");
    }
    let parent = PinnedDirectory::open(&parent_path)?;
    Ok((parent_path.join(&target_name), target_name, parent))
}

fn finish_durable_restore_publication(
    control: &ControlStore,
    record_id: &[u8],
    expected_record: &[u8],
    job: &RestoreJob,
    parent: &PinnedDirectory,
    target_name: &str,
) -> Result<()> {
    let expected = job
        .staged_identity
        .context("publishing restore job has no staged directory identity")?;
    publish_owned_restore(parent, &job.staging_name, target_name, expected)?;
    if parent.descriptor_path().canonicalize()? != containing_directory(&job.target) {
        bail!("restore parent directory was renamed during publication");
    }
    match control.delete_record_if_value(RESTORE_JOB_KIND, record_id, expected_record) {
        Ok(()) => {}
        Err(mb_store::DatabaseError::Conflict)
            if control.get_record(RESTORE_JOB_KIND, record_id)?.is_none()
                && parent.entry_identity(target_name, true)? == Some(expected) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(crate) fn publish_owned_restore(
    parent: &PinnedDirectory,
    staging_name: &str,
    target_name: &str,
    expected: NativeFileId,
) -> Result<()> {
    match (
        parent.entry_identity(staging_name, true)?,
        parent.entry_identity(target_name, true)?,
    ) {
        (Some(actual), None) if actual == expected => {
            parent.rename_child_no_replace(staging_name, target_name)?;
            run_after_restore_rename_hook()?;
            if parent.entry_identity(target_name, true)? != Some(expected) {
                bail!("restore target changed during publication");
            }
        }
        (None, Some(actual)) if actual == expected => {}
        (Some(_), None) => bail!("durable restore staging directory was replaced"),
        (None, Some(_)) => bail!("restore target was created by another actor"),
        (Some(_), Some(_)) => bail!("both restore staging and target names exist"),
        (None, None) => bail!("durable restore staging and published target are both missing"),
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(test)]
fn run_after_restore_rename_hook() -> Result<()> {
    AFTER_RESTORE_RENAME.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn interrupt_next_restore_after_rename() {
    AFTER_RESTORE_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| anyhow::bail!("injected parent sync failure")));
    });
}

#[cfg(not(test))]
fn run_after_restore_rename_hook() -> Result<()> {
    Ok(())
}

fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn restore_entries<F>(
    staging: &PinnedDirectory,
    metadata: &PrivateMetadata,
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
    apply_root_metadata: bool,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let mut directory_metadata = BTreeMap::new();
    let mut expected_entries = BTreeMap::<PathBuf, ExpectedRestoreEntry>::new();
    let mut declared_paths = BTreeSet::new();
    let mut restored_links = BTreeMap::<u64, RestoredLink>::new();
    let link_pool_name = loop {
        let candidate = format!(".mutualbackup-restore-links-{}", Uuid::new_v4());
        if !metadata.entries.iter().any(|entry| {
            Path::new(private_entry_path(entry))
                .components()
                .next()
                .is_some_and(|component| component.as_os_str() == candidate.as_str())
        }) {
            break candidate;
        }
    };
    let link_pool = staging.create_child_directory(&link_pool_name)?;
    let link_pool_identity = link_pool.identity()?;
    let mut pooled_links = Vec::new();
    for entry in &metadata.entries {
        match entry {
            PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                ensure_restore_directory(staging, &destination, &mut expected_entries)?;
                directory_metadata.insert(destination, (*mode, *modified_secs, *modified_nanos));
            }
            PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                let (parent, name) =
                    restore_destination(staging, &destination, &mut expected_entries)?;
                let mut file = parent.create_child_file(&name)?;
                let identity = native_id_for_file(staging, &file)?;
                let mut written = 0_u64;
                for reference in sectors {
                    let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
                    file.write_all(&plaintext)?;
                    written += plaintext.len() as u64;
                }
                if written != *logical_len {
                    bail!("restored file length does not match signed metadata");
                }
                set_metadata_durable(&file, *mode, *modified_secs, *modified_nanos)?;
                expected_entries.insert(
                    destination,
                    ExpectedRestoreEntry {
                        directory: false,
                        identity,
                    },
                );
            }
            PrivateEntry::FileV2 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                link_group,
                data_extents,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                let (parent, name) =
                    restore_destination(staging, &destination, &mut expected_entries)?;
                if let Some(existing) = restored_links.get(link_group) {
                    if existing.mode != *mode
                        || existing.logical_len != *logical_len
                        || existing.modified_secs != *modified_secs
                        || existing.modified_nanos != *modified_nanos
                        || existing.data_extents != *data_extents
                    {
                        bail!("hard-linked aliases have inconsistent signed metadata");
                    }
                    link_pool.hard_link_child_from(&existing.pool_name, &parent, &name)?;
                    expected_entries.insert(
                        destination,
                        ExpectedRestoreEntry {
                            directory: false,
                            identity: existing.identity,
                        },
                    );
                } else {
                    let mut file = parent.create_child_file(&name)?;
                    restore_sparse_file(
                        &mut file,
                        *logical_len,
                        data_extents,
                        encryption_key,
                        load_ciphertext,
                    )?;
                    set_metadata_durable(&file, *mode, *modified_secs, *modified_nanos)?;
                    let identity = native_id_for_file(staging, &file)?;
                    let pool_name = link_group.to_string();
                    parent.hard_link_child_from(&name, &link_pool, &pool_name)?;
                    pooled_links.push(pool_name.clone());
                    expected_entries.insert(
                        destination,
                        ExpectedRestoreEntry {
                            directory: false,
                            identity,
                        },
                    );
                    restored_links.insert(
                        *link_group,
                        RestoredLink {
                            pool_name,
                            identity,
                            mode: *mode,
                            logical_len: *logical_len,
                            modified_secs: *modified_secs,
                            modified_nanos: *modified_nanos,
                            data_extents: data_extents.clone(),
                        },
                    );
                }
            }
            PrivateEntry::HardLinkV3 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                link_group,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                let (parent, name) =
                    restore_destination(staging, &destination, &mut expected_entries)?;
                let existing = restored_links
                    .get(link_group)
                    .context("hard-link alias precedes its signed primary file")?;
                if existing.mode != *mode
                    || existing.logical_len != *logical_len
                    || existing.modified_secs != *modified_secs
                    || existing.modified_nanos != *modified_nanos
                {
                    bail!("hard-linked alias has inconsistent signed metadata");
                }
                link_pool.hard_link_child_from(&existing.pool_name, &parent, &name)?;
                expected_entries.insert(
                    destination,
                    ExpectedRestoreEntry {
                        directory: false,
                        identity: existing.identity,
                    },
                );
            }
        }
    }
    for name in pooled_links {
        link_pool.remove_child_file(name)?;
    }
    link_pool.sync_all()?;
    staging.remove_child_directory(&link_pool_name, link_pool_identity)?;

    for (path, expected) in &expected_entries {
        if staging.entry_identity(path, expected.directory)? != Some(expected.identity) {
            bail!(
                "restored entry changed during construction: {}",
                path.display()
            );
        }
    }
    let mut directories = expected_entries
        .iter()
        .filter(|(_, expected)| expected.directory)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        let directory = open_expected_restore_directory(staging, &path, &expected_entries)?;
        if let Some((mode, modified_secs, modified_nanos)) = directory_metadata.remove(&path) {
            set_metadata_durable(directory.as_file(), mode, modified_secs, modified_nanos)?;
        } else {
            directory.sync_all()?;
        }
    }
    if !directory_metadata.is_empty() {
        bail!("restored directory metadata has no matching directory");
    }
    if apply_root_metadata {
        set_metadata_durable(
            staging.as_file(),
            metadata.root_mode,
            metadata.root_modified_secs,
            metadata.root_modified_nanos,
        )?;
    } else {
        staging.sync_all()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_guarded_entries<F>(
    staging: &PinnedDirectory,
    metadata: &GuardedPrivateMetadataV6,
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
    apply_root_metadata: bool,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    metadata.validate()?;
    let mut expected = BTreeMap::<PathBuf, ExpectedRestoreEntry>::new();
    let mut directory_stats = BTreeMap::<PathBuf, GuardedPrivateStatV6>::new();
    let mut links = BTreeMap::<u64, (String, NativeFileId)>::new();
    let link_pool_name = loop {
        let candidate = format!(".mutualbackup-restore-links-{}", Uuid::new_v4());
        if !metadata.entries.iter().any(|entry| {
            let path = match entry {
                GuardedPrivateEntryV6::Directory { path, .. }
                | GuardedPrivateEntryV6::File { path, .. }
                | GuardedPrivateEntryV6::HardLink { path, .. } => path,
            };
            path.split(|byte| *byte == b'/')
                .next()
                .is_some_and(|first| first == candidate.as_bytes())
        }) {
            break candidate;
        }
    };
    let link_pool = staging.create_child_directory(&link_pool_name)?;
    let link_pool_identity = link_pool.identity()?;
    for entry in &metadata.entries {
        match entry {
            GuardedPrivateEntryV6::Directory { path, stat, .. } => {
                let path = PathBuf::from(OsString::from_vec(path.clone()));
                ensure_restore_directory(staging, &path, &mut expected)?;
                directory_stats.insert(path, stat.clone());
            }
            GuardedPrivateEntryV6::File {
                path,
                stat,
                logical_len,
                link_group,
                data_extents,
            } => {
                let path = PathBuf::from(OsString::from_vec(path.clone()));
                let (parent, name) = restore_destination(staging, &path, &mut expected)?;
                let mut file = parent.create_child_file(&name)?;
                restore_sparse_file(
                    &mut file,
                    *logical_len,
                    data_extents,
                    encryption_key,
                    load_ciphertext,
                )?;
                set_guarded_metadata_durable(&file, stat)?;
                let identity = native_id_for_file(staging, &file)?;
                let pool_name = link_group.to_string();
                parent.hard_link_child_from(&name, &link_pool, &pool_name)?;
                links.insert(*link_group, (pool_name, identity));
                expected.insert(
                    path,
                    ExpectedRestoreEntry {
                        directory: false,
                        identity,
                    },
                );
            }
            GuardedPrivateEntryV6::HardLink {
                path, link_group, ..
            } => {
                let path = PathBuf::from(OsString::from_vec(path.clone()));
                let (parent, name) = restore_destination(staging, &path, &mut expected)?;
                let (pool_name, identity) = links
                    .get(link_group)
                    .context("guarded hard-link primary is missing during restore")?;
                link_pool.hard_link_child_from(pool_name, &parent, &name)?;
                expected.insert(
                    path,
                    ExpectedRestoreEntry {
                        directory: false,
                        identity: *identity,
                    },
                );
            }
        }
    }
    for (pool_name, _) in links.values() {
        link_pool.remove_child_file(pool_name)?;
    }
    link_pool.sync_all()?;
    staging.remove_child_directory(&link_pool_name, link_pool_identity)?;

    for (path, entry) in &expected {
        ensure!(
            staging.entry_identity(path, entry.directory)? == Some(entry.identity),
            "guarded restored entry changed during construction: {}",
            path.display()
        );
    }
    let mut directories = expected
        .iter()
        .filter(|(_, entry)| entry.directory)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        let directory = open_expected_restore_directory(staging, &path, &expected)?;
        let stat = directory_stats
            .remove(&path)
            .context("guarded restored directory has no signed metadata")?;
        set_guarded_metadata_durable(directory.as_file(), &stat)?;
    }
    ensure!(
        directory_stats.is_empty(),
        "guarded directory metadata has no restored directory"
    );
    if apply_root_metadata {
        set_guarded_metadata_durable(staging.as_file(), &metadata.root)?;
    } else {
        staging.sync_all()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_guarded_metadata_durable(file: &File, stat: &GuardedPrivateStatV6) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let current = file.metadata()?;
    if current.uid() != stat.uid || current.gid() != stat.gid {
        // SAFETY: the descriptor is an identity-checked restored inode and
        // the signed uid/gid have already passed the private-format decoder.
        if unsafe { libc::fchown(file.as_raw_fd(), stat.uid, stat.gid) } != 0 {
            return Err(std::io::Error::last_os_error()).context("restore guarded owner");
        }
    }
    file.set_permissions(fs::Permissions::from_mode(stat.mode.into()))?;
    let timestamps = [
        libc::timespec {
            tv_sec: stat.atime_secs,
            tv_nsec: i64::from(stat.atime_nanos),
        },
        libc::timespec {
            tv_sec: stat.modified_secs,
            tv_nsec: i64::from(stat.modified_nanos),
        },
    ];
    // SAFETY: both signed nanosecond values are below one billion and the
    // descriptor remains open across the syscall.
    if unsafe { libc::futimens(file.as_raw_fd(), timestamps.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("restore guarded times");
    }
    file.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy)]
struct ExpectedRestoreEntry {
    directory: bool,
    identity: NativeFileId,
}

struct RestoredLink {
    pool_name: String,
    identity: NativeFileId,
    mode: u32,
    logical_len: u64,
    modified_secs: i64,
    modified_nanos: u32,
    data_extents: Vec<PrivateDataExtent>,
}

fn ensure_restore_directory(
    root: &PinnedDirectory,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, ExpectedRestoreEntry>,
) -> Result<PinnedDirectory> {
    let mut current = root.try_clone()?;
    let mut traversed = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("unsafe path in recovered metadata");
        };
        traversed.push(name);
        current = match expected.get(&traversed) {
            Some(entry) if entry.directory => {
                let directory = current
                    .open_child_directory(name)?
                    .context("expected restored directory disappeared")?;
                if directory.identity()? != entry.identity {
                    bail!("restored directory was replaced: {}", traversed.display());
                }
                directory
            }
            Some(_) => bail!("restored path is both a file and directory"),
            None => {
                if current.open_child_directory(name)?.is_some() {
                    bail!("unexpected directory appeared in restore staging");
                }
                let directory = current.create_child_directory(name)?;
                expected.insert(
                    traversed.clone(),
                    ExpectedRestoreEntry {
                        directory: true,
                        identity: directory.identity()?,
                    },
                );
                directory
            }
        };
    }
    Ok(current)
}

fn restore_destination(
    root: &PinnedDirectory,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, ExpectedRestoreEntry>,
) -> Result<(PinnedDirectory, PathBuf)> {
    let name = relative
        .file_name()
        .map(PathBuf::from)
        .context("restored path has no file name")?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let directory = if parent.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        ensure_restore_directory(root, parent, expected)?
    };
    if expected.contains_key(relative) {
        bail!("duplicate path in recovered metadata");
    }
    Ok((directory, name))
}

fn open_expected_restore_directory(
    root: &PinnedDirectory,
    relative: &Path,
    expected: &BTreeMap<PathBuf, ExpectedRestoreEntry>,
) -> Result<PinnedDirectory> {
    let entry = expected
        .get(relative)
        .filter(|entry| entry.directory)
        .context("restored directory is not tracked")?;
    let directory = root.open_descendant_directory(relative)?;
    if directory.identity()? != entry.identity {
        bail!("restored directory was replaced: {}", relative.display());
    }
    Ok(directory)
}

fn native_id_for_file(root: &PinnedDirectory, file: &File) -> Result<NativeFileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok(NativeFileId {
            filesystem_id: root.identity()?.filesystem_id,
            inode: file.metadata()?.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (root, file);
        bail!("native restore identity is not implemented on this platform")
    }
}

fn restore_sparse_file<F>(
    file: &mut File,
    logical_len: u64,
    data_extents: &[PrivateDataExtent],
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    validate_file_extents(
        logical_len,
        data_extents
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)),
    )?;
    file.set_len(logical_len)?;
    for extent in data_extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        let mut written = 0_u64;
        for reference in &extent.sectors {
            let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
            file.write_all(&plaintext)?;
            written = written
                .checked_add(plaintext.len() as u64)
                .context("restored extent length overflow")?;
        }
        if written != extent.logical_len {
            bail!("restored extent length does not match signed metadata");
        }
    }
    file.sync_all()?;
    Ok(())
}

fn decrypt_reference<F>(
    encryption_key: &[u8; 32],
    reference: &SectorRef,
    load_ciphertext: &mut F,
) -> Result<Vec<u8>>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let mut bytes = load_ciphertext(&reference.id)?;
    if bytes.len() != V1_SECTOR_SIZE || sector_root(&bytes) != reference.root {
        bail!("recovered sector failed its signed root");
    }
    crypt_sector(encryption_key, reference.id, &mut bytes)?;
    let logical_len = reference.logical_len as usize;
    if logical_len > bytes.len() {
        bail!("invalid logical sector length");
    }
    bytes.truncate(logical_len);
    Ok(bytes)
}

fn safe_relative_path(relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe path in recovered metadata");
    }
    Ok(relative.to_path_buf())
}

fn set_metadata_durable(
    file: &File,
    mode: u32,
    modified_secs: i64,
    modified_nanos: u32,
) -> Result<()> {
    if modified_nanos >= 1_000_000_000 {
        bail!("invalid modification timestamp");
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(mode))?;
        let timestamps = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: modified_secs,
                tv_nsec: i64::from(modified_nanos),
            },
        ];
        if unsafe { libc::futimens(file.as_raw_fd(), timestamps.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(unix))]
    let _ = (mode, modified_secs, modified_nanos);
    file.sync_all()?;
    Ok(())
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod metadata_compatibility_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn guarded_private_metadata_restores_raw_paths_sparse_bytes_and_hard_links() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::MetadataExt;

        let temporary = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-restore-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root_path = temporary.path().join("restored");
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([219; 32]));
        let guild_id = [220; 32];
        let mut control = ControlStore::open(temporary.path().join("control.db"), &keys).unwrap();
        let revision_id = Uuid::new_v4();
        let encryption_key = keys.guild_data_key(&guild_id);
        let data_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, 0);
        let (data_ref, data_ciphertext) =
            encrypted_sector(&encryption_key, data_id, b"raw").unwrap();
        let owner = unsafe { libc::geteuid() };
        let group = unsafe { libc::getegid() };
        let stat = |mode| GuardedPrivateStatV6 {
            mode,
            uid: owner,
            gid: group,
            atime_secs: 1_700_000_000,
            atime_nanos: 123,
            modified_secs: 1_700_000_001,
            modified_nanos: 456,
        };
        let metadata = GuardedPrivateMetadataV6 {
            format_version: 6,
            root: stat(0o750),
            entries: vec![
                GuardedPrivateEntryV6::Directory {
                    path: b"nested".to_vec(),
                    stat: stat(0o700),
                    logical_len: 4096,
                },
                GuardedPrivateEntryV6::File {
                    path: b"nested/\xfe".to_vec(),
                    stat: stat(0o640),
                    logical_len: 1024,
                    link_group: 0,
                    data_extents: vec![PrivateDataExtent {
                        offset: 1000,
                        logical_len: 3,
                        sectors: vec![data_ref.clone()],
                    }],
                },
                GuardedPrivateEntryV6::HardLink {
                    path: b"nested/\xff".to_vec(),
                    stat: stat(0o640),
                    logical_len: 1024,
                    link_group: 0,
                },
            ],
        };
        metadata.validate().unwrap();
        let metadata_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Metadata, 0);
        let metadata_bytes = canonical_bytes(&metadata).unwrap();
        let (metadata_ref, metadata_ciphertext) =
            encrypted_sector(&encryption_key, metadata_id, &metadata_bytes).unwrap();
        let ciphertexts = BTreeMap::from([
            (data_id, data_ciphertext.clone()),
            (metadata_id, metadata_ciphertext.clone()),
        ]);
        let writer = SigningKey::from_bytes(&[221; 32]);
        let mut revision = UserRevision {
            format_version: 5,
            guild_id,
            protected_root_id: Uuid::new_v4(),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![metadata_ref.clone()],
            data_sectors: vec![data_ref],
            sector_commitments: Some(vec![
                merkle_commit(&metadata_ciphertext).unwrap(),
                merkle_commit(&data_ciphertext).unwrap(),
            ]),
        };
        revision.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, &keys).unwrap();
        restore_revision(
            &control,
            &keys,
            guild_id,
            &revision,
            &ciphertexts,
            &root_path,
        )
        .unwrap();
        let root = PinnedDirectory::open(&root_path).unwrap();

        let first = root_path.join(OsString::from_vec(b"nested/\xfe".to_vec()));
        let second = root_path.join(OsString::from_vec(b"nested/\xff".to_vec()));
        let first_stat = fs::metadata(&first).unwrap();
        let second_stat = fs::metadata(&second).unwrap();
        assert_eq!(first_stat.ino(), second_stat.ino());
        assert_eq!(first_stat.len(), 1024);
        assert_eq!(first_stat.uid(), owner);
        assert_eq!(first_stat.gid(), group);
        assert_eq!(first_stat.mode() & 0o7777, 0o640);
        assert_eq!(first_stat.mtime(), 1_700_000_001);
        assert_eq!(first_stat.mtime_nsec(), 456);
        assert_eq!(first_stat.atime(), 1_700_000_000);
        assert_eq!(first_stat.atime_nsec(), 123);
        assert_eq!(fs::read(&first).unwrap()[1000..1003], *b"raw");
        assert_eq!(fs::read(&second).unwrap(), fs::read(&first).unwrap());
        let root_stat = fs::metadata(&root_path).unwrap();
        assert_eq!(root_stat.mode() & 0o7777, 0o750);
        assert_eq!(root_stat.mtime(), 1_700_000_001);
        assert_eq!(root_stat.mtime_nsec(), 456);
        install_inline_recipe(&mut control, guild_id, metadata_ref, metadata_bytes).unwrap();
        assert!(
            revision_git_backup(&control, &keys, guild_id, &revision)
                .unwrap()
                .is_none()
        );
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        restore_signed_root_metadata_at(&control, &keys, guild_id, &revision, &root).unwrap();
        let root_stat = fs::metadata(&root_path).unwrap();
        assert_eq!(root_stat.mode() & 0o7777, 0o750);
        assert_eq!(root_stat.atime(), 1_700_000_000);
        assert_eq!(root_stat.atime_nsec(), 123);
        if std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").is_some() {
            let mut plaintext = vec![0_u8; 1024];
            plaintext[1000..1003].copy_from_slice(b"raw");
            let data_reference = revision.value.data_sectors[0].clone();
            install_inline_recipe(&mut control, guild_id, data_reference.clone(), plaintext)
                .unwrap();
            control
                .put_record(
                    "user-revision",
                    revision_id.as_bytes(),
                    &canonical_bytes(&revision).unwrap(),
                )
                .unwrap();
            INTERRUPT_GUARDED_RECOVERY_AFTER_CAPTURE.with(|interrupt| interrupt.set(true));
            assert!(
                reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &root_path)
                    .is_err()
            );
            assert!(
                control
                    .get_record(GUARDED_RECOVERY_INTENT_KIND, revision_id.as_bytes())
                    .unwrap()
                    .is_some()
            );
            drop(control);
            let mut control =
                ControlStore::open(temporary.path().join("control.db"), &keys).unwrap();
            reconcile_pending_captures(&control).unwrap();
            reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &root_path)
                .unwrap();
            assert!(
                recovered_recipe_is_stable(&control, &keys, guild_id, &data_reference).unwrap()
            );
            let mut captured: GuardedRecoveredCaptureV1 = decode_canonical(
                &control
                    .get_record(GUARDED_RECOVERY_CAPTURE_KIND, revision_id.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(captured.files.len(), 1);
            assert_eq!(captured.files[0].path, b"nested/\xfe");
            assert_eq!(
                captured.files[0]
                    .anchor
                    .open_verified()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .len(),
                1024
            );
            reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &root_path)
                .unwrap();
            let replacement = GuardedRecoveryIntentV1 {
                format_version: 1,
                guild_id,
                revision_id,
                source_root: root_path.canonicalize().unwrap(),
                metadata_hash: *blake3::hash(&canonical_bytes(&metadata).unwrap()).as_bytes(),
                files: vec![GuardedRecoveredFilePlanV1 {
                    path: b"nested/\xfe".to_vec(),
                    plan: SourceFileCapturePlan::plan_reflink_raw(
                        &root_path,
                        PathBuf::from(OsString::from_vec(b"nested/\xfe".to_vec())),
                    )
                    .unwrap(),
                }],
                replaced: Some(captured.clone()),
            };
            control
                .put_record(
                    GUARDED_RECOVERY_INTENT_KIND,
                    revision_id.as_bytes(),
                    &canonical_bytes(&replacement).unwrap(),
                )
                .unwrap();
            reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &root_path)
                .unwrap();
            assert!(
                control
                    .get_record(GUARDED_RECOVERY_INTENT_KIND, revision_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            let replacement_capture: GuardedRecoveredCaptureV1 = decode_canonical(
                &control
                    .get_record(GUARDED_RECOVERY_CAPTURE_KIND, revision_id.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_ne!(
                replacement_capture.files[0].anchor.anchor_id,
                captured.files[0].anchor.anchor_id
            );
            assert!(captured.files[0].anchor.open_verified().is_err());
            captured = replacement_capture;
            assert!(!retire_revision_anchor(&mut control, revision_id).unwrap());
            control
                .delete_record("user-revision", revision_id.as_bytes())
                .unwrap();
            assert!(!retire_revision_anchor(&mut control, revision_id).unwrap());
            control
                .delete_record("local-sector", &data_reference.id)
                .unwrap();
            assert!(retire_revision_anchor(&mut control, revision_id).unwrap());
            assert!(captured.files[0].anchor.open_verified().is_err());
        }
    }

    #[test]
    fn git_prune_pins_exact_anchor_used_by_a_local_sector_recipe() {
        let temporary = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(temporary.path().join("control.db"), &[42; 32]).unwrap();
        let anchor_id = Uuid::new_v4();
        let reference = SectorRef {
            id: [43; 32],
            root: [44; 32],
            logical_len: 1,
        };
        let recipe = LocalSectorRecipe {
            guild_id: [45; 32],
            reference: reference.clone(),
            source: LocalPlaintextSource::StableAnchorFile {
                locator: StableAnchorFileLocator {
                    area: mb_store::StableAnchorAreaLocator {
                        area_id: Uuid::new_v4(),
                        path_hint: temporary.path().to_path_buf(),
                        filesystem_id: 1,
                        volume_root_hint: temporary.path().to_path_buf(),
                    },
                    anchor_id,
                    relative_path: "payload".to_owned(),
                },
                offset: 0,
            },
        };
        control
            .put_record(
                "local-sector",
                &reference.id,
                &canonical_bytes(&recipe).unwrap(),
            )
            .unwrap();
        assert_eq!(
            git_prune_recipe_anchor_ids(&control).unwrap(),
            BTreeSet::from([anchor_id])
        );
        control
            .delete_record("local-sector", &reference.id)
            .unwrap();
        assert!(git_prune_recipe_anchor_ids(&control).unwrap().is_empty());
        control
            .put_record(
                "local-sector",
                &[46; 32],
                &canonical_bytes(&recipe).unwrap(),
            )
            .unwrap();
        assert!(git_prune_recipe_anchor_ids(&control).is_err());
    }

    #[test]
    fn historical_git_graph_intent_migrates_with_main_head() {
        let repository_id = Uuid::new_v4();
        let legacy = LegacyGitGraphIntentV1 {
            format_version: 1,
            guild_id: [17; 32],
            revision_id: Uuid::new_v4(),
            protected_root_id: repository_id,
            graph: GitGraphSource {
                format_version: 1,
                repository_id,
                refs: Vec::new(),
                objects: Vec::new(),
                blobs: Vec::new(),
            },
        };
        let (current, migrated) =
            decode_git_graph_intent(&canonical_bytes(&legacy).unwrap()).unwrap();
        assert!(migrated);
        assert_eq!(current.format_version, 2);
        assert_eq!(current.head_branch, "main");
        let (reopened, migrated) =
            decode_git_graph_intent(&canonical_bytes(&current).unwrap()).unwrap();
        assert!(!migrated);
        assert_eq!(reopened, current);
        let mut invalid = current;
        invalid.head_branch = "missing".to_owned();
        assert!(decode_git_graph_intent(&canonical_bytes(&invalid).unwrap()).is_err());
    }

    #[test]
    fn unborn_head_with_fetched_refs_uses_recoverable_git_descriptor() {
        let temporary = tempfile::tempdir().unwrap();
        let repository = git2::Repository::init_bare(temporary.path()).unwrap();
        let tree_oid = repository.treebuilder(None).unwrap().write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("Stock", "stock@example.test").unwrap();
        let commit_oid = repository
            .commit(None, &signature, &signature, "base", &tree, &[])
            .unwrap();
        let commit = repository
            .find_object(commit_oid, Some(git2::ObjectType::Commit))
            .unwrap();
        let tag_oid = repository
            .tag_annotation_create("release", &commit, &signature, "release")
            .unwrap();
        let odb = repository.odb().unwrap();
        let object = |kind, oid: git2::Oid| GitGraphObject {
            kind,
            oid: oid.as_bytes().try_into().unwrap(),
            bytes: odb.read(oid).unwrap().data().to_vec(),
        };
        let repository_id = Uuid::new_v4();
        let graph = GitGraphSource {
            format_version: 2,
            repository_id,
            refs: vec![
                GitGraphRef {
                    name: b"refs/remotes/origin/main".to_vec(),
                    oid: commit_oid.as_bytes().try_into().unwrap(),
                },
                GitGraphRef {
                    name: b"refs/tags/release".to_vec(),
                    oid: tag_oid.as_bytes().try_into().unwrap(),
                },
            ],
            objects: vec![
                object(1, commit_oid),
                object(2, tree_oid),
                object(3, tag_oid),
            ],
            blobs: Vec::new(),
        };
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([207; 32]));
        let descriptor = prepare_git_backup_descriptor(
            &mut Vec::new(),
            &mut Vec::new(),
            &keys,
            [31; 32],
            repository_id,
            &[33; 32],
            &mut 0,
            &mut BTreeMap::new(),
            GitGraphIntent {
                format_version: 2,
                guild_id: [31; 32],
                revision_id: Uuid::new_v4(),
                protected_root_id: repository_id,
                graph,
                head_branch: "main".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(descriptor.format_version, 4);
        assert!(
            descriptor
                .refs
                .iter()
                .all(|reference| reference.name.as_slice() != b"refs/heads/main")
        );
        let encoded = canonical_bytes(&GitPrivateMetadataV5 {
            format_version: 5,
            root_mode: 0o755,
            root_modified_secs: 0,
            root_modified_nanos: 0,
            entries: Vec::new(),
            git: descriptor.clone(),
        })
        .unwrap();
        let (_, recovered) = decode_private_metadata_with_git(&encoded).unwrap();
        assert_eq!(recovered, Some(descriptor));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn git_backup_rejects_blob_id_that_disagrees_with_replayed_anchor() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        let anchor = mb_store::SourceBlobImportPlan::plan_direct(&source, 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"other"))
            .unwrap();
        let repository = git2::Repository::init_bare(temporary.path().join("git")).unwrap();
        let blob_oid = repository.blob(b"hello").unwrap();
        let mut builder = repository.treebuilder(None).unwrap();
        builder.insert("file", blob_oid, 0o100644).unwrap();
        let tree_oid = builder.write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("Author", "a@example.test").unwrap();
        let commit_oid = repository
            .commit(None, &signature, &signature, "file", &tree, &[])
            .unwrap();
        let odb = repository.odb().unwrap();
        let object = |kind, oid: git2::Oid| GitGraphObject {
            kind,
            oid: oid.as_bytes().try_into().unwrap(),
            bytes: odb.read(oid).unwrap().data().to_vec(),
        };
        let repository_id = Uuid::new_v4();
        let graph = GitGraphSource {
            format_version: 1,
            repository_id,
            refs: vec![GitGraphRef {
                name: b"refs/heads/main".to_vec(),
                oid: commit_oid.as_bytes().try_into().unwrap(),
            }],
            objects: vec![object(1, commit_oid), object(2, tree_oid)],
            blobs: vec![mb_git::GitGraphBlobSource {
                oid: blob_oid.as_bytes().try_into().unwrap(),
                anchor,
            }],
        };
        let mut recipes = Vec::new();
        let mut data_references = Vec::new();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([213; 32]));
        let mut matching_graph = graph.clone();
        assert!(
            prepare_git_backup_descriptor(
                &mut recipes,
                &mut data_references,
                &keys,
                [31; 32],
                repository_id,
                &[33; 32],
                &mut 0,
                &mut BTreeMap::new(),
                GitGraphIntent {
                    format_version: 2,
                    guild_id: [31; 32],
                    revision_id: Uuid::new_v4(),
                    protected_root_id: repository_id,
                    graph,
                    head_branch: "main".to_owned(),
                },
            )
            .is_err()
        );
        assert!(recipes.is_empty());
        assert!(data_references.is_empty());

        matching_graph.blobs[0].anchor = mb_store::SourceBlobImportPlan::plan_direct(&source, 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"hello"))
            .unwrap();
        let descriptor = prepare_git_backup_descriptor(
            &mut recipes,
            &mut data_references,
            &keys,
            [31; 32],
            repository_id,
            &[33; 32],
            &mut 0,
            &mut BTreeMap::new(),
            GitGraphIntent {
                format_version: 2,
                guild_id: [31; 32],
                revision_id: Uuid::new_v4(),
                protected_root_id: repository_id,
                graph: matching_graph,
                head_branch: "main".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(descriptor.blobs[0].oid, blob_oid.as_bytes());
        assert_eq!(recipes.len(), 1);
        assert_eq!(data_references.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn git_backup_rejects_nul_symlink_with_matching_blob_id() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        let anchor = mb_store::SourceBlobImportPlan::plan_direct(&source, 1)
            .unwrap()
            .capture(std::io::Cursor::new([0]))
            .unwrap();
        let repository = git2::Repository::init_bare(temporary.path().join("git")).unwrap();
        let blob_oid = repository.blob(&[0]).unwrap();
        let mut builder = repository.treebuilder(None).unwrap();
        builder.insert("link", blob_oid, 0o120000).unwrap();
        let tree_oid = builder.write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("Author", "a@example.test").unwrap();
        let commit_oid = repository
            .commit(None, &signature, &signature, "link", &tree, &[])
            .unwrap();
        let odb = repository.odb().unwrap();
        let object = |kind, oid: git2::Oid| GitGraphObject {
            kind,
            oid: oid.as_bytes().try_into().unwrap(),
            bytes: odb.read(oid).unwrap().data().to_vec(),
        };
        let repository_id = Uuid::new_v4();
        let graph = GitGraphSource {
            format_version: 1,
            repository_id,
            refs: vec![GitGraphRef {
                name: b"refs/heads/main".to_vec(),
                oid: commit_oid.as_bytes().try_into().unwrap(),
            }],
            objects: vec![object(1, commit_oid), object(2, tree_oid)],
            blobs: vec![mb_git::GitGraphBlobSource {
                oid: blob_oid.as_bytes().try_into().unwrap(),
                anchor,
            }],
        };
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([214; 32]));
        assert!(
            prepare_git_backup_descriptor(
                &mut Vec::new(),
                &mut Vec::new(),
                &keys,
                [31; 32],
                repository_id,
                &[33; 32],
                &mut 0,
                &mut BTreeMap::new(),
                GitGraphIntent {
                    format_version: 2,
                    guild_id: [31; 32],
                    revision_id: Uuid::new_v4(),
                    protected_root_id: repository_id,
                    graph,
                    head_branch: "main".to_owned(),
                },
            )
            .is_err()
        );
    }

    fn restore_fixture(
        keys: &KeyMaterial,
        guild_id: [u8; 32],
        entries: Vec<PrivateEntry>,
        data: Vec<(u64, Vec<u8>)>,
    ) -> (SignedRecord<UserRevision>, BTreeMap<SectorId, Vec<u8>>) {
        let revision_id = Uuid::new_v4();
        let encryption_key = keys.guild_data_key(&guild_id);
        let mut ciphertexts = BTreeMap::new();
        let mut data_sectors = Vec::new();
        for (ordinal, plaintext) in data {
            let id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, ordinal);
            let (reference, ciphertext) =
                encrypted_sector(&encryption_key, id, &plaintext).unwrap();
            data_sectors.push(reference);
            ciphertexts.insert(id, ciphertext);
        }
        let metadata = PrivateMetadata {
            format_version: 3,
            root_mode: 0o755,
            root_modified_secs: 1_700_000_000,
            root_modified_nanos: 123,
            entries,
        };
        let encoded = canonical_bytes(&metadata).unwrap();
        let mut metadata_sectors = Vec::new();
        for (ordinal, plaintext) in encoded.chunks(V1_SECTOR_SIZE).enumerate() {
            let id = make_sector_id(
                keys.node_id(),
                revision_id,
                SectorPurpose::Metadata,
                ordinal as u64,
            );
            let (reference, ciphertext) = encrypted_sector(&encryption_key, id, plaintext).unwrap();
            metadata_sectors.push(reference);
            ciphertexts.insert(id, ciphertext);
        }
        let writer = SigningKey::from_bytes(&[75; 32]);
        let mut revision_body = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors,
            data_sectors,
            sector_commitments: None,
        };
        revision_body.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision_body, keys).unwrap();
        (revision, ciphertexts)
    }

    fn current_restore_job_record_id(target: &Path) -> [u8; 32] {
        let parent = containing_directory(target).canonicalize().unwrap();
        restore_job_record_id(&parent.join(target.file_name().unwrap())).unwrap()
    }

    #[test]
    fn ordinary_restore_resumes_after_rename_before_parent_sync() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([201; 32]));
        let guild_id = [202; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");

        AFTER_RESTORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| anyhow::bail!("injected parent sync failure")));
        });
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert!(target.is_dir());
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_some()
        );

        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ordinary_restore_resumes_from_publishing_before_rename() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([220; 32]));
        let guild_id = [221; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let staging_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let staging = parent.create_child_directory(&staging_name).unwrap();
        parent.sync_all().unwrap();
        let job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: revision.value.revision_id,
            target: temp.path().canonicalize().unwrap().join("restored"),
            parent_identity: parent.identity().unwrap(),
            staging_name,
            staged_identity: Some(staging.identity().unwrap()),
            state: RestoreJobState::Publishing,
        };
        control
            .put_record(
                RESTORE_JOB_KIND,
                revision.value.revision_id.as_bytes(),
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();

        let target = temp.path().join("restored");
        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();
        assert!(target.is_dir());
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ordinary_restore_rebuilds_a_durably_owned_partial_tree() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([222; 32]));
        let guild_id = [223; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &revision,
                &target,
                |_| anyhow::bail!("injected sector read failure"),
            )
            .is_err()
        );
        let bytes = control
            .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
            .unwrap()
            .unwrap();
        let interrupted: RestoreJob = decode_canonical(&bytes).unwrap();
        assert_eq!(interrupted.state, RestoreJobState::Building);
        assert!(temp.path().join(&interrupted.staging_name).is_dir());

        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();
        assert!(target.is_dir());
        assert!(!temp.path().join(interrupted.staging_name).exists());
    }

    #[test]
    fn ordinary_restore_reserves_a_target_across_revisions() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([224; 32]));
        let guild_id = [225; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (first, first_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (second, second_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &first,
                &target,
                |_| anyhow::bail!("injected first restore interruption"),
            )
            .is_err()
        );
        let error = restore_revision(
            &control,
            &keys,
            guild_id,
            &second,
            &second_ciphertexts,
            &target,
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts with an unfinished"));

        restore_revision(
            &control,
            &keys,
            guild_id,
            &first,
            &first_ciphertexts,
            &target,
        )
        .unwrap();
        assert!(target.is_dir());
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn concurrent_ordinary_restores_cannot_share_a_target() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([226; 32]));
        let guild_id = [227; 32];
        let database = temp.path().join("control.db");
        let first_control = ControlStore::open(&database, &keys).unwrap();
        let second_control = ControlStore::open(&database, &keys).unwrap();
        let (first, _) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (second, _) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let barrier = Arc::new(Barrier::new(2));

        let run = |control: ControlStore,
                   revision: SignedRecord<UserRevision>,
                   barrier: Arc<Barrier>| {
            let target = target.clone();
            std::thread::spawn(move || {
                let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([226; 32]));
                barrier.wait();
                restore_revision_from_source(&control, &keys, guild_id, &revision, &target, |_| {
                    anyhow::bail!("injected winning restore interruption")
                })
                .unwrap_err()
                .to_string()
            })
        };
        let first_thread = run(first_control, first, barrier.clone());
        let second_thread = run(second_control, second, barrier);
        let errors = [first_thread.join().unwrap(), second_thread.join().unwrap()];

        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("injected winning restore interruption"))
                .count(),
            1
        );
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("conflicts with an unfinished"))
                .count(),
            1
        );
        let control = ControlStore::open(&database, &keys).unwrap();
        assert_eq!(control.records(RESTORE_JOB_KIND).unwrap().len(), 1);
    }

    #[test]
    fn completed_restore_cannot_be_followed_by_a_late_reservation() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([231; 32]));
        let guild_id = [232; 32];
        let database = temp.path().join("control.db");
        let first_control = ControlStore::open(&database, &keys).unwrap();
        let second_control = ControlStore::open(&database, &keys).unwrap();
        let (first, first_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (second, second_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let barrier = Arc::new(Barrier::new(2));

        let run = |control: ControlStore,
                   revision: SignedRecord<UserRevision>,
                   ciphertexts: BTreeMap<SectorId, Vec<u8>>,
                   barrier: Arc<Barrier>| {
            let target = target.clone();
            std::thread::spawn(move || {
                let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([231; 32]));
                barrier.wait();
                restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target)
            })
        };
        let first_thread = run(first_control, first, first_ciphertexts, barrier.clone());
        let second_thread = run(second_control, second, second_ciphertexts, barrier);
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let control = ControlStore::open(&database, &keys).unwrap();
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
        assert!(target.is_dir());
        assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".mutualbackup-restore-")
        }));
    }

    #[test]
    fn same_revision_restore_callers_cannot_recreate_a_published_job() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([233; 32]));
        let guild_id = [234; 32];
        let database = temp.path().join("control.db");
        let first_control = ControlStore::open(&database, &keys).unwrap();
        let second_control = ControlStore::open(&database, &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let barrier = Arc::new(Barrier::new(2));

        let run = |control: ControlStore, barrier: Arc<Barrier>| {
            let target = target.clone();
            let revision = revision.clone();
            let ciphertexts = ciphertexts.clone();
            std::thread::spawn(move || {
                let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([233; 32]));
                barrier.wait();
                restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target)
            })
        };
        let first_thread = run(first_control, barrier.clone());
        let second_thread = run(second_control, barrier);
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let control = ControlStore::open(&database, &keys).unwrap();
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
        assert!(target.is_dir());
    }

    #[test]
    fn multiple_legacy_restore_jobs_are_reconciled_without_unbound_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([235; 32]));
        let guild_id = [236; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (selected_revision, ciphertexts) =
            restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (retired_revision, _) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let selected_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let retired_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let selected_staging = parent.create_child_directory(&selected_name).unwrap();
        let retired_staging = parent.create_child_directory(&retired_name).unwrap();
        fs::write(
            temp.path().join(&retired_name).join("must-survive"),
            b"unbound staging",
        )
        .unwrap();
        parent.sync_all().unwrap();
        let canonical_target = temp.path().canonicalize().unwrap().join("restored");
        let selected_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: selected_revision.value.revision_id,
            target: canonical_target.clone(),
            parent_identity: parent.identity().unwrap(),
            staging_name: selected_name.clone(),
            staged_identity: Some(selected_staging.identity().unwrap()),
            state: RestoreJobState::Building,
        };
        let retired_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: retired_revision.value.revision_id,
            target: canonical_target,
            parent_identity: parent.identity().unwrap(),
            staging_name: retired_name.clone(),
            staged_identity: None,
            state: RestoreJobState::Building,
        };
        drop(retired_staging);
        control
            .put_record(
                RESTORE_JOB_KIND,
                selected_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&selected_job).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                RESTORE_JOB_KIND,
                retired_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&retired_job).unwrap(),
            )
            .unwrap();

        restore_revision(
            &control,
            &keys,
            guild_id,
            &selected_revision,
            &ciphertexts,
            &target,
        )
        .unwrap();

        assert!(target.is_dir());
        assert!(!temp.path().join(selected_name).exists());
        assert_eq!(
            fs::read(temp.path().join(retired_name).join("must-survive")).unwrap(),
            b"unbound staging"
        );
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn retired_legacy_publishing_job_rebuilds_after_reconciliation_crash() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([239; 32]));
        let guild_id = [240; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (first_revision, first_ciphertexts) =
            restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (retired_revision, retired_ciphertexts) =
            restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let first_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let retired_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let first_staging = parent.create_child_directory(&first_name).unwrap();
        let retired_staging = parent.create_child_directory(&retired_name).unwrap();
        parent.sync_all().unwrap();
        let canonical_target = temp.path().canonicalize().unwrap().join("restored");
        let first_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: first_revision.value.revision_id,
            target: canonical_target.clone(),
            parent_identity: parent.identity().unwrap(),
            staging_name: first_name.clone(),
            staged_identity: Some(first_staging.identity().unwrap()),
            state: RestoreJobState::Building,
        };
        let retired_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: retired_revision.value.revision_id,
            target: canonical_target,
            parent_identity: parent.identity().unwrap(),
            staging_name: retired_name.clone(),
            staged_identity: Some(retired_staging.identity().unwrap()),
            state: RestoreJobState::Publishing,
        };
        control
            .put_record(
                RESTORE_JOB_KIND,
                first_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&first_job).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                RESTORE_JOB_KIND,
                retired_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&retired_job).unwrap(),
            )
            .unwrap();

        INTERRUPT_AFTER_LEGACY_RESTORE_RETIRE.with(|interrupt| interrupt.set(true));
        assert!(
            restore_revision(
                &control,
                &keys,
                guild_id,
                &first_revision,
                &first_ciphertexts,
                &target,
            )
            .is_err()
        );
        assert!(!temp.path().join(&retired_name).exists());
        assert_eq!(control.records(RESTORE_JOB_KIND).unwrap().len(), 2);
        let resumed =
            resume_restore_publication(&control, &keys, guild_id, &retired_revision, &target)
                .unwrap();
        assert!(!resumed);

        restore_revision(
            &control,
            &keys,
            guild_id,
            &retired_revision,
            &retired_ciphertexts,
            &target,
        )
        .unwrap();

        assert!(target.is_dir());
        assert!(!temp.path().join(first_name).exists());
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn ordinary_restore_never_deletes_an_unbound_staging_name() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([237; 32]));
        let guild_id = [238; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let unbound_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        fs::create_dir(temp.path().join(&unbound_name)).unwrap();
        fs::write(
            temp.path().join(&unbound_name).join("must-survive"),
            b"unverified directory",
        )
        .unwrap();
        let canonical_target = temp.path().canonicalize().unwrap().join("restored");
        let job = RestoreJob {
            format_version: 2,
            guild_id,
            revision_id: revision.value.revision_id,
            target: canonical_target.clone(),
            parent_identity: parent.identity().unwrap(),
            staging_name: unbound_name.clone(),
            staged_identity: None,
            state: RestoreJobState::Building,
        };
        control
            .put_record(
                RESTORE_JOB_KIND,
                &restore_job_record_id(&canonical_target).unwrap(),
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();

        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();

        assert!(target.is_dir());
        assert_eq!(
            fs::read(temp.path().join(unbound_name).join("must-survive")).unwrap(),
            b"unverified directory"
        );
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn ordinary_restore_keeps_renamed_parent_obligation() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let moved = temp.path().join("moved-parent");
        fs::create_dir(&parent).unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([203; 32]));
        let guild_id = [204; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = parent.join("restored");
        let parent_for_hook = parent.clone();
        let moved_for_hook = moved.clone();

        AFTER_RESTORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::rename(&parent_for_hook, &moved_for_hook)?;
                fs::create_dir(&parent_for_hook)?;
                fs::write(parent_for_hook.join("foreign"), b"must survive")?;
                Ok(())
            }));
        });
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert!(moved.join("restored").is_dir());
        assert_eq!(fs::read(parent.join("foreign")).unwrap(), b"must survive");
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_some()
        );
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert_eq!(fs::read(parent.join("foreign")).unwrap(), b"must survive");
    }

    #[test]
    fn ordinary_restore_keeps_obligation_when_target_is_replaced_after_rename() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([209; 32]));
        let guild_id = [210; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let moved = temp.path().join("moved-restored");
        let target_for_hook = target.clone();
        let moved_for_hook = moved.clone();

        AFTER_RESTORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::rename(&target_for_hook, &moved_for_hook)?;
                fs::create_dir(&target_for_hook)?;
                fs::write(target_for_hook.join("foreign"), b"must survive")?;
                Ok(())
            }));
        });
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert!(moved.is_dir());
        assert_eq!(fs::read(target.join("foreign")).unwrap(), b"must survive");
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_restore_rejects_staging_root_replacement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"must survive").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([205; 32]));
        let guild_id = [206; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let mut replaced = false;

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &revision,
                &target,
                |sector_id| {
                    if !replaced {
                        let bytes = control
                            .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))?
                            .context("restore job missing")?;
                        let job: RestoreJob = decode_canonical(&bytes)?;
                        let moved = temp.path().join("moved-staging");
                        fs::rename(temp.path().join(&job.staging_name), &moved)?;
                        symlink(&external, temp.path().join(&job.staging_name))?;
                        replaced = true;
                    }
                    ciphertexts
                        .get(sector_id)
                        .cloned()
                        .context("missing fixture sector")
                },
            )
            .is_err()
        );
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"must survive"
        );
        assert!(!target.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_restore_rejects_descendant_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"must survive").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([207; 32]));
        let guild_id = [208; 32];
        let revision_id = Uuid::new_v4();
        let data_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, 0);
        let plaintext = b"payload".to_vec();
        let (data_reference, data_ciphertext) =
            encrypted_sector(&keys.guild_data_key(&guild_id), data_id, &plaintext).unwrap();
        let entries = vec![
            PrivateEntry::Directory {
                path: "nested".into(),
                mode: 0o755,
                modified_secs: 1,
                modified_nanos: 0,
            },
            PrivateEntry::File {
                path: "nested/payload".into(),
                mode: 0o644,
                logical_len: plaintext.len() as u64,
                modified_secs: 1,
                modified_nanos: 0,
                sectors: vec![data_reference.clone()],
            },
        ];
        let (mut revision, mut ciphertexts) = restore_fixture(&keys, guild_id, entries, Vec::new());
        revision.value.revision_id = revision_id;
        revision.value.data_sectors = vec![data_reference];
        revision
            .value
            .sign_writer(&SigningKey::from_bytes(&[75; 32]))
            .unwrap();
        revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision.value, &keys).unwrap();
        ciphertexts.insert(data_id, data_ciphertext);
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let target = temp.path().join("restored");
        let mut replaced = false;

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &revision,
                &target,
                |sector_id| {
                    if *sector_id == data_id && !replaced {
                        let bytes = control
                            .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))?
                            .context("restore job missing")?;
                        let job: RestoreJob = decode_canonical(&bytes)?;
                        let staging = temp.path().join(&job.staging_name);
                        fs::rename(staging.join("nested"), staging.join("moved-nested"))?;
                        symlink(&external, staging.join("nested"))?;
                        replaced = true;
                    }
                    ciphertexts
                        .get(sector_id)
                        .cloned()
                        .context("missing fixture sector")
                },
            )
            .is_err()
        );
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"must survive"
        );
        assert!(!target.exists());
    }

    #[cfg(target_os = "linux")]
    fn bind_mount_for_recovery_test(source: &Path, target: &Path) {
        let output = std::process::Command::new("sudo")
            .args(["-n", "mount", "--bind"])
            .arg(source)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot create recovery-test bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    fn unmount_for_recovery_test(target: &Path) {
        let output = std::process::Command::new("sudo")
            .args(["-n", "umount"])
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot remove recovery-test bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn git_history_enters_encrypted_revision_sectors_without_changing_root_restore() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-revision-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        let restored = run_root.join("restored");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("tracked"), b"first\r\nbytes\0").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([91; 32]));
        let root_id = Uuid::new_v4();
        let repo =
            GitRepository::init(&source, root_id, &mb_git::catalog_key(&keys, root_id)).unwrap();
        assert!(repo.create_branch("unborn").is_err());
        let first_blob = repo.stage_file("tracked").unwrap();
        let first_commit = repo.commit("Author", "a@example.test", "first").unwrap();
        let old_branch = repo.create_branch("older").unwrap();
        assert_eq!(old_branch.oid, first_commit.oid);
        assert!(repo.create_branch("older").is_err());
        assert!(repo.create_branch("older/nested").is_err());
        repo.switch_branch("older").unwrap();
        fs::write(source.join("tracked"), b"second\nbytes").unwrap();
        let second_blob = repo.stage_file("tracked").unwrap();
        let second_commit = repo.commit("Author", "a@example.test", "second").unwrap();
        let graph = repo.export_graph_source().unwrap();
        drop(repo);

        let mut control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        control
            .put_record(
                "git-repository",
                root_id.as_bytes(),
                &canonical_bytes(&crate::control::GitRepositoryInfo {
                    format_version: 1,
                    repository_id: root_id,
                    path: source.clone(),
                })
                .unwrap(),
            )
            .unwrap();
        let guild_id = [92; 32];
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            root_id,
            &source,
            1,
            None,
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[93; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        let mut encoded = Vec::new();
        for reference in &revision.value.metadata_sectors {
            encoded.extend(
                decrypt_reference(&keys.guild_data_key(&guild_id), reference, &mut |id| {
                    render_sector(&control, &keys, id, Some(&guild_id))
                })
                .unwrap(),
            );
        }
        let metadata: GitPrivateMetadataV5 = decode_canonical(&encoded).unwrap();
        assert_eq!(metadata.format_version, 5);
        assert_eq!(metadata.git.format_version, 2);
        assert_eq!(metadata.git.head_branch, "older");
        metadata.git.validate().unwrap();
        let historical = GitPrivateMetadataV4 {
            format_version: 4,
            root_mode: metadata.root_mode,
            root_modified_secs: metadata.root_modified_secs,
            root_modified_nanos: metadata.root_modified_nanos,
            entries: metadata.entries.clone(),
            git: LegacyGitBackupDescriptorV1 {
                format_version: 1,
                repository_id: metadata.git.repository_id,
                refs: metadata.git.refs.clone(),
                objects: metadata.git.objects.clone(),
                blobs: metadata.git.blobs.clone(),
            },
        };
        let (historical_metadata, historical_git) =
            decode_private_metadata_with_git(&canonical_bytes(&historical).unwrap()).unwrap();
        assert_eq!(historical_metadata.format_version, 4);
        assert_eq!(historical_git.unwrap().head_branch, "main");
        let mut conflicting_refs = metadata.git.clone();
        conflicting_refs.refs.push(mb_git::GitGraphRef {
            name: b"refs/heads/older.foo".to_vec(),
            oid: first_commit.oid,
        });
        conflicting_refs.refs.push(mb_git::GitGraphRef {
            name: b"refs/heads/older/nested".to_vec(),
            oid: first_commit.oid,
        });
        assert!(conflicting_refs.validate().is_err());
        assert!(metadata.git.refs.iter().any(|reference| {
            reference.name == b"refs/heads/main" && reference.oid == first_commit.oid
        }));
        assert!(metadata.git.refs.iter().any(|reference| {
            reference.name == b"refs/heads/older" && reference.oid == second_commit.oid
        }));
        assert!(
            metadata
                .git
                .objects
                .iter()
                .any(|item| item.oid == first_commit.oid)
        );
        assert!(
            metadata
                .git
                .blobs
                .iter()
                .any(|item| item.oid == first_blob.oid)
        );
        assert!(
            metadata
                .git
                .blobs
                .iter()
                .any(|item| item.oid == second_blob.oid)
        );
        assert!(
            control
                .get_record(GIT_GRAPH_INTENT_KIND, revision.value.revision_id.as_bytes())
                .unwrap()
                .is_none()
        );
        restore_revision_from_source(&control, &keys, guild_id, &revision, &restored, |id| {
            render_sector(&control, &keys, id, Some(&guild_id))
        })
        .unwrap();
        assert_eq!(
            fs::read(restored.join("tracked")).unwrap(),
            b"second\nbytes"
        );
        let recovered_repo =
            GitRepository::open(&restored, root_id, &mb_git::catalog_key(&keys, root_id)).unwrap();
        let recovered_history = recovered_repo.log(10).unwrap();
        assert_eq!(recovered_history.len(), 2);
        assert_eq!(recovered_history[0].oid, second_commit.oid);
        assert_eq!(recovered_history[1].oid, first_commit.oid);
        assert_eq!(recovered_repo.status().unwrap().branch, "older");
        assert_eq!(
            recovered_repo.status().unwrap().head_oid,
            Some(second_commit.oid)
        );
        assert_eq!(
            recovered_repo
                .branches()
                .unwrap()
                .into_iter()
                .find(|branch| branch.name == "older")
                .unwrap()
                .oid,
            second_commit.oid
        );
        assert!(recovered_repo.status().unwrap().changes.is_empty());
        let recovered_graph = recovered_repo.export_graph_source().unwrap();
        assert_eq!(recovered_graph.blobs.len(), 2);
        drop(recovered_repo);
        let manifest: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        manifest.remove().unwrap();
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(&source).unwrap();
        reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored).unwrap();
        let first_backup_blob = metadata
            .git
            .blobs
            .iter()
            .find(|item| item.oid == first_blob.oid)
            .unwrap();
        let historical_sector = &first_backup_blob.data_extents[0].sectors[0];
        let restored_historical = decrypt_reference(
            &keys.guild_data_key(&guild_id),
            historical_sector,
            &mut |id| render_sector(&control, &keys, id, Some(&guild_id)),
        )
        .unwrap();
        assert_eq!(restored_historical, b"first\r\nbytes\0");
        let recovered_manifest: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        recovered_manifest.remove().unwrap();
        for blob in recovered_graph.blobs {
            blob.anchor.remove().unwrap();
        }
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn fetched_history_with_unborn_head_recovers_after_source_loss() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-unborn-revision-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        let remote_path = run_root.join("remote.git");
        let restored = run_root.join("restored");
        fs::create_dir_all(&source).unwrap();
        let remote = git2::Repository::init_bare(&remote_path).unwrap();
        let signature = git2::Signature::now("Stock", "stock@example.test").unwrap();
        let main_bytes = b"main\r\nraw\0bytes";
        let main_blob = remote.blob(main_bytes).unwrap();
        let mut main_builder = remote.treebuilder(None).unwrap();
        main_builder.insert("tracked", main_blob, 0o100644).unwrap();
        let main_tree = remote.find_tree(main_builder.write().unwrap()).unwrap();
        let main_commit = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "main",
                &main_tree,
                &[],
            )
            .unwrap();
        let tag_bytes = b"tag-only\nraw\xffbytes";
        let tag_blob = remote.blob(tag_bytes).unwrap();
        let mut tag_builder = remote.treebuilder(None).unwrap();
        tag_builder.insert("tracked", tag_blob, 0o100644).unwrap();
        let tag_tree = remote.find_tree(tag_builder.write().unwrap()).unwrap();
        let tagged_commit = remote
            .commit(None, &signature, &signature, "tagged", &tag_tree, &[])
            .unwrap();
        let target = remote
            .find_object(tagged_commit, Some(git2::ObjectType::Commit))
            .unwrap();
        let tag = remote
            .tag_annotation_create("release", &target, &signature, "release\r\n")
            .unwrap();
        remote
            .reference("refs/tags/release", tag, false, "annotated tag")
            .unwrap();
        drop(target);
        drop(main_tree);
        drop(main_builder);
        drop(tag_tree);
        drop(tag_builder);
        drop(remote);

        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([211; 32]));
        let root_id = Uuid::new_v4();
        let catalog_key = mb_git::catalog_key(&keys, root_id);
        let repo = GitRepository::init(&source, root_id, &catalog_key).unwrap();
        assert_eq!(repo.fetch_bare(&remote_path).unwrap(), 1);
        assert!(repo.status().unwrap().head_oid.is_none());
        let graph = repo.export_graph_source().unwrap();
        assert_eq!(graph.refs.len(), 2);
        drop(repo);

        let mut control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        control
            .put_record(
                "git-repository",
                root_id.as_bytes(),
                &canonical_bytes(&crate::control::GitRepositoryInfo {
                    format_version: 1,
                    repository_id: root_id,
                    path: source.clone(),
                })
                .unwrap(),
            )
            .unwrap();
        let guild_id = [212; 32];
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            root_id,
            &source,
            1,
            None,
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[213; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        let descriptor = revision_git_backup(&control, &keys, guild_id, &revision)
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.format_version, 4);
        assert!(
            descriptor
                .refs
                .iter()
                .all(|reference| reference.name.as_slice() != b"refs/heads/main")
        );
        assert!(descriptor.refs.iter().any(|reference| {
            reference.name == b"refs/remotes/origin/main"
                && reference.oid.as_slice() == main_commit.as_bytes()
        }));
        assert!(descriptor.refs.iter().any(|reference| {
            reference.name == b"refs/tags/release" && reference.oid.as_slice() == tag.as_bytes()
        }));
        let mut ciphertexts = BTreeMap::new();
        for reference in revision
            .value
            .metadata_sectors
            .iter()
            .chain(&revision.value.data_sectors)
        {
            ciphertexts.insert(
                reference.id,
                render_sector(&control, &keys, &reference.id, Some(&guild_id)).unwrap(),
            );
        }
        let manifest: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        manifest.remove().unwrap();
        for blob in &graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(&source).unwrap();

        restore_revision_from_source(&control, &keys, guild_id, &revision, &restored, |id| {
            ciphertexts
                .get(id)
                .cloned()
                .context("missing captured ciphertext")
        })
        .unwrap();
        let recovered = GitRepository::open(&restored, root_id, &catalog_key).unwrap();
        assert_eq!(recovered.selected_branch().unwrap(), "main");
        assert!(recovered.status().unwrap().head_oid.is_none());
        assert!(recovered.branches().unwrap().is_empty());
        assert_eq!(recovered.tags().unwrap()[0].oid, *tag.as_bytes());
        let recovered_graph = recovered.export_graph_source().unwrap();
        assert_eq!(recovered_graph.refs, graph.refs);
        assert_eq!(recovered_graph.objects, graph.objects);
        let tag_anchor = recovered_graph
            .blobs
            .iter()
            .find(|blob| blob.oid == *tag_blob.as_bytes())
            .unwrap();
        let mut recovered_tag_bytes = Vec::new();
        tag_anchor
            .anchor
            .open_verified()
            .unwrap()
            .read_to_end(&mut recovered_tag_bytes)
            .unwrap();
        assert_eq!(recovered_tag_bytes, tag_bytes);
        recovered
            .create_branch_from("topic", "origin/main")
            .unwrap();
        recovered.switch_branch("topic").unwrap();
        assert_eq!(fs::read(restored.join("tracked")).unwrap(), main_bytes);
        drop(recovered);
        for blob in recovered_graph.blobs {
            blob.anchor.remove().unwrap();
        }
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn rejected_capture_can_be_repaired_and_replanned() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("capture-replan-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"recoverable capture").unwrap();
        let fifo = source.join("unsupported");
        let encoded = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);

        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([41; 32]));
        let mut control =
            ControlStore::open(run_root.join("control.db"), &keys).expect("open control store");
        let guild_id = [42; 32];
        let revision_id = Uuid::from_bytes([43; 16]);
        let first = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            Uuid::from_bytes([1; 16]),
            &source,
            1,
            Some(revision_id),
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[17; 32],
                captured_change_sequence: None,
            },
        );
        assert!(first.is_err());
        assert!(
            control
                .get_record("capture-intent", revision_id.as_bytes())
                .unwrap()
                .is_none()
        );

        fs::remove_file(&fifo).unwrap();
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            Uuid::from_bytes([1; 16]),
            &source,
            1,
            Some(revision_id),
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[17; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        assert_eq!(revision.value.revision_id, revision_id);
        let manifest: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        manifest.remove().unwrap();
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn version_one_capture_intent_migrates_conservatively() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("capture-intent-v1-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"legacy pending capture").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([51; 32]));
        let control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let revision_id = Uuid::from_bytes([52; 16]);
        let legacy = LegacyCaptureIntentV1 {
            format_version: 1,
            guild_id: [53; 32],
            revision_id,
            sequence: 1,
            parent: None,
            requested_source: source.clone(),
            plan: ReflinkAnchor::plan(&source).unwrap(),
        };
        control
            .put_record(
                "capture-intent",
                revision_id.as_bytes(),
                &canonical_bytes(&legacy).unwrap(),
            )
            .unwrap();

        reconcile_pending_captures(&control).unwrap();

        let migrated: CaptureIntent = decode_canonical(
            &control
                .get_record("capture-intent", revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(migrated.format_version, 3);
        assert_eq!(migrated.revision_id, revision_id);
        assert_eq!(migrated.requested_source, source);
        assert_eq!(migrated.captured_change_sequence, None);
        assert!(matches!(migrated.plan, SourceCapturePlan::ReflinkV1(_)));
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn version_two_capture_and_recovery_intents_migrate_to_source_backend() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("source-backend-v1-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"pending capture").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([54; 32]));
        let control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let revision_id = Uuid::from_bytes([55; 16]);
        let recovery_revision_id = Uuid::from_bytes([56; 16]);
        let plan = ReflinkAnchor::plan(&source).unwrap();
        let legacy_capture = LegacyCaptureIntentV2 {
            format_version: 2,
            guild_id: [57; 32],
            revision_id,
            sequence: 1,
            parent: None,
            captured_change_sequence: Some(9),
            requested_source: source.clone(),
            plan: plan.clone(),
        };
        let legacy_recovery = LegacyRecoveryAnchorIntentV1 {
            format_version: 1,
            guild_id: [57; 32],
            revision_id: recovery_revision_id,
            source_root: source.clone(),
            plan,
            replaced_anchor: None,
        };
        control
            .put_record(
                "capture-intent",
                revision_id.as_bytes(),
                &canonical_bytes(&legacy_capture).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                RECOVERY_ANCHOR_INTENT_KIND,
                recovery_revision_id.as_bytes(),
                &canonical_bytes(&legacy_recovery).unwrap(),
            )
            .unwrap();

        reconcile_pending_captures(&control).unwrap();

        let capture_bytes = control
            .get_record("capture-intent", revision_id.as_bytes())
            .unwrap()
            .unwrap();
        let (capture, capture_migrated) = decode_capture_intent(&capture_bytes).unwrap();
        assert!(!capture_migrated);
        assert_eq!(capture.format_version, 3);
        assert_eq!(capture.captured_change_sequence, Some(9));
        assert_eq!(capture.plan.source_root(), source);
        let recovery_bytes = control
            .get_record(RECOVERY_ANCHOR_INTENT_KIND, recovery_revision_id.as_bytes())
            .unwrap()
            .unwrap();
        let (recovery, recovery_migrated) = decode_recovery_anchor_intent(&recovery_bytes).unwrap();
        assert!(!recovery_migrated);
        assert_eq!(recovery.format_version, 2);
        assert_eq!(recovery.plan.source_root(), source);
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn recovered_anchor_resumes_after_capture_before_database_commit() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("reanchor-resume-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        let restored = run_root.join("restored");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"recovered anchor payload").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([47; 32]));
        let mut control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let guild_id = [48; 32];
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            Uuid::from_bytes([1; 16]),
            &source,
            1,
            None,
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[18; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        restore_revision_from_source(
            &control,
            &keys,
            guild_id,
            &revision,
            &restored,
            |sector_id| render_sector(&control, &keys, sector_id, Some(&guild_id)),
        )
        .unwrap();
        let old: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        old.remove().unwrap();

        INTERRUPT_RECOVERY_ANCHOR_AFTER_CAPTURE.with(|interrupt| interrupt.set(true));
        assert!(
            reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored)
                .is_err()
        );
        assert!(
            control
                .get_record(
                    RECOVERY_ANCHOR_INTENT_KIND,
                    revision.value.revision_id.as_bytes(),
                )
                .unwrap()
                .is_some()
        );

        reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored).unwrap();
        assert!(
            control
                .get_record(
                    RECOVERY_ANCHOR_INTENT_KIND,
                    revision.value.revision_id.as_bytes(),
                )
                .unwrap()
                .is_none()
        );
        let current: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_ne!(current.anchor_id, old.anchor_id);
        assert!(control.records(ANCHOR_RETIREMENT_KIND).unwrap().is_empty());
        let mut payload = String::new();
        current
            .file_locator("payload".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_string(&mut payload)
            .unwrap();
        assert_eq!(payload, "recovered anchor payload");

        let reference = revision.value.data_sectors[0].clone();
        let ciphertext = render_sector(&control, &keys, &reference.id, Some(&guild_id)).unwrap();
        assert!(!local_recipe_is_inline(&control, &reference.id).unwrap());
        install_recovered_sector_recipe(
            &mut control,
            &keys,
            guild_id,
            reference.clone(),
            &ciphertext,
        )
        .unwrap();
        assert!(!local_recipe_is_inline(&control, &reference.id).unwrap());

        current.remove().unwrap();
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn failed_old_anchor_removal_remains_a_durable_retirement() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("reanchor-retire-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        let restored = run_root.join("restored");
        let external = run_root.join("external");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(source.join("payload"), b"retirement payload").unwrap();
        let sentinel = external.join("must-survive");
        fs::write(&sentinel, b"external bytes").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([49; 32]));
        let mut control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let guild_id = [50; 32];
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            Uuid::from_bytes([1; 16]),
            &source,
            1,
            None,
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[19; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        restore_revision_from_source(
            &control,
            &keys,
            guild_id,
            &revision,
            &restored,
            |sector_id| render_sector(&control, &keys, sector_id, Some(&guild_id)),
        )
        .unwrap();
        let old: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let old_root = old.area.path_hint.join(old.anchor_id.to_string());
        bind_mount_for_recovery_test(&external, &old_root);

        reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored).unwrap();
        assert_eq!(control.records(ANCHOR_RETIREMENT_KIND).unwrap().len(), 1);
        unmount_for_recovery_test(&old_root);
        assert_eq!(fs::read(&sentinel).unwrap(), b"external bytes");

        reconcile_pending_captures(&control).unwrap();
        assert!(control.records(ANCHOR_RETIREMENT_KIND).unwrap().is_empty());
        assert!(!old_root.exists());
        let current: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        current.remove().unwrap();
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    fn bare_restore_target_uses_the_current_directory() {
        assert_eq!(containing_directory(Path::new("restored")), Path::new("."));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "temporarily lowers the process descriptor limit"]
    fn restore_directory_descriptor_use_is_bounded() {
        struct OpenFileLimitGuard(libc::rlimit);

        impl Drop for OpenFileLimitGuard {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let staging = PinnedDirectory::open(temp.path()).unwrap();
        let metadata = PrivateMetadata {
            format_version: 3,
            root_mode: 0o755,
            root_modified_secs: 1_700_000_000,
            root_modified_nanos: 0,
            entries: (0..512)
                .map(|ordinal| PrivateEntry::Directory {
                    path: format!("directory-{ordinal:04}"),
                    mode: 0o755,
                    modified_secs: 1_700_000_000,
                    modified_nanos: 0,
                })
                .collect(),
        };
        let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
            0
        );
        let original = unsafe { original.assume_init() };
        assert!(original.rlim_cur >= 96);
        let limited = libc::rlimit {
            rlim_cur: 96,
            rlim_max: original.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        let limit = OpenFileLimitGuard(original);

        restore_entries(
            &staging,
            &metadata,
            &[0; 32],
            &mut |_| unreachable!(),
            false,
        )
        .unwrap();

        drop(limit);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 512);
    }

    #[test]
    fn decodes_immutable_native_id_v2_fixture() {
        const FIXTURE: &[u8] = &[
            2, 237, 3, 1, 123, 2, 2, 1, 97, 164, 3, 0, 3, 200, 3, 7, 9, 0, 2, 1, 98, 164, 3, 0, 3,
            200, 3, 7, 9, 0,
        ];
        assert_v2_hard_link_fixture(decode_private_metadata(FIXTURE).unwrap());
    }

    #[test]
    fn decodes_immutable_link_group_v2_fixture() {
        const FIXTURE: &[u8] = &[
            2, 237, 3, 1, 123, 2, 2, 1, 97, 164, 3, 0, 3, 200, 3, 0, 0, 2, 1, 98, 164, 3, 0, 3,
            200, 3, 0, 0,
        ];
        assert_v2_hard_link_fixture(decode_private_metadata(FIXTURE).unwrap());
    }

    fn assert_v2_hard_link_fixture(metadata: PrivateMetadata) {
        assert_eq!(metadata.format_version, 2);
        assert_eq!(metadata.root_mode, 0o755);
        assert_eq!(metadata.entries.len(), 2);
        for (entry, path) in metadata.entries.iter().zip(["a", "b"]) {
            assert!(matches!(
                entry,
                PrivateEntry::FileV2 {
                    path: actual_path,
                    mode: 0o644,
                    logical_len: 0,
                    modified_secs: -2,
                    modified_nanos: 456,
                    link_group: 0,
                    data_extents,
                } if actual_path == path && data_extents.is_empty()
            ));
        }
    }
}

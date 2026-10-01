use std::path::PathBuf;

use mb_core::{NodeId, QuorumPolicy, Seed};
use mb_git::{
    GitBranchInfo, GitCommitInfo, GitDiff, GitLogEntry, GitPruneReport, GitRemoteBranchInfo,
    GitStatus, GitTagInfo, GitWorktreeInfo,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{GitRepositoryInfo, GitStagedFile, NodeStatus, ProtectedRoot};
use crate::{
    BackupJob, DhtRecoveryResult, GuildAuditReport, GuildSummary, SnapshotInfo, StorageScrubReport,
    StorageVolumeStatus, WireError,
};

pub(super) const LOCAL_WIRE_FORMAT_VERSION: u16 = 2;

#[derive(Serialize, Deserialize)]
pub struct LocalRequestEnvelope<T> {
    pub format_version: u16,
    pub request_id: [u8; 16],
    pub request: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalResponseEnvelope {
    pub format_version: u16,
    pub request_id: [u8; 16],
    pub result: Result<LocalResponse, WireError>,
}

#[derive(Serialize, Deserialize)]
pub enum LocalRequest {
    Status,
    StorageStatus,
    StorageScrub,
    StorageReclaim {
        volume_id: Option<Uuid>,
    },
    StorageDrain {
        volume_id: Uuid,
    },
    StorageMigrate,
    StorageReactivate {
        volume_id: Uuid,
    },
    StorageReconcile,
    GuildAudit {
        repair: bool,
    },
    Unlock {
        secret: UnlockSecret,
    },
    AddRoot {
        path: PathBuf,
    },
    GitInit {
        path: PathBuf,
    },
    GitWorktreeAdd {
        repository_id: Uuid,
        path: PathBuf,
        branch: String,
    },
    GitWorktrees {
        repository_id: Uuid,
    },
    GitWorktreeResume {
        repository_id: Uuid,
        worktree_id: Uuid,
    },
    GitWorktreeStatus {
        repository_id: Uuid,
        worktree_id: Uuid,
    },
    GitWorktreeAddPath {
        repository_id: Uuid,
        worktree_id: Uuid,
        path: PathBuf,
    },
    GitWorktreeRemoveCached {
        repository_id: Uuid,
        worktree_id: Uuid,
        path: PathBuf,
    },
    GitWorktreeAbandonPendingAdd {
        repository_id: Uuid,
        worktree_id: Uuid,
        path: PathBuf,
    },
    GitWorktreeCommit {
        repository_id: Uuid,
        worktree_id: Uuid,
        author_name: String,
        author_email: String,
        message: String,
    },
    GitWorktreeLog {
        repository_id: Uuid,
        worktree_id: Uuid,
        limit: u32,
    },
    GitWorktreeBranches {
        repository_id: Uuid,
        worktree_id: Uuid,
    },
    GitWorktreeResetIndex {
        repository_id: Uuid,
        worktree_id: Uuid,
        paths: Vec<PathBuf>,
    },
    GitWorktreeCreateBranch {
        repository_id: Uuid,
        worktree_id: Uuid,
        name: String,
    },
    GitWorktreeCreateBranchFrom {
        repository_id: Uuid,
        worktree_id: Uuid,
        name: String,
        start_point: String,
    },
    GitWorktreeDeleteBranch {
        repository_id: Uuid,
        worktree_id: Uuid,
        name: String,
        force: bool,
    },
    GitWorktreeDiff {
        repository_id: Uuid,
        worktree_id: Uuid,
        cached: bool,
    },
    GitWorktreeSwitchBranch {
        repository_id: Uuid,
        worktree_id: Uuid,
        name: String,
    },
    GitAdd {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitRemoveCached {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitAbandonPendingAdd {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitCommit {
        repository_id: Uuid,
        author_name: String,
        author_email: String,
        message: String,
    },
    GitLog {
        repository_id: Uuid,
        limit: u32,
    },
    GitBranches {
        repository_id: Uuid,
    },
    GitTags {
        repository_id: Uuid,
    },
    GitCreateTag {
        repository_id: Uuid,
        worktree_id: Option<Uuid>,
        name: String,
        start_point: Option<String>,
    },
    GitCreateAnnotatedTag {
        repository_id: Uuid,
        worktree_id: Option<Uuid>,
        name: String,
        start_point: Option<String>,
        tagger_name: String,
        tagger_email: String,
        message: String,
    },
    GitDeleteTag {
        repository_id: Uuid,
        name: String,
    },
    GitExportToGitRepository {
        repository_id: Uuid,
        source_root: PathBuf,
        destination: PathBuf,
        advertised: Vec<GitBranchInfo>,
    },
    GitExportToGitRepositoryV2 {
        repository_id: Uuid,
        source_root: PathBuf,
        destination: PathBuf,
        advertised_branches: Vec<GitBranchInfo>,
        advertised_tags: Vec<GitTagInfo>,
    },
    GitReceivePushedBranch {
        repository_id: Uuid,
        source_root: PathBuf,
        source_git_directory: PathBuf,
        target_branch: String,
        target_oid: [u8; 20],
        expected_old: Option<[u8; 20]>,
    },
    GitReceivePushedTag {
        repository_id: Uuid,
        source_root: PathBuf,
        source_git_directory: PathBuf,
        target_tag: String,
        target_oid: [u8; 20],
        expected_old: Option<[u8; 20]>,
    },
    GitRemoteBranches {
        repository_id: Uuid,
    },
    GitCommitPins {
        repository_id: Uuid,
    },
    GitPinCommit {
        repository_id: Uuid,
        oid: [u8; 20],
    },
    GitUnpinCommit {
        repository_id: Uuid,
        oid: [u8; 20],
    },
    GitPrune {
        repository_id: Uuid,
    },
    GitResetIndex {
        repository_id: Uuid,
        paths: Vec<PathBuf>,
    },
    GitCreateBranch {
        repository_id: Uuid,
        name: String,
    },
    GitCreateBranchFrom {
        repository_id: Uuid,
        name: String,
        start_point: String,
    },
    GitDeleteBranch {
        repository_id: Uuid,
        name: String,
        force: bool,
    },
    GitSwitchBranch {
        repository_id: Uuid,
        name: String,
    },
    GitPushBare {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitWorktreePushBare {
        repository_id: Uuid,
        worktree_id: Uuid,
        path: PathBuf,
    },
    GitPushBranchBare {
        repository_id: Uuid,
        path: PathBuf,
        source_branch: String,
        target_branch: String,
    },
    GitPushTagBare {
        repository_id: Uuid,
        path: PathBuf,
        name: String,
    },
    GitFetchBare {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitPullBare {
        repository_id: Uuid,
        path: PathBuf,
        #[serde(default)]
        author_name: String,
        #[serde(default)]
        author_email: String,
    },
    GitMergeBranch {
        repository_id: Uuid,
        branch: String,
        #[serde(default)]
        author_name: String,
        #[serde(default)]
        author_email: String,
    },
    GitMergeContinue {
        repository_id: Uuid,
    },
    GitMergeAbort {
        repository_id: Uuid,
    },
    GitDiff {
        repository_id: Uuid,
        cached: bool,
    },
    GitStatus {
        repository_id: Uuid,
    },
    GuildStatus,
    GuildCreate,
    GuildInvite,
    GuildJoin {
        token: String,
    },
    GuildRetry,
    GuildCancel,
    GuildFinalize,
    GuildRemoveMember {
        node_id: NodeId,
    },
    GuildRelabelMember {
        node_id: NodeId,
        failure_domain: String,
    },
    GuildSetQuorum {
        policy: QuorumPolicy,
    },
    GuildRotateRecoveryKey,
    GuildRevokeRecoveryKey {
        subject: NodeId,
        epoch: u64,
    },
    Backup {
        wait: bool,
        root_id: Option<Uuid>,
    },
    BackupStatus {
        revision_id: Uuid,
    },
    Recover {
        target: PathBuf,
    },
    SnapshotList,
    SnapshotRestore {
        revision_id: Option<Uuid>,
        target: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalResponse {
    Locked {
        expected_node_id: NodeId,
    },
    Unlocked {
        node_id: NodeId,
    },
    Status(Box<NodeStatus>),
    StorageVolumes(Vec<StorageVolumeStatus>),
    StorageScrubbed(Vec<StorageScrubReport>),
    StorageReclaimed {
        bytes: u64,
    },
    StorageMigrated {
        objects: u64,
    },
    StorageReactivated,
    StorageReconciled,
    GuildAudited(GuildAuditReport),
    RootAdded(ProtectedRoot),
    GitRepositoryInitialized(GitRepositoryInfo),
    GitWorktreeRegistered(GitWorktreeInfo),
    GitWorktrees(Vec<GitWorktreeInfo>),
    GitFileStaged(GitStagedFile),
    GitDeletionStaged {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitCachedPathRemoved {
        removed: bool,
    },
    GitIndexReset {
        repository_id: Uuid,
        changed_paths: u32,
    },
    GitPendingAddAbandoned {
        abandoned: bool,
    },
    GitCommitted(GitCommitInfo),
    GitLog(Vec<GitLogEntry>),
    GitBranches(Vec<GitBranchInfo>),
    GitTags(Vec<GitTagInfo>),
    GitTagCreated(GitTagInfo),
    GitTagDeleted(GitTagInfo),
    GitObjectsExported {
        repository_id: Uuid,
        object_count: u32,
    },
    GitPushReceived {
        repository_id: Uuid,
        branch: String,
        oid: [u8; 20],
    },
    GitTagPushReceived {
        repository_id: Uuid,
        name: String,
        oid: [u8; 20],
    },
    GitRemoteBranches(Vec<GitRemoteBranchInfo>),
    GitCommitPins {
        repository_id: Uuid,
        oids: Vec<[u8; 20]>,
    },
    GitCommitPinChanged {
        repository_id: Uuid,
        oid: [u8; 20],
        pinned: bool,
    },
    GitPruned(GitPruneReport),
    GitBranchCreated(GitBranchInfo),
    GitBranchDeleted(GitBranchInfo),
    GitBranchSelected(GitBranchInfo),
    GitPushed {
        repository_id: Uuid,
        oid: [u8; 20],
    },
    GitFetched {
        repository_id: Uuid,
        branch_count: u32,
    },
    GitPulled {
        repository_id: Uuid,
        oid: [u8; 20],
    },
    GitMerged {
        repository_id: Uuid,
        oid: [u8; 20],
    },
    GitMergeAborted {
        repository_id: Uuid,
    },
    GitDiff(GitDiff),
    GitStatus(GitStatus),
    Guild(Option<GuildSummary>),
    GuildInvite {
        token: String,
        expires_at_unix_seconds: u64,
    },
    GuildEventCommitted {
        sequence: u64,
        event_hash: [u8; 32],
    },
    BackupJob(BackupJob),
    Recovered(DhtRecoveryResult),
    Snapshots(Vec<SnapshotInfo>),
    SnapshotRestored(SnapshotInfo),
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UnlockSecret([u8; 32]);

impl UnlockSecret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn seed(&self) -> Seed {
        Seed::from_bytes(self.0)
    }
}

impl std::fmt::Debug for UnlockSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UnlockSecret(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = include_str!("../../../../protocol/local-control.cddl");
    const STATUS_REQUEST: &str =
        include_str!("../../../../protocol/vectors/local-status-request.json");
    const LOCKED_ERROR_RESPONSE: &str =
        include_str!("../../../../protocol/vectors/local-locked-error-response.json");
    const STATUS_RESPONSE: &str =
        include_str!("../../../../protocol/vectors/local-status-response.json");
    const ROOT_ADDED_RESPONSE: &str =
        include_str!("../../../../protocol/vectors/local-root-added-response.json");
    const INVALID_VERSION: &str =
        include_str!("../../../../protocol/vectors/local-invalid-version.json");

    #[test]
    fn local_json_vectors_match_cddl_and_round_trip() {
        cddl_cat::validate_json_str("local-request-envelope", SCHEMA, STATUS_REQUEST).unwrap();
        let request: LocalRequestEnvelope<LocalRequest> =
            serde_json::from_str(STATUS_REQUEST).unwrap();
        assert!(matches!(request.request, LocalRequest::Status));
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            STATUS_REQUEST.trim_end()
        );

        cddl_cat::validate_json_str("local-response-envelope", SCHEMA, LOCKED_ERROR_RESPONSE)
            .unwrap();
        let response: LocalResponseEnvelope = serde_json::from_str(LOCKED_ERROR_RESPONSE).unwrap();
        assert!(matches!(
            response.result,
            Err(WireError {
                code: crate::WireErrorCode::Locked,
                ..
            })
        ));
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            LOCKED_ERROR_RESPONSE.trim_end()
        );

        cddl_cat::validate_json_str("local-response-envelope", SCHEMA, STATUS_RESPONSE).unwrap();
        let response: LocalResponseEnvelope = serde_json::from_str(STATUS_RESPONSE).unwrap();
        assert!(matches!(
            &response.result,
            Ok(LocalResponse::Status(status))
                if status.protected_roots.first().is_some_and(|root|
                    root.filesystem_id == 41 && root.root_inode == 43)
        ));
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            STATUS_RESPONSE.trim_end()
        );

        cddl_cat::validate_json_str("local-response-envelope", SCHEMA, ROOT_ADDED_RESPONSE)
            .unwrap();
        let response: LocalResponseEnvelope = serde_json::from_str(ROOT_ADDED_RESPONSE).unwrap();
        assert!(matches!(
            &response.result,
            Ok(LocalResponse::RootAdded(root))
                if root.filesystem_id == 41 && root.root_inode == 43
        ));
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            ROOT_ADDED_RESPONSE.trim_end()
        );

        assert!(
            cddl_cat::validate_json_str("local-request-envelope", SCHEMA, INVALID_VERSION).is_err()
        );
    }

    #[test]
    fn dynamic_guild_administration_matches_local_schema() {
        let node_id = NodeId([7; 32]);
        let requests = [
            LocalRequest::GuildRemoveMember { node_id },
            LocalRequest::GuildRelabelMember {
                node_id,
                failure_domain: "new-domain".to_owned(),
            },
            LocalRequest::GuildSetQuorum {
                policy: QuorumPolicy {
                    format_version: 1,
                    rule: mb_core::QuorumRule::Threshold(3),
                },
            },
            LocalRequest::GuildRotateRecoveryKey,
            LocalRequest::GuildRevokeRecoveryKey {
                subject: node_id,
                epoch: 2,
            },
        ];
        for request in requests {
            let envelope = LocalRequestEnvelope {
                format_version: LOCAL_WIRE_FORMAT_VERSION,
                request_id: [9; 16],
                request,
            };
            let encoded = serde_json::to_string(&envelope).unwrap();
            cddl_cat::validate_json_str("local-request-envelope", SCHEMA, &encoded).unwrap();
            let decoded: LocalRequestEnvelope<LocalRequest> =
                serde_json::from_str(&encoded).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
        }

        let response = LocalResponseEnvelope {
            format_version: LOCAL_WIRE_FORMAT_VERSION,
            request_id: [9; 16],
            result: Ok(LocalResponse::GuildEventCommitted {
                sequence: 12,
                event_hash: [8; 32],
            }),
        };
        let encoded = serde_json::to_string(&response).unwrap();
        cddl_cat::validate_json_str("local-response-envelope", SCHEMA, &encoded).unwrap();
        let decoded: LocalResponseEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
    }

    #[test]
    fn git_frontend_requests_and_responses_match_local_schema() {
        let repository_id = Uuid::from_bytes([6; 16]);
        for request in [
            LocalRequest::GitInit {
                path: PathBuf::from("/home/user/work"),
            },
            LocalRequest::GitWorktreeAdd {
                repository_id,
                path: PathBuf::from("/home/user/linked"),
                branch: "topic".to_owned(),
            },
            LocalRequest::GitWorktrees { repository_id },
            LocalRequest::GitWorktreeResume {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
            },
            LocalRequest::GitWorktreeStatus {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
            },
            LocalRequest::GitWorktreeAddPath {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("tracked"),
            },
            LocalRequest::GitWorktreeRemoveCached {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("tracked"),
            },
            LocalRequest::GitWorktreeAbandonPendingAdd {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("tracked"),
            },
            LocalRequest::GitWorktreeCommit {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                author_name: "Author".to_owned(),
                author_email: "a@example.test".to_owned(),
                message: "linked".to_owned(),
            },
            LocalRequest::GitWorktreeLog {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                limit: 5,
            },
            LocalRequest::GitWorktreeBranches {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
            },
            LocalRequest::GitWorktreeResetIndex {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                paths: vec![PathBuf::from("tracked")],
            },
            LocalRequest::GitWorktreeCreateBranch {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                name: "copy".to_owned(),
            },
            LocalRequest::GitWorktreeCreateBranchFrom {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                name: "copy".to_owned(),
                start_point: "topic".to_owned(),
            },
            LocalRequest::GitWorktreeDeleteBranch {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                name: "copy".to_owned(),
                force: false,
            },
            LocalRequest::GitWorktreeDiff {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                cached: true,
            },
            LocalRequest::GitWorktreeSwitchBranch {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                name: "topic".to_owned(),
            },
            LocalRequest::GitWorktreeAddPath {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("tracked"),
            },
            LocalRequest::GitWorktreeRemoveCached {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("tracked"),
            },
            LocalRequest::GitWorktreeCommit {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                author_name: "Author".to_owned(),
                author_email: "a@example.test".to_owned(),
                message: "linked".to_owned(),
            },
            LocalRequest::GitWorktreeLog {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                limit: 5,
            },
            LocalRequest::GitWorktreeBranches {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
            },
            LocalRequest::GitWorktreeDiff {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                cached: true,
            },
            LocalRequest::GitWorktreeSwitchBranch {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                name: "topic".to_owned(),
            },
            LocalRequest::GitAdd {
                repository_id,
                path: PathBuf::from("folder/file"),
            },
            LocalRequest::GitRemoveCached {
                repository_id,
                path: PathBuf::from("folder/file"),
            },
            LocalRequest::GitAbandonPendingAdd {
                repository_id,
                path: PathBuf::from("folder/file"),
            },
            LocalRequest::GitCommit {
                repository_id,
                author_name: "Test Author".to_owned(),
                author_email: "author@example.test".to_owned(),
                message: "first".to_owned(),
            },
            LocalRequest::GitLog {
                repository_id,
                limit: 10,
            },
            LocalRequest::GitBranches { repository_id },
            LocalRequest::GitTags { repository_id },
            LocalRequest::GitCreateTag {
                repository_id,
                worktree_id: None,
                name: "v1".to_owned(),
                start_point: Some("main".to_owned()),
            },
            LocalRequest::GitCreateAnnotatedTag {
                repository_id,
                worktree_id: None,
                name: "v2".to_owned(),
                start_point: Some("main".to_owned()),
                tagger_name: "Test Tagger".to_owned(),
                tagger_email: "tagger@example.test".to_owned(),
                message: "release".to_owned(),
            },
            LocalRequest::GitDeleteTag {
                repository_id,
                name: "v1".to_owned(),
            },
            LocalRequest::GitExportToGitRepository {
                repository_id,
                source_root: PathBuf::from("/tmp/source"),
                destination: PathBuf::from("/tmp/stock-git/.git"),
                advertised: vec![GitBranchInfo {
                    format_version: 1,
                    repository_id,
                    name: "main".to_owned(),
                    oid: [3; 20],
                    current: true,
                }],
            },
            LocalRequest::GitExportToGitRepositoryV2 {
                repository_id,
                source_root: PathBuf::from("/tmp/source"),
                destination: PathBuf::from("/tmp/stock-git/.git"),
                advertised_branches: vec![GitBranchInfo {
                    format_version: 1,
                    repository_id,
                    name: "main".to_owned(),
                    oid: [3; 20],
                    current: true,
                }],
                advertised_tags: vec![GitTagInfo {
                    format_version: 1,
                    repository_id,
                    name: "release".to_owned(),
                    oid: [4; 20],
                }],
            },
            LocalRequest::GitReceivePushedBranch {
                repository_id,
                source_root: PathBuf::from("/tmp/source"),
                source_git_directory: PathBuf::from("/tmp/stock-git/.git"),
                target_branch: "topic".to_owned(),
                target_oid: [4; 20],
                expected_old: Some([3; 20]),
            },
            LocalRequest::GitReceivePushedTag {
                repository_id,
                source_root: PathBuf::from("/tmp/source"),
                source_git_directory: PathBuf::from("/tmp/stock-git/.git"),
                target_tag: "release".to_owned(),
                target_oid: [4; 20],
                expected_old: None,
            },
            LocalRequest::GitRemoteBranches { repository_id },
            LocalRequest::GitCommitPins { repository_id },
            LocalRequest::GitPinCommit {
                repository_id,
                oid: [7; 20],
            },
            LocalRequest::GitUnpinCommit {
                repository_id,
                oid: [7; 20],
            },
            LocalRequest::GitPrune { repository_id },
            LocalRequest::GitResetIndex {
                repository_id,
                paths: Vec::new(),
            },
            LocalRequest::GitCreateBranch {
                repository_id,
                name: "older".to_owned(),
            },
            LocalRequest::GitCreateBranchFrom {
                repository_id,
                name: "topic".to_owned(),
                start_point: "origin/topic".to_owned(),
            },
            LocalRequest::GitDeleteBranch {
                repository_id,
                name: "older".to_owned(),
                force: false,
            },
            LocalRequest::GitSwitchBranch {
                repository_id,
                name: "older".to_owned(),
            },
            LocalRequest::GitPushBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
            },
            LocalRequest::GitWorktreePushBare {
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("/home/user/remote.git"),
            },
            LocalRequest::GitPushBranchBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
                source_branch: "topic".to_owned(),
                target_branch: "review/topic".to_owned(),
            },
            LocalRequest::GitPushTagBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
                name: "release".to_owned(),
            },
            LocalRequest::GitFetchBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
            },
            LocalRequest::GitPullBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
                author_name: "Author".to_owned(),
                author_email: "a@example.test".to_owned(),
            },
            LocalRequest::GitMergeBranch {
                repository_id,
                branch: "older".to_owned(),
                author_name: "Author".to_owned(),
                author_email: "a@example.test".to_owned(),
            },
            LocalRequest::GitMergeContinue { repository_id },
            LocalRequest::GitMergeAbort { repository_id },
            LocalRequest::GitDiff {
                repository_id,
                cached: true,
            },
            LocalRequest::GitStatus { repository_id },
        ] {
            let envelope = LocalRequestEnvelope {
                format_version: LOCAL_WIRE_FORMAT_VERSION,
                request_id: [9; 16],
                request,
            };
            let encoded = serde_json::to_string(&envelope).unwrap();
            cddl_cat::validate_json_str("local-request-envelope", SCHEMA, &encoded).unwrap();
            let decoded: LocalRequestEnvelope<LocalRequest> =
                serde_json::from_str(&encoded).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
        }
        let older_merge = serde_json::json!({
            "format_version": LOCAL_WIRE_FORMAT_VERSION,
            "request_id": vec![9_u8; 16],
            "request": { "GitMergeBranch": {
                "repository_id": repository_id,
                "branch": "older"
            }}
        });
        let older_merge = serde_json::to_string(&older_merge).unwrap();
        cddl_cat::validate_json_str("local-request-envelope", SCHEMA, &older_merge).unwrap();
        let decoded: LocalRequestEnvelope<LocalRequest> =
            serde_json::from_str(&older_merge).unwrap();
        assert!(matches!(
            decoded.request,
            LocalRequest::GitMergeBranch {
                author_name,
                author_email,
                ..
            } if author_name.is_empty() && author_email.is_empty()
        ));
        let older_pull = serde_json::json!({
            "format_version": LOCAL_WIRE_FORMAT_VERSION,
            "request_id": vec![9_u8; 16],
            "request": { "GitPullBare": {
                "repository_id": repository_id,
                "path": "/home/user/remote.git"
            }}
        });
        let older_pull = serde_json::to_string(&older_pull).unwrap();
        cddl_cat::validate_json_str("local-request-envelope", SCHEMA, &older_pull).unwrap();
        let decoded: LocalRequestEnvelope<LocalRequest> =
            serde_json::from_str(&older_pull).unwrap();
        assert!(matches!(
            decoded.request,
            LocalRequest::GitPullBare {
                author_name,
                author_email,
                ..
            } if author_name.is_empty() && author_email.is_empty()
        ));
        for response in [
            LocalResponse::GitRepositoryInitialized(GitRepositoryInfo {
                format_version: 1,
                repository_id,
                path: PathBuf::from("/home/user/work"),
            }),
            LocalResponse::GitWorktreeRegistered(GitWorktreeInfo {
                format_version: 1,
                repository_id,
                worktree_id: Uuid::from_bytes([5; 16]),
                path: PathBuf::from("/home/user/linked"),
                root_id: mb_store::NativeFileId {
                    filesystem_id: 1,
                    inode: 2,
                },
                target_branch: "topic".to_owned(),
                state: mb_git::GitWorktreeState::Ready,
            }),
            LocalResponse::GitWorktrees(vec![]),
            LocalResponse::GitFileStaged(GitStagedFile {
                format_version: 1,
                repository_id,
                path: PathBuf::from("folder/file"),
                oid: "81b2d75d7f1e1b71438019a1128f25986bebd588".to_owned(),
                mode: 0o100644,
            }),
            LocalResponse::GitDeletionStaged {
                repository_id,
                path: PathBuf::from("folder/file"),
            },
            LocalResponse::GitCachedPathRemoved { removed: true },
            LocalResponse::GitIndexReset {
                repository_id,
                changed_paths: 2,
            },
            LocalResponse::GitPendingAddAbandoned { abandoned: true },
            LocalResponse::GitCommitted(GitCommitInfo {
                format_version: 1,
                repository_id,
                oid: [7; 20],
                tree_oid: [8; 20],
                parent_oid: None,
                branch: "main".to_owned(),
            }),
            LocalResponse::GitLog(vec![GitLogEntry {
                oid: [7; 20],
                tree_oid: [8; 20],
                parent_oids: vec![[6; 20]],
                author_name: b"Test Author".to_vec(),
                author_email: b"author@example.test".to_vec(),
                message: b"first\n".to_vec(),
            }]),
            LocalResponse::GitBranches(vec![GitBranchInfo {
                format_version: 1,
                repository_id,
                name: "main".to_owned(),
                oid: [7; 20],
                current: true,
            }]),
            LocalResponse::GitTags(vec![GitTagInfo {
                format_version: 1,
                repository_id,
                name: "v1".to_owned(),
                oid: [7; 20],
            }]),
            LocalResponse::GitTagCreated(GitTagInfo {
                format_version: 1,
                repository_id,
                name: "v1".to_owned(),
                oid: [7; 20],
            }),
            LocalResponse::GitTagDeleted(GitTagInfo {
                format_version: 1,
                repository_id,
                name: "v1".to_owned(),
                oid: [7; 20],
            }),
            LocalResponse::GitObjectsExported {
                repository_id,
                object_count: 2,
            },
            LocalResponse::GitPushReceived {
                repository_id,
                branch: "topic".to_owned(),
                oid: [4; 20],
            },
            LocalResponse::GitTagPushReceived {
                repository_id,
                name: "release".to_owned(),
                oid: [4; 20],
            },
            LocalResponse::GitRemoteBranches(vec![GitRemoteBranchInfo {
                format_version: 1,
                repository_id,
                name: "origin/topic".to_owned(),
                oid: [7; 20],
            }]),
            LocalResponse::GitCommitPins {
                repository_id,
                oids: vec![[7; 20]],
            },
            LocalResponse::GitCommitPinChanged {
                repository_id,
                oid: [7; 20],
                pinned: true,
            },
            LocalResponse::GitPruned(GitPruneReport {
                format_version: 1,
                repository_id,
                metadata_objects_removed: 1,
                native_anchors_removed: 2,
                logical_anchor_bytes_removed: 1024,
                physical_bytes_reclaimed: None,
            }),
            LocalResponse::GitBranchCreated(GitBranchInfo {
                format_version: 1,
                repository_id,
                name: "older".to_owned(),
                oid: [7; 20],
                current: false,
            }),
            LocalResponse::GitBranchDeleted(GitBranchInfo {
                format_version: 1,
                repository_id,
                name: "older".to_owned(),
                oid: [7; 20],
                current: false,
            }),
            LocalResponse::GitBranchSelected(GitBranchInfo {
                format_version: 1,
                repository_id,
                name: "older".to_owned(),
                oid: [7; 20],
                current: true,
            }),
            LocalResponse::GitPushed {
                repository_id,
                oid: [7; 20],
            },
            LocalResponse::GitFetched {
                repository_id,
                branch_count: 2,
            },
            LocalResponse::GitPulled {
                repository_id,
                oid: [7; 20],
            },
            LocalResponse::GitMerged {
                repository_id,
                oid: [7; 20],
            },
            LocalResponse::GitMergeAborted { repository_id },
            LocalResponse::GitDiff(GitDiff {
                format_version: 1,
                repository_id,
                cached: true,
                patch: b"diff --git a/tracked b/tracked\n".to_vec(),
            }),
            LocalResponse::GitStatus(GitStatus {
                format_version: 1,
                repository_id,
                branch: "main".to_owned(),
                head_oid: Some([7; 20]),
                history_backed_up: false,
                changes: vec![mb_git::GitStatusChange {
                    path: b"tracked".to_vec(),
                    staged: Some(mb_git::GitChange::Modified),
                    worktree: None,
                }],
                untracked: vec![b"new".to_vec()],
                pending_adds: vec![],
                merge: Some(mb_git::GitMergeState {
                    source_ref: b"refs/heads/topic".to_vec(),
                    ours: [7; 20],
                    theirs: [8; 20],
                    unresolved_paths: vec![b"tracked".to_vec()],
                }),
            }),
        ] {
            let envelope = LocalResponseEnvelope {
                format_version: LOCAL_WIRE_FORMAT_VERSION,
                request_id: [9; 16],
                result: Ok(response),
            };
            let encoded = serde_json::to_string(&envelope).unwrap();
            cddl_cat::validate_json_str("local-response-envelope", SCHEMA, &encoded).unwrap();
            let decoded: LocalResponseEnvelope = serde_json::from_str(&encoded).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
        }
    }
}

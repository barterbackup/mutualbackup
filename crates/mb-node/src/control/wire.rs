use std::path::PathBuf;

use mb_core::{NodeId, QuorumPolicy, Seed};
use mb_git::{GitBranchInfo, GitCommitInfo, GitDiff, GitLogEntry, GitStatus};
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
    GitCreateBranch {
        repository_id: Uuid,
        name: String,
    },
    GitSwitchBranch {
        repository_id: Uuid,
        name: String,
    },
    GitPushBare {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitFetchBare {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitPullBare {
        repository_id: Uuid,
        path: PathBuf,
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
    GitFileStaged(GitStagedFile),
    GitDeletionStaged {
        repository_id: Uuid,
        path: PathBuf,
    },
    GitCachedPathRemoved {
        removed: bool,
    },
    GitPendingAddAbandoned {
        abandoned: bool,
    },
    GitCommitted(GitCommitInfo),
    GitLog(Vec<GitLogEntry>),
    GitBranches(Vec<GitBranchInfo>),
    GitBranchCreated(GitBranchInfo),
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
            LocalRequest::GitCreateBranch {
                repository_id,
                name: "older".to_owned(),
            },
            LocalRequest::GitSwitchBranch {
                repository_id,
                name: "older".to_owned(),
            },
            LocalRequest::GitPushBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
            },
            LocalRequest::GitFetchBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
            },
            LocalRequest::GitPullBare {
                repository_id,
                path: PathBuf::from("/home/user/remote.git"),
            },
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
        for response in [
            LocalResponse::GitRepositoryInitialized(GitRepositoryInfo {
                format_version: 1,
                repository_id,
                path: PathBuf::from("/home/user/work"),
            }),
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
            LocalResponse::GitBranchCreated(GitBranchInfo {
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

use std::path::PathBuf;

use mb_core::{NodeId, Seed};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{NodeStatus, ProtectedRoot};
use crate::{
    BackupJob, DhtRecoveryResult, GuildAuditReport, GuildSummary, SnapshotInfo, StorageScrubReport,
    StorageVolumeStatus, WireError,
};

pub(super) const LOCAL_WIRE_FORMAT_VERSION: u16 = 1;

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
    GuildStatus,
    GuildCreate,
    GuildInvite,
    GuildJoin {
        token: String,
    },
    GuildRetry,
    GuildCancel,
    GuildFinalize,
    Backup {
        wait: bool,
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
    Guild(Option<GuildSummary>),
    GuildInvite {
        token: String,
        expires_at_unix_seconds: u64,
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
                if status.protected_root.as_ref().is_some_and(|root|
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
}

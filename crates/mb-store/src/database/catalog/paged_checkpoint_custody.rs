//! Resumable local custody under the original, enclosing checkpoint owner.
//! Completion is a local acquisition fence, not distributed availability or
//! permission to activate a checkpoint. One call visits one revision or group.

use mb_core::{
    CatalogCheckpointAuthorityRecord as R, CatalogCheckpointRevisionKey, CatalogCodingSummary,
    CatalogCodingTraversalBudget as Work, NodeId, PagedCheckpointTrust, ShardRoleV2,
};

use super::checkpoint_body::Header;
use super::paged_checkpoint_retention::{Layout, Proof, owned_certificate};
use super::retention_journal as journal;
use super::*;

const JOURNAL: &str = "catalog-checkpoint-local-custody-v1";
const ROW_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogCheckpointLocalCustodyPhase {
    Revisions,
    Coding,
    Complete,
}

/// Durable progress for one holder and the exact original checkpoint owner.
/// Completed custody keeps local private/bootstrap/source and READY payload
/// dependencies alive through the owner's existing guarded retirement path.
/// It does not claim that an unavailable volume is healthy or that other
/// holders have acquired their assignments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointLocalCustody {
    pub format_version: u16,
    pub id: Uuid,
    pub holder: NodeId,
    pub checkpoint_hash: [u8; 32],
    pub certificate_hash: [u8; 32],
    pub trust_hash: [u8; 32],
    pub phase: CatalogCheckpointLocalCustodyPhase,
    pub revision_cursor: Option<CatalogCheckpointRevisionKey>,
    pub group_cursor: Option<[u8; 32]>,
    pub revisions: u64,
    pub legacy_revisions: u64,
    pub local_revisions: u64,
    pub local_payloads: u64,
    pub coding: CatalogCodingSummary,
    pub scan_work: Work,
}

fn read<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<CatalogCheckpointLocalCustody>, CatalogStoreError> {
    let Some(bytes) = bounded_record(connection, JOURNAL, retention.id.as_bytes(), ROW_BYTES)?
    else {
        return Ok(None);
    };
    let progress: CatalogCheckpointLocalCustody = decode_canonical(&bytes)?;
    let authority = retention.checkpoint.authority_root().summary;
    let coding = retention.checkpoint.coding();
    let observed = progress.coding;
    if progress.format_version != 1
        || progress.id != retention.id
        || progress.holder.0 == [0; 32]
        || progress.checkpoint_hash != retention.checkpoint.hash()?
        || progress.certificate_hash != retention.certificate_hash
        || progress.trust_hash != retention.trust_hash
        || progress.revisions > authority.revisions
        || progress.legacy_revisions > authority.legacy_revisions
        || progress.legacy_revisions > progress.revisions
        || progress.local_revisions > progress.revisions - progress.legacy_revisions
        || progress.local_payloads
            > observed
                .information_roles
                .checked_add(observed.parity_roles)
                .ok_or(CatalogError::Bounds)?
        || (progress.revisions == 0) != progress.revision_cursor.is_none()
        || (observed.groups == 0) != progress.group_cursor.is_none()
        || progress.group_cursor == Some([0; 32])
        || observed.groups > coding.groups
        || observed.retired_groups > coding.retired_groups
        || observed.retired_groups > observed.groups
        || observed.information_roles > coding.information_roles
        || observed.parity_roles > coding.parity_roles
        || observed.transcript_bytes > coding.transcript_bytes
        || observed.fragments > coding.fragments
        || (progress.phase == CatalogCheckpointLocalCustodyPhase::Revisions
            && observed != CatalogCodingSummary::default())
        || (progress.phase != CatalogCheckpointLocalCustodyPhase::Revisions
            && (progress.revisions != authority.revisions
                || progress.legacy_revisions != authority.legacy_revisions))
        || (progress.phase == CatalogCheckpointLocalCustodyPhase::Complete && observed != coding)
        || canonical_bytes(&progress)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    if let Some(cursor) = progress.revision_cursor
        && (cursor.owner.0 == [0; 32] || cursor.revision_id.is_nil() || cursor.sequence == 0)
    {
        return Err(DatabaseError::Integrity.into());
    }
    if progress.phase == CatalogCheckpointLocalCustodyPhase::Complete
        && (paged_checkpoint_revision::owned_work(connection, retention)?
            .unwrap_or_default()
            .records
            != progress
                .local_revisions
                .checked_mul(3)
                .ok_or(CatalogError::Bounds)?
            || paged_checkpoint_payload::owned_count(connection, retention)?
                != progress.local_payloads)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(progress))
}

pub(super) fn owned_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    read(connection, retention)?
        .map(|progress| {
            Ok(progress.scan_work.checked_add(Work {
                bytes: ROW_BYTES as u64,
                page_occurrences: 0,
                records: 1,
            })?)
        })
        .unwrap_or(Ok(Work::default()))
}

pub(super) fn require_unowned(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, JOURNAL, id.as_bytes(), ROW_BYTES)?.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

/// Cancellation invalidates completion in the same enclosing writer transaction.
/// Existing private/payload pins continue to retire one dependency at a time.
pub(super) fn cancel<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<(), CatalogStoreError> {
    if let Some(progress) = read(connection, retention)?
        && (connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![
                JOURNAL,
                retention.id.as_bytes(),
                canonical_bytes(&progress)?
            ],
        )? != 1
            || bounded_record(connection, JOURNAL, retention.id.as_bytes(), ROW_BYTES)?.is_some())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn add(count: &mut u64, amount: u64) -> Result<(), CatalogStoreError> {
    *count = count.checked_add(amount).ok_or(CatalogError::Bounds)?;
    Ok(())
}

impl ControlStore {
    pub(super) fn checkpoint_local_custody_step<P: Proof, E: From<CatalogStoreError>>(
        &self,
        id: Uuid,
        proof: &P,
        holder: NodeId,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
        mut check_revision: impl FnMut(&PagedCatalogSnapshot) -> Result<(), E>,
        mut check_payload: impl FnMut(&CatalogCheckpointPayload) -> Result<(), E>,
    ) -> Result<CatalogCheckpointLocalCustody, E> {
        proof.recheck(&mut read_trust)?;
        if !proof.has_member(holder) {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let retention = proof.retention(id)?;
        let previous = {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(CatalogStoreError::from)?;
            self.guard_paged_candidate(retention, &mut read_trust)?;
            if journal::require(&tx, retention)?.state
                != CatalogPagedCheckpointRetentionState::Published
            {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            owned_certificate(&tx, retention)?;
            let progress = if let Some(progress) = read(&tx, retention)? {
                if progress.holder != holder {
                    return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
                }
                progress
            } else {
                let progress = CatalogCheckpointLocalCustody {
                    format_version: 1,
                    id,
                    holder,
                    checkpoint_hash: retention
                        .checkpoint
                        .hash()
                        .map_err(CatalogStoreError::from)?,
                    certificate_hash: retention.certificate_hash,
                    trust_hash: retention.trust_hash,
                    phase: CatalogCheckpointLocalCustodyPhase::Revisions,
                    revision_cursor: None,
                    group_cursor: None,
                    revisions: 0,
                    legacy_revisions: 0,
                    local_revisions: 0,
                    local_payloads: 0,
                    coding: CatalogCodingSummary::default(),
                    scan_work: Work::default(),
                };
                insert_exact(
                    &tx,
                    JOURNAL,
                    id.as_bytes(),
                    &canonical_bytes(&progress).map_err(CatalogStoreError::from)?,
                )?;
                progress
            };
            paged_checkpoint_revision::admitted_work(&tx, retention)?;
            self.guard_paged_candidate(retention, &mut read_trust)?;
            tx.commit().map_err(CatalogStoreError::from)?;
            progress
        };
        if previous.phase == CatalogCheckpointLocalCustodyPhase::Complete {
            return Ok(previous);
        }
        let mut next = previous;
        match previous.phase {
            CatalogCheckpointLocalCustodyPhase::Revisions => {
                if let Some(revision) = proof.next_revision(previous.revision_cursor)? {
                    let key = revision
                        .revision_key()
                        .ok_or_else(|| CatalogStoreError::from(DatabaseError::Integrity))?;
                    if previous.revision_cursor.is_some_and(|cursor| key <= cursor) {
                        return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
                    }
                    // Fixed/flat local private custody needs its original legacy
                    // owner bridge. Do not silently declare it complete or migrate IDs.
                    if matches!(revision, R::LegacyRevision(_)) && key.owner == holder {
                        return Err(CatalogStoreError::from(DatabaseError::NotReady).into());
                    }
                    if matches!(revision, R::PagedRevision(_)) && key.owner == holder {
                        self.retain_checkpoint_revision_checked(
                            id,
                            proof,
                            key,
                            &mut read_trust,
                            &mut check_revision,
                        )?;
                        add(&mut next.local_revisions, 1)?;
                    }
                    add(&mut next.revisions, 1)?;
                    add(
                        &mut next.legacy_revisions,
                        u64::from(matches!(revision, R::LegacyRevision(_))),
                    )?;
                    next.revision_cursor = Some(key);
                    next.scan_work = next
                        .scan_work
                        .checked_add(Work {
                            bytes: mb_core::canonical_bytes_bounded(
                                &revision,
                                mb_core::CATALOG_CHECKPOINT_RECORD_BYTES,
                            )
                            .map_err(CatalogStoreError::from)?
                            .len() as u64,
                            page_occurrences: 0,
                            records: 1,
                        })
                        .map_err(CatalogStoreError::from)?;
                } else {
                    next.phase = CatalogCheckpointLocalCustodyPhase::Coding;
                }
            }
            CatalogCheckpointLocalCustodyPhase::Coding => {
                if let Some(row) = proof.next_group(previous.group_cursor)? {
                    let group = row.group.range.group_id;
                    if previous.group_cursor.is_some_and(|cursor| group <= cursor) {
                        return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
                    }
                    let remaining = (|| -> Result<Work, CatalogStoreError> {
                        Ok(retention.budget.remaining_after(
                            retention
                                .proof_work
                                .checked_add(retention.checkpoint.work()?)?
                                .checked_add(owned_work(&self.connection, retention)?)?
                                .checked_add(
                                    paged_checkpoint_revision::owned_work(
                                        &self.connection,
                                        retention,
                                    )?
                                    .unwrap_or_default(),
                                )?
                                .checked_add(
                                    paged_checkpoint_payload::owned_work(
                                        &self.connection,
                                        retention,
                                    )?
                                    .unwrap_or_default(),
                                )?,
                        )?)
                    })()?;
                    let (entry, work) = proof
                        .read_group(group, remaining, |page| {
                            self.catalog_page(
                                CatalogScope::Guild {
                                    guild_id: retention.checkpoint.guild_id(),
                                },
                                CatalogSection::Coding,
                                page,
                            )
                        })?
                        .ok_or_else(|| CatalogStoreError::from(DatabaseError::Integrity))?;
                    for (shard, role) in entry.retained.group.roles.iter().enumerate() {
                        let assigned = match role {
                            ShardRoleV2::Information(role) => {
                                !role.sector.virtual_zero && role.owner == holder
                            }
                            ShardRoleV2::Parity(role) => role.holder == holder,
                        };
                        if assigned {
                            self.retain_checkpoint_payload_checked(
                                id,
                                proof,
                                group,
                                shard as u16,
                                &mut read_trust,
                                &mut check_payload,
                            )?;
                            add(&mut next.local_payloads, 1)?;
                        }
                    }
                    add(&mut next.coding.groups, 1)?;
                    add(
                        &mut next.coding.retired_groups,
                        u64::from(entry.retained.retired_at_event.is_some()),
                    )?;
                    add(
                        &mut next.coding.information_roles,
                        u64::from(entry.retained.group.profile.data_shards),
                    )?;
                    add(
                        &mut next.coding.parity_roles,
                        u64::from(entry.retained.group.profile.parity_shards),
                    )?;
                    let bytes = mb_core::canonical_bytes_bounded(
                        &entry.transcript,
                        mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
                    )
                    .map_err(CatalogStoreError::from)?
                    .len();
                    add(&mut next.coding.transcript_bytes, bytes as u64)?;
                    add(
                        &mut next.coding.fragments,
                        bytes.div_ceil(mb_core::CATALOG_CODING_FRAGMENT_BYTES) as u64,
                    )?;
                    next.group_cursor = Some(group);
                    next.scan_work = next
                        .scan_work
                        .checked_add(work)
                        .map_err(CatalogStoreError::from)?;
                } else {
                    next.phase = CatalogCheckpointLocalCustodyPhase::Complete;
                }
            }
            CatalogCheckpointLocalCustodyPhase::Complete => unreachable!(),
        }
        proof.recheck(&mut read_trust)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
            || read(&tx, retention)? != Some(previous)
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        owned_certificate(&tx, retention)?;
        let bytes = canonical_bytes(&next).map_err(CatalogStoreError::from)?;
        if bytes.len() > ROW_BYTES || tx.execute(
            "UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![JOURNAL, id.as_bytes(), canonical_bytes(&previous).map_err(CatalogStoreError::from)?, bytes],
        ).map_err(CatalogStoreError::from)? != 1
            || read(&tx, retention)? != Some(next)
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        paged_checkpoint_revision::admitted_work(&tx, retention)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(next)
    }
}

macro_rules! custody_api {
    ($proof:ty, $step:ident) => {
        impl ControlStore {
            /// Acquire one revision or at most one bounded coding group for this
            /// local holder. Call until Complete. Errors preserve already acquired
            /// dependencies and leave the cursor unchanged; replay reauthenticates
            /// them. Local legacy revisions explicitly require their migration bridge.
            /// The callbacks must authenticate the encrypted local private descriptor
            /// and full READY bytes. Each runs under its dependency's control writer.
            /// Completion does not authorize checkpoint activation.
            pub fn $step<E: From<CatalogStoreError>>(
                &self,
                id: Uuid,
                proof: &$proof,
                holder: NodeId,
                read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
                check_revision: impl FnMut(&PagedCatalogSnapshot) -> Result<(), E>,
                check_payload: impl FnMut(&CatalogCheckpointPayload) -> Result<(), E>,
            ) -> Result<CatalogCheckpointLocalCustody, E> {
                self.checkpoint_local_custody_step(
                    id,
                    proof,
                    holder,
                    read_trust,
                    check_revision,
                    check_payload,
                )
            }
        }
    };
}
custody_api!(
    CatalogQuorumPagedCheckpointIndex,
    retain_catalog_paged_checkpoint_local_custody_step_checked
);
custody_api!(
    CatalogQuorumPagedCheckpointDirectoryIndex,
    retain_catalog_paged_checkpoint_directory_local_custody_step_checked
);

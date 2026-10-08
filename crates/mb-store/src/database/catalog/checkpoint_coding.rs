//! Exact certified-current variable coding state and placement joins. This
//! does not migrate fixed legacy groups or own private/source/parity payloads.

use mb_core::{
    CATALOG_CODING_TRANSCRIPT_BYTES, CatalogCodingLifecycle, CatalogCodingTraversalBudget as Work,
    CodingProfile, PagedCheckpointTrust, PagedGuildCheckpoint, RetainedCodingGroup,
    canonical_hash_bounded, canonical_size_bounded,
};

use super::checkpoint_transition::snapshot_hash;
use super::checkpoint_validation::MEMBER_BYTES;
use super::coding_coverage::{ROW_BYTES, decode_row, put};
use super::packing_validation::SECTORS;
use super::*;

const PLACEMENT: &str = "checkpoint-certified-coding-placement";
const COMPLETE: &str = "checkpoint-certified-coding-complete";
const DESCRIPTOR_BYTES: usize = 4096;
const KINDS: [&str; 2] = [PLACEMENT, COMPLETE];

/// Independently certified event state, never counts learned from the proposed
/// directory. Counts include all retained variable groups, including retired
/// and unrelated groups until a certified ForgetCodingGroup removes them.
/// Obtain these scalars and the roster from one consistent history snapshot;
/// do not load a whole DynamicGuildState for this bounded join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogCheckpointCodingTrust {
    pub checkpoint: PagedCheckpointTrust,
    pub retained_groups: u64,
    pub retired_groups: u64,
}

impl CatalogCheckpointCodingTrust {
    fn validate(&self) -> Result<(), CatalogStoreError> {
        self.checkpoint.validate()?;
        if self.retired_groups > self.retained_groups {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }
    fn hash(&self) -> Result<[u8; 32], CatalogStoreError> {
        canonical_hash_bounded(
            &(
                snapshot_hash(&self.checkpoint)?,
                self.retained_groups,
                self.retired_groups,
            ),
            ROW_BYTES,
        )
        .map_err(Into::into)
    }
}

/// Fixed facts returned by a trusted indexed certified-history lookup, not an
/// authority token or a peer claim. The witness hash is plain BLAKE3 of the
/// exact original signed transcript named by AddCodingGroupBound or its
/// verified legacy add binding. Authorization must also check original
/// delegation/membership/domains; CurrentPlacement additionally checks the
/// same current snapshot's membership and domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogCertifiedCodingGroup {
    pub guild_id: [u8; 32],
    pub lifecycle: CatalogCodingLifecycle,
    pub profile: CodingProfile,
    pub transcript_hash: [u8; 32],
    pub authorization: CatalogCodingAuthorization,
}

impl CatalogCertifiedCodingGroup {
    pub fn from_retained(
        retained: &RetainedCodingGroup,
        transcript_hash: [u8; 32],
        authorization: CatalogCodingAuthorization,
    ) -> Result<Self, CatalogStoreError> {
        // Bound typed callers too, before the legacy descriptor validator
        // computes an encoded identity. The original witness contains this
        // entire descriptor and already has this fixed per-object ceiling.
        canonical_size_bounded(&retained.group, CATALOG_CODING_TRANSCRIPT_BYTES)?;
        retained.group.validate()?;
        if transcript_hash == [0; 32] {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Self {
            guild_id: retained.group.guild_id,
            lifecycle: CatalogCodingLifecycle {
                group_id: retained.group.id,
                added_at_event: retained.added_at_event,
                retired_at_event: retained.retired_at_event,
                retain_through_event: retained.retain_through_event,
            },
            profile: retained.group.profile,
            transcript_hash,
            authorization,
        })
    }

    fn matches(
        self,
        group: CatalogIndexedDirectoryCodingGroup,
        trust: &CatalogCheckpointCodingTrust,
    ) -> bool {
        self.guild_id == trust.checkpoint.guild_id
            && self.lifecycle.group_id == group.group.range.group_id
            && self.profile == group.group.profile
            && self.transcript_hash == group.group.range.transcript_hash
            && self.lifecycle.added_at_event == group.group.added_at_event
            && self.lifecycle.retired_at_event == group.group.retired_at_event
            && self.lifecycle.retain_through_event == group.group.retain_through_event
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Manifest {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    work: Work,
}

fn scan_reservation(groups: u64, sectors: u64, members: usize) -> Result<Work, CatalogStoreError> {
    // Charge fixed cursor/fact/writeback rows at 256 bytes, roster rows at
    // 512 and fixed markers at 4 KiB. Internal row access preserves every
    // geometry check while completion is rechecked around the whole scan,
    // avoiding repeated descriptor reads for millions of point lookups.
    let members = (members as u64)
        .checked_mul(8)
        .ok_or(CatalogError::Bounds)?;
    let data = groups
        .checked_mul(12)
        .and_then(|rows| rows.checked_add(sectors.checked_mul(16)?))
        .ok_or(CatalogError::Bounds)?;
    let rows = 64_u64
        .checked_add(members)
        .and_then(|rows| rows.checked_add(data))
        .ok_or(CatalogError::Bounds)?;
    let bytes = 64_u64
        .checked_mul(DESCRIPTOR_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(members.checked_mul(MEMBER_BYTES as u64)?))
        .and_then(|bytes| bytes.checked_add(data.checked_mul(ROW_BYTES as u64)?))
        .and_then(|bytes| bytes.checked_add(DESCRIPTOR_BYTES as u64))
        .ok_or(CatalogError::Bounds)?;
    Ok(Work {
        bytes,
        records: rows,
        page_occurrences: 0,
    })
}

fn build(
    index: &CatalogCheckpointCodingDirectoryIndex,
    trust: &CatalogCheckpointCodingTrust,
    header: PagedGuildCheckpoint,
    manifest: Manifest,
    read_trust: &mut impl FnMut() -> Result<CatalogCheckpointCodingTrust, CatalogStoreError>,
    read_group: &mut impl FnMut(
        [u8; 32],
        &CatalogCheckpointCodingTrust,
    ) -> Result<Option<CatalogCertifiedCodingGroup>, CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    let directory = index.index();
    let store = &directory.packing().store;
    let summary = header.coding.summary.coding;
    for kind in KINDS {
        if store
            .next_record_bounded(kind, None, 32, DESCRIPTOR_BYTES)?
            .is_some()
        {
            return Err(DatabaseError::Conflict.into());
        }
    }
    let mut after = None;
    let mut groups = 0_u64;
    let mut retired = 0_u64;
    while let Some(group) = directory.next_group_row(after)? {
        groups = groups.checked_add(1).ok_or(CatalogError::Bounds)?;
        if groups > summary.groups {
            return Err(DatabaseError::Integrity.into());
        }
        let id = group.group.range.group_id;
        let certified = read_group(id, trust)?.ok_or(DatabaseError::NotReady)?;
        if !certified.matches(group, trust) {
            return Err(DatabaseError::Conflict.into());
        }
        let is_retired = group.group.retired_at_event.is_some();
        retired += u64::from(is_retired);
        put(
            store,
            PLACEMENT,
            &id,
            &(!is_retired
                && certified.authorization == CatalogCodingAuthorization::CurrentPlacement),
            ROW_BYTES,
        )?;
        after = Some(id);
    }
    if groups != summary.groups || retired != summary.retired_groups {
        return Err(DatabaseError::Integrity.into());
    }
    let mut after: Option<[u8; 32]> = None;
    let mut sectors = 0_u64;
    while let Some((key, bytes)) = store.next_record_bounded(
        SECTORS,
        after.as_ref().map(|key| key.as_slice()),
        32,
        ROW_BYTES,
    )? {
        sectors = sectors.checked_add(1).ok_or(CatalogError::Bounds)?;
        if sectors > header.packed_sectors.sectors {
            return Err(DatabaseError::Integrity.into());
        }
        let sector: CatalogPackingSector = decode_row(&bytes)?;
        if key != sector.id || directory.packing().sector_row(sector.id)? != Some(sector.clone()) {
            return Err(DatabaseError::Integrity.into());
        }
        let coverage = directory
            .coverage_row(sector.id)?
            .ok_or(DatabaseError::NotReady)?;
        let placement = store
            .get_record_bounded(PLACEMENT, &coverage.group_id, ROW_BYTES)?
            .ok_or(DatabaseError::NotReady)?;
        if !decode_row::<bool>(&placement)? {
            return Err(DatabaseError::NotReady.into());
        }
        after = Some(sector.id);
    }
    if sectors != header.packed_sectors.sectors {
        return Err(DatabaseError::Integrity.into());
    }
    if read_trust()? != *trust || index.header(&trust.checkpoint)? != header {
        return Err(DatabaseError::Conflict.into());
    }
    put(store, COMPLETE, b"root", &manifest, DESCRIPTOR_BYTES)
}

/// Complete exact certified-current variable coding state in the same private
/// encrypted index. Only this wrapper can proceed to authority transition and
/// draft paged signing. Fixed legacy migration, full lifecycle transition/
/// publication, private joins, payload custody and quotas remain mandatory.
pub struct CatalogCheckpointCodingStateIndex {
    index: CatalogCheckpointCodingDirectoryIndex,
    trust: CatalogCheckpointCodingTrust,
    manifest: Manifest,
    budget: Work,
}

impl CatalogCheckpointCodingDirectoryIndex {
    /// `read_trust` and `read_group` must use the same independently certified
    /// history snapshot. Each lookup returns already verified fixed indexed
    /// facts for the original retained group, add witness and placement. Any
    /// history ingestion/replay needs its own enclosing admission before this
    /// phase; these point reads must not load or replay a catalog-sized state.
    /// Reject unavailable/unverified history, legacy binding gaps and delegation
    /// failures rather than deriving facts from this proposal.
    /// The supplied job budget admits the complete public input and all scan
    /// work before any group lookup. No production writer spans these calls.
    pub fn validate_certified_coding_state(
        self,
        budget: Work,
        read_trust: impl FnMut() -> Result<CatalogCheckpointCodingTrust, CatalogStoreError>,
        read_group: impl FnMut(
            [u8; 32],
            &CatalogCheckpointCodingTrust,
        )
            -> Result<Option<CatalogCertifiedCodingGroup>, CatalogStoreError>,
    ) -> Result<CatalogCheckpointCodingStateIndex, CatalogStoreError> {
        self.validate_certified_coding_state_with_work(
            budget,
            Work::default(),
            read_trust,
            read_group,
        )
    }

    /// Use the completed bounded original-history reader and carry its whole
    /// replay debt into this proof and subsequent authority transitions. The
    /// independent current tip is rechecked around the enclosing group scan.
    pub fn validate_certified_history_coding_state(
        self,
        history: &CatalogGuildHistoryIndex,
        budget: Work,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<CatalogCheckpointCodingStateIndex, CatalogStoreError> {
        let view = history.view(&mut read_trust)?;
        self.validate_certified_coding_state_with_work(
            budget,
            history.represented_work(),
            || Ok(history.view(&mut read_trust)?.coding_trust()),
            |id, trust| view.coding_group(id, trust),
        )
    }

    fn validate_certified_coding_state_with_work(
        self,
        budget: Work,
        prior_work: Work,
        mut read_trust: impl FnMut() -> Result<CatalogCheckpointCodingTrust, CatalogStoreError>,
        mut read_group: impl FnMut(
            [u8; 32],
            &CatalogCheckpointCodingTrust,
        )
            -> Result<Option<CatalogCertifiedCodingGroup>, CatalogStoreError>,
    ) -> Result<CatalogCheckpointCodingStateIndex, CatalogStoreError> {
        let trust = read_trust()?;
        trust.validate()?;
        let header = self.header(&trust.checkpoint)?;
        let summary = header.coding.summary.coding;
        if summary.groups != trust.retained_groups || summary.retired_groups != trust.retired_groups
        {
            return Err(DatabaseError::Conflict.into());
        }
        let work = prior_work
            .checked_add(header.represented_work()?)?
            .checked_add(scan_reservation(
                summary.groups,
                header.packed_sectors.sectors,
                trust.checkpoint.members.len(),
            )?)?;
        budget.remaining_after(work)?;
        let manifest = Manifest {
            format_version: 1,
            checkpoint_hash: header.hash()?,
            snapshot_hash: trust.hash()?,
            work,
        };
        self.index().packing().store.with_record_transaction(|| {
            build(
                &self,
                &trust,
                header,
                manifest,
                &mut read_trust,
                &mut read_group,
            )
        })?;
        Ok(CatalogCheckpointCodingStateIndex {
            index: self,
            trust,
            manifest,
            budget,
        })
    }
}

impl CatalogCheckpointCodingStateIndex {
    pub fn index(&self) -> &CatalogCheckpointCodingDirectoryIndex {
        &self.index
    }
    pub fn trust(&self) -> &CatalogCheckpointCodingTrust {
        &self.trust
    }
    pub fn represented_work(&self) -> Work {
        self.manifest.work
    }
    pub fn budget(&self) -> Work {
        self.budget
    }
    pub(super) fn header(
        &self,
        trust: &PagedCheckpointTrust,
    ) -> Result<PagedGuildCheckpoint, CatalogStoreError> {
        if trust != &self.trust.checkpoint {
            return Err(DatabaseError::Conflict.into());
        }
        let header = self.index.header(trust)?;
        self.budget.remaining_after(self.manifest.work)?;
        let store = &self.index.index().packing().store;
        if self.manifest.format_version != 1
            || self.manifest.checkpoint_hash != header.hash()?
            || self.manifest.snapshot_hash != self.trust.hash()?
            || store
                .get_record_bounded(COMPLETE, b"root", DESCRIPTOR_BYTES)?
                .as_deref()
                != Some(
                    mb_core::canonical_bytes_bounded(&self.manifest, DESCRIPTOR_BYTES)?.as_slice(),
                )
        {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::super::checkpoint_validation::tests::Fixture;
    use super::super::coding_coverage::tests::entry;
    use super::*;
    use mb_core::canonical_bytes_bounded;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    type Facts = BTreeMap<[u8; 32], CatalogCertifiedCodingGroup>;

    fn budget() -> Work {
        Work {
            bytes: 96 << 30,
            page_occurrences: 2_000_000,
            records: 128_000_000,
        }
    }
    fn facts(entries: &[mb_core::CatalogCodingEntry]) -> Facts {
        entries
            .iter()
            .map(|entry| {
                let value = CatalogCertifiedCodingGroup::from_retained(
                    &entry.retained,
                    canonical_hash_bounded(&entry.transcript, CATALOG_CODING_TRANSCRIPT_BYTES)
                        .unwrap(),
                    CatalogCodingAuthorization::CurrentPlacement,
                )
                .unwrap();
                (value.lifecycle.group_id, value)
            })
            .collect()
    }
    fn one() -> (
        CatalogCheckpointCodingDirectoryIndex,
        CatalogCheckpointCodingTrust,
        Facts,
    ) {
        let mut fixture = Fixture::new(true, false);
        let (index, original) =
            fixture.joined_with_entry(budget(), CatalogCodingCoveragePolicy::Current);
        let trust = CatalogCheckpointCodingTrust {
            checkpoint: fixture.trust(),
            retained_groups: 1,
            retired_groups: 0,
        };
        (index, trust, facts(&[original]))
    }
    fn many() -> (
        CatalogCheckpointCodingDirectoryIndex,
        CatalogCheckpointCodingTrust,
        Facts,
    ) {
        let mut fixture = Fixture::new(true, false);
        let (index, originals) = fixture.joined_with_groups(
            budget(),
            CatalogCodingCoveragePolicy::Current,
            |inputs, entries| {
                entries
                    .into_iter()
                    .chain((1..32).map(|id| entry(inputs, [0, 1, 2], 701 + id, 2, None)))
                    .collect()
            },
        );
        let trust = CatalogCheckpointCodingTrust {
            checkpoint: fixture.trust(),
            retained_groups: 32,
            retired_groups: 0,
        };
        (index, trust, facts(&originals))
    }
    fn join(
        index: CatalogCheckpointCodingDirectoryIndex,
        trust: &CatalogCheckpointCodingTrust,
        facts: &Facts,
        limit: Work,
    ) -> Result<CatalogCheckpointCodingStateIndex, CatalogStoreError> {
        index.validate_certified_coding_state(
            limit,
            || Ok(trust.clone()),
            |id, snapshot| {
                assert_eq!(snapshot, trust);
                Ok(facts.get(&id).copied())
            },
        )
    }
    fn prepare(
        index: &CatalogCheckpointCodingDirectoryIndex,
        trust: &CatalogCheckpointCodingTrust,
    ) -> (PagedGuildCheckpoint, Manifest) {
        let header = index.header(&trust.checkpoint).unwrap();
        let work = header
            .represented_work()
            .unwrap()
            .checked_add(
                scan_reservation(
                    trust.retained_groups,
                    header.packed_sectors.sectors,
                    trust.checkpoint.members.len(),
                )
                .unwrap(),
            )
            .unwrap();
        (
            header,
            Manifest {
                format_version: 1,
                checkpoint_hash: header.hash().unwrap(),
                snapshot_hash: trust.hash().unwrap(),
                work,
            },
        )
    }
    fn assert_rollback(index: &CatalogCheckpointCodingDirectoryIndex) {
        for kind in KINDS {
            assert!(
                index
                    .index()
                    .packing()
                    .store
                    .next_record_bounded(kind, None, 32, DESCRIPTOR_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
        index.require_complete().unwrap();
    }

    #[test]
    fn certified_coding_state_binds_original_identity_and_complete_retained_counts() {
        let mut fixture = Fixture::new(true, false);
        let (index, originals) = fixture.joined_with_groups(
            budget(),
            CatalogCodingCoveragePolicy::Current,
            |inputs, mut entries| {
                let mut retired = entry(inputs, [0, 1, 2], 702, 2, None);
                retired.retained.retired_at_event = Some(7);
                retired.retained.retain_through_event = Some(1000);
                entries.push(retired);
                let mut unrelated = super::super::packing_validation::tests::fixture(3, true);
                unrelated.manifest.scope = inputs.manifest.scope;
                for (index, sector) in unrelated.sectors.iter_mut().enumerate() {
                    sector.id = [220 + index as u8; 32];
                }
                entries.push(entry(&unrelated, [0, 1, 2], 703, 2, None));
                entries
            },
        );
        let trust = CatalogCheckpointCodingTrust {
            checkpoint: fixture.trust(),
            retained_groups: 3,
            retired_groups: 1,
        };
        let mut facts = facts(&originals);
        assert!(
            CatalogCertifiedCodingGroup::from_retained(
                &originals[0].retained,
                [0; 32],
                CatalogCodingAuthorization::Retained
            )
            .is_err()
        );
        let mut invalid = originals[0].retained.clone();
        invalid.group.id[0] ^= 1;
        assert!(
            CatalogCertifiedCodingGroup::from_retained(
                &invalid,
                [1; 32],
                CatalogCodingAuthorization::Retained
            )
            .is_err()
        );
        let mut oversized = originals[0].retained.clone();
        let mb_core::ShardRoleV2::Information(info) = &mut oversized.group.roles[0] else {
            unreachable!()
        };
        info.failure_domain = "x".repeat(CATALOG_CODING_TRANSCRIPT_BYTES + 1);
        assert!(matches!(
            CatalogCertifiedCodingGroup::from_retained(
                &oversized,
                [1; 32],
                CatalogCodingAuthorization::Retained
            ),
            Err(CatalogStoreError::Model(
                ModelError::EncodingTooLarge { .. }
            ))
        ));
        // Only the original active group covers current input. Retired and
        // unrelated retained history need no current-placement claim.
        for fact in facts.values_mut() {
            if fact.lifecycle.retired_at_event.is_some() {
                fact.authorization = CatalogCodingAuthorization::Retained;
            }
        }
        let unrelated = originals
            .iter()
            .find(|entry| {
                entry.transcript.value.plan.value.attempt_id[..8] == 703_u64.to_be_bytes()
            })
            .unwrap();
        facts
            .get_mut(&unrelated.retained.group.id)
            .unwrap()
            .authorization = CatalogCodingAuthorization::Retained;
        let calls = Cell::new(0);
        let completed = index
            .validate_certified_coding_state(
                budget(),
                || Ok(trust.clone()),
                |id, snapshot| {
                    assert_eq!(snapshot, &trust);
                    calls.set(calls.get() + 1);
                    Ok(facts.get(&id).copied())
                },
            )
            .unwrap();
        assert_eq!(calls.get(), 3);
        assert_eq!(completed.trust(), &trust);
        assert_eq!(completed.budget(), budget());
        assert_eq!(
            completed
                .header(&trust.checkpoint)
                .unwrap()
                .coding
                .summary
                .coding
                .groups,
            3
        );
        let mut after = None;
        for expected in &originals {
            let group = completed
                .index()
                .index()
                .next_group(after)
                .unwrap()
                .unwrap();
            assert_eq!(group.group.range.group_id, expected.retained.group.id);
            assert_eq!(
                group.group.range.transcript_hash,
                facts[&group.group.range.group_id].transcript_hash
            );
            after = Some(group.group.range.group_id);
        }
        assert!(
            completed
                .index()
                .index()
                .next_group(after)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn certified_coding_state_rejects_untrusted_counts_and_original_fact_substitutions() {
        for mode in 0..9 {
            let (index, mut trust, _) = one();
            match mode {
                0 => trust.retained_groups = 0,
                1 => trust.retained_groups += 1,
                2 => trust.retired_groups = 1,
                3 => trust.retired_groups = 2,
                4 => trust.checkpoint.event_head[0] ^= 1,
                5 => trust.checkpoint.authority.membership_epoch += 1,
                6 => trust.checkpoint.members[0].failure_domain.push('x'),
                7 => trust.checkpoint.event_sequence -= 1,
                _ => trust.checkpoint.guild_id[0] ^= 1,
            }
            assert!(
                index
                    .validate_certified_coding_state(
                        budget(),
                        || Ok(trust.clone()),
                        |_, _| panic!("invalid independent snapshot looked up a group")
                    )
                    .is_err(),
                "mode {mode}"
            );
        }
        for mode in 0..10 {
            let (index, trust, mut facts) = one();
            let fact = facts.values_mut().next().unwrap();
            match mode {
                0 => fact.guild_id[0] ^= 1,
                1 => fact.lifecycle.group_id[0] ^= 1,
                2 => fact.transcript_hash[0] ^= 1,
                3 => fact.profile.data_shards += 1,
                4 => fact.lifecycle.added_at_event += 1,
                5 => fact.lifecycle.retired_at_event = Some(7),
                6 => fact.lifecycle.retain_through_event = Some(1000),
                7 => facts.clear(),
                8 => {
                    assert!(
                        index
                            .validate_certified_coding_state(
                                budget(),
                                || Ok(trust.clone()),
                                |_, _| Err(DatabaseError::NotReady.into())
                            )
                            .is_err()
                    );
                    continue;
                }
                _ => fact.authorization = CatalogCodingAuthorization::Retained,
            }
            assert!(
                join(index, &trust, &facts, budget()).is_err(),
                "mode {mode}"
            );
        }
    }

    #[test]
    fn certified_coding_state_rechecks_snapshot_after_all_groups_and_rejects_historical_coverage() {
        for mode in 0..6 {
            let (index, trust, facts) = one();
            let snapshots = Cell::new(0);
            let groups = Cell::new(0);
            assert!(
                index
                    .validate_certified_coding_state(
                        budget(),
                        || {
                            snapshots.set(snapshots.get() + 1);
                            let mut current = trust.clone();
                            if snapshots.get() == 2 {
                                match mode {
                                    0 => current.retained_groups += 1,
                                    1 => current.retired_groups += 1,
                                    2 => current.checkpoint.event_head[0] ^= 1,
                                    3 => current.checkpoint.previous.as_mut().unwrap().hash[0] ^= 1,
                                    4 => current.checkpoint.members[0].failure_domain.push('x'),
                                    _ => return Err(DatabaseError::NotReady.into()),
                                }
                            }
                            Ok(current)
                        },
                        |id, _| {
                            groups.set(groups.get() + 1);
                            Ok(facts.get(&id).copied())
                        }
                    )
                    .is_err(),
                "mode {mode}"
            );
            assert_eq!(snapshots.get(), 2);
            assert_eq!(groups.get(), 1);
        }
        let mut fixture = Fixture::new(true, false);
        let index = fixture.joined(budget(), CatalogCodingCoveragePolicy::Historical);
        let trust = CatalogCheckpointCodingTrust {
            checkpoint: fixture.trust(),
            retained_groups: 1,
            retired_groups: 0,
        };
        assert!(
            index
                .validate_certified_coding_state(
                    budget(),
                    || Ok(trust.clone()),
                    |_, _| panic!("historical-only coverage looked up coding state")
                )
                .is_err()
        );
    }

    #[test]
    fn certified_coding_state_admits_complete_public_input_and_all_scan_work_before_lookup() {
        let (index, trust, facts) = one();
        let public = index
            .header(&trust.checkpoint)
            .unwrap()
            .represented_work()
            .unwrap();
        let completed = join(index, &trust, &facts, budget()).unwrap();
        let work = completed.represented_work();
        assert!(work.bytes > public.bytes);
        assert!(work.records > public.records);
        assert_eq!(work.page_occurrences, public.page_occurrences);
        drop(completed);
        let (index, trust, facts) = one();
        let completed = join(index, &trust, &facts, work).unwrap();
        assert_eq!(completed.budget(), work);
        assert_eq!(completed.represented_work(), work);
        drop(completed);
        for dimension in 0..3 {
            let (index, trust, _) = one();
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                index
                    .validate_certified_coding_state(
                        limit,
                        || Ok(trust.clone()),
                        |_, _| panic!("exhausted certified coding budget looked up history")
                    )
                    .is_err()
            );
        }
        for (groups, sectors) in [(u64::MAX, 0), (0, u64::MAX)] {
            assert!(scan_reservation(groups, sectors, 256).is_err());
        }
    }

    #[test]
    fn certified_history_replay_debt_survives_the_coding_join() {
        let (index, trust, facts) = one();
        let base = join(index, &trust, &facts, budget())
            .unwrap()
            .represented_work();
        let prior = Work {
            bytes: 123_456,
            page_occurrences: 17,
            records: 701,
        };
        let exact = base.checked_add(prior).unwrap();
        let (index, trust, facts) = one();
        let proof = index
            .validate_certified_coding_state_with_work(
                exact,
                prior,
                || Ok(trust.clone()),
                |id, _| Ok(facts.get(&id).copied()),
            )
            .unwrap();
        assert_eq!(proof.represented_work(), exact);
        proof.header(&trust.checkpoint).unwrap();
        for dimension in 0..3 {
            let (index, trust, _) = one();
            let mut short = exact;
            match dimension {
                0 => short.bytes -= 1,
                1 => short.page_occurrences -= 1,
                _ => short.records -= 1,
            }
            assert!(
                index
                    .validate_certified_coding_state_with_work(
                        short,
                        prior,
                        || Ok(trust.clone()),
                        |_, _| panic!("under-admitted history debt reached a group lookup")
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn certified_coding_state_rejects_orphan_ignored_missing_and_extra_rows() {
        for kind in KINDS {
            let (index, trust, facts) = one();
            index
                .index()
                .packing()
                .store
                .put_record_if_absent(kind, b"orphan", b"")
                .unwrap();
            assert!(join(index, &trust, &facts, budget()).is_err());
        }
        for kind in KINDS {
            let (index, trust, facts) = one();
            let (header, manifest) = prepare(&index, &trust);
            let store = &index.index().packing().store;
            store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_coding BEFORE INSERT ON scratch.protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
            assert!(
                store
                    .with_record_transaction(|| build(
                        &index,
                        &trust,
                        header,
                        manifest,
                        &mut || Ok(trust.clone()),
                        &mut |id, _| Ok(facts.get(&id).copied())
                    ))
                    .is_err()
            );
            assert_rollback(&index);
        }
        for kind in [
            "packing-coding-directory-group",
            "packing-coding-directory-coverage",
            SECTORS,
        ] {
            let (index, trust, facts) = one();
            let store = &index.index().packing().store;
            let (key, bytes) = store
                .next_record_bounded(kind, None, 32, ROW_BYTES)
                .unwrap()
                .unwrap();
            store.delete_record_if_value(kind, &key, &bytes).unwrap();
            assert!(join(index, &trust, &facts, budget()).is_err(), "{kind}");
        }
        let (index, trust, facts) = one();
        let mut extra = index.index().next_group(None).unwrap().unwrap();
        extra.group.range.group_id = [255; 32];
        index
            .index()
            .packing()
            .store
            .put_record_if_absent(
                "packing-coding-directory-group",
                &[255; 32],
                &canonical_bytes_bounded(&extra, ROW_BYTES).unwrap(),
            )
            .unwrap();
        assert!(join(index, &trust, &facts, budget()).is_err());
        let (index, trust, facts) = one();
        join(index, &trust, &facts, budget()).unwrap();
    }

    #[test]
    fn certified_coding_state_rolls_back_late_history_and_real_storage_failures_then_rebuilds() {
        let (index, trust, facts) = many();
        let (header, manifest) = prepare(&index, &trust);
        let store = &index.index().packing().store;
        let last = *facts.last_key_value().unwrap().0;
        let calls = Cell::new(0);
        assert!(
            store
                .with_record_transaction(|| build(
                    &index,
                    &trust,
                    header,
                    manifest,
                    &mut || Ok(trust.clone()),
                    &mut |id, _| {
                        calls.set(calls.get() + 1);
                        if id == last {
                            Err(DatabaseError::NotReady.into())
                        } else {
                            Ok(facts.get(&id).copied())
                        }
                    }
                ))
                .is_err()
        );
        assert_eq!(calls.get(), 32);
        assert_rollback(&index);
        let pages = store
            .database_shell_statement("PRAGMA scratch.page_count", false)
            .unwrap()
            .rows[0][0]
            .parse::<u64>()
            .unwrap();
        store
            .database_shell_statement(&format!("PRAGMA scratch.max_page_count={pages}"), false)
            .unwrap();
        calls.set(0);
        assert!(
            store
                .with_record_transaction(|| build(
                    &index,
                    &trust,
                    header,
                    manifest,
                    &mut || Ok(trust.clone()),
                    &mut |id, _| {
                        calls.set(calls.get() + 1);
                        Ok(facts.get(&id).copied())
                    }
                ))
                .is_err()
        );
        assert!(calls.get() > 0);
        assert_rollback(&index);
        drop(index);
        let (index, trust, facts) = many();
        let completed = join(index, &trust, &facts, budget()).unwrap();
        assert_eq!(completed.trust().retained_groups, 32);
        completed.header(&trust.checkpoint).unwrap();
    }
}

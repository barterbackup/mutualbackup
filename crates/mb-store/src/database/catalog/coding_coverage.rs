//! Bounded packing/coding joins in the same admitted disposable index. These
//! proofs bind public metadata, not durable payloads or checkpoint activation.

use mb_core::{
    CATALOG_CODING_MAX_BYTES, CATALOG_MAX_PAGE_OCCURRENCES, CatalogCodingEntry,
    CatalogCodingGroupRange, CatalogCodingReader, CodingProfile, NodeId, ShardRoleV2,
    canonical_bytes_bounded, canonical_size_bounded,
};

use super::packing_validation::unwrap_stream;
use super::*;
use crate::RecordScratchStore;

const MANIFEST_BYTES: usize = 4096;
const ROW_BYTES: usize = 256;
const GROUPS: &str = "packing-coding-group";
const COVERAGE: &str = "packing-coding-coverage";
const COMPLETE: &str = "packing-coding-complete";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogCodingCoveragePolicy {
    Current,
    Historical,
}

/// The required authorizer checks certified delegation, original membership
/// and domains, the retained add/retire events and their original witness hash.
/// CurrentPlacement additionally certifies placement against current membership
/// and domains. Historical authority alone cannot cover a current checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogCodingAuthorization {
    Retained,
    CurrentPlacement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingCodingValidation {
    pub format_version: u16,
    pub packing: CatalogPackingValidation,
    pub coding: CatalogCodingValidation,
    pub policy: CatalogCodingCoveragePolicy,
}

impl CatalogPackingCodingValidation {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > MANIFEST_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate()?;
        if canonical_bytes_bounded(&manifest, MANIFEST_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), CatalogStoreError> {
        self.packing.validate()?;
        self.coding.validate()?;
        if self.format_version != 1 || self.packing.scope != self.coding.scope {
            return Err(DatabaseError::Conflict.into());
        }
        let (bytes, pages) = self.represented_work()?;
        if bytes > CATALOG_CODING_MAX_BYTES || pages > CATALOG_MAX_PAGE_OCCURRENCES {
            return Err(CatalogError::Bounds.into());
        }
        Ok(())
    }

    /// One aggregate budget, including the combined descriptor and every page
    /// occurrence across packing and coding. Repeated roots are charged again.
    pub fn represented_work(&self) -> Result<(u64, u64), CatalogStoreError> {
        let mut bytes = canonical_size_bounded(self, MANIFEST_BYTES)? as u64;
        let mut pages = 0_u64;
        for page in [
            self.packing.descriptors.records.page,
            self.packing.sources.records.page,
        ]
        .into_iter()
        .chain(self.coding.root.parts.iter().map(|part| part.page))
        {
            bytes = bytes
                .checked_add(page.byte_len)
                .ok_or(CatalogError::Bounds)?;
            pages = pages
                .checked_add(page.page_occurrences)
                .ok_or(CatalogError::Bounds)?;
        }
        Ok((bytes, pages))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingCoverage {
    pub group_id: [u8; 32],
    pub shard_index: u16,
    pub holder: NodeId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogIndexedCodingGroup {
    pub profile: CodingProfile,
    pub range: CatalogCodingGroupRange,
    pub added_at_event: u64,
    pub retired_at_event: Option<u64>,
    pub retain_through_event: Option<u64>,
}

fn put<T: Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
    value: &T,
    limit: usize,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes_bounded(value, limit)?;
    if !store.put_record_if_absent(kind, key, &bytes)?
        || store.get_record_bounded(kind, key, limit)?.as_deref() != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn decode_row<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value: T = decode_canonical(bytes)?;
    if canonical_bytes_bounded(&value, ROW_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

pub(super) fn build(
    packing: &CatalogPackingIndex,
    manifest: &CatalogPackingCodingValidation,
    fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    authorize: &mut impl FnMut(
        &CatalogCodingEntry,
    ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    packing.require_complete()?;
    manifest.validate()?;
    if packing.manifest != manifest.packing {
        return Err(DatabaseError::Conflict.into());
    }
    for kind in [GROUPS, COVERAGE, COMPLETE] {
        if packing
            .store
            .next_record_bounded(kind, None, 32, MANIFEST_BYTES)?
            .is_some()
        {
            return Err(DatabaseError::Conflict.into());
        }
    }
    let mut pending = packing.manifest.descriptors.sectors;
    let mut reader = CatalogCodingReader::new(manifest.coding.scope, manifest.coding.root.clone())?;
    while let Some(entry) = unwrap_stream(reader.next_group(fetch))? {
        let authority = authorize(&entry)?;
        let group = &entry.retained.group;
        let range = reader.last_group_range().ok_or(DatabaseError::Integrity)?;
        put(
            &packing.store,
            GROUPS,
            &group.id,
            &CatalogIndexedCodingGroup {
                profile: group.profile,
                range,
                added_at_event: entry.retained.added_at_event,
                retired_at_event: entry.retained.retired_at_event,
                retain_through_event: entry.retained.retain_through_event,
            },
            ROW_BYTES,
        )?;
        for (index, role) in group.roles.iter().enumerate() {
            let ShardRoleV2::Information(info) = role else {
                continue;
            };
            if info.sector.virtual_zero {
                continue;
            }
            let Some(sector) = packing.sector(info.sector.id)? else {
                continue;
            };
            let plan = &entry.transcript.value.plan.value;
            if info.sector.commitment != sector.commitment
                || info.sector.logical_len != sector.commitment.byte_len
                || group.profile.shard_size != sector.commitment.byte_len
                || plan
                    .information_root(index)
                    .is_some_and(|root| root != sector.flat_root)
            {
                return Err(DatabaseError::Conflict.into());
            }
            if plan.information_root(index).is_none()
                || entry.retained.retired_at_event.is_some()
                || manifest.policy == CatalogCodingCoveragePolicy::Current
                    && (authority != CatalogCodingAuthorization::CurrentPlacement
                        || sector.flat_root != sector.commitment.root && plan.format_version != 3)
            {
                continue;
            }
            if packing
                .store
                .get_record_bounded(COVERAGE, &sector.id, ROW_BYTES)?
                .is_none()
            {
                put(
                    &packing.store,
                    COVERAGE,
                    &sector.id,
                    &CatalogCodingCoverage {
                        group_id: group.id,
                        shard_index: index as u16,
                        holder: info.owner,
                    },
                    ROW_BYTES,
                )?;
                pending = pending.checked_sub(1).ok_or(DatabaseError::Integrity)?;
            }
        }
    }
    if pending != 0 {
        return Err(DatabaseError::NotReady.into());
    }
    put(&packing.store, COMPLETE, b"root", manifest, MANIFEST_BYTES)
}

/// Created only after both packing EOFs, the complete coding forest and exact
/// coverage of every verified packed descriptor. One group witness is decoded
/// at a time; fixed index rows provide recovery lookup without a catalog scan.
pub struct CatalogPackingCodingIndex {
    pub(super) packing: CatalogPackingIndex,
    pub(super) manifest: CatalogPackingCodingValidation,
}

impl CatalogPackingIndex {
    pub fn validate_coding(
        self,
        coding: CatalogCodingValidation,
        policy: CatalogCodingCoveragePolicy,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(
            &CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogPackingCodingIndex, CatalogStoreError> {
        let manifest = CatalogPackingCodingValidation {
            format_version: 1,
            packing: self.manifest,
            coding,
            policy,
        };
        self.store
            .with_record_transaction(|| build(&self, &manifest, &mut fetch, &mut authorize))?;
        Ok(CatalogPackingCodingIndex {
            packing: self,
            manifest,
        })
    }
}

impl CatalogPackingCodingIndex {
    pub fn manifest(&self) -> &CatalogPackingCodingValidation {
        &self.manifest
    }
    pub fn packing(&self) -> &CatalogPackingIndex {
        &self.packing
    }

    fn require_complete(&self) -> Result<(), CatalogStoreError> {
        self.packing.require_complete()?;
        let expected = canonical_bytes_bounded(&self.manifest, MANIFEST_BYTES)?;
        if self
            .packing
            .store
            .get_record_bounded(COMPLETE, b"root", MANIFEST_BYTES)?
            .as_deref()
            != Some(expected.as_slice())
        {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }

    pub fn coverage(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogCodingCoverage>, CatalogStoreError> {
        self.require_complete()?;
        let Some(bytes) = self
            .packing
            .store
            .get_record_bounded(COVERAGE, &id, ROW_BYTES)?
        else {
            return Ok(None);
        };
        let value: CatalogCodingCoverage = decode_row(&bytes)?;
        if self.packing.sector(id)?.is_none()
            || value.group_id == [0; 32]
            || value.holder.0 == [0; 32]
            || self.group(value.group_id)?.is_none_or(|group| {
                group.retired_at_event.is_some() || value.shard_index >= group.profile.data_shards
            })
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(value))
    }

    fn group(&self, id: [u8; 32]) -> Result<Option<CatalogIndexedCodingGroup>, CatalogStoreError> {
        let Some(bytes) = self
            .packing
            .store
            .get_record_bounded(GROUPS, &id, ROW_BYTES)?
        else {
            return Ok(None);
        };
        let group: CatalogIndexedCodingGroup = decode_row(&bytes)?;
        self.validate_group(&group)?;
        if group.range.group_id != id {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(group))
    }

    fn validate_group(&self, group: &CatalogIndexedCodingGroup) -> Result<(), CatalogStoreError> {
        let range = group.range;
        let part = self
            .manifest
            .coding
            .root
            .parts
            .get(usize::from(range.part))
            .ok_or(DatabaseError::Integrity)?;
        let end = range
            .offset
            .checked_add(u64::from(range.len))
            .ok_or(DatabaseError::Integrity)?;
        if group.profile.validate().is_err()
            || range.group_id == [0; 32]
            || range.transcript_hash == [0; 32]
            || range.offset < 8
            || range.len == 0
            || range.len as usize > mb_core::CATALOG_CODING_GROUP_BYTES
            || end > part.page.byte_len
            || group.added_at_event == 0
            || group.added_at_event > self.manifest.coding.root.guild_event_sequence
            || group.retired_at_event.is_some() != group.retain_through_event.is_some()
            || group.retired_at_event.is_some_and(|event| {
                event < group.added_at_event
                    || event > self.manifest.coding.root.guild_event_sequence
            })
            || group
                .retain_through_event
                .is_some_and(|event| event < group.retired_at_event.unwrap_or(0))
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }

    pub fn next_group(
        &self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedCodingGroup>, CatalogStoreError> {
        self.require_complete()?;
        let Some((key, bytes)) = self.packing.store.next_record_bounded(
            GROUPS,
            after.as_ref().map(|key| key.as_slice()),
            32,
            ROW_BYTES,
        )?
        else {
            return Ok(None);
        };
        let group: CatalogIndexedCodingGroup = decode_row(&bytes)?;
        self.validate_group(&group)?;
        if key != group.range.group_id {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(group))
    }

    pub fn read_group(
        &self,
        id: [u8; 32],
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStoreError> {
        self.require_complete()?;
        let Some(group) = self.group(id)? else {
            return Ok(None);
        };
        let entry = unwrap_stream(self.manifest.coding.root.read_group(
            self.manifest.coding.scope,
            group.range,
            &mut fetch,
        ))?;
        if entry.retained.group.profile != group.profile
            || entry.retained.added_at_event != group.added_at_event
            || entry.retained.retired_at_event != group.retired_at_event
            || entry.retained.retain_through_event != group.retain_through_event
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(entry))
    }

    /// Atomically bind both packing streams and every coding part to one local
    /// bundle. Signing and live certified-authority rechecks remain external.
    pub fn as_local_bundle(
        &self,
        id: Uuid,
        packing: [CatalogIntent; 2],
        coding: &[CatalogIntent],
    ) -> Result<CatalogBundle, CatalogStoreError> {
        self.require_complete()?;
        if coding.len() != self.manifest.coding.root.parts.len() {
            return Err(DatabaseError::Conflict.into());
        }
        let mut bundle = self.packing.as_local_bundle(id, packing)?;
        for (intent, part) in coding.iter().zip(&self.manifest.coding.root.parts) {
            if intent.scope != self.manifest.coding.scope
                || intent.section != CatalogSection::Coding
            {
                return Err(DatabaseError::Conflict.into());
            }
            bundle.roots.push(CatalogBundleRoot {
                intent: *intent,
                root: part.page,
            });
        }
        bundle.descriptor = canonical_bytes_bounded(&self.manifest, MANIFEST_BYTES)?;
        bundle.validate()?;
        Ok(bundle)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::packing_validation::tests::{Fixture as PackingFixture, fixture};
    use super::*;
    use mb_core::{
        CODING_ATTEMPT_PLAN_DOMAIN, CODING_CHALLENGE_COMMITMENT_DOMAIN,
        CODING_CHALLENGE_REVEAL_DOMAIN, CODING_SHARD_OPENING_DOMAIN, CODING_TRANSCRIPT_DOMAIN,
        CatalogCodingBuilder, CatalogCodingRoot, CodingAttemptPlan, CodingChallengeCommitment,
        CodingChallengeReveal, CodingPlanGeometry, CodingProfile, CodingReplayFinding,
        CodingShardOpening, CodingVerificationTranscript, InformationRoleV2, KeyMaterial,
        ParityPlacementV2, RangeSectorRef, RetainedCodingGroup, STAGED_STORAGE_RECEIPT_DOMAIN,
        Seed, SignedRecord, StagedStorageReceipt, challenged_leaf, coding_challenge,
        coding_challenge_commitment, coding_evidence_hash, encode_coding_attempt, merkle_commit,
        merkle_open_range, replay_coding_transcript, sector_root,
    };
    use std::collections::HashMap;

    pub(crate) fn entry(
        fixture: &PackingFixture,
        indices: [usize; 3],
        id: u64,
        version: u16,
        virtual_index: Option<usize>,
    ) -> CatalogCodingEntry {
        let CatalogScope::Guild { guild_id } = fixture.manifest.scope else {
            panic!("test scope must be guild");
        };
        let keys = (0..8)
            .map(|index| {
                let mut seed = [index as u8 + 38; 32];
                seed[..8].copy_from_slice(&id.to_be_bytes());
                KeyMaterial::from_seed(&Seed::from_bytes(seed))
            })
            .collect::<Vec<_>>();
        let shard_size = fixture.manifest.descriptors.profile.sector_size;
        let information = indices
            .iter()
            .map(|index| fixture.bytes[*index].clone())
            .collect::<Vec<_>>();
        let mut attempt_id = [0; 16];
        attempt_id[..8].copy_from_slice(&id.to_be_bytes());
        let information_roles = indices
            .iter()
            .enumerate()
            .map(|(index, selected)| {
                let sector = &fixture.sectors[*selected];
                InformationRoleV2 {
                    owner: keys[index].node_id(),
                    failure_domain: format!("{id}:{index:012}"),
                    sector: RangeSectorRef {
                        id: sector.id,
                        commitment: sector.commitment.clone(),
                        logical_len: shard_size,
                        virtual_zero: virtual_index == Some(index),
                    },
                }
            })
            .collect();
        let plan = SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            CodingAttemptPlan {
                format_version: version,
                attempt_id,
                checkpoint_hash: [46; 32],
                membership_epoch: 1,
                geometry: CodingPlanGeometry {
                    format_version: 1,
                    guild_id,
                    profile: CodingProfile::new(3, 2, shard_size),
                    information: information_roles,
                    parity: (0..2)
                        .map(|row| ParityPlacementV2 {
                            holder: keys[row + 3].node_id(),
                            failure_domain: format!("{id}:{:012}", row + 3),
                            row: row as u16,
                        })
                        .collect(),
                },
                delegator: keys[5].node_id(),
                coding_coordinator: keys[6].node_id(),
                verification_coordinator: keys[7].node_id(),
                expires_at_unix_seconds: u64::MAX,
                information_roots: (version != 1).then(|| {
                    information
                        .iter()
                        .enumerate()
                        .map(|(index, bytes)| {
                            if virtual_index == Some(index) {
                                [0; 32]
                            } else if version == 2 {
                                fixture.sectors[indices[index]].flat_root
                            } else {
                                sector_root(bytes)
                            }
                        })
                        .collect()
                }),
            },
            &keys[5],
        )
        .unwrap();
        let plan_hash = plan.value.hash().unwrap();
        let (manifest, parity) = encode_coding_attempt(
            &plan,
            information
                .iter()
                .enumerate()
                .map(|(index, bytes)| (virtual_index != Some(index)).then(|| bytes.clone()))
                .collect(),
            &keys[6],
        )
        .unwrap();
        let receipts = (3..5)
            .map(|index| {
                let ShardRoleV2::Parity(parity) = &manifest.value.group.roles[index] else {
                    unreachable!()
                };
                SignedRecord::sign(
                    STAGED_STORAGE_RECEIPT_DOMAIN,
                    StagedStorageReceipt {
                        format_version: 1,
                        attempt_id,
                        plan_hash,
                        guild_id,
                        group_id: manifest.value.group.id,
                        shard_index: index as u16,
                        holder: parity.holder,
                        commitment: parity.commitment.clone(),
                    },
                    &keys[index],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let nonce = [47; 32];
        let evidence_hash = coding_evidence_hash(&manifest, &receipts).unwrap();
        let challenge = coding_challenge(plan_hash, nonce, evidence_hash);
        let commitment = SignedRecord::sign(
            CODING_CHALLENGE_COMMITMENT_DOMAIN,
            CodingChallengeCommitment {
                format_version: 1,
                attempt_id,
                plan_hash,
                commitment: coding_challenge_commitment(plan_hash, nonce),
            },
            &keys[7],
        )
        .unwrap();
        let reveal = SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            CodingChallengeReveal {
                format_version: 1,
                attempt_id,
                plan_hash,
                nonce,
                evidence_hash,
            },
            &keys[7],
        )
        .unwrap();
        let openings = information
            .iter()
            .chain(&parity)
            .enumerate()
            .map(|(index, bytes)| {
                let commitment = merkle_commit(bytes).unwrap();
                let leaf = challenged_leaf(&challenge, &commitment).unwrap();
                SignedRecord::sign(
                    CODING_SHARD_OPENING_DOMAIN,
                    CodingShardOpening {
                        format_version: 1,
                        attempt_id,
                        plan_hash,
                        verifier: keys[7].node_id(),
                        challenge,
                        shard_index: index as u16,
                        commitment,
                        proof: merkle_open_range(bytes, leaf, 1).unwrap(),
                    },
                    &keys[index],
                )
                .unwrap()
            })
            .collect();
        let retained = RetainedCodingGroup {
            group: manifest.value.group.clone(),
            added_at_event: 1,
            retired_at_event: None,
            retain_through_event: None,
        };
        let transcript = SignedRecord::sign(
            CODING_TRANSCRIPT_DOMAIN,
            CodingVerificationTranscript {
                format_version: 1,
                verified_at_unix_seconds: u64::MAX,
                plan,
                manifest,
                challenge_commitment: commitment,
                staged_receipts: receipts,
                challenge_reveal: reveal,
                openings,
            },
            &keys[7],
        )
        .unwrap();
        assert_eq!(
            replay_coding_transcript(&transcript).unwrap(),
            CodingReplayFinding::Verified
        );
        CatalogCodingEntry {
            retained,
            transcript,
        }
    }

    struct Fixture {
        packing: PackingFixture,
        entries: Vec<CatalogCodingEntry>,
        manifest: CatalogCodingValidation,
        pages: HashMap<[u8; 32], Vec<u8>>,
        roles: Vec<Vec<(CatalogPageRef, Vec<u8>)>>,
    }

    impl Fixture {
        fn new(count: u32) -> Self {
            let packing = fixture(count, true);
            let entries = (0..count as usize)
                .step_by(3)
                .map(|index| {
                    entry(
                        &packing,
                        [index, index + 1, index + 2],
                        index as u64 + 1,
                        2,
                        None,
                    )
                })
                .collect();
            let mut fixture = Self {
                packing,
                entries,
                manifest: CatalogCodingValidation {
                    format_version: 1,
                    scope: CatalogScope::Guild { guild_id: [7; 32] },
                    root: CatalogCodingRoot {
                        format_version: 1,
                        guild_event_sequence: 100,
                        parts: Vec::new(),
                        summary: Default::default(),
                    },
                },
                pages: HashMap::new(),
                roles: Vec::new(),
            };
            fixture.rebuild(false);
            fixture
        }
        fn rebuild(&mut self, four_parts: bool) {
            self.entries.sort_by_key(|entry| entry.retained.group.id);
            self.pages.clear();
            self.roles.clear();
            let chunks = if four_parts {
                self.entries.len().div_ceil(4)
            } else {
                self.entries.len().max(1)
            };
            let mut root = CatalogCodingRoot {
                format_version: 1,
                guild_event_sequence: 100,
                parts: Vec::new(),
                summary: Default::default(),
            };
            for entries in self.entries.chunks(chunks) {
                let mut role = Vec::new();
                let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| {
                    self.pages.insert(page.hash, bytes.clone());
                    role.push((page, bytes));
                    Ok::<_, ()>(())
                };
                let mut builder = CatalogCodingBuilder::new(self.manifest.scope, 100).unwrap();
                for entry in entries {
                    builder.push_group(entry, &mut sink).unwrap();
                }
                let part = builder.finish(&mut sink).unwrap();
                root.parts.extend(part.parts);
                root.summary.groups += part.summary.groups;
                root.summary.retired_groups += part.summary.retired_groups;
                root.summary.information_roles += part.summary.information_roles;
                root.summary.parity_roles += part.summary.parity_roles;
                root.summary.transcript_bytes += part.summary.transcript_bytes;
                root.summary.fragments += part.summary.fragments;
                self.roles.push(role);
            }
            root.validate().unwrap();
            self.manifest.root = root;
        }
        fn fetch(&self, page: CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError> {
            self.pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        }
        fn build(&self, maximum: u64) -> Result<CatalogPackingCodingIndex, CatalogStoreError> {
            self.packing.build(maximum)?.validate_coding(
                self.manifest.clone(),
                CatalogCodingCoveragePolicy::Current,
                |page| self.fetch(page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
        }
    }

    #[test]
    fn coding_join_covers_every_sector_retains_replacements_and_seeks_original_witnesses() {
        let mut fixture = Fixture::new(12);
        fixture
            .entries
            .push(entry(&fixture.packing, [0, 1, 2], 100, 2, None));
        let mut retired = entry(&fixture.packing, [3, 4, 5], 101, 2, None);
        retired.retained.retired_at_event = Some(2);
        retired.retained.retain_through_event = Some(1000);
        fixture.entries.push(retired);
        // Valid retained groups outside the current packing are still preserved.
        let mut unrelated = super::super::packing_validation::tests::fixture(3, true);
        for (index, sector) in unrelated.sectors.iter_mut().enumerate() {
            sector.id = [190 + index as u8; 32];
        }
        fixture
            .entries
            .push(entry(&unrelated, [0, 1, 2], 102, 2, None));
        fixture
            .entries
            .push(entry(&unrelated, [0, 1, 2], 103, 2, None));
        fixture.rebuild(true);
        assert_eq!(fixture.manifest.root.parts.len(), 4);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        for sector in &fixture.packing.sectors {
            let coverage = index.coverage(sector.id).unwrap().unwrap();
            let entry = fixture
                .entries
                .iter()
                .find(|entry| entry.retained.group.id == coverage.group_id)
                .unwrap();
            assert!(entry.retained.retired_at_event.is_none());
            let ShardRoleV2::Information(info) =
                &entry.retained.group.roles[coverage.shard_index as usize]
            else {
                panic!("coverage selected parity");
            };
            assert_eq!(info.sector.id, sector.id);
            assert_eq!(info.owner, coverage.holder);
            let first = fixture.entries.iter().find(|entry| entry.retained.retired_at_event.is_none() && entry.retained.group.roles.iter().any(|role| matches!(role, ShardRoleV2::Information(info) if info.sector.id == sector.id))).unwrap();
            assert_eq!(coverage.group_id, first.retained.group.id);
        }
        let mut after = None;
        for expected in &fixture.entries {
            let group = index.next_group(after).unwrap().unwrap();
            assert_eq!(group.range.group_id, expected.retained.group.id);
            after = Some(group.range.group_id);
            let mut fetched = 0;
            assert_eq!(
                index
                    .read_group(group.range.group_id, |page| {
                        fetched += 1;
                        fixture.fetch(page)
                    })
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
            assert!(fetched <= 2);
        }
        assert!(index.next_group(after).unwrap().is_none());
        assert!(index.coverage([255; 32]).unwrap().is_none());
        assert!(
            index
                .read_group([255; 32], |_| panic!("unknown group fetched pages"))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            CatalogPackingCodingValidation::decode(
                &canonical_bytes_bounded(index.manifest(), MANIFEST_BYTES).unwrap()
            )
            .unwrap(),
            *index.manifest()
        );
    }

    #[test]
    fn coding_join_rejects_omissions_retired_virtual_zero_and_substituted_inputs() {
        let mut fixture = Fixture::new(12);
        let originals = fixture.entries.clone();
        for mutation in 0..5 {
            fixture.entries = originals.clone();
            match mutation {
                0 => {
                    fixture.entries.pop();
                }
                1 => {
                    fixture.entries[0].retained.retired_at_event = Some(2);
                    fixture.entries[0].retained.retain_through_event = Some(1000);
                }
                2 => {
                    // A zero packed input still requires a stored information
                    // role; virtual filler cannot claim that input's identity.
                    let mut zero = Fixture::new(3);
                    zero.packing = super::super::packing_validation::tests::fixture(1, true);
                    assert!(zero.packing.bytes[0].iter().all(|byte| *byte == 0));
                    for id in [220, 221] {
                        let mut sector = zero.packing.sectors[0].clone();
                        sector.id = [id; 32];
                        zero.packing.sectors.push(sector);
                        zero.packing.bytes.push(zero.packing.bytes[0].clone());
                    }
                    zero.entries = vec![entry(&zero.packing, [0, 1, 2], 200, 2, Some(0))];
                    zero.rebuild(false);
                    assert!(zero.build(4 * 1024 * 1024).is_err());
                    continue;
                }
                3 => {
                    let mut bad = super::super::packing_validation::tests::fixture(12, true);
                    bad.bytes[0][0] ^= 1;
                    bad.sectors[0].commitment = merkle_commit(&bad.bytes[0]).unwrap();
                    bad.sectors[0].flat_root = bad.sectors[0].commitment.root;
                    fixture.entries.push(entry(&bad, [0, 1, 2], 201, 2, None));
                }
                4 => {
                    fixture
                        .entries
                        .push(entry(&fixture.packing, [0, 1, 2], 202, 3, None));
                }
                _ => unreachable!(),
            }
            fixture.rebuild(false);
            assert!(
                fixture.build(4 * 1024 * 1024).is_err(),
                "accepted mutation {mutation}"
            );
        }
        fixture.entries = originals;
        fixture.rebuild(false);
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding(
                    fixture.manifest.clone(),
                    CatalogCodingCoveragePolicy::Current,
                    |page| fixture.fetch(page),
                    |_| Ok(CatalogCodingAuthorization::Retained)
                )
                .is_err()
        );
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding(
                    fixture.manifest.clone(),
                    CatalogCodingCoveragePolicy::Historical,
                    |page| fixture.fetch(page),
                    |_| Ok(CatalogCodingAuthorization::Retained)
                )
                .is_ok()
        );
        fixture.build(4 * 1024 * 1024).unwrap();
    }

    #[test]
    fn coding_join_rolls_back_ignored_writes_and_late_authority_or_fetch_failures() {
        let mut fixture = Fixture::new(12);
        fixture.rebuild(true);
        for kind in [GROUPS, COVERAGE, COMPLETE] {
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            packing.store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignored BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
            let manifest = CatalogPackingCodingValidation {
                format_version: 1,
                packing: packing.manifest,
                coding: fixture.manifest.clone(),
                policy: CatalogCodingCoveragePolicy::Current,
            };
            let result = packing.store.with_record_transaction(|| {
                build(
                    &packing,
                    &manifest,
                    &mut |page| fixture.fetch(page),
                    &mut |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
                )
            });
            assert!(result.is_err());
            for kind in [GROUPS, COVERAGE, COMPLETE] {
                assert!(
                    packing
                        .store
                        .next_record_bounded(kind, None, 32, MANIFEST_BYTES)
                        .unwrap()
                        .is_none()
                );
            }
            assert!(
                packing
                    .sector(fixture.packing.sectors[0].id)
                    .unwrap()
                    .is_some()
            );
        }
        for mutation in 0..3 {
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            let manifest = CatalogPackingCodingValidation {
                format_version: 1,
                packing: packing.manifest,
                coding: fixture.manifest.clone(),
                policy: CatalogCodingCoveragePolicy::Current,
            };
            let last = fixture.manifest.root.parts[3].page.hash;
            let mut count = 0;
            let result = packing.store.with_record_transaction(|| {
                build(
                    &packing,
                    &manifest,
                    &mut |page| {
                        let mut bytes = fixture.fetch(page)?;
                        if page.hash == last && mutation < 2 {
                            if mutation == 0 {
                                return Err(DatabaseError::NotReady.into());
                            }
                            bytes[0] ^= 1;
                        }
                        Ok(bytes)
                    },
                    &mut |_| {
                        count += 1;
                        if mutation == 2 && count == 4 {
                            Err(DatabaseError::Conflict.into())
                        } else {
                            Ok(CatalogCodingAuthorization::CurrentPlacement)
                        }
                    },
                )
            });
            assert!(result.is_err());
            for kind in [GROUPS, COVERAGE, COMPLETE] {
                assert!(
                    packing
                        .store
                        .next_record_bounded(kind, None, 32, MANIFEST_BYTES)
                        .unwrap()
                        .is_none()
                );
            }
            packing
                .validate_coding(
                    fixture.manifest.clone(),
                    CatalogCodingCoveragePolicy::Current,
                    |page| fixture.fetch(page),
                    |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
                )
                .unwrap();
        }
        for kind in [GROUPS, COVERAGE, COMPLETE] {
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            packing
                .store
                .put_record_if_absent(kind, b"orphan", &[1])
                .unwrap();
            assert!(
                packing
                    .validate_coding(
                        fixture.manifest.clone(),
                        CatalogCodingCoveragePolicy::Current,
                        |_| panic!("orphan fetched pages"),
                        |_| panic!("orphan authorized groups")
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn coding_join_spills_and_rebuilds_after_exhausting_its_admitted_index() {
        let fixture = Fixture::new(768);
        let packing = fixture.packing.build(8 * 1024 * 1024).unwrap();
        let pages = packing
            .store
            .database_shell_statement("PRAGMA scratch.page_count", false)
            .unwrap()
            .rows[0][0]
            .parse::<u64>()
            .unwrap();
        packing
            .store
            .database_shell_statement(&format!("PRAGMA scratch.max_page_count={pages}"), false)
            .unwrap();
        let manifest = CatalogPackingCodingValidation {
            format_version: 1,
            packing: packing.manifest,
            coding: fixture.manifest.clone(),
            policy: CatalogCodingCoveragePolicy::Current,
        };
        assert!(
            packing
                .store
                .with_record_transaction(|| build(
                    &packing,
                    &manifest,
                    &mut |page| fixture.fetch(page),
                    &mut |_| Ok(CatalogCodingAuthorization::CurrentPlacement)
                ))
                .is_err()
        );
        for kind in [GROUPS, COVERAGE, COMPLETE] {
            assert!(
                packing
                    .store
                    .next_record_bounded(kind, None, 32, MANIFEST_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
        drop(packing);
        let index = fixture.build(8 * 1024 * 1024).unwrap();
        let pages = index
            .packing
            .store
            .database_shell_statement("PRAGMA scratch.page_count", false)
            .unwrap()
            .rows[0][0]
            .parse::<u64>()
            .unwrap();
        assert!(pages * 4096 > 1024 * 1024);
        assert_eq!(
            index
                .packing
                .store
                .database_shell_statement("PRAGMA scratch.cache_size", false)
                .unwrap()
                .rows[0][0],
            "-1024"
        );
        for sector in &fixture.packing.sectors {
            assert!(index.coverage(sector.id).unwrap().is_some());
        }
        let target = fixture.entries.last().unwrap();
        let mut fetched = 0;
        assert_eq!(
            index
                .read_group(target.retained.group.id, |page| {
                    fetched += 1;
                    fixture.fetch(page)
                })
                .unwrap()
                .as_ref(),
            Some(target)
        );
        assert!(fetched <= 3);
        assert!(fetched < fixture.manifest.root.page_occurrences().unwrap());
        let marker = canonical_bytes_bounded(index.manifest(), MANIFEST_BYTES).unwrap();
        index
            .packing
            .store
            .delete_record_if_value(COMPLETE, b"root", &marker)
            .unwrap();
        assert!(index.coverage(fixture.packing.sectors[0].id).is_err());
        assert!(index.next_group(None).is_err());
        assert!(
            index
                .read_group(target.retained.group.id, |_| panic!(
                    "incomplete proof fetched pages"
                ))
                .is_err()
        );
    }

    #[test]
    fn coding_join_binds_all_six_roots_atomically_across_reopen_and_cancelled_successors() {
        let mut fixture = Fixture::new(12);
        fixture.rebuild(true);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([170; 32]));
        let mut store = ControlStore::open(&path, &keys).unwrap();
        let stage = |base: u128| {
            let intents = (0_u128..6)
                .map(|offset| CatalogIntent {
                    id: Uuid::from_u128(base + offset),
                    scope: fixture.manifest.scope,
                    section: if offset < 2 {
                        CatalogSection::Packing
                    } else {
                        CatalogSection::Coding
                    },
                })
                .collect::<Vec<_>>();
            for (intent, role) in intents
                .iter()
                .zip(fixture.packing.roles.iter().chain(&fixture.roles))
            {
                store.begin_catalog(*intent).unwrap();
                for (page, bytes) in role {
                    store.stage_catalog_page(*intent, *page, bytes).unwrap();
                }
            }
            intents
        };
        let intents = stage(10);
        let next = stage(20);
        let cancelled = stage(30);
        let packing = [intents[0], intents[1]];
        let bundle = index
            .as_local_bundle(Uuid::from_u128(40), packing, &intents[2..])
            .unwrap();
        let successor = index
            .as_local_bundle(Uuid::from_u128(41), [next[0], next[1]], &next[2..])
            .unwrap();
        let rejected = index
            .as_local_bundle(
                Uuid::from_u128(42),
                [cancelled[0], cancelled[1]],
                &cancelled[2..],
            )
            .unwrap();
        assert_eq!(bundle.roots.len(), 6);
        assert_eq!(
            CatalogPackingCodingValidation::decode(&bundle.descriptor).unwrap(),
            *index.manifest()
        );
        assert!(
            index
                .as_local_bundle(Uuid::new_v4(), packing, &intents[2..5])
                .is_err()
        );
        let mut wrong = intents[2..].to_vec();
        wrong[0].section = CatalogSection::Packing;
        assert!(
            index
                .as_local_bundle(Uuid::new_v4(), packing, &wrong)
                .is_err()
        );
        wrong[0] = wrong[1];
        assert!(
            index
                .as_local_bundle(Uuid::new_v4(), packing, &wrong)
                .is_err()
        );
        store.publish_catalog_bundle(&bundle).unwrap();
        store.publish_catalog_bundle(&successor).unwrap();
        store.cancel_catalog(cancelled[5]).unwrap();
        assert!(store.publish_catalog_bundle(&rejected).is_err());
        assert!(store.catalog_bundle(rejected.id).unwrap().is_none());
        for intent in &cancelled[..5] {
            assert_eq!(
                store.catalog_intent_state(*intent).unwrap(),
                CatalogIntentState::Building
            );
        }
        for intent in &cancelled {
            store.cancel_catalog(*intent).unwrap();
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        drop(store);
        store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store.catalog_bundle(bundle.id).unwrap(),
            Some((bundle.clone(), CatalogBundleState::Published))
        );
        store.cancel_catalog_bundle(bundle.id).unwrap();
        for intent in &intents {
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        for entry in &fixture.entries {
            assert_eq!(
                index
                    .read_group(entry.retained.group.id, |page| store.catalog_page(
                        fixture.manifest.scope,
                        CatalogSection::Coding,
                        page
                    ))
                    .unwrap()
                    .as_ref(),
                Some(entry)
            );
        }
        assert_eq!(
            store.catalog_bundle(successor.id).unwrap(),
            Some((successor.clone(), CatalogBundleState::Published))
        );
        store.cancel_catalog_bundle(successor.id).unwrap();
        for intent in &next {
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        for page in &bundle.roots {
            assert!(
                store
                    .catalog_page(page.intent.scope, page.intent.section, page.root)
                    .is_err()
            );
        }
    }

    #[test]
    fn coding_join_checks_combined_admission_before_fetching_and_keeps_empty_packing_valid() {
        let fixture = Fixture::new(12);
        let mut manifest = CatalogPackingCodingValidation {
            format_version: 1,
            packing: fixture.packing.manifest,
            coding: fixture.manifest.clone(),
            policy: CatalogCodingCoveragePolicy::Current,
        };
        manifest.validate().unwrap();
        let part = &mut manifest.coding.root.parts[0];
        part.page.height = 3;
        part.page.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES;
        manifest.coding.validate().unwrap();
        assert!(manifest.validate().is_err());
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding(
                    manifest.coding,
                    manifest.policy,
                    |_| panic!("over-budget fetched pages"),
                    |_| panic!("over-budget authorized groups")
                )
                .is_err()
        );
        let mut wrong = fixture.manifest.clone();
        wrong.scope = CatalogScope::Guild { guild_id: [9; 32] };
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding(
                    wrong,
                    manifest.policy,
                    |_| panic!("wrong scope fetched pages"),
                    |_| panic!("wrong scope authorized groups")
                )
                .is_err()
        );
        let mut near_limit = fixture.manifest.clone();
        let mut part = near_limit.root.parts[0];
        part.page.height = 3;
        part.page.page_occurrences = 200_000;
        part.page.byte_len = mb_core::CATALOG_MAX_STREAM_BYTES - 1024;
        part.records = 2_000_000;
        near_limit.root.parts = vec![part; 4];
        near_limit.root.summary = mb_core::CatalogCodingSummary {
            groups: 4_000_000,
            retired_groups: 0,
            information_roles: 12_000_000,
            parity_roles: 8_000_000,
            transcript_bytes: 4_000_000,
            fragments: 4_000_000,
        };
        near_limit.validate().unwrap();
        let combined = CatalogPackingCodingValidation {
            format_version: 1,
            packing: fixture.packing.manifest,
            coding: near_limit.clone(),
            policy: CatalogCodingCoveragePolicy::Current,
        };
        assert!(combined.represented_work().unwrap().0 > CATALOG_CODING_MAX_BYTES);
        assert!(combined.validate().is_err());
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding(
                    near_limit,
                    combined.policy,
                    |_| panic!("byte over-budget fetched pages"),
                    |_| panic!("byte over-budget authorized groups")
                )
                .is_err()
        );
        let empty = Fixture::new(0);
        let index = empty.build(1024 * 1024).unwrap();
        assert!(index.next_group(None).unwrap().is_none());
        assert!(index.coverage([1; 32]).unwrap().is_none());
        let intents = [
            CatalogIntent {
                id: Uuid::from_u128(1),
                scope: empty.manifest.scope,
                section: CatalogSection::Packing,
            },
            CatalogIntent {
                id: Uuid::from_u128(2),
                scope: empty.manifest.scope,
                section: CatalogSection::Packing,
            },
        ];
        assert_eq!(
            index
                .as_local_bundle(Uuid::new_v4(), intents, &[])
                .unwrap()
                .roots
                .len(),
            2
        );
        assert!(CatalogPackingCodingValidation::decode(&vec![0; MANIFEST_BYTES + 1]).is_err());
    }
    #[test]
    fn coding_join_requires_full_byte_witnesses_for_current_flat_inputs() {
        let mut fixture = Fixture::new(3);
        let mut builder = mb_core::CatalogPackedSectorBuilder::new_compact(
            fixture.packing.manifest.scope,
            2,
            fixture.packing.manifest.descriptors.profile,
        )
        .unwrap();
        let mut role = Vec::new();
        let mut sink = |page, bytes: Vec<u8>| {
            role.push((page, bytes));
            Ok::<_, ()>(())
        };
        for (sector, bytes) in fixture
            .packing
            .sectors
            .iter_mut()
            .zip(&fixture.packing.bytes)
        {
            sector.flat_root = sector_root(bytes);
            sector.id = sector
                .calculate_id(fixture.packing.manifest.descriptors.profile)
                .unwrap();
            builder.push_sector(sector, &mut sink).unwrap();
        }
        fixture.packing.manifest.descriptors = builder.finish(&mut sink).unwrap();
        for (page, bytes) in &role {
            fixture.packing.pages.insert(page.hash, bytes.clone());
        }
        fixture.packing.roles[0] = role;
        fixture.entries = vec![entry(&fixture.packing, [0, 1, 2], 300, 2, None)];
        fixture.rebuild(false);
        assert!(fixture.build(4 * 1024 * 1024).is_err());
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding(
                    fixture.manifest.clone(),
                    CatalogCodingCoveragePolicy::Historical,
                    |page| fixture.fetch(page),
                    |_| Ok(CatalogCodingAuthorization::Retained)
                )
                .is_ok()
        );
        fixture.entries = vec![entry(&fixture.packing, [0, 1, 2], 301, 3, None)];
        // Original unbound witnesses remain retainable but cannot cover inputs.
        let mut unbound = entry(&fixture.packing, [0, 1, 2], 302, 1, None);
        unbound.retained.retired_at_event = Some(2);
        unbound.retained.retain_through_event = Some(1000);
        fixture.entries.push(unbound);
        fixture.rebuild(false);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        for sector in &fixture.packing.sectors {
            assert!(index.coverage(sector.id).unwrap().is_some());
        }
        fixture
            .entries
            .retain(|entry| entry.transcript.value.plan.value.format_version == 1);
        fixture.rebuild(false);
        assert!(fixture.build(4 * 1024 * 1024).is_err());
    }
    #[test]
    fn coding_index_rejects_malformed_local_cursors_before_recovery_fetches() {
        let fixture = Fixture::new(12);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        let first = index.next_group(None).unwrap().unwrap();
        let ShardRoleV2::Information(info) = &fixture.entries[0].retained.group.roles[0] else {
            unreachable!();
        };
        assert_eq!(
            index.coverage(info.sector.id).unwrap().unwrap().group_id,
            first.range.group_id
        );
        let original = canonical_bytes_bounded(&first, ROW_BYTES).unwrap();
        for mutation in 0..4 {
            let mut group = first;
            match mutation {
                0 => group.profile.data_shards = 0,
                1 => group.range.offset = u64::MAX,
                2 => group.added_at_event = 0,
                3 => group.range.group_id[0] ^= 1,
                _ => unreachable!(),
            }
            let bad = canonical_bytes_bounded(&group, ROW_BYTES).unwrap();
            index
                .packing
                .store
                .replace_record_if_value(GROUPS, &first.range.group_id, &original, &bad)
                .unwrap();
            assert!(index.next_group(None).is_err());
            assert!(index.coverage(info.sector.id).is_err());
            assert!(
                index
                    .read_group(first.range.group_id, |_| panic!(
                        "malformed local cursor fetched pages"
                    ))
                    .is_err()
            );
            index
                .packing
                .store
                .replace_record_if_value(GROUPS, &first.range.group_id, &bad, &original)
                .unwrap();
        }
        assert_eq!(index.next_group(None).unwrap(), Some(first));
    }
}

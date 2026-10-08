//! Ordered, fragmented original coding transcripts in a bounded public forest.
//! Replay checks evidence; current delegation, membership, source coverage and
//! retained lifecycle authority must be joined by the enclosing checkpoint.

use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer, Serialize};

use super::*;
use crate::{
    CodingAttemptPlan, CodingChallengeCommitment, CodingChallengeReveal, CodingReplayFinding,
    CodingRootManifest, CodingShardOpening, CodingVerificationTranscript, RetainedCodingGroup,
    SignedRecord, StagedStorageReceipt, canonical_bytes_bounded, canonical_size_bounded,
    replay_coding_transcript,
};

pub const CATALOG_CODING_FRAGMENT_BYTES: usize = 16 * 1024;
pub const CATALOG_CODING_RECORD_BYTES: usize = CATALOG_CODING_FRAGMENT_BYTES + 256;
pub const CATALOG_CODING_ROOT_BYTES: usize = 512;
/// Original peer evidence remains one bounded object, including full-byte
/// compatibility witnesses. No transcript receives a separate byte-tree root.
pub const CATALOG_CODING_TRANSCRIPT_BYTES: usize = 600 * 1024;
/// Bounded framed header and fragments for one original witness.
pub const CATALOG_CODING_GROUP_BYTES: usize = CATALOG_CODING_TRANSCRIPT_BYTES + 4096;
/// Four existing 16 GiB trees allow evidence larger than a single byte stream.
/// The forest still shares one million page occurrences. The enclosing
/// checkpoint must charge all other sections against its combined policy too.
pub const CATALOG_CODING_PARTS: usize = 4;
pub const CATALOG_CODING_MAX_BYTES: u64 = CATALOG_MAX_STREAM_BYTES * CATALOG_CODING_PARTS as u64;
const MAX_FRAGMENTS: u64 =
    CATALOG_CODING_TRANSCRIPT_BYTES.div_ceil(CATALOG_CODING_FRAGMENT_BYTES) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingLifecycle {
    pub group_id: [u8; 32],
    pub added_at_event: u64,
    pub retired_at_event: Option<u64>,
    pub retain_through_event: Option<u64>,
}

impl CatalogCodingLifecycle {
    fn validate(self, event_sequence: u64) -> Result<(), CatalogError> {
        if self.group_id == [0; 32]
            || self.added_at_event == 0
            || self.added_at_event > event_sequence
            || self.retired_at_event.is_some() != self.retain_through_event.is_some()
            || self
                .retired_at_event
                .is_some_and(|event| event < self.added_at_event || event > event_sequence)
            || self
                .retain_through_event
                .is_some_and(|event| event < self.retired_at_event.unwrap_or(0))
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    fn from_group(group: &RetainedCodingGroup) -> Self {
        Self {
            group_id: group.group.id,
            added_at_event: group.added_at_event,
            retired_at_event: group.retired_at_event,
            retain_through_event: group.retain_through_event,
        }
    }
}

/// The manifest already contains the original complete group. The header
/// binds its identity/lifecycle without duplicating that descriptor per group.
/// Serialized variants are append-only within record format one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogCodingRecord {
    Header {
        format_version: u16,
        lifecycle: CatalogCodingLifecycle,
        transcript_hash: [u8; 32],
        transcript_bytes: u32,
    },
    Transcript {
        offset: u32,
        #[serde(deserialize_with = "decode_fragment")]
        bytes: Vec<u8>,
    },
}

fn decode_fragment<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    crate::bounded::VecSeed::new(CATALOG_CODING_FRAGMENT_BYTES).deserialize(decoder)
}

impl CatalogCodingRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_CODING_RECORD_BYTES {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        match &record {
            Self::Header {
                format_version,
                lifecycle,
                transcript_hash,
                transcript_bytes,
            } if *format_version != 1
                || lifecycle.group_id == [0; 32]
                || *transcript_hash == [0; 32]
                || *transcript_bytes == 0
                || *transcript_bytes as usize > CATALOG_CODING_TRANSCRIPT_BYTES =>
            {
                return Err(CatalogError::InvalidPage);
            }
            Self::Transcript { bytes, .. }
                if bytes.is_empty() || bytes.len() > CATALOG_CODING_FRAGMENT_BYTES =>
            {
                return Err(CatalogError::Bounds);
            }
            _ => {}
        }
        if canonical_bytes_bounded(&record, CATALOG_CODING_RECORD_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingSummary {
    pub groups: u64,
    pub retired_groups: u64,
    pub information_roles: u64,
    pub parity_roles: u64,
    pub transcript_bytes: u64,
    pub fragments: u64,
}

impl CatalogCodingSummary {
    fn validate(self) -> Result<(), CatalogError> {
        self.validate_with_record_limit(CATALOG_MAX_RECORDS)
    }

    pub(super) fn validate_with_record_limit(self, records: u64) -> Result<(), CatalogError> {
        if self.groups == 0 {
            if self != Self::default() {
                return Err(CatalogError::Bounds);
            }
            return Ok(());
        }
        let max = self
            .groups
            .checked_mul(crate::MAX_CODING_SHARDS as u64)
            .ok_or(CatalogError::Bounds)?;
        if self.retired_groups > self.groups
            || self.information_roles < self.groups
            || self.parity_roles < self.groups
            || self
                .information_roles
                .checked_add(self.parity_roles)
                .ok_or(CatalogError::Bounds)?
                > max
            || self.fragments < self.groups
            || self.fragments
                > self
                    .groups
                    .checked_mul(MAX_FRAGMENTS)
                    .ok_or(CatalogError::Bounds)?
            || self.transcript_bytes < self.fragments
            || self.transcript_bytes
                > self
                    .groups
                    .checked_mul(CATALOG_CODING_TRANSCRIPT_BYTES as u64)
                    .ok_or(CatalogError::Bounds)?
            || self.transcript_bytes
                > self
                    .fragments
                    .checked_mul(CATALOG_CODING_FRAGMENT_BYTES as u64)
                    .ok_or(CatalogError::Bounds)?
            || self.records()? > records
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    fn records(self) -> Result<u64, CatalogError> {
        self.groups
            .checked_add(self.fragments)
            .ok_or(CatalogError::Bounds)
    }

    fn add(&mut self, entry: &CatalogCodingEntry, bytes: usize) -> Result<(), CatalogError> {
        let profile = entry.retained.group.profile;
        for (count, increment) in [
            (&mut self.groups, 1),
            (
                &mut self.retired_groups,
                u64::from(entry.retained.retired_at_event.is_some()),
            ),
            (&mut self.information_roles, u64::from(profile.data_shards)),
            (&mut self.parity_roles, u64::from(profile.parity_shards)),
            (&mut self.transcript_bytes, bytes as u64),
            (
                &mut self.fragments,
                bytes.div_ceil(CATALOG_CODING_FRAGMENT_BYTES) as u64,
            ),
        ] {
            *count = count.checked_add(increment).ok_or(CatalogError::Bounds)?;
        }
        self.validate()
    }
}

fn decode_parts<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<CatalogRecordRoot>, D::Error> {
    crate::bounded::VecSeed::new(CATALOG_CODING_PARTS).deserialize(decoder)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingRoot {
    pub format_version: u16,
    pub guild_event_sequence: u64,
    #[serde(deserialize_with = "decode_parts")]
    pub parts: Vec<CatalogRecordRoot>,
    pub summary: CatalogCodingSummary,
}

/// A local cursor recorded during a complete verified traversal. Reading this
/// range replays one original witness; it does not establish global coverage,
/// ordering or EOF. Accept cursors only from a trusted completed index.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingGroupRange {
    pub part: u8,
    pub offset: u64,
    pub len: u32,
    pub group_id: [u8; 32],
    pub transcript_hash: [u8; 32],
}

/// A trusted completed traversal records the authenticated part reference as
/// well as the original group range. Its storage is fixed even for directories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingGroupLocation {
    pub page: CatalogPageRef,
    pub range: CatalogCodingGroupRange,
}

impl CatalogCodingGroupLocation {
    pub(super) fn read_group<E>(
        self,
        scope: CatalogScope,
        sequence: u64,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<CatalogCodingEntry, CatalogStreamError<E>> {
        self.read_group_with_work(scope, sequence, fetch)
            .map(|(entry, _)| entry)
    }

    pub(super) fn read_group_with_work<E>(
        self,
        scope: CatalogScope,
        sequence: u64,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<(CatalogCodingEntry, CatalogCodingTraversalBudget), CatalogStreamError<E>> {
        // Exact whole-directory membership and counters belong to the trusted
        // completed traversal; the part/range decoder authenticates this group.
        read_group_at(scope, sequence, self.page, self.range, fetch)
    }
}

impl CatalogCodingRoot {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_CODING_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate()?;
        if canonical_bytes_bounded(&root, CATALOG_CODING_ROOT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        self.summary.validate()?;
        if self.format_version != 1
            || self.guild_event_sequence > i64::MAX as u64
            || self.parts.len() > CATALOG_CODING_PARTS
            || self.parts.is_empty() != (self.summary.groups == 0)
        {
            return Err(CatalogError::Bounds);
        }
        let mut records = 0_u64;
        let mut bytes = canonical_size_bounded(self, CATALOG_CODING_ROOT_BYTES)? as u64;
        let mut pages = 0_u64;
        for part in &self.parts {
            part.validate()?;
            if part.records == 0 {
                return Err(CatalogError::Bounds);
            }
            records = records
                .checked_add(part.records)
                .ok_or(CatalogError::Bounds)?;
            bytes = bytes
                .checked_add(part.page.byte_len)
                .ok_or(CatalogError::Bounds)?;
            pages = pages
                .checked_add(part.page.page_occurrences)
                .ok_or(CatalogError::Bounds)?;
        }
        if records != self.summary.records()?
            || bytes > CATALOG_CODING_MAX_BYTES
            || pages > CATALOG_MAX_PAGE_OCCURRENCES
            || (self.summary.groups > 0 && self.guild_event_sequence == 0)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    pub fn represented_bytes(&self) -> Result<u64, CatalogError> {
        self.validate()?;
        Ok(self
            .parts
            .iter()
            .map(|part| part.page.byte_len)
            .sum::<u64>()
            + canonical_size_bounded(self, CATALOG_CODING_ROOT_BYTES)? as u64)
    }

    pub fn page_occurrences(&self) -> Result<u64, CatalogError> {
        self.validate()?;
        Ok(self
            .parts
            .iter()
            .map(|part| part.page.page_occurrences)
            .sum())
    }

    pub fn read_group<E>(
        &self,
        scope: CatalogScope,
        range: CatalogCodingGroupRange,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<CatalogCodingEntry, CatalogStreamError<E>> {
        self.validate()?;
        let part = self
            .parts
            .get(usize::from(range.part))
            .ok_or(CatalogError::Bounds)?;
        read_group_at(scope, self.guild_event_sequence, part.page, range, fetch)
            .map(|(entry, _)| entry)
    }
}

fn read_group_at<E>(
    scope: CatalogScope,
    sequence: u64,
    page: CatalogPageRef,
    range: CatalogCodingGroupRange,
    fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
) -> Result<(CatalogCodingEntry, CatalogCodingTraversalBudget), CatalogStreamError<E>> {
    let guild_id = guild(scope)?;
    page.validate()?;
    if sequence == 0 || sequence > i64::MAX as u64 {
        return Err(CatalogError::Bounds.into());
    }
    let end = range
        .offset
        .checked_add(u64::from(range.len))
        .ok_or(CatalogError::Bounds)?;
    if usize::from(range.part) >= CATALOG_CODING_PARTS
        || range.offset < 8
        || range.len == 0
        || range.len as usize > CATALOG_CODING_GROUP_BYTES
        || end > page.byte_len
        || range.group_id == [0; 32]
        || range.transcript_hash == [0; 32]
    {
        return Err(CatalogError::Bounds.into());
    }
    let mut reader =
        CatalogRangeReader::new(scope, CatalogSection::Coding, page, range.offset..end)?;
    let mut bytes = Vec::with_capacity(range.len as usize);
    let mut work = CatalogCodingTraversalBudget::default();
    let mut measured_fetch = |page| -> Result<Vec<u8>, CatalogStreamError<E>> {
        let bytes = fetch(page).map_err(CatalogStreamError::Storage)?;
        work = work.checked_add(CatalogCodingTraversalBudget {
            bytes: bytes.len() as u64,
            page_occurrences: 1,
            records: 0,
        })?;
        Ok(bytes)
    };
    while let Some(chunk) = reader
        .next_chunk(&mut measured_fetch)
        .map_err(|error| match error {
            CatalogStreamError::Catalog(error) => CatalogStreamError::Catalog(error),
            CatalogStreamError::Storage(error) => error,
        })?
    {
        bytes.extend(chunk);
    }
    let mut position = 0;
    let mut next = || -> Result<Option<Vec<u8>>, CatalogStreamError<E>> {
        if position == bytes.len() {
            return Ok(None);
        }
        let length_end = position.checked_add(4).ok_or(CatalogError::Bounds)?;
        let length = bytes
            .get(position..length_end)
            .ok_or(CatalogError::InvalidPage)?;
        let length = u32::from_be_bytes(length.try_into().expect("four bytes")) as usize;
        if length == 0 || length > CATALOG_CODING_RECORD_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let end = length_end.checked_add(length).ok_or(CatalogError::Bounds)?;
        let record = bytes
            .get(length_end..end)
            .ok_or(CatalogError::InvalidPage)?
            .to_vec();
        position = end;
        work.records = work.records.checked_add(1).ok_or(CatalogError::Bounds)?;
        Ok(Some(record))
    };
    let header = CatalogCodingRecord::decode(&next()?.ok_or(CatalogError::InvalidPage)?)?;
    if !matches!(&header, CatalogCodingRecord::Header { lifecycle, transcript_hash, .. }
            if lifecycle.group_id == range.group_id && *transcript_hash == range.transcript_hash)
    {
        return Err(CatalogError::InvalidPage.into());
    }
    let (entry, _) = read_entry(header, guild_id, sequence, &mut next)?;
    if next()?.is_some() {
        return Err(CatalogError::InvalidPage.into());
    }
    Ok((entry, work))
}

/// Exactly one decoded, replayed group and its original bounded signed witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogCodingEntry {
    pub retained: RetainedCodingGroup,
    pub transcript: SignedRecord<CodingVerificationTranscript>,
}

fn validate_entry(
    entry: &CatalogCodingEntry,
    guild_id: [u8; 32],
    event_sequence: u64,
) -> Result<(), CatalogError> {
    CatalogCodingLifecycle::from_group(&entry.retained).validate(event_sequence)?;
    if entry.retained.group.guild_id != guild_id
        || entry.retained.group != entry.transcript.value.manifest.value.group
        || replay_coding_transcript(&entry.transcript)? != CodingReplayFinding::Verified
    {
        return Err(CatalogError::InvalidPage);
    }
    Ok(())
}

pub(super) fn guild(scope: CatalogScope) -> Result<[u8; 32], CatalogError> {
    scope.validate(CatalogSection::Coding)?;
    match scope {
        CatalogScope::Guild { guild_id } if guild_id != [0; 32] => Ok(guild_id),
        _ => Err(CatalogError::InvalidPage),
    }
}

struct PartBuilder {
    records: CatalogRecordBuilder,
    bytes: u64,
}

pub struct CatalogCodingBuilder {
    scope: CatalogScope,
    event_sequence: u64,
    parts: Vec<CatalogRecordRoot>,
    active: Option<PartBuilder>,
    summary: CatalogCodingSummary,
    previous: Option<[u8; 32]>,
    part_limit: u64,
    failed: bool,
}

impl CatalogCodingBuilder {
    pub fn new(scope: CatalogScope, event_sequence: u64) -> Result<Self, CatalogError> {
        guild(scope)?;
        if event_sequence > i64::MAX as u64 {
            return Err(CatalogError::Bounds);
        }
        Ok(Self {
            scope,
            event_sequence,
            parts: Vec::new(),
            active: None,
            summary: CatalogCodingSummary::default(),
            previous: None,
            part_limit: CATALOG_MAX_STREAM_BYTES,
            failed: false,
        })
    }

    pub(super) fn stream_bytes(&self) -> u64 {
        self.parts
            .iter()
            .map(|part| part.page.byte_len)
            .sum::<u64>()
            + self.active.as_ref().map_or(0, |part| part.bytes)
    }

    pub(super) fn summary(&self) -> CatalogCodingSummary {
        self.summary
    }

    pub fn push_group<E>(
        &mut self,
        entry: &CatalogCodingEntry,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.push_inner(entry, sink);
        self.failed = result.is_err();
        result
    }

    fn push_inner<E>(
        &mut self,
        entry: &CatalogCodingEntry,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        let bytes = canonical_bytes_bounded(&entry.transcript, CATALOG_CODING_TRANSCRIPT_BYTES)
            .map_err(CatalogError::from)?;
        validate_entry(entry, guild(self.scope)?, self.event_sequence)?;
        let id = entry.retained.group.id;
        if self.previous.is_some_and(|previous| previous >= id) {
            return Err(CatalogError::InvalidPage.into());
        }
        let header = CatalogCodingRecord::Header {
            format_version: 1,
            lifecycle: CatalogCodingLifecycle::from_group(&entry.retained),
            transcript_hash: *blake3::hash(&bytes).as_bytes(),
            transcript_bytes: bytes.len() as u32,
        };
        let header = canonical_bytes_bounded(&header, CATALOG_CODING_RECORD_BYTES)
            .map_err(CatalogError::from)?;
        // Serialize only one fragment at a time. Include actual variable-length
        // offsets/counts when deciding the part boundary.
        let mut group_bytes = 4 + header.len() as u64;
        for (index, fragment) in bytes.chunks(CATALOG_CODING_FRAGMENT_BYTES).enumerate() {
            group_bytes += 4 + canonical_size_bounded(
                &CatalogCodingRecord::Transcript {
                    offset: (index * CATALOG_CODING_FRAGMENT_BYTES) as u32,
                    bytes: fragment.to_vec(),
                },
                CATALOG_CODING_RECORD_BYTES,
            )
            .map_err(CatalogError::from)? as u64;
        }
        if group_bytes > CATALOG_CODING_GROUP_BYTES as u64 || group_bytes + 8 > self.part_limit {
            return Err(CatalogError::Bounds.into());
        }
        if self
            .active
            .as_ref()
            .is_some_and(|part| part.bytes + group_bytes > self.part_limit)
        {
            self.finish_part(sink)?;
        }
        if self.active.is_none() {
            if self.parts.len() == CATALOG_CODING_PARTS {
                return Err(CatalogError::Bounds.into());
            }
            self.active = Some(PartBuilder {
                records: CatalogRecordBuilder::new(self.scope, CatalogSection::Coding)?,
                bytes: 8,
            });
        }
        let part = self.active.as_mut().expect("active part was initialized");
        part.records.push_encoded(&header, sink)?;
        for (index, fragment) in bytes.chunks(CATALOG_CODING_FRAGMENT_BYTES).enumerate() {
            part.records.push(
                &CatalogCodingRecord::Transcript {
                    offset: (index * CATALOG_CODING_FRAGMENT_BYTES) as u32,
                    bytes: fragment.to_vec(),
                },
                sink,
            )?;
        }
        part.bytes += group_bytes;
        self.summary.add(entry, bytes.len())?;
        self.previous = Some(id);
        Ok(())
    }

    fn finish_part<E>(
        &mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if let Some(part) = self.active.take() {
            let root = part.records.finish(sink)?;
            if root.page.byte_len != part.bytes {
                return Err(CatalogError::InvalidPage.into());
            }
            self.parts.push(root);
        }
        Ok(())
    }

    pub fn finish<E>(
        mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogCodingRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.finish_part(sink)?;
        let root = CatalogCodingRoot {
            format_version: 1,
            guild_event_sequence: self.event_sequence,
            parts: self.parts,
            summary: self.summary,
        };
        root.validate()?;
        Ok(root)
    }
}

#[derive(Deserialize)]
struct BoundedTranscript {
    format_version: u16,
    verified_at_unix_seconds: u64,
    #[serde(deserialize_with = "crate::bounded::signed_record")]
    plan: SignedRecord<CodingAttemptPlan>,
    #[serde(deserialize_with = "crate::bounded::signed_record")]
    manifest: SignedRecord<CodingRootManifest>,
    #[serde(deserialize_with = "crate::bounded::signed_record")]
    challenge_commitment: SignedRecord<CodingChallengeCommitment>,
    #[serde(deserialize_with = "crate::bounded::signed_coding")]
    staged_receipts: Vec<SignedRecord<StagedStorageReceipt>>,
    #[serde(deserialize_with = "crate::bounded::signed_record")]
    challenge_reveal: SignedRecord<CodingChallengeReveal>,
    #[serde(deserialize_with = "crate::bounded::signed_coding")]
    openings: Vec<SignedRecord<CodingShardOpening>>,
}

/// Decode the exact original signed witness with bounded nested allocations.
/// Signature/RS replay, event binding and historical delegation checks remain
/// mandatory; decoding alone grants no authority.
pub fn decode_coding_transcript_bounded(
    bytes: &[u8],
) -> Result<SignedRecord<CodingVerificationTranscript>, CatalogError> {
    #[derive(Deserialize)]
    struct Bounded(
        #[serde(deserialize_with = "crate::bounded::signed_record")]
        SignedRecord<BoundedTranscript>,
    );
    if bytes.is_empty() || bytes.len() > CATALOG_CODING_TRANSCRIPT_BYTES {
        return Err(CatalogError::Bounds);
    }
    let Bounded(signed) = decode_canonical(bytes)?;
    let value = signed.value;
    let signed = SignedRecord {
        signer: signed.signer,
        signature: signed.signature,
        value: CodingVerificationTranscript {
            format_version: value.format_version,
            verified_at_unix_seconds: value.verified_at_unix_seconds,
            plan: value.plan,
            manifest: value.manifest,
            challenge_commitment: value.challenge_commitment,
            staged_receipts: value.staged_receipts,
            challenge_reveal: value.challenge_reveal,
            openings: value.openings,
        },
    };
    if canonical_bytes_bounded(&signed, CATALOG_CODING_TRANSCRIPT_BYTES)? != bytes {
        return Err(CatalogError::InvalidPage);
    }
    Ok(signed)
}

fn read_entry<E>(
    header: CatalogCodingRecord,
    guild_id: [u8; 32],
    event_sequence: u64,
    next: &mut impl FnMut() -> Result<Option<Vec<u8>>, CatalogStreamError<E>>,
) -> Result<(CatalogCodingEntry, usize), CatalogStreamError<E>> {
    let CatalogCodingRecord::Header {
        lifecycle,
        transcript_hash,
        transcript_bytes,
        ..
    } = header
    else {
        return Err(CatalogError::InvalidPage.into());
    };
    lifecycle.validate(event_sequence)?;
    let mut bytes = Vec::new();
    while bytes.len() < transcript_bytes as usize {
        let raw = next()?.ok_or(CatalogError::InvalidPage)?;
        let CatalogCodingRecord::Transcript {
            offset,
            bytes: fragment,
        } = CatalogCodingRecord::decode(&raw)?
        else {
            return Err(CatalogError::InvalidPage.into());
        };
        if offset as usize != bytes.len()
            || fragment.len()
                != (transcript_bytes as usize - bytes.len()).min(CATALOG_CODING_FRAGMENT_BYTES)
        {
            return Err(CatalogError::InvalidPage.into());
        }
        bytes.extend(fragment);
    }
    if *blake3::hash(&bytes).as_bytes() != transcript_hash {
        return Err(CatalogError::InvalidPage.into());
    }
    let transcript = decode_coding_transcript_bounded(&bytes)?;
    let entry = CatalogCodingEntry {
        retained: RetainedCodingGroup {
            group: transcript.value.manifest.value.group.clone(),
            added_at_event: lifecycle.added_at_event,
            retired_at_event: lifecycle.retired_at_event,
            retain_through_event: lifecycle.retain_through_event,
        },
        transcript,
    };
    if entry.retained.group.id != lifecycle.group_id {
        return Err(CatalogError::InvalidPage.into());
    }
    validate_entry(&entry, guild_id, event_sequence)?;
    Ok((entry, bytes.len()))
}

pub struct CatalogCodingReader {
    scope: CatalogScope,
    root: CatalogCodingRoot,
    part: usize,
    active: Option<CatalogRecordReader>,
    summary: CatalogCodingSummary,
    previous: Option<[u8; 32]>,
    failed: bool,
    last_group: Option<CatalogCodingGroupRange>,
}

impl CatalogCodingReader {
    pub fn new(scope: CatalogScope, root: CatalogCodingRoot) -> Result<Self, CatalogError> {
        guild(scope)?;
        root.validate()?;
        Ok(Self {
            scope,
            root,
            part: 0,
            active: None,
            summary: CatalogCodingSummary::default(),
            previous: None,
            failed: false,
            last_group: None,
        })
    }

    pub fn next_group<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.last_group = None;
        let result = self.next_inner(fetch);
        self.failed = result.is_err();
        result
    }

    /// Valid only for the last yielded group, and cleared at EOF or failure.
    /// Completion of the enclosing traversal is still required before indexing.
    pub fn last_group_range(&self) -> Option<CatalogCodingGroupRange> {
        if self.failed { None } else { self.last_group }
    }

    pub fn last_group_location(&self) -> Option<CatalogCodingGroupLocation> {
        let range = self.last_group_range()?;
        Some(CatalogCodingGroupLocation {
            page: self.root.parts[usize::from(range.part)].page,
            range,
        })
    }

    fn next_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStreamError<E>> {
        let (header, start) = loop {
            if let Some(active) = &mut self.active {
                if let Some(bytes) = active.next_record(fetch)? {
                    break (
                        CatalogCodingRecord::decode(&bytes)?,
                        active
                            .last_record_range()
                            .ok_or(CatalogError::InvalidPage)?
                            .start,
                    );
                }
                self.active = None;
            }
            let Some(part) = self.root.parts.get(self.part) else {
                if self.summary != self.root.summary {
                    return Err(CatalogError::InvalidPage.into());
                }
                return Ok(None);
            };
            self.active = Some(CatalogRecordReader::new(
                self.scope,
                CatalogSection::Coding,
                *part,
            )?);
            self.part += 1;
        };
        let CatalogCodingRecord::Header {
            lifecycle,
            transcript_hash,
            ..
        } = &header
        else {
            return Err(CatalogError::InvalidPage.into());
        };
        let group_id = lifecycle.group_id;
        let transcript_hash = *transcript_hash;
        if self.summary.groups == self.root.summary.groups
            || self.previous.is_some_and(|previous| previous >= group_id)
        {
            return Err(CatalogError::InvalidPage.into());
        }
        let active = self
            .active
            .as_mut()
            .expect("header belongs to an active part");
        let (entry, bytes) = read_entry(
            header,
            guild(self.scope)?,
            self.root.guild_event_sequence,
            &mut || active.next_record(fetch),
        )?;
        let end = active
            .last_record_range()
            .ok_or(CatalogError::InvalidPage)?
            .end;
        if end - start > CATALOG_CODING_GROUP_BYTES as u64 {
            return Err(CatalogError::Bounds.into());
        }
        self.last_group = Some(CatalogCodingGroupRange {
            part: (self.part - 1) as u8,
            offset: start,
            len: u32::try_from(end - start).map_err(|_| CatalogError::Bounds)?,
            group_id,
            transcript_hash,
        });
        self.summary.add(&entry, bytes)?;
        self.previous = Some(group_id);
        Ok(Some(entry))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{
        CODING_ATTEMPT_PLAN_DOMAIN, CODING_CHALLENGE_COMMITMENT_DOMAIN,
        CODING_CHALLENGE_REVEAL_DOMAIN, CODING_ROOT_MANIFEST_DOMAIN, CODING_SHARD_OPENING_DOMAIN,
        CODING_TRANSCRIPT_DOMAIN, CodingPlanGeometry, CodingProfile, InformationRoleV2,
        KeyMaterial, ParityPlacementV2, RangeSectorRef, STAGED_STORAGE_RECEIPT_DOMAIN, Seed,
        ShardRoleV2, challenged_leaf, coding_challenge, coding_challenge_commitment,
        coding_evidence_hash, encode_coding_attempt, merkle_commit, merkle_open_range, sector_root,
    };
    use std::collections::HashMap;

    type Pages = HashMap<[u8; 32], Vec<u8>>;
    fn scope() -> CatalogScope {
        CatalogScope::Guild { guild_id: [37; 32] }
    }
    fn keys() -> Vec<KeyMaterial> {
        (0..8)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 38; 32])))
            .collect()
    }
    pub(in crate::catalog) fn entry(
        version: u16,
        id: u64,
        shard_size: u32,
        domain_bytes: usize,
    ) -> CatalogCodingEntry {
        entry_with_legacy_group(version, id, shard_size, domain_bytes, false)
    }

    fn entry_with_legacy_group(
        version: u16,
        id: u64,
        shard_size: u32,
        domain_bytes: usize,
        legacy_group: bool,
    ) -> CatalogCodingEntry {
        let keys = keys();
        let information = (1..=3)
            .map(|value| vec![value; shard_size as usize])
            .collect::<Vec<_>>();
        let mut attempt_id = [0; 16];
        attempt_id[..8].copy_from_slice(&id.to_be_bytes());
        let information_roles = information
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let mut sector_id = [index as u8 + 1; 32];
                sector_id[..8].copy_from_slice(&id.to_be_bytes());
                InformationRoleV2 {
                    owner: keys[index].node_id(),
                    failure_domain: format!("{:0width$}", index, width = domain_bytes),
                    sector: RangeSectorRef {
                        id: sector_id,
                        commitment: merkle_commit(bytes).unwrap(),
                        logical_len: shard_size,
                        virtual_zero: false,
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
                membership_epoch: u64::MAX,
                geometry: CodingPlanGeometry {
                    format_version: 1,
                    guild_id: [37; 32],
                    profile: CodingProfile::new(3, 2, shard_size),
                    information: information_roles,
                    parity: (0..2)
                        .map(|row| ParityPlacementV2 {
                            holder: keys[row + 3].node_id(),
                            failure_domain: format!("{:0width$}", row + 3, width = domain_bytes),
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
                        .map(|bytes| {
                            if version == 2 {
                                merkle_commit(bytes).unwrap().root
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
        let (mut manifest, parity) = encode_coding_attempt(
            &plan,
            information.iter().cloned().map(Some).collect(),
            &keys[6],
        )
        .unwrap();
        if legacy_group {
            assert_eq!(version, 3);
            let mut value = manifest.value;
            value.group.format_version = 2;
            value.group.id = value.group.calculate_id().unwrap();
            manifest = SignedRecord::sign(CODING_ROOT_MANIFEST_DOMAIN, value, &keys[6]).unwrap();
        }
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
                        guild_id: [37; 32],
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

    fn build(entries: &[CatalogCodingEntry], part_limit: u64) -> (CatalogCodingRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogCodingBuilder::new(scope(), i64::MAX as u64).unwrap();
        builder.part_limit = part_limit;
        for entry in entries {
            builder.push_group(entry, &mut sink).unwrap();
        }
        (builder.finish(&mut sink).unwrap(), pages)
    }

    fn read(
        root: CatalogCodingRoot,
        pages: &Pages,
    ) -> Result<Vec<CatalogCodingEntry>, CatalogStreamError<&'static str>> {
        let mut reader = CatalogCodingReader::new(scope(), root)?;
        let mut entries = Vec::new();
        while let Some(entry) =
            reader.next_group(&mut |page| pages.get(&page.hash).cloned().ok_or("missing"))?
        {
            entries.push(entry);
        }
        Ok(entries)
    }

    fn original_records(entry: &CatalogCodingEntry) -> Vec<CatalogCodingRecord> {
        let bytes = canonical_bytes(&entry.transcript).unwrap();
        let mut records = vec![CatalogCodingRecord::Header {
            format_version: 1,
            lifecycle: CatalogCodingLifecycle::from_group(&entry.retained),
            transcript_hash: *blake3::hash(&bytes).as_bytes(),
            transcript_bytes: bytes.len() as u32,
        }];
        records.extend(bytes.chunks(CATALOG_CODING_FRAGMENT_BYTES).enumerate().map(
            |(index, bytes)| CatalogCodingRecord::Transcript {
                offset: (index * CATALOG_CODING_FRAGMENT_BYTES) as u32,
                bytes: bytes.to_vec(),
            },
        ));
        records
    }

    fn raw_part(records: &[CatalogCodingRecord], pages: &mut Pages) -> CatalogRecordRoot {
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::Coding).unwrap();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        builder.finish(&mut sink).unwrap()
    }

    #[test]
    fn malformed_fragments_bad_transcripts_trailers_and_cross_part_groups_fail_closed() {
        let good = entry(3, 1, 65536, 12);
        let (original, _) = build(std::slice::from_ref(&good), CATALOG_MAX_STREAM_BYTES);
        let records = original_records(&good);
        for mutation in 0..10 {
            let mut records = records.clone();
            let mut extra_record = false;
            let mut missing_record = false;
            match mutation {
                0 => {
                    if let CatalogCodingRecord::Transcript { offset, .. } = &mut records[1] {
                        *offset = 1;
                    }
                }
                1 => {
                    if let CatalogCodingRecord::Transcript { bytes, .. } = &mut records[1] {
                        bytes.pop();
                    }
                }
                2 => records[1] = records[0].clone(),
                3 => {
                    if let CatalogCodingRecord::Transcript { bytes, .. } = &mut records[1] {
                        bytes[0] ^= 1;
                    }
                }
                4 => {
                    if let CatalogCodingRecord::Header {
                        transcript_hash, ..
                    } = &mut records[0]
                    {
                        transcript_hash[0] ^= 1;
                    }
                }
                5 => {
                    if let CatalogCodingRecord::Header { lifecycle, .. } = &mut records[0] {
                        lifecycle.group_id[0] ^= 1;
                    }
                }
                6 => {
                    let mut bad = good.clone();
                    bad.transcript.signature[0] ^= 1;
                    records = original_records(&bad);
                }
                7 => {
                    if let CatalogCodingRecord::Header {
                        transcript_bytes, ..
                    } = &mut records[0]
                    {
                        *transcript_bytes += 1;
                    }
                }
                8 => {
                    records.pop();
                    missing_record = true;
                }
                _ => {
                    records.push(records[1].clone());
                    extra_record = true;
                }
            }
            let mut pages = Pages::new();
            let mut root = original.clone();
            let mut part = raw_part(&records, &mut pages);
            if missing_record {
                part.records += 1;
            }
            if extra_record {
                part.records -= 1;
            }
            root.parts = vec![part];
            let mut reader = CatalogCodingReader::new(scope(), root).unwrap();
            let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone());
            assert!(
                reader.next_group(&mut fetch).is_err(),
                "mutation {mutation}"
            );
            assert!(matches!(
                reader.next_group(&mut fetch),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
        let mut pages = Pages::new();
        let mut split = original;
        split.parts = vec![
            raw_part(&records[..2], &mut pages),
            raw_part(&records[2..], &mut pages),
        ];
        assert!(read(split, &pages).is_err());
        let (root, mut pages) = build(&[good], CATALOG_MAX_STREAM_BYTES);
        let mut reader =
            CatalogReader::new(scope(), CatalogSection::Coding, root.parts[0].page).unwrap();
        let mut last = None;
        while reader
            .next_leaf(&mut |page| {
                let bytes = pages[&page.hash].clone();
                if matches!(
                    page.verify_page(scope(), CatalogSection::Coding, &bytes)
                        .unwrap(),
                    CatalogPageContents::Leaf(_)
                ) {
                    last = Some(page.hash);
                }
                Ok::<_, ()>(bytes)
            })
            .unwrap()
            .is_some()
        {}
        pages.get_mut(&last.unwrap()).unwrap()[0] ^= 1;
        assert!(read(root, &pages).is_err());
    }

    #[test]
    fn coding_root_and_record_bounds_include_all_forest_parts_and_exact_summaries() {
        let (root, _) = build(&[entry(2, 1, 64, 12)], CATALOG_MAX_STREAM_BYTES);
        let bytes = canonical_bytes(&root).unwrap();
        assert_eq!(CatalogCodingRoot::decode(&bytes).unwrap(), root);
        for length in 0..bytes.len() {
            assert!(CatalogCodingRoot::decode(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(CatalogCodingRoot::decode(&extra).is_err());
        assert!(CatalogCodingRoot::decode(&vec![0; CATALOG_CODING_ROOT_BYTES + 1]).is_err());
        for mutation in 0..9 {
            let mut invalid = root.clone();
            match mutation {
                0 => invalid.format_version = 2,
                1 => invalid.guild_event_sequence = u64::MAX,
                2 => invalid.summary.groups = u64::MAX,
                3 => invalid.summary.fragments = u64::MAX,
                4 => invalid.summary.transcript_bytes = u64::MAX,
                5 => invalid.summary.information_roles = u64::MAX,
                6 => invalid.summary.retired_groups = 2,
                7 => invalid.parts = vec![invalid.parts[0]; CATALOG_CODING_PARTS + 1],
                _ => invalid.parts[0].records += 1,
            }
            assert!(CatalogCodingRoot::decode(&canonical_bytes(&invalid).unwrap()).is_err());
        }
        // Each component passes its existing tree bounds. The forest must
        // reject aggregate page/byte amplification before fetching any page.
        let mut amplified = root.clone();
        let part = &mut amplified.parts[0];
        part.page.height = 3;
        part.page.page_occurrences = 300_000;
        part.page.byte_len = CATALOG_MAX_STREAM_BYTES;
        part.records = 2_000_000;
        amplified.parts = vec![*part; 4];
        amplified.summary = CatalogCodingSummary {
            groups: 4_000_000,
            retired_groups: 0,
            information_roles: 12_000_000,
            parity_roles: 8_000_000,
            transcript_bytes: 4_000_000,
            fragments: 4_000_000,
        };
        assert!(amplified.parts.iter().all(|part| part.validate().is_ok()));
        assert!(amplified.validate().is_err());
        for part in &mut amplified.parts {
            part.page.page_occurrences = 200_000;
        }
        assert!(amplified.page_occurrences().is_err()); // fixed root exceeds 4 * 16 GiB
        for part in &mut amplified.parts {
            part.page.byte_len -= 4096;
        }
        amplified.validate().unwrap();
        assert_eq!(amplified.page_occurrences().unwrap(), 800_000);
        assert!(amplified.summary.groups > crate::V1_MAX_CODING_GROUPS as u64);
        assert!(
            CatalogCodingBuilder::new(
                CatalogScope::Dataset {
                    guild_id: [37; 32],
                    owner: keys()[0].node_id(),
                    protected_root_id: uuid::Uuid::from_u128(1)
                },
                1
            )
            .is_err()
        );
        assert!(CatalogCodingBuilder::new(scope(), u64::MAX).is_err());
        // A valid fixed record vector captures positional variant/field order.
        let record = CatalogCodingRecord::Header {
            format_version: 1,
            lifecycle: CatalogCodingLifecycle {
                group_id: [1; 32],
                added_at_event: 1,
                retired_at_event: Some(2),
                retain_through_event: Some(3),
            },
            transcript_hash: [2; 32],
            transcript_bytes: 100,
        };
        let encoded = canonical_bytes(&record).unwrap();
        assert_eq!(CatalogCodingRecord::decode(&encoded).unwrap(), record);
        for length in 0..encoded.len() {
            assert!(CatalogCodingRecord::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(CatalogCodingRecord::decode(&trailing).is_err());
    }

    #[test]
    fn original_coding_evidence_round_trips_all_plan_versions_and_empty_forests() {
        let (root, pages) = build(&[], CATALOG_MAX_STREAM_BYTES);
        assert!(root.parts.is_empty());
        assert!(pages.is_empty());
        assert_eq!(root.page_occurrences().unwrap(), 0);
        assert!(read(root.clone(), &pages).unwrap().is_empty());
        assert_eq!(
            CatalogCodingRoot::decode(&canonical_bytes(&root).unwrap()).unwrap(),
            root
        );
        for (version, legacy_group) in [(1, false), (2, false), (3, false), (3, true)] {
            let mut entry = entry_with_legacy_group(
                version,
                1,
                if version == 3 { 65536 } else { 64 },
                12,
                legacy_group,
            );
            entry.retained.retired_at_event = Some(2);
            entry.retained.retain_through_event = Some(u64::MAX);
            let original = canonical_bytes(&entry.transcript).unwrap();
            let group_id = entry.retained.group.id;
            let (root, pages) = build(&[entry.clone()], CATALOG_MAX_STREAM_BYTES);
            assert_eq!(root.summary.groups, 1);
            assert_eq!(root.summary.retired_groups, 1);
            assert_eq!(root.summary.transcript_bytes, original.len() as u64);
            if version == 3 {
                assert!(root.summary.fragments > 10);
                assert!(root.parts[0].page.page_occurrences > 1);
            }
            let decoded = read(root, &pages).unwrap();
            assert_eq!(decoded, vec![entry]);
            assert_eq!(canonical_bytes(&decoded[0].transcript).unwrap(), original);
            assert_eq!(decoded[0].retained.group.id, group_id);
        }
    }

    #[test]
    fn part_boundaries_preserve_global_order_and_complete_eof() {
        let mut entries = (1..=5).map(|id| entry(2, id, 64, 12)).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.retained.group.id);
        let bytes = canonical_bytes(&entries[0].transcript).unwrap().len() as u64;
        let part_limit = bytes + 512;
        let (root, pages) = build(&entries[..4], part_limit);
        assert_eq!(root.parts.len(), 4);
        assert_eq!(read(root.clone(), &pages).unwrap(), entries[..4]);
        let mut reordered = root.clone();
        reordered.parts.swap(0, 1);
        assert!(read(reordered, &pages).is_err());
        let mut duplicated = root.clone();
        duplicated.parts[1] = duplicated.parts[0];
        assert!(read(duplicated, &pages).is_err());
        let mut missing = pages.clone();
        missing.remove(&root.parts[3].page.hash);
        assert!(read(root.clone(), &missing).is_err());
        let mut wrong_summary = root;
        wrong_summary.summary.retired_groups += 1;
        assert!(read(wrong_summary, &pages).is_err());
        let mut builder = CatalogCodingBuilder::new(scope(), 2).unwrap();
        builder.part_limit = part_limit;
        let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
        for entry in &entries[..4] {
            builder.push_group(entry, &mut sink).unwrap();
        }
        assert!(builder.push_group(&entries[4], &mut sink).is_err());
        assert!(matches!(
            builder.push_group(&entries[0], &mut sink),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        assert!(builder.finish(&mut sink).is_err());
    }

    #[test]
    fn many_compact_groups_share_byte_pages_without_per_group_roots() {
        let mut entries = (1..=64).map(|id| entry(2, id, 64, 12)).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.retained.group.id);
        let (root, pages) = build(&entries, CATALOG_MAX_STREAM_BYTES);
        assert_eq!(root.parts.len(), 1);
        assert_eq!(root.summary.groups, 64);
        assert!(root.parts[0].page.page_occurrences > 4);
        assert!(root.parts[0].page.page_occurrences < root.summary.groups);
        assert_eq!(read(root.clone(), &pages).unwrap(), entries);
        let mut reader = CatalogCodingReader::new(scope(), root.clone()).unwrap();
        for expected in &entries {
            assert_eq!(
                reader
                    .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
            let range = reader.last_group_range().unwrap();
            let mut fetches = 0;
            assert_eq!(
                root.read_group(scope(), range, &mut |page| {
                    fetches += 1;
                    Ok::<_, ()>(pages[&page.hash].clone())
                })
                .unwrap(),
                *expected
            );
            assert!(fetches <= 3);
            assert!(fetches < root.parts[0].page.page_occurrences);
        }
        assert!(
            reader
                .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
                .unwrap()
                .is_none()
        );
        assert!(reader.last_group_range().is_none());
        let mut builder = CatalogCodingBuilder::new(scope(), 2).unwrap();
        let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
        builder.push_group(&entries[0], &mut sink).unwrap();
        assert!(builder.push_group(&entries[0], &mut sink).is_err());
        assert!(builder.finish(&mut sink).is_err());
    }

    #[test]
    fn authenticated_group_ranges_replay_full_witnesses_and_reject_invalid_cursors() {
        let expected = entry(3, 1, 65536, 12);
        let (root, pages) = build(std::slice::from_ref(&expected), CATALOG_MAX_STREAM_BYTES);
        let mut reader = CatalogCodingReader::new(scope(), root.clone()).unwrap();
        assert_eq!(
            reader
                .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
                .unwrap(),
            Some(expected.clone())
        );
        let range = reader.last_group_range().unwrap();
        assert_eq!(range.offset, 8);
        assert!(range.len > 65536);
        assert_eq!(
            root.read_group(scope(), range, &mut |page| Ok::<_, ()>(
                pages[&page.hash].clone()
            ))
            .unwrap(),
            expected
        );
        for mutation in 0..9 {
            let mut bad = range;
            match mutation {
                0 => bad.offset = 0,
                1 => bad.offset = u64::MAX,
                2 => bad.offset += 1,
                3 => bad.len = 0,
                4 => bad.len -= 1,
                5 => bad.len = u32::MAX,
                6 => bad.part = CATALOG_CODING_PARTS as u8,
                7 => bad.group_id[0] ^= 1,
                8 => bad.transcript_hash[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                root.read_group(scope(), bad, &mut |page| Ok::<_, ()>(
                    pages[&page.hash].clone()
                ))
                .is_err(),
                "mutation {mutation}"
            );
        }
        assert!(
            root.read_group(
                CatalogScope::Guild { guild_id: [99; 32] },
                range,
                &mut |page| Ok::<_, ()>(pages[&page.hash].clone())
            )
            .is_err()
        );
        assert!(
            root.read_group(scope(), range, &mut |_| Err::<Vec<u8>, _>("cancelled"))
                .is_err()
        );
        assert!(
            root.read_group(scope(), range, &mut |page| {
                let mut bytes = pages[&page.hash].clone();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                Ok::<_, ()>(bytes)
            })
            .is_err()
        );
        let mut reader = CatalogCodingReader::new(scope(), root).unwrap();
        assert!(
            reader
                .next_group(&mut |_| Err::<Vec<u8>, _>("cancelled"))
                .is_err()
        );
        assert!(reader.last_group_range().is_none());
    }

    #[test]
    fn bounded_nested_signatures_and_witness_collections_reject_before_replay() {
        let entry = entry(2, 1, 64, 12);
        let bytes = canonical_bytes(&entry.transcript).unwrap();
        assert_eq!(
            decode_coding_transcript_bounded(&bytes).unwrap(),
            entry.transcript
        );
        for field in 0..7 {
            let mut signed = entry.transcript.clone();
            let signature = match field {
                0 => &mut signed.signature,
                1 => &mut signed.value.plan.signature,
                2 => &mut signed.value.manifest.signature,
                3 => &mut signed.value.challenge_commitment.signature,
                4 => &mut signed.value.staged_receipts[0].signature,
                5 => &mut signed.value.challenge_reveal.signature,
                _ => &mut signed.value.openings[0].signature,
            };
            signature.push(0);
            assert!(decode_coding_transcript_bounded(&canonical_bytes(&signed).unwrap()).is_err());
        }
        let mut signed = entry.transcript.clone();
        signed.value.staged_receipts = vec![signed.value.staged_receipts[0].clone(); 65];
        assert!(decode_coding_transcript_bounded(&canonical_bytes(&signed).unwrap()).is_err());
        let mut signed = entry.transcript.clone();
        signed.value.openings = vec![signed.value.openings[0].clone(); 65];
        assert!(decode_coding_transcript_bounded(&canonical_bytes(&signed).unwrap()).is_err());
        let record = CatalogCodingRecord::Transcript {
            offset: 0,
            bytes: vec![0; CATALOG_CODING_FRAGMENT_BYTES + 1],
        };
        assert!(CatalogCodingRecord::decode(&canonical_bytes(&record).unwrap()).is_err());
        assert!(CatalogCodingRecord::decode(&vec![0; CATALOG_CODING_RECORD_BYTES + 1]).is_err());
        assert!(
            decode_coding_transcript_bounded(&vec![0; CATALOG_CODING_TRANSCRIPT_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn lifecycle_bad_evidence_wrong_group_and_sink_failures_fence_builders() {
        let good = entry(2, 1, 64, 12);
        let mut invalid = Vec::new();
        let mut next = good.clone();
        next.retained.added_at_event = 0;
        invalid.push(next);
        let mut next = good.clone();
        next.retained.added_at_event = 4;
        invalid.push(next);
        let mut next = good.clone();
        next.retained.retired_at_event = Some(2);
        invalid.push(next);
        let mut next = good.clone();
        next.retained.retired_at_event = Some(4);
        next.retained.retain_through_event = Some(4);
        invalid.push(next);
        let mut next = good.clone();
        next.retained.retired_at_event = Some(2);
        next.retained.retain_through_event = Some(1);
        invalid.push(next);
        let mut next = good.clone();
        next.retained.group.id[0] ^= 1;
        invalid.push(next);
        let mut next = good.clone();
        next.transcript.signature[0] ^= 1;
        invalid.push(next);
        let mut next = good.clone();
        next.transcript.value.openings[0].signature[0] ^= 1;
        next.transcript =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, next.transcript.value, &keys()[7])
                .unwrap();
        invalid.push(next);
        let mut next = good.clone();
        next.transcript.value.openings[0].value.proof.leaves[0][0] ^= 1;
        next.transcript.value.openings[0] = SignedRecord::sign(
            CODING_SHARD_OPENING_DOMAIN,
            next.transcript.value.openings[0].value.clone(),
            &keys()[0],
        )
        .unwrap();
        next.transcript =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, next.transcript.value, &keys()[7])
                .unwrap();
        invalid.push(next);
        for entry in invalid {
            let mut builder = CatalogCodingBuilder::new(scope(), 3).unwrap();
            let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
            assert!(builder.push_group(&entry, &mut sink).is_err());
            assert!(matches!(
                builder.push_group(&good, &mut sink),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
        let large = entry(3, 1, 65536, 12);
        let mut builder = CatalogCodingBuilder::new(scope(), 3).unwrap();
        assert!(matches!(
            builder.push_group(&large, &mut |_, _| Err("sink")),
            Err(CatalogStreamError::Storage("sink"))
        ));
        assert!(builder.finish(&mut |_, _| Ok::<_, &str>(())).is_err());
    }

    #[test]
    fn dense_one_tib_default_coding_shape_fits_the_bounded_forest() {
        // Maximum failure-domain length and integer widths, using real signed
        // compact witnesses for the default 3+2 / 64 KiB profile. This is a
        // metadata/work calculation, not retained-data runtime qualification.
        let mut entry = entry(2, 1, 65536, 256);
        entry.retained.added_at_event = i64::MAX as u64 - 1;
        entry.retained.retired_at_event = Some(i64::MAX as u64);
        entry.retained.retain_through_event = Some(u64::MAX);
        // A real random challenge may select a one-byte leaf index. Charge
        // the two-byte maximum for every 64 KiB sample regardless of that draw.
        let sample_padding = entry
            .transcript
            .value
            .openings
            .iter()
            .map(|opening| {
                2 - canonical_size_bounded(&opening.value.proof.start_leaf, 5).unwrap() as u64
            })
            .sum::<u64>();
        let (root, _) = build(&[entry], CATALOG_MAX_STREAM_BYTES);
        let per_group = root.parts[0].page.byte_len - 8 + sample_padding;
        let groups = (1_u64 << 40).div_ceil(65536 * 3);
        let bytes =
            groups * per_group + 8 * CATALOG_CODING_PARTS as u64 + CATALOG_CODING_ROOT_BYTES as u64;
        let mut nodes = bytes.div_ceil(CATALOG_LEAF_BYTES as u64) + CATALOG_CODING_PARTS as u64;
        let mut pages = nodes;
        for _ in 0..CATALOG_MAX_HEIGHT {
            nodes = nodes.div_ceil(CATALOG_FANOUT as u64) + CATALOG_CODING_PARTS as u64;
            pages += nodes;
        }
        assert!(nodes <= CATALOG_CODING_PARTS as u64 + 1);
        eprintln!(
            "dense coding shape: {groups} groups, {per_group} bytes/group, {bytes} represented bytes, at most {pages} page occurrences"
        );
        assert!(bytes <= CATALOG_CODING_MAX_BYTES);
        assert!(pages <= CATALOG_MAX_PAGE_OCCURRENCES);
        assert!(groups * (root.summary.fragments + 1) <= CATALOG_MAX_RECORDS);
    }

    #[test]
    fn single_owner_dense_one_tib_requires_more_than_one_million_coding_pages() {
        // Audit the actual allocator, rather than assume four occupied slots.
        // One owner leaves a slot available for a future different owner.
        let profile = crate::PackingProfile {
            format_version: 1,
            sector_size: 65536,
            slot_size: 16384,
        };
        let owner = keys()[0].node_id();
        let inputs = (1..=3)
            .map(|index| {
                let bytes = vec![index; profile.sector_size as usize];
                crate::PackingInput {
                    owner,
                    protected_root: [4; 32],
                    object_id: [index; 32],
                    source_commitment: Some(merkle_commit(&bytes).unwrap()),
                    bytes,
                }
            })
            .collect();
        let packed = crate::pack_incremental(profile, None, inputs).unwrap();
        assert_eq!(packed.catalog.sectors.len(), 4);
        for sector in &packed.catalog.sectors {
            assert_eq!(
                sector
                    .slots
                    .iter()
                    .filter(|slot| slot.source().is_some())
                    .count(),
                3
            );
        }
        let sources = (1_u64 << 40) / u64::from(profile.sector_size);
        let packed_sectors = (sources * 4).div_ceil(3);
        let groups = packed_sectors.div_ceil(3);
        assert_eq!(packed_sectors, 22_369_622);
        assert_eq!(groups, 7_456_541);

        // A real default compact witness with the maximum supported certified
        // domain lengths. Strip *all* optional scalar-width expansion: three
        // u64 fields can each shrink by nine bytes, and five sampled leaf
        // indices by one. This is a lower bound for this supported family,
        // independent of the particular epoch/timestamps/random challenge.
        let entry = entry(2, 1, 65536, 256);
        let (root, _) = build(&[entry], CATALOG_MAX_STREAM_BYTES);
        let per_group_lower = root.parts[0].page.byte_len - 8 - 3 * 9 - 5;
        let coding_bytes_lower = groups * per_group_lower;
        let coding_leaves_lower = coding_bytes_lower.div_ceil(CATALOG_LEAF_BYTES as u64);
        assert!(coding_leaves_lower > 1_000_000);
        assert!(
            coding_bytes_lower + CATALOG_CODING_ROOT_BYTES as u64 + 32 < CATALOG_CODING_MAX_BYTES
        );
        assert!(groups * root.parts[0].records <= CATALOG_MAX_RECORDS);

        let sector = &packed.catalog.sectors[0];
        let header = CatalogPackedSectorRecord::Header {
            format_version: 1,
            id: sector.id,
            sector_index: 0,
            flat_root: sector.flat_root,
            commitment: sector.commitment.clone(),
        };
        let slots = CatalogPackedSectorRecord::CompactSlots {
            offset: 0,
            slots: sector
                .slots
                .iter()
                .map(|slot| {
                    if let Some(source) = slot.source() {
                        CatalogPackedSlotReference::Data(CatalogPackedChunkReference {
                            source_key: CatalogPackedSourceId {
                                owner: source.id.owner,
                                protected_root: source.id.protected_root,
                                object_id: source.id.object_id,
                            }
                            .key(),
                            chunk_index: source.id.chunk_index,
                            content_hash: source.content_hash,
                        })
                    } else {
                        CatalogPackedSlotReference::VirtualZero { source: None }
                    }
                })
                .collect(),
        };
        let descriptor_bytes_lower = 8 + packed_sectors * (8
            + canonical_size_bounded(&header, CATALOG_PACKED_RECORD_BYTES).unwrap() as u64
            + canonical_size_bounded(&slots, CATALOG_PACKED_RECORD_BYTES).unwrap() as u64)
            // Only the final sector may have fewer than three occupied slots.
            - 2 * 66;
        let source_header = CatalogPackedSourceRecord::Source {
            format_version: 1,
            id: CatalogPackedSourceId {
                owner,
                protected_root: [4; 32],
                object_id: [1; 32],
            },
            commitment: sector.commitment.clone(),
        };
        let subtrees = CatalogPackedSourceRecord::Subtrees {
            first_chunk: 0,
            roots: vec![[1; 32]; 4],
        };
        let source_bytes = 8 + sources
            * (8 + canonical_size_bounded(&source_header, CATALOG_PACKED_SOURCE_RECORD_BYTES)
                .unwrap() as u64
                + canonical_size_bounded(&subtrees, CATALOG_PACKED_SOURCE_RECORD_BYTES).unwrap()
                    as u64);
        assert!(descriptor_bytes_lower < CATALOG_MAX_STREAM_BYTES);
        assert!(source_bytes < CATALOG_MAX_STREAM_BYTES);
        assert!(packed_sectors * 2 <= CATALOG_MAX_RECORDS);
        assert!(sources * 2 <= CATALOG_MAX_RECORDS);
        let combined_bytes_lower = descriptor_bytes_lower + source_bytes + coding_bytes_lower;
        assert!(combined_bytes_lower > 64 * 1024 * 1024 * 1024);
        eprintln!(
            "single-owner 1 TiB lower bound: {sources} data sources, {packed_sectors} packed sectors, {groups} groups, {per_group_lower} coding bytes/group, {coding_bytes_lower} coding bytes, {coding_leaves_lower} coding leaves, {descriptor_bytes_lower} descriptor bytes, {source_bytes} source-proof bytes, {combined_bytes_lower} combined bytes before signed source trees/private metadata/history"
        );
        // This pins a necessary capacity correction. It is not a successful
        // retained-data runtime gate, and does not raise primitive limits.
    }

    #[test]
    fn coding_forest_and_original_transcripts_have_fixed_protocol_vectors() {
        let mut entries = (1..=4).map(|id| entry(2, id, 64, 12)).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.retained.group.id);
        let part_limit = canonical_bytes(&entries[0].transcript).unwrap().len() as u64 + 512;
        let (root, pages) = build(&entries, part_limit);
        assert_eq!(root.parts.len(), 4);
        assert_eq!(read(root.clone(), &pages).unwrap(), entries);
        let witnesses = entries
            .into_iter()
            .map(|entry| entry.transcript)
            .collect::<Vec<_>>();
        assert_eq!(
            hex::encode(canonical_bytes(&root).unwrap()),
            include_str!("../../../../protocol/vectors/coding-evidence-v1.postcard.hex").trim()
        );
        assert_eq!(
            hex::encode(canonical_bytes(&witnesses).unwrap()),
            include_str!("../../../../protocol/vectors/coding-transcripts-v1.postcard.hex").trim()
        );
    }
}

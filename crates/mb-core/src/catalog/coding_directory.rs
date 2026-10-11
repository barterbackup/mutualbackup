//! Ordered directories of original coding forests. A required trusted budget
//! covers the directory and every referenced witness, without resetting work
//! admission at a forest boundary. This does not authorize checkpoint activation.

use serde::{Deserialize, Serialize};

use super::*;
use crate::{canonical_bytes_bounded, canonical_size_bounded};

pub const CATALOG_CODING_DIRECTORY_ROOT_BYTES: usize = 512;

mod capacity;
pub use capacity::CatalogCodingDirectoryCapacity;
pub(super) use capacity::dense_forest_pages;

/// Local limits from the enclosing authenticated admission policy, never from
/// an untrusted directory's own claims. The eventual checkpoint must debit its
/// other sections before supplying the remaining budget here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingTraversalBudget {
    pub bytes: u64,
    pub page_occurrences: u64,
    pub records: u64,
}

impl CatalogCodingTraversalBudget {
    pub fn checked_add(self, work: Self) -> Result<Self, CatalogError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(work.bytes)
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self
                .page_occurrences
                .checked_add(work.page_occurrences)
                .ok_or(CatalogError::Bounds)?,
            records: self
                .records
                .checked_add(work.records)
                .ok_or(CatalogError::Bounds)?,
        })
    }

    /// Debit other admitted sections before constructing a nested reader. Each
    /// dimension is independent; exhaustion never wraps or resets the budget.
    pub fn remaining_after(self, work: Self) -> Result<Self, CatalogError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_sub(work.bytes)
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self
                .page_occurrences
                .checked_sub(work.page_occurrences)
                .ok_or(CatalogError::Bounds)?,
            records: self
                .records
                .checked_sub(work.records)
                .ok_or(CatalogError::Bounds)?,
        })
    }

    pub(super) fn check(self, work: Self) -> Result<(), CatalogError> {
        self.remaining_after(work).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingDirectorySummary {
    pub forests: u64,
    pub coding: CatalogCodingSummary,
    /// Only referenced part streams. Their forest descriptors already appear
    /// inside the directory's record stream and must not be charged twice.
    pub evidence_bytes: u64,
    pub evidence_pages: u64,
}

impl CatalogCodingDirectorySummary {
    fn add(&mut self, root: &CatalogCodingRoot) -> Result<(), CatalogError> {
        root.validate()?;
        if root.summary.groups == 0 {
            return Err(CatalogError::InvalidPage);
        }
        for (value, increment) in [
            (&mut self.forests, 1),
            (&mut self.coding.groups, root.summary.groups),
            (&mut self.coding.retired_groups, root.summary.retired_groups),
            (
                &mut self.coding.information_roles,
                root.summary.information_roles,
            ),
            (&mut self.coding.parity_roles, root.summary.parity_roles),
            (
                &mut self.coding.transcript_bytes,
                root.summary.transcript_bytes,
            ),
            (&mut self.coding.fragments, root.summary.fragments),
        ] {
            *value = value.checked_add(increment).ok_or(CatalogError::Bounds)?;
        }
        for part in &root.parts {
            self.evidence_bytes = self
                .evidence_bytes
                .checked_add(part.page.byte_len)
                .ok_or(CatalogError::Bounds)?;
            self.evidence_pages = self
                .evidence_pages
                .checked_add(part.page.page_occurrences)
                .ok_or(CatalogError::Bounds)?;
        }
        self.validate()
    }

    fn validate(self) -> Result<(), CatalogError> {
        if self.forests > CATALOG_MAX_RECORDS
            || self.coding.groups < self.forests
            || self.forests == 0 && self != Self::default()
            || self.evidence_bytes < self.forests * 8
            || self.evidence_bytes > self.forests * CATALOG_CODING_MAX_BYTES
            || self.evidence_pages < self.forests
            || self.evidence_pages > self.forests * CATALOG_MAX_PAGE_OCCURRENCES
        {
            return Err(CatalogError::Bounds);
        }
        self.coding
            .validate_with_record_limit(self.forests * CATALOG_MAX_RECORDS)
    }
}

/// Each directory record is one existing bounded CatalogCodingRoot. There is
/// no directory-sized vector and no new root per group. Formats/identities of
/// original forests, frames, transcripts and groups remain unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingDirectoryRoot {
    pub format_version: u16,
    pub guild_event_sequence: u64,
    pub records: CatalogRecordRoot,
    pub summary: CatalogCodingDirectorySummary,
}

impl CatalogCodingDirectoryRoot {
    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_CODING_DIRECTORY_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate(budget)?;
        if canonical_bytes_bounded(&root, CATALOG_CODING_DIRECTORY_ROOT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }

    pub fn validate(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogError> {
        self.records.validate()?;
        self.summary.validate()?;
        if self.format_version != 1
            || self.guild_event_sequence > i64::MAX as u64
            || self.summary.forests != self.records.records
            || self.summary.forests > 0 && self.guild_event_sequence == 0
        {
            return Err(CatalogError::Bounds);
        }
        budget.check(self.work()?)
    }

    /// Charge a fixed 512-byte root envelope, every directory frame and each
    /// referenced part occurrence. Repeated logical references count again.
    pub fn work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        Ok(CatalogCodingTraversalBudget {
            bytes: self
                .summary
                .evidence_bytes
                .checked_add(self.records.page.byte_len)
                .and_then(|bytes| bytes.checked_add(CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64))
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self
                .summary
                .evidence_pages
                .checked_add(self.records.page.page_occurrences)
                .ok_or(CatalogError::Bounds)?,
            records: self
                .summary
                .coding
                .groups
                .checked_add(self.summary.coding.fragments)
                .and_then(|records| records.checked_add(self.records.records))
                .ok_or(CatalogError::Bounds)?,
        })
    }

    /// The location must come from a trusted completed traversal/index. A point
    /// read does not establish global order, complete EOF or authority/coverage.
    pub fn read_group<E>(
        self,
        scope: CatalogScope,
        budget: CatalogCodingTraversalBudget,
        location: CatalogCodingGroupLocation,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<CatalogCodingEntry, CatalogStreamError<E>> {
        self.validate(budget)?;
        location.read_group(scope, self.guild_event_sequence, fetch)
    }

    /// Return the additional physical page reads and framed records consumed
    /// by an authenticated point replay, for enclosing custody admission.
    pub fn read_group_with_work<E>(
        self,
        scope: CatalogScope,
        budget: CatalogCodingTraversalBudget,
        location: CatalogCodingGroupLocation,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<(CatalogCodingEntry, CatalogCodingTraversalBudget), CatalogStreamError<E>> {
        self.validate(budget)?;
        location.read_group_with_work(scope, self.guild_event_sequence, fetch)
    }

    /// Replay one indexed original witness within the owner's remaining work
    /// budget. Admit each authenticated page before fetching it and each framed
    /// record before decoding it. Directory admission remains independent.
    pub fn read_group_with_work_budget<E>(
        self,
        scope: CatalogScope,
        directory_budget: CatalogCodingTraversalBudget,
        location: CatalogCodingGroupLocation,
        replay_budget: CatalogCodingTraversalBudget,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<(CatalogCodingEntry, CatalogCodingTraversalBudget), CatalogStreamError<E>> {
        self.validate(directory_budget)?;
        location.read_group_with_work_budget(scope, self.guild_event_sequence, replay_budget, fetch)
    }
}

fn dense_pages(bytes: u64) -> Result<u64, CatalogError> {
    let mut nodes = bytes.div_ceil(CATALOG_LEAF_BYTES as u64).max(1);
    let mut pages = nodes;
    for _ in 0..CATALOG_MAX_HEIGHT {
        if nodes == 1 {
            return Ok(pages);
        }
        nodes = nodes.div_ceil(CATALOG_FANOUT as u64);
        pages = pages.checked_add(nodes).ok_or(CatalogError::Bounds)?;
    }
    if nodes != 1 {
        return Err(CatalogError::Bounds);
    }
    Ok(pages)
}

pub struct CatalogCodingDirectoryBuilder {
    scope: CatalogScope,
    sequence: u64,
    budget: CatalogCodingTraversalBudget,
    directory: CatalogRecordBuilder,
    directory_bytes: u64,
    active: Option<CatalogCodingBuilder>,
    summary: CatalogCodingDirectorySummary,
    previous: Option<[u8; 32]>,
    forest_limit: u64,
    group_limit: Option<u64>,
    failed: bool,
}

impl CatalogCodingDirectoryBuilder {
    pub fn new(
        scope: CatalogScope,
        sequence: u64,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        super::coding_evidence::guild(scope)?;
        if sequence > i64::MAX as u64 {
            return Err(CatalogError::Bounds);
        }
        budget.check(CatalogCodingTraversalBudget {
            bytes: 8 + CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64,
            page_occurrences: 1,
            records: 0,
        })?;
        Ok(Self {
            scope,
            sequence,
            budget,
            directory: CatalogRecordBuilder::new(scope, CatalogSection::Coding)?,
            directory_bytes: 8,
            active: None,
            summary: Default::default(),
            previous: None,
            // A dense single-tree forest remains below the original forest's
            // page ceiling. Additional forests share the enclosing budget.
            forest_limit: CATALOG_MAX_STREAM_BYTES,
            group_limit: None,
            failed: false,
        })
    }

    /// Reserve the full supported original-witness upper bound before staging.
    /// The enclosing trusted budget must cover it, after debiting every other
    /// checkpoint section. Refuse extra groups even if their encodings are
    /// smaller. This does not admit SQL, payload, scratch or physical storage.
    pub fn for_group_capacity(
        scope: CatalogScope,
        sequence: u64,
        groups: u64,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        budget.check(CatalogCodingDirectoryCapacity::for_groups(groups)?.work)?;
        let mut builder = Self::new(scope, sequence, budget)?;
        builder.group_limit = Some(groups);
        Ok(builder)
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
        let accepted = self
            .summary
            .coding
            .groups
            .checked_add(
                self.active
                    .as_ref()
                    .map_or(0, |active| active.summary().groups),
            )
            .ok_or(CatalogError::Bounds)?;
        if self.group_limit.is_some_and(|limit| accepted >= limit) {
            return Err(CatalogError::Bounds.into());
        }
        if self
            .previous
            .is_some_and(|id| id >= entry.retained.group.id)
        {
            return Err(CatalogError::InvalidPage.into());
        }
        let witness = canonical_size_bounded(&entry.transcript, CATALOG_CODING_TRANSCRIPT_BYTES)
            .map_err(CatalogError::from)? as u64;
        let upper_group_bytes =
            witness + (CATALOG_CODING_GROUP_BYTES - CATALOG_CODING_TRANSCRIPT_BYTES) as u64;
        if upper_group_bytes + 8 + CATALOG_CODING_ROOT_BYTES as u64 > self.forest_limit {
            return Err(CatalogError::Bounds.into());
        }
        if self.active.as_ref().is_some_and(|active| {
            active.stream_bytes() + upper_group_bytes + CATALOG_CODING_ROOT_BYTES as u64
                > self.forest_limit
        }) {
            self.finish_forest(sink)?;
        }
        if self.active.is_none() && self.summary.forests >= CATALOG_MAX_RECORDS {
            return Err(CatalogError::Bounds.into());
        }
        let stream_bytes = self
            .active
            .as_ref()
            .map_or(8, CatalogCodingBuilder::stream_bytes)
            + upper_group_bytes;
        let active_records = self.active.as_ref().map_or(0, |active| {
            active.summary().groups + active.summary().fragments
        });
        let directory_bytes = self.directory_bytes + 4 + CATALOG_CODING_ROOT_BYTES as u64;
        if directory_bytes > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let directory_pages = dense_pages(directory_bytes)?;
        self.budget.check(CatalogCodingTraversalBudget {
            bytes: self
                .summary
                .evidence_bytes
                .checked_add(stream_bytes)
                .and_then(|bytes| bytes.checked_add(directory_bytes))
                .and_then(|bytes| bytes.checked_add(CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64))
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self
                .summary
                .evidence_pages
                .checked_add(dense_pages(stream_bytes)?)
                .and_then(|pages| pages.checked_add(directory_pages))
                .ok_or(CatalogError::Bounds)?,
            records: self
                .summary
                .coding
                .groups
                .checked_add(self.summary.coding.fragments)
                .and_then(|records| records.checked_add(active_records))
                .and_then(|records| {
                    records.checked_add(1 + witness.div_ceil(CATALOG_CODING_FRAGMENT_BYTES as u64))
                })
                .and_then(|records| records.checked_add(self.summary.forests + 1))
                .ok_or(CatalogError::Bounds)?,
        })?;
        if self.active.is_none() {
            self.active = Some(CatalogCodingBuilder::new(self.scope, self.sequence)?);
        }
        self.active
            .as_mut()
            .expect("active forest")
            .push_group(entry, sink)?;
        self.previous = Some(entry.retained.group.id);
        Ok(())
    }

    fn append_forest<E>(
        &mut self,
        root: &CatalogCodingRoot,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if root.guild_event_sequence != self.sequence {
            return Err(CatalogError::InvalidPage.into());
        }
        self.summary.add(root)?;
        let bytes =
            canonical_bytes_bounded(root, CATALOG_CODING_ROOT_BYTES).map_err(CatalogError::from)?;
        self.directory_bytes = self
            .directory_bytes
            .checked_add(4 + bytes.len() as u64)
            .ok_or(CatalogError::Bounds)?;
        self.budget.check(CatalogCodingTraversalBudget {
            bytes: self
                .summary
                .evidence_bytes
                .checked_add(self.directory_bytes)
                .and_then(|bytes| bytes.checked_add(CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64))
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self
                .summary
                .evidence_pages
                .checked_add(dense_pages(self.directory_bytes)?)
                .ok_or(CatalogError::Bounds)?,
            records: self
                .summary
                .coding
                .groups
                .checked_add(self.summary.coding.fragments)
                .and_then(|records| records.checked_add(self.summary.forests))
                .ok_or(CatalogError::Bounds)?,
        })?;
        self.directory.push_encoded(&bytes, sink)
    }

    fn finish_forest<E>(
        &mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if let Some(builder) = self.active.take() {
            let root = builder.finish(sink)?;
            self.append_forest(&root, sink)?;
        }
        Ok(())
    }

    pub fn finish<E>(
        mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogCodingDirectoryRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.finish_forest(sink)?;
        let root = CatalogCodingDirectoryRoot {
            format_version: 1,
            guild_event_sequence: self.sequence,
            records: self.directory.finish(sink)?,
            summary: self.summary,
        };
        root.validate(self.budget)?;
        Ok(root)
    }
}

pub struct CatalogCodingDirectoryReader {
    scope: CatalogScope,
    root: CatalogCodingDirectoryRoot,
    budget: CatalogCodingTraversalBudget,
    directory: CatalogRecordReader,
    active: Option<CatalogCodingReader>,
    summary: CatalogCodingDirectorySummary,
    previous: Option<[u8; 32]>,
    last: Option<CatalogCodingGroupLocation>,
    failed: bool,
}

impl CatalogCodingDirectoryReader {
    pub fn new(
        scope: CatalogScope,
        root: CatalogCodingDirectoryRoot,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        super::coding_evidence::guild(scope)?;
        root.validate(budget)?;
        Ok(Self {
            scope,
            root,
            budget,
            directory: CatalogRecordReader::new(scope, CatalogSection::Coding, root.records)?,
            active: None,
            summary: Default::default(),
            previous: None,
            last: None,
            failed: false,
        })
    }

    pub fn next_group<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStreamError<E>> {
        self.next_group_with_forest(fetch, &mut |_| Ok(()))
    }

    /// Visit each structurally admitted forest once, before fetching any of its
    /// evidence pages. Durable owners can pin its bounded set of part roots in
    /// short transactions here. This callback grants no protocol authority;
    /// complete replayed EOF and enclosing authorization remain required.
    pub fn next_group_with_forest<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        forest: &mut impl FnMut(&CatalogCodingRoot) -> Result<(), E>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.last = None;
        let result = self.next_inner(fetch, forest);
        self.failed = result.is_err();
        result
    }

    pub fn last_group_location(&self) -> Option<CatalogCodingGroupLocation> {
        if self.failed { None } else { self.last }
    }

    fn next_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        visit: &mut impl FnMut(&CatalogCodingRoot) -> Result<(), E>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStreamError<E>> {
        loop {
            if let Some(active) = &mut self.active {
                if let Some(entry) = active.next_group(fetch)? {
                    let id = entry.retained.group.id;
                    if self.previous.is_some_and(|previous| previous >= id) {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    self.previous = Some(id);
                    self.last = active.last_group_location();
                    return Ok(Some(entry));
                }
                self.active = None;
            }
            let Some(bytes) = self.directory.next_record(fetch)? else {
                if self.summary != self.root.summary {
                    return Err(CatalogError::InvalidPage.into());
                }
                return Ok(None);
            };
            let forest = CatalogCodingRoot::decode(&bytes)?;
            if forest.guild_event_sequence != self.root.guild_event_sequence {
                return Err(CatalogError::InvalidPage.into());
            }
            self.summary.add(&forest)?;
            let declared = self.root.summary;
            if self.summary.forests > declared.forests
                || self.summary.coding.groups > declared.coding.groups
                || self.summary.coding.retired_groups > declared.coding.retired_groups
                || self.summary.coding.information_roles > declared.coding.information_roles
                || self.summary.coding.parity_roles > declared.coding.parity_roles
                || self.summary.coding.transcript_bytes > declared.coding.transcript_bytes
                || self.summary.coding.fragments > declared.coding.fragments
                || self.summary.evidence_bytes > declared.evidence_bytes
                || self.summary.evidence_pages > declared.evidence_pages
            {
                return Err(CatalogError::InvalidPage.into());
            }
            self.root.validate(self.budget)?;
            visit(&forest).map_err(CatalogStreamError::Storage)?;
            self.active = Some(CatalogCodingReader::new(self.scope, forest)?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::coding_evidence::tests::entry;
    use super::*;
    use crate::{NodeId, canonical_bytes};
    use std::collections::HashMap;

    type Pages = HashMap<[u8; 32], Vec<u8>>;
    fn scope() -> CatalogScope {
        CatalogScope::Guild { guild_id: [37; 32] }
    }
    fn budget() -> CatalogCodingTraversalBudget {
        CatalogCodingTraversalBudget {
            bytes: 96 * 1024 * 1024 * 1024,
            page_occurrences: 2_000_000,
            records: 64_000_000,
        }
    }
    fn entries(count: u64) -> Vec<CatalogCodingEntry> {
        let mut entries = (1..=count)
            .map(|id| entry(2, id, 64, 12))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.retained.group.id);
        entries
    }
    fn build(entries: &[CatalogCodingEntry], limit: u64) -> (CatalogCodingDirectoryRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder =
            CatalogCodingDirectoryBuilder::new(scope(), i64::MAX as u64, budget()).unwrap();
        builder.forest_limit = limit;
        for entry in entries {
            builder.push_group(entry, &mut sink).unwrap();
        }
        (builder.finish(&mut sink).unwrap(), pages)
    }
    fn forests(root: CatalogCodingDirectoryRoot, pages: &Pages) -> Vec<CatalogCodingRoot> {
        let mut reader =
            CatalogRecordReader::new(scope(), CatalogSection::Coding, root.records).unwrap();
        let mut roots = Vec::new();
        while let Some(bytes) = reader
            .next_record(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
            .unwrap()
        {
            roots.push(CatalogCodingRoot::decode(&bytes).unwrap());
        }
        roots
    }
    fn directory(roots: &[CatalogCodingRoot], pages: &mut Pages) -> CatalogCodingDirectoryRoot {
        let mut builder =
            CatalogCodingDirectoryBuilder::new(scope(), i64::MAX as u64, budget()).unwrap();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for root in roots {
            builder.append_forest(root, &mut sink).unwrap();
        }
        builder.finish(&mut sink).unwrap()
    }
    fn read(
        root: CatalogCodingDirectoryRoot,
        pages: &Pages,
    ) -> Result<Vec<CatalogCodingEntry>, CatalogStreamError<&'static str>> {
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget())?;
        let mut entries = Vec::new();
        while let Some(entry) =
            reader.next_group(&mut |page| pages.get(&page.hash).cloned().ok_or("missing"))?
        {
            entries.push(entry);
        }
        assert!(reader.last_group_location().is_none());
        Ok(entries)
    }

    #[test]
    fn declared_group_capacity_fences_extra_groups_before_staging_and_failure_is_sticky() {
        let entries = entries(3);
        let capacity = CatalogCodingDirectoryCapacity::for_groups(2).unwrap();
        let mut builder = CatalogCodingDirectoryBuilder::for_group_capacity(
            scope(),
            i64::MAX as u64,
            2,
            capacity.work,
        )
        .unwrap();
        let mut pages = Pages::new();
        let calls = std::cell::Cell::new(0);
        let mut sink = |page: CatalogPageRef, bytes| {
            calls.set(calls.get() + 1);
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for entry in &entries[..2] {
            builder.push_group(entry, &mut sink).unwrap();
        }
        let staged = calls.get();
        assert!(matches!(
            builder.push_group(&entries[2], &mut sink),
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
        assert_eq!(calls.get(), staged);
        assert!(matches!(
            builder.push_group(&entries[2], &mut sink),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        assert!(builder.finish(&mut sink).is_err());
        assert_eq!(calls.get(), staged);
        for dimension in 0..3 {
            let mut insufficient = capacity.work;
            match dimension {
                0 => insufficient.bytes -= 1,
                1 => insufficient.page_occurrences -= 1,
                _ => insufficient.records -= 1,
            }
            assert!(
                CatalogCodingDirectoryBuilder::for_group_capacity(
                    scope(),
                    i64::MAX as u64,
                    2,
                    insufficient,
                )
                .is_err()
            );
        }
        let empty = CatalogCodingDirectoryCapacity::for_groups(0).unwrap();
        let root = CatalogCodingDirectoryBuilder::for_group_capacity(scope(), 1, 0, empty.work)
            .unwrap()
            .finish(&mut |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(root.work().unwrap(), empty.work);
    }

    #[test]
    fn full_original_witnesses_shard_within_the_declared_construction_capacity() {
        let mut entries = (1..=12)
            .map(|id| entry(3, id, 65536, 256))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.retained.group.id);
        let forest_limit = 1024 * 1024;
        let capacity =
            CatalogCodingDirectoryCapacity::with_forest_limit(entries.len() as u64, forest_limit)
                .unwrap();
        let mut builder = CatalogCodingDirectoryBuilder::for_group_capacity(
            scope(),
            i64::MAX as u64,
            entries.len() as u64,
            capacity.work,
        )
        .unwrap();
        // Exercise the same shard algorithm at a smaller forest boundary. The
        // budget still reserves full 600 KiB originals, rather than this fixture.
        builder.forest_limit = forest_limit;
        let mut pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for entry in &entries {
            assert!(canonical_bytes(&entry.transcript).unwrap().len() > 192 * 1024);
            builder.push_group(entry, &mut sink).unwrap();
        }
        let root = builder.finish(&mut sink).unwrap();
        assert!(root.summary.forests > 1 && root.summary.forests <= capacity.forests);
        assert!(root.summary.evidence_bytes <= capacity.evidence_bytes);
        assert!(root.records.page.byte_len <= capacity.directory_bytes);
        assert!(root.summary.coding.transcript_bytes <= capacity.transcript_bytes);
        capacity.work.check(root.work().unwrap()).unwrap();
        assert!(
            pages.values().map(|bytes| bytes.len() as u64).sum::<u64>()
                <= capacity.encoded_page_bytes
        );
        assert_eq!(read(root, &pages).unwrap(), entries);
    }

    #[test]
    fn coding_directory_streams_more_than_four_forests_and_seeks_original_witnesses() {
        let entries = entries(12);
        let (root, pages) = build(&entries, 9000);
        assert_eq!(root.summary.forests, 12);
        assert_eq!(root.summary.coding.groups, 12);
        assert_eq!(read(root, &pages).unwrap(), entries);
        let roots = forests(root, &pages);
        assert!(roots.iter().all(|root| root.parts.len() == 1));
        assert_eq!(
            root.summary.evidence_bytes,
            roots
                .iter()
                .map(|root| root.parts[0].page.byte_len)
                .sum::<u64>()
        );
        assert_eq!(
            root.work().unwrap().records,
            root.records.records + roots.iter().map(|root| root.parts[0].records).sum::<u64>()
        );
        let encoded = canonical_bytes(&root).unwrap();
        assert_eq!(
            CatalogCodingDirectoryRoot::decode(&encoded, budget()).unwrap(),
            root
        );
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        for expected in &entries {
            assert_eq!(
                reader
                    .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
            let location = reader.last_group_location().unwrap();
            let mut fetches = 0;
            assert_eq!(
                root.read_group(scope(), budget(), location, &mut |page| {
                    fetches += 1;
                    Ok::<_, ()>(pages[&page.hash].clone())
                })
                .unwrap(),
                *expected
            );
            assert_eq!(fetches, 1);
            let mut bytes = 0;
            let mut pages_read = 0;
            let (decoded, work) = root
                .read_group_with_work(scope(), budget(), location, &mut |page| {
                    let encoded = pages[&page.hash].clone();
                    bytes += encoded.len() as u64;
                    pages_read += 1;
                    Ok::<_, ()>(encoded)
                })
                .unwrap();
            assert_eq!(decoded, *expected);
            assert_eq!(work.bytes, bytes);
            assert_eq!(work.page_occurrences, pages_read);
            assert_eq!(
                work.records,
                1 + crate::canonical_bytes(&expected.transcript)
                    .unwrap()
                    .len()
                    .div_ceil(CATALOG_CODING_FRAGMENT_BYTES) as u64
            );
        }
        assert!(
            reader
                .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
                .unwrap()
                .is_none()
        );
        assert!(reader.last_group_location().is_none());
        assert_eq!(
            root.work().unwrap().bytes,
            root.summary.evidence_bytes
                + root.records.page.byte_len
                + CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64
        );
    }

    #[test]
    fn coding_directory_budgets_do_not_reset_at_forest_boundaries_or_before_fetch() {
        let entries = entries(4);
        let (root, pages) = build(&entries, 9000);
        let work = root.work().unwrap();
        root.validate(work).unwrap();
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(CatalogCodingDirectoryReader::new(scope(), root, limit).is_err());
            assert!(
                CatalogCodingDirectoryRoot::decode(&canonical_bytes(&root).unwrap(), limit)
                    .is_err()
            );
        }
        for dimension in 0..3 {
            let mut small = budget();
            match dimension {
                0 => small.bytes = work.bytes - 1,
                1 => small.page_occurrences = work.page_occurrences - 1,
                _ => small.records = work.records - 1,
            }
            let mut builder =
                CatalogCodingDirectoryBuilder::new(scope(), i64::MAX as u64, small).unwrap();
            builder.forest_limit = 9000;
            let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
            let mut accepted = 0;
            for entry in &entries {
                if builder.push_group(entry, &mut sink).is_err() {
                    break;
                }
                accepted += 1;
            }
            assert!(accepted >= 2 && accepted < entries.len());
            assert!(matches!(
                builder.push_group(&entries[0], &mut sink),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
            assert!(builder.finish(&mut sink).is_err());
        }
        assert_eq!(read(root, &pages).unwrap(), entries);
    }

    #[test]
    fn coding_directory_global_order_nested_eof_and_exact_summaries_are_mandatory() {
        let entries = entries(4);
        let (root, original) = build(&entries, 9000);
        let roots = forests(root, &original);
        for mutation in 0..8 {
            let mut pages = original.clone();
            let mut roots = roots.clone();
            let mut root = root;
            match mutation {
                0 => {
                    roots.swap(0, 1);
                    root = directory(&roots, &mut pages);
                }
                1 => {
                    roots[1] = roots[0].clone();
                    root = directory(&roots, &mut pages);
                }
                2 => {
                    pages.remove(&roots[3].parts[0].page.hash);
                }
                3 => {
                    pages.get_mut(&roots[3].parts[0].page.hash).unwrap()[0] ^= 1;
                }
                4 => {
                    root.summary.coding.transcript_bytes += 1;
                }
                5 => {
                    root.summary.evidence_bytes += 1;
                }
                6 => {
                    root.summary.evidence_pages += 1;
                }
                7 => {
                    root.guild_event_sequence -= 1;
                }
                _ => unreachable!(),
            }
            assert!(read(root, &pages).is_err(), "accepted mutation {mutation}");
        }
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        assert!(
            reader
                .next_group(&mut |_| Err::<Vec<u8>, _>("cancelled"))
                .is_err()
        );
        assert!(reader.last_group_location().is_none());
        assert!(matches!(
            reader.next_group(&mut |_| Ok::<_, ()>(Vec::new())),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }

    #[test]
    fn coding_directory_root_bounds_empty_forests_and_sink_failure_fence_construction() {
        let (root, pages) = build(&[], CATALOG_MAX_STREAM_BYTES);
        assert_eq!(root.summary, CatalogCodingDirectorySummary::default());
        assert!(read(root, &pages).unwrap().is_empty());
        assert_eq!(root.work().unwrap().records, 0);
        let encoded = canonical_bytes(&root).unwrap();
        for length in 0..encoded.len() {
            assert!(CatalogCodingDirectoryRoot::decode(&encoded[..length], budget()).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(CatalogCodingDirectoryRoot::decode(&trailing, budget()).is_err());
        assert!(
            CatalogCodingDirectoryRoot::decode(
                &vec![0; CATALOG_CODING_DIRECTORY_ROOT_BYTES + 1],
                budget()
            )
            .is_err()
        );
        for mutation in 0..6 {
            let mut bad = root;
            match mutation {
                0 => bad.format_version = 2,
                1 => bad.guild_event_sequence = u64::MAX,
                2 => bad.summary.forests = u64::MAX,
                3 => bad.summary.evidence_bytes = u64::MAX,
                4 => bad.summary.evidence_pages = u64::MAX,
                _ => bad.summary.coding.groups = u64::MAX,
            }
            assert!(bad.validate(budget()).is_err());
        }
        assert!(
            CatalogCodingDirectoryBuilder::new(
                CatalogScope::Dataset {
                    guild_id: [37; 32],
                    owner: NodeId([1; 32]),
                    protected_root_id: uuid::Uuid::new_v4()
                },
                1,
                budget()
            )
            .is_err()
        );
        let entry = entry(3, 1, 65536, 12);
        let mut builder =
            CatalogCodingDirectoryBuilder::new(scope(), i64::MAX as u64, budget()).unwrap();
        assert!(
            builder
                .push_group(&entry, &mut |_, _| Err::<(), _>("sink"))
                .is_err()
        );
        assert!(builder.finish(&mut |_, _| Ok::<_, ()>(())).is_err());
        let empty = CatalogCodingRoot {
            format_version: 1,
            guild_event_sequence: i64::MAX as u64,
            parts: Vec::new(),
            summary: Default::default(),
        };
        let mut builder =
            CatalogCodingDirectoryBuilder::new(scope(), i64::MAX as u64, budget()).unwrap();
        assert!(
            builder
                .append_forest(&empty, &mut |_, _| Ok::<_, ()>(()))
                .is_err()
        );
    }

    #[test]
    fn coding_directory_pages_and_large_admission_do_not_expand_original_forests() {
        let (small, mut pages) = build(&entries(1), 9000);
        let forest = forests(small, &pages).remove(0);
        // Structural directory fixture only: repeated descriptors do not make
        // duplicate group identities admissible to the complete reader.
        let roots = vec![forest.clone(); 1024];
        let root = directory(&roots, &mut pages);
        assert!(root.records.page.height > 0);
        assert_eq!(forests(root, &pages), roots);
        assert!(read(root, &pages).is_err());

        // Represent a large closure without pretending to materialize its
        // evidence. Every child keeps the original byte/page/record limits.
        let mut large = forest.clone();
        large.parts[0].page.height = CATALOG_MAX_HEIGHT;
        large.parts[0].page.byte_len = CATALOG_MAX_STREAM_BYTES - 512;
        large.parts[0].page.page_occurrences = dense_pages(large.parts[0].page.byte_len).unwrap();
        large.parts[0].records = 2_000_000;
        large.summary.groups = 1_000_000;
        large.summary.information_roles = 3_000_000;
        large.summary.parity_roles = 2_000_000;
        large.summary.transcript_bytes = 10_000_000_000;
        large.summary.fragments = 1_000_000;
        large.validate().unwrap();
        let root = directory(&vec![large.clone(); 5], &mut pages);
        assert!(root.work().unwrap().page_occurrences > CATALOG_MAX_PAGE_OCCURRENCES);
        assert!(root.work().unwrap().bytes > CATALOG_CODING_MAX_BYTES);
        root.validate(budget()).unwrap();
        let mut original_limit = budget();
        original_limit.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES;
        assert!(CatalogCodingDirectoryReader::new(scope(), root, original_limit).is_err());
        assert!(read(root, &pages).is_err());
        large.parts[0].page.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES + 1;
        assert!(large.validate().is_err());

        let mut builder =
            CatalogCodingDirectoryBuilder::new(scope(), i64::MAX as u64, budget()).unwrap();
        builder.directory_bytes = CATALOG_MAX_STREAM_BYTES - 100;
        let mut writes = 0;
        assert!(
            builder
                .push_group(&entries(1)[0], &mut |_, _| {
                    writes += 1;
                    Ok::<_, ()>(())
                })
                .is_err()
        );
        assert_eq!(writes, 0);
    }

    #[test]
    fn coding_directory_ownership_hook_precedes_evidence_and_failure_fences_replay() {
        let (root, pages) = build(&entries(4), 9000);
        let pinned = std::cell::RefCell::new(Vec::new());
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        let mut fetch = |page: CatalogPageRef| {
            if page != root.records.page {
                assert!(pinned.borrow().contains(&page));
            }
            Ok::<_, ()>(pages[&page.hash].clone())
        };
        let mut visit = |forest: &CatalogCodingRoot| {
            pinned
                .borrow_mut()
                .extend(forest.parts.iter().map(|part| part.page));
            Ok(())
        };
        while reader
            .next_group_with_forest(&mut fetch, &mut visit)
            .unwrap()
            .is_some()
        {}
        assert_eq!(pinned.borrow().len(), 4);
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        let mut fetches = 0;
        assert!(
            reader
                .next_group_with_forest(
                    &mut |page| {
                        fetches += 1;
                        Ok::<_, _>(pages[&page.hash].clone())
                    },
                    &mut |_| Err("cancelled")
                )
                .is_err()
        );
        assert_eq!(fetches, 1);
        assert!(reader.last_group_location().is_none());
        assert!(matches!(
            reader.next_group(&mut |_| Ok::<_, ()>(Vec::new())),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }

    #[test]
    fn coding_directory_rejects_malformed_nested_descriptors_before_evidence_fetch() {
        let (root, pages) = build(&entries(1), 9000);
        let original = forests(root, &pages).remove(0);
        for mutation in 0..5 {
            let mut forest = original.clone();
            match mutation {
                0 => forest.parts = vec![forest.parts[0]; CATALOG_CODING_PARTS + 1],
                1 => forest.guild_event_sequence -= 1,
                2 => forest.parts[0].page.byte_len = CATALOG_MAX_STREAM_BYTES + 1,
                3 => {
                    forest.parts.clear();
                    forest.summary = Default::default();
                }
                _ => {}
            }
            let mut encoded = canonical_bytes(&forest).unwrap();
            if mutation == 4 {
                encoded.push(0);
            }
            let mut pages = Pages::new();
            let mut raw = CatalogRecordBuilder::new(scope(), CatalogSection::Coding).unwrap();
            let mut sink = |page: CatalogPageRef, bytes| {
                pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            raw.push_encoded(&encoded, &mut sink).unwrap();
            let mut bad = root;
            bad.records = raw.finish(&mut sink).unwrap();
            let mut reader = CatalogCodingDirectoryReader::new(scope(), bad, budget()).unwrap();
            let mut visits = 0;
            assert!(
                reader
                    .next_group_with_forest(
                        &mut |page| {
                            assert_eq!(page, bad.records.page);
                            Ok::<_, ()>(pages[&page.hash].clone())
                        },
                        &mut |_| {
                            visits += 1;
                            Ok(())
                        }
                    )
                    .is_err()
            );
            assert_eq!(visits, 0);
        }
    }

    #[test]
    fn coding_directory_preserves_four_part_forests_and_full_byte_witness_ranges() {
        let entries = entries(4);
        let (root, mut pages) = build(&entries, 9000);
        let forest = CatalogCodingRoot {
            format_version: 1,
            guild_event_sequence: root.guild_event_sequence,
            parts: forests(root, &pages)
                .into_iter()
                .flat_map(|root| root.parts)
                .collect(),
            summary: root.summary.coding,
        };
        forest.validate().unwrap();
        let root = directory(&[forest], &mut pages);
        assert_eq!(root.summary.forests, 1);
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone());
        for (part, expected) in entries.iter().enumerate() {
            assert_eq!(
                reader.next_group(&mut fetch).unwrap().as_ref(),
                Some(expected)
            );
            let location = reader.last_group_location().unwrap();
            assert_eq!(usize::from(location.range.part), part);
            assert_eq!(
                root.read_group(scope(), budget(), location, &mut fetch)
                    .unwrap(),
                *expected
            );
        }
        assert!(reader.next_group(&mut fetch).unwrap().is_none());

        let full = entry(3, 9, 65536, 12);
        let (root, pages) = build(std::slice::from_ref(&full), CATALOG_MAX_STREAM_BYTES);
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        assert_eq!(
            reader
                .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
                .unwrap(),
            Some(full.clone())
        );
        let location = reader.last_group_location().unwrap();
        assert!(location.range.len as usize > CATALOG_LEAF_BYTES);
        let mut fetched = 0;
        assert_eq!(
            root.read_group(scope(), budget(), location, &mut |page| {
                fetched += 1;
                Ok::<_, ()>(pages[&page.hash].clone())
            })
            .unwrap(),
            full
        );
        assert!(fetched > 1 && fetched <= 8);
        assert!(
            root.read_group(scope(), budget(), location, &mut |page| {
                let mut bytes = pages[&page.hash].clone();
                bytes[0] ^= 1;
                Ok::<_, ()>(bytes)
            })
            .is_err()
        );
    }

    #[test]
    fn coding_point_replay_admits_pages_and_records_with_exact_remaining_work() {
        let expected = entry(3, 9, 65536, 12);
        let (root, pages) = build(std::slice::from_ref(&expected), CATALOG_MAX_STREAM_BYTES);
        let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
        reader
            .next_group(&mut |page| Ok::<_, ()>(pages[&page.hash].clone()))
            .unwrap();
        let location = reader.last_group_location().unwrap();
        let (_, exact) = root
            .read_group_with_work(scope(), budget(), location, &mut |page| {
                Ok::<_, ()>(pages[&page.hash].clone())
            })
            .unwrap();
        assert!(exact.page_occurrences > 1 && exact.records > 2);
        assert_eq!(
            root.read_group_with_work_budget(scope(), budget(), location, exact, &mut |page| Ok::<
                _,
                (),
            >(
                pages[&page.hash].clone()
            ))
            .unwrap(),
            (expected, exact)
        );
        for exhausted in [
            CatalogCodingTraversalBudget { bytes: 0, ..exact },
            CatalogCodingTraversalBudget {
                page_occurrences: 0,
                ..exact
            },
            CatalogCodingTraversalBudget {
                records: 1,
                ..exact
            },
        ] {
            assert!(matches!(
                root.read_group_with_work_budget(
                    scope(),
                    budget(),
                    location,
                    exhausted,
                    &mut |_| -> Result<Vec<u8>, ()> {
                        panic!("exhausted point replay fetched a page")
                    }
                ),
                Err(CatalogStreamError::Catalog(CatalogError::Bounds))
            ));
        }
        for short in [
            CatalogCodingTraversalBudget {
                bytes: exact.bytes - 1,
                ..exact
            },
            CatalogCodingTraversalBudget {
                page_occurrences: exact.page_occurrences - 1,
                ..exact
            },
            CatalogCodingTraversalBudget {
                records: exact.records - 1,
                ..exact
            },
        ] {
            let mut fetched = CatalogCodingTraversalBudget::default();
            assert!(matches!(
                root.read_group_with_work_budget(scope(), budget(), location, short, &mut |page| {
                    fetched.bytes += u64::from(page.encoded_len);
                    fetched.page_occurrences += 1;
                    assert!(fetched.bytes <= short.bytes);
                    assert!(fetched.page_occurrences <= short.page_occurrences);
                    Ok::<_, ()>(pages[&page.hash].clone())
                }),
                Err(CatalogStreamError::Catalog(CatalogError::Bounds))
            ));
            if short.records == exact.records {
                assert!(fetched.page_occurrences < exact.page_occurrences);
            }
        }
    }

    #[test]
    fn coding_directory_has_a_fixed_protocol_vector() {
        let (root, pages) = build(&entries(4), 9000);
        assert_eq!(read(root, &pages).unwrap().len(), 4);
        assert_eq!(
            hex::encode(canonical_bytes(&root).unwrap()),
            include_str!("../../../../protocol/vectors/coding-directory-v1.postcard.hex").trim()
        );
    }

    #[test]
    fn coding_directory_understated_summaries_reject_before_the_affected_forest_fetch() {
        let (original, pages) = build(&entries(4), 9000);
        for dimension in 0..4 {
            let mut root = original;
            match dimension {
                0 => root.summary.coding.information_roles -= 1,
                1 => root.summary.coding.parity_roles -= 1,
                2 => root.summary.coding.transcript_bytes -= 1,
                _ => root.summary.evidence_bytes -= 1,
            }
            let mut reader = CatalogCodingDirectoryReader::new(scope(), root, budget()).unwrap();
            let mut visits = 0;
            let mut evidence_fetches = 0;
            loop {
                match reader.next_group_with_forest(
                    &mut |page| {
                        if page != root.records.page {
                            evidence_fetches += 1;
                        }
                        Ok::<_, ()>(pages[&page.hash].clone())
                    },
                    &mut |_| {
                        visits += 1;
                        Ok(())
                    },
                ) {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("accepted understated summary"),
                    Err(_) => break,
                }
            }
            assert_eq!(visits, 3);
            assert_eq!(evidence_fetches, 3);
            assert!(reader.last_group_location().is_none());
        }
    }
}

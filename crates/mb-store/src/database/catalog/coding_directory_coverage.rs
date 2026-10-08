//! Complete packing coverage across a directory of unchanged coding forests.
//! The required enclosing budget includes already admitted authority work.

use mb_core::{
    CATALOG_CODING_DIRECTORY_ROOT_BYTES, CatalogCodingDirectoryReader, CatalogCodingDirectoryRoot,
    CatalogCodingEntry, CatalogCodingGroupLocation, CatalogCodingTraversalBudget,
    canonical_bytes_bounded,
};

use super::coding_coverage::{
    MANIFEST_BYTES, ROW_BYTES, cover_entry, decode_row, ensure_empty, put, validate_group,
};
use super::packing_validation::unwrap_stream;
use super::*;

const GROUPS: &str = "packing-coding-directory-group";
const COVERAGE: &str = "packing-coding-directory-coverage";
const COMPLETE: &str = "packing-coding-directory-complete";
pub(super) const KINDS: [&str; 3] = [GROUPS, COVERAGE, COMPLETE];

/// Fixed local descriptor, never an authority token by itself. `prior_work`
/// records the admitted source-authority prefix. The trusted total budget is
/// required separately rather than read from this descriptor's own claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingCodingDirectoryValidation {
    pub format_version: u16,
    pub packing: CatalogPackingValidation,
    pub coding: CatalogCodingDirectoryRoot,
    pub policy: CatalogCodingCoveragePolicy,
    pub prior_work: CatalogCodingTraversalBudget,
}

impl CatalogPackingCodingDirectoryValidation {
    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > MANIFEST_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate(budget)?;
        if canonical_bytes_bounded(&manifest, MANIFEST_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }

    pub fn validate(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogStoreError> {
        self.packing.validate()?;
        if self.format_version != 1 {
            return Err(DatabaseError::Conflict.into());
        }
        canonical_bytes_bounded(&self, MANIFEST_BYTES)?;
        self.coding.validate(self.coding_budget(budget)?)?;
        Ok(())
    }

    fn other_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        // The directory already reserves 512 bytes for its embedded root. Add
        // the remainder of one fixed 4096-byte combined descriptor, not another
        // root charge. Both packing root descriptors fit inside this envelope.
        let mut work = self.prior_work.checked_add(CatalogCodingTraversalBudget {
            bytes: (MANIFEST_BYTES - CATALOG_CODING_DIRECTORY_ROOT_BYTES) as u64,
            ..Default::default()
        })?;
        for root in [
            self.packing.descriptors.records,
            self.packing.sources.records,
        ] {
            work = work.checked_add(CatalogCodingTraversalBudget {
                bytes: root.page.byte_len,
                page_occurrences: root.page.page_occurrences,
                records: root.records,
            })?;
        }
        Ok(work)
    }

    pub fn represented_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(self.other_work()?.checked_add(self.coding.work()?)?)
    }

    pub fn coding_budget(
        self,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(budget.remaining_after(self.other_work()?)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogIndexedDirectoryCodingGroup {
    pub group: CatalogIndexedCodingGroup,
    pub page: CatalogPageRef,
}

impl CatalogIndexedDirectoryCodingGroup {
    fn location(self) -> CatalogCodingGroupLocation {
        CatalogCodingGroupLocation {
            page: self.page,
            range: self.group.range,
        }
    }
}

pub(super) fn build(
    packing: &CatalogPackingIndex,
    manifest: CatalogPackingCodingDirectoryValidation,
    budget: CatalogCodingTraversalBudget,
    fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    authorize: &mut impl FnMut(
        &CatalogCodingEntry,
    ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    packing.require_complete()?;
    manifest.validate(budget)?;
    if packing.manifest != manifest.packing {
        return Err(DatabaseError::Conflict.into());
    }
    ensure_empty(packing)?;
    let mut pending = packing.manifest.descriptors.sectors;
    let mut reader = CatalogCodingDirectoryReader::new(
        manifest.packing.scope,
        manifest.coding,
        manifest.coding_budget(budget)?,
    )?;
    while let Some(entry) = unwrap_stream(reader.next_group(fetch))? {
        let authority = authorize(&entry)?;
        let group = &entry.retained.group;
        let location = reader
            .last_group_location()
            .ok_or(DatabaseError::Integrity)?;
        put(
            &packing.store,
            GROUPS,
            &group.id,
            &CatalogIndexedDirectoryCodingGroup {
                group: CatalogIndexedCodingGroup {
                    profile: group.profile,
                    range: location.range,
                    added_at_event: entry.retained.added_at_event,
                    retired_at_event: entry.retained.retired_at_event,
                    retain_through_event: entry.retained.retain_through_event,
                },
                page: location.page,
            },
            ROW_BYTES,
        )?;
        cover_entry(
            packing,
            &entry,
            authority,
            manifest.policy,
            COVERAGE,
            &mut pending,
        )?;
    }
    if pending != 0 {
        return Err(DatabaseError::NotReady.into());
    }
    put(&packing.store, COMPLETE, b"root", &manifest, MANIFEST_BYTES)
}

/// Constructed only after all packing/coding EOFs, external authorization and
/// exact active coverage. It owns the existing admitted encrypted index rather
/// than allocating another scratch store or a whole-catalog collection.
pub struct CatalogPackingCodingDirectoryIndex {
    packing: CatalogPackingIndex,
    manifest: CatalogPackingCodingDirectoryValidation,
    budget: CatalogCodingTraversalBudget,
}

impl CatalogPackingIndex {
    /// Supply the trusted remaining budget after debiting external authority
    /// and other sections not carried by this standalone packing index. The
    /// certified source wrapper debits its admitted authority prefix itself.
    pub fn validate_coding_directory(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        budget: CatalogCodingTraversalBudget,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(
            &CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogPackingCodingDirectoryIndex, CatalogStoreError> {
        self.validate_directory_with_prior(
            coding,
            policy,
            budget,
            Default::default(),
            fetch,
            authorize,
        )
    }

    pub(super) fn validate_directory_with_prior(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        budget: CatalogCodingTraversalBudget,
        prior_work: CatalogCodingTraversalBudget,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(
            &CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogPackingCodingDirectoryIndex, CatalogStoreError> {
        let manifest = CatalogPackingCodingDirectoryValidation {
            format_version: 1,
            packing: self.manifest,
            coding,
            policy,
            prior_work,
        };
        self.store.with_record_transaction(|| {
            build(&self, manifest, budget, &mut fetch, &mut authorize)
        })?;
        Ok(CatalogPackingCodingDirectoryIndex {
            packing: self,
            manifest,
            budget,
        })
    }
}

impl CatalogPackingCodingDirectoryIndex {
    pub fn manifest(&self) -> CatalogPackingCodingDirectoryValidation {
        self.manifest
    }
    pub fn packing(&self) -> &CatalogPackingIndex {
        &self.packing
    }
    pub fn budget(&self) -> CatalogCodingTraversalBudget {
        self.budget
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

    fn validate_group(
        &self,
        group: &CatalogIndexedDirectoryCodingGroup,
    ) -> Result<(), CatalogStoreError> {
        validate_group(
            &group.group,
            self.manifest.coding.guild_event_sequence,
            group.page,
        )
    }

    fn group(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
        let Some(bytes) = self
            .packing
            .store
            .get_record_bounded(GROUPS, &id, ROW_BYTES)?
        else {
            return Ok(None);
        };
        let group: CatalogIndexedDirectoryCodingGroup = decode_row(&bytes)?;
        self.validate_group(&group)?;
        if group.group.range.group_id != id {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(group))
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
                group.group.retired_at_event.is_some()
                    || value.shard_index >= group.group.profile.data_shards
            })
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(value))
    }

    pub fn next_group(
        &self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
        self.require_complete()?;
        let Some((key, bytes)) = self.packing.store.next_record_bounded(
            GROUPS,
            after.as_ref().map(|id| id.as_slice()),
            32,
            ROW_BYTES,
        )?
        else {
            return Ok(None);
        };
        let group: CatalogIndexedDirectoryCodingGroup = decode_row(&bytes)?;
        self.validate_group(&group)?;
        if key != group.group.range.group_id {
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
        let entry = unwrap_stream(self.manifest.coding.read_group(
            self.manifest.packing.scope,
            self.manifest.coding_budget(self.budget)?,
            group.location(),
            &mut fetch,
        ))?;
        if entry.retained.group.profile != group.group.profile
            || entry.retained.added_at_event != group.group.added_at_event
            || entry.retained.retired_at_event != group.group.retired_at_event
            || entry.retained.retain_through_event != group.group.retain_through_event
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(entry))
    }
}

#[cfg(test)]
mod tests {
    use super::super::coding_coverage::tests::entry;
    use super::super::packing_validation::tests::{Fixture as PackingFixture, fixture};
    use super::*;
    use mb_core::{
        CatalogCodingBuilder, CatalogCodingDirectorySummary, CatalogCodingRoot,
        CatalogRecordBuilder,
    };
    use std::collections::HashMap;

    struct Fixture {
        packing: PackingFixture,
        entries: Vec<CatalogCodingEntry>,
        root: CatalogCodingDirectoryRoot,
        forests: Vec<CatalogCodingRoot>,
        pages: HashMap<[u8; 32], Vec<u8>>,
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
            let mut value = Self {
                packing,
                entries,
                root: CatalogCodingDirectoryRoot {
                    format_version: 1,
                    guild_event_sequence: 100,
                    records: mb_core::CatalogRecordRoot {
                        format_version: 1,
                        records: 0,
                        page: CatalogPageRef {
                            hash: [0; 32],
                            encoded_len: 1,
                            byte_len: 8,
                            page_occurrences: 1,
                            height: 0,
                        },
                    },
                    summary: Default::default(),
                },
                forests: Vec::new(),
                pages: HashMap::new(),
            };
            value.rebuild();
            value
        }

        fn rebuild(&mut self) {
            self.entries.sort_by_key(|entry| entry.retained.group.id);
            self.pages.clear();
            self.forests.clear();
            let mut sink = |page: CatalogPageRef, bytes| {
                self.pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            for entry in &self.entries {
                let mut builder =
                    CatalogCodingBuilder::new(self.packing.manifest.scope, 100).unwrap();
                builder.push_group(entry, &mut sink).unwrap();
                self.forests.push(builder.finish(&mut sink).unwrap());
            }
            self.write_directory();
        }

        fn write_directory(&mut self) {
            let mut builder =
                CatalogRecordBuilder::new(self.packing.manifest.scope, CatalogSection::Coding)
                    .unwrap();
            let mut summary = CatalogCodingDirectorySummary::default();
            let mut sink = |page: CatalogPageRef, bytes| {
                self.pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            for root in &self.forests {
                builder.push(root, &mut sink).unwrap();
                summary.forests += 1;
                summary.coding.groups += root.summary.groups;
                summary.coding.retired_groups += root.summary.retired_groups;
                summary.coding.information_roles += root.summary.information_roles;
                summary.coding.parity_roles += root.summary.parity_roles;
                summary.coding.transcript_bytes += root.summary.transcript_bytes;
                summary.coding.fragments += root.summary.fragments;
                for part in &root.parts {
                    summary.evidence_bytes += part.page.byte_len;
                    summary.evidence_pages += part.page.page_occurrences;
                }
            }
            self.root.records = builder.finish(&mut sink).unwrap();
            self.root.summary = summary;
        }

        fn manifest(
            &self,
            policy: CatalogCodingCoveragePolicy,
            prior_work: CatalogCodingTraversalBudget,
        ) -> CatalogPackingCodingDirectoryValidation {
            CatalogPackingCodingDirectoryValidation {
                format_version: 1,
                packing: self.packing.manifest,
                coding: self.root,
                policy,
                prior_work,
            }
        }
        fn fetch(&self, page: CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError> {
            self.pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        }
        fn build(
            &self,
            maximum: u64,
        ) -> Result<CatalogPackingCodingDirectoryIndex, CatalogStoreError> {
            let manifest = self.manifest(CatalogCodingCoveragePolicy::Current, Default::default());
            self.packing.build(maximum)?.validate_coding_directory(
                self.root,
                manifest.policy,
                manifest.represented_work()?,
                |page| self.fetch(page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
        }
    }

    fn assert_rollback(packing: &CatalogPackingIndex) {
        for kind in KINDS {
            assert!(
                packing
                    .store
                    .next_record_bounded(kind, None, 32, MANIFEST_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
        packing.require_complete().unwrap();
    }

    #[test]
    fn directory_join_covers_inputs_retains_replacements_and_seeks_original_witnesses() {
        let mut fixture = Fixture::new(36);
        fixture
            .entries
            .push(entry(&fixture.packing, [0, 1, 2], 300, 2, None));
        let mut retired = entry(&fixture.packing, [3, 4, 5], 301, 2, None);
        retired.retained.retired_at_event = Some(2);
        retired.retained.retain_through_event = Some(1000);
        fixture.entries.push(retired);
        let mut unrelated = super::super::packing_validation::tests::fixture(3, true);
        for (index, sector) in unrelated.sectors.iter_mut().enumerate() {
            sector.id = [220 + index as u8; 32];
        }
        fixture
            .entries
            .push(entry(&unrelated, [0, 1, 2], 302, 2, None));
        fixture.rebuild();
        assert_eq!(fixture.root.summary.forests, 15);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        for sector in &fixture.packing.sectors {
            let coverage = index.coverage(sector.id).unwrap().unwrap();
            let expected = fixture.entries.iter().find(|entry| entry.retained.retired_at_event.is_none()
                && entry.retained.group.roles.iter().any(|role| matches!(role, mb_core::ShardRoleV2::Information(info) if info.sector.id == sector.id))).unwrap();
            assert_eq!(coverage.group_id, expected.retained.group.id);
        }
        let mut after = None;
        for expected in &fixture.entries {
            let group = index.next_group(after).unwrap().unwrap();
            after = Some(group.group.range.group_id);
            assert_eq!(group.group.range.group_id, expected.retained.group.id);
            let mut fetches = 0;
            assert_eq!(
                index
                    .read_group(group.group.range.group_id, |page| {
                        fetches += 1;
                        fixture.fetch(page)
                    })
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
            assert_eq!(fetches, 1);
            assert!(canonical_bytes_bounded(&group, ROW_BYTES).unwrap().len() <= ROW_BYTES);
        }
        assert!(index.next_group(after).unwrap().is_none());
        assert!(
            index
                .read_group([255; 32], |_| panic!("unknown group fetched pages"))
                .unwrap()
                .is_none()
        );
        assert!(index.coverage([255; 32]).unwrap().is_none());
        assert_eq!(
            CatalogPackingCodingDirectoryValidation::decode(
                &canonical_bytes(&index.manifest()).unwrap(),
                index.budget()
            )
            .unwrap(),
            index.manifest()
        );
    }

    #[test]
    fn directory_join_debits_all_sections_and_prefix_work_before_fetch() {
        let fixture = Fixture::new(12);
        let prior = CatalogCodingTraversalBudget {
            bytes: 1077,
            page_occurrences: 7,
            records: 9,
        };
        let manifest = fixture.manifest(CatalogCodingCoveragePolicy::Current, prior);
        let work = manifest.represented_work().unwrap();
        assert_eq!(
            manifest.coding_budget(work).unwrap(),
            fixture.root.work().unwrap()
        );
        assert_eq!(
            work.bytes,
            prior.bytes
                + MANIFEST_BYTES as u64
                + manifest.packing.descriptors.records.page.byte_len
                + manifest.packing.sources.records.page.byte_len
                + fixture.root.records.page.byte_len
                + fixture.root.summary.evidence_bytes
        );
        assert_eq!(
            work.records,
            prior.records
                + manifest.packing.descriptors.records.records
                + manifest.packing.sources.records.records
                + fixture.root.work().unwrap().records
        );
        manifest.validate(work).unwrap();
        assert_eq!(
            work.remaining_after(work).unwrap(),
            CatalogCodingTraversalBudget::default()
        );
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                CatalogPackingCodingDirectoryValidation::decode(
                    &canonical_bytes(&manifest).unwrap(),
                    limit
                )
                .is_err()
            );
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            assert!(
                packing
                    .validate_directory_with_prior(
                        fixture.root,
                        manifest.policy,
                        limit,
                        prior,
                        |_| panic!("over-budget join fetched pages"),
                        |_| panic!("over-budget join authorized groups")
                    )
                    .is_err()
            );
            let mut bad = manifest;
            match dimension {
                0 => bad.prior_work.bytes = u64::MAX,
                1 => bad.prior_work.page_occurrences = u64::MAX,
                _ => bad.prior_work.records = u64::MAX,
            }
            assert!(bad.represented_work().is_err());
            assert!(bad.validate(work).is_err());
        }
        let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
        assert!(
            packing
                .validate_coding_directory(
                    fixture.root,
                    manifest.policy,
                    fixture.root.work().unwrap(),
                    |_| panic!("reset budget fetched pages"),
                    |_| panic!("reset budget authorized groups")
                )
                .is_err()
        );
        let mut bad = canonical_bytes(&manifest).unwrap();
        bad.push(0);
        assert!(CatalogPackingCodingDirectoryValidation::decode(&bad, work).is_err());
        assert!(
            CatalogPackingCodingDirectoryValidation::decode(&vec![0; MANIFEST_BYTES + 1], work)
                .is_err()
        );
        let empty = Fixture::new(0);
        let index = empty.build(4 * 1024 * 1024).unwrap();
        assert_eq!(index.manifest().represented_work().unwrap().records, 0);
        assert!(index.next_group(None).unwrap().is_none());
        assert!(index.coverage([255; 32]).unwrap().is_none());
        assert!(
            index
                .read_group([255; 32], |_| panic!(
                    "empty directory fetched witness pages"
                ))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn directory_join_failures_after_valid_prefixes_roll_back_every_row() {
        let mut fixture = Fixture::new(12);
        let original = fixture.root;
        let forests = fixture.forests.clone();
        for mutation in 0..7 {
            fixture.root = original;
            fixture.forests = forests.clone();
            if mutation == 3 {
                fixture.forests.swap(2, 3);
                fixture.write_directory();
            }
            if mutation == 4 {
                fixture.forests[3] = fixture.forests[2].clone();
                fixture.write_directory();
            }
            if mutation == 5 {
                fixture.root.summary.evidence_bytes += 1;
            }
            if mutation == 6 {
                fixture.root.summary.coding.information_roles -= 1;
            }
            let manifest =
                fixture.manifest(CatalogCodingCoveragePolicy::Current, Default::default());
            let limit = manifest.represented_work().unwrap();
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            let last = forests[3].parts[0].page.hash;
            let mut authorized = 0;
            let result = packing.store.with_record_transaction(|| {
                build(
                    &packing,
                    manifest,
                    limit,
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
                        authorized += 1;
                        if mutation == 2 && authorized == 4 {
                            Err(DatabaseError::Conflict.into())
                        } else {
                            Ok(CatalogCodingAuthorization::CurrentPlacement)
                        }
                    },
                )
            });
            assert!(result.is_err(), "accepted mutation {mutation}");
            assert_rollback(&packing);
            assert!(authorized >= 2);
        }
        fixture.root = original;
        fixture.forests = forests;
        fixture.build(4 * 1024 * 1024).unwrap();
    }

    #[test]
    fn directory_join_rejects_uncovered_retired_virtual_and_historical_current_inputs() {
        let mut fixture = Fixture::new(3);
        let original = fixture.entries.clone();
        for mutation in 0..4 {
            fixture.entries = original.clone();
            match mutation {
                0 => {
                    fixture.entries.clear();
                }
                1 => {
                    fixture.entries[0].retained.retired_at_event = Some(2);
                    fixture.entries[0].retained.retain_through_event = Some(1000);
                }
                2 => {
                    let mut zero = Fixture::new(0);
                    zero.packing = super::super::packing_validation::tests::fixture(1, true);
                    while zero.packing.sectors.len() < 3 {
                        let mut sector = zero.packing.sectors[0].clone();
                        sector.id = [220 + zero.packing.sectors.len() as u8; 32];
                        zero.packing.sectors.push(sector);
                        zero.packing.bytes.push(zero.packing.bytes[0].clone());
                    }
                    zero.entries = vec![entry(&zero.packing, [0, 1, 2], 400, 2, Some(0))];
                    zero.rebuild();
                    assert!(matches!(
                        zero.build(4 * 1024 * 1024),
                        Err(CatalogStoreError::Database(DatabaseError::NotReady))
                    ));
                    continue;
                }
                _ => {
                    fixture.entries = vec![entry(&fixture.packing, [0, 1, 2], 401, 1, None)];
                }
            }
            fixture.rebuild();
            assert!(fixture.build(4 * 1024 * 1024).is_err());
        }
        fixture.entries = original;
        fixture.rebuild();
        let manifest = fixture.manifest(CatalogCodingCoveragePolicy::Current, Default::default());
        let limit = manifest.represented_work().unwrap();
        assert!(
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_coding_directory(
                    fixture.root,
                    CatalogCodingCoveragePolicy::Current,
                    limit,
                    |page| fixture.fetch(page),
                    |_| Ok(CatalogCodingAuthorization::Retained)
                )
                .is_err()
        );
        fixture
            .packing
            .build(4 * 1024 * 1024)
            .unwrap()
            .validate_coding_directory(
                fixture.root,
                CatalogCodingCoveragePolicy::Historical,
                limit,
                |page| fixture.fetch(page),
                |_| Ok(CatalogCodingAuthorization::Retained),
            )
            .unwrap();
    }

    #[test]
    fn directory_join_ignored_writes_and_both_join_namespace_orphans_fail_closed() {
        let fixture = Fixture::new(12);
        let manifest = fixture.manifest(CatalogCodingCoveragePolicy::Current, Default::default());
        let limit = manifest.represented_work().unwrap();
        for kind in KINDS {
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            packing.store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignored BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
            assert!(
                packing
                    .store
                    .with_record_transaction(|| build(
                        &packing,
                        manifest,
                        limit,
                        &mut |page| fixture.fetch(page),
                        &mut |_| Ok(CatalogCodingAuthorization::CurrentPlacement)
                    ))
                    .is_err()
            );
            assert_rollback(&packing);
        }
        for kind in KINDS.into_iter().chain([
            "packing-coding-group",
            "packing-coding-coverage",
            "packing-coding-complete",
        ]) {
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            packing
                .store
                .put_record_if_absent(kind, b"orphan", &[1])
                .unwrap();
            assert!(
                packing
                    .validate_coding_directory(
                        fixture.root,
                        manifest.policy,
                        limit,
                        |_| panic!("orphan fetched pages"),
                        |_| panic!("orphan authorized groups")
                    )
                    .is_err()
            );
        }
        for kind in KINDS {
            let packing = fixture.packing.build(4 * 1024 * 1024).unwrap();
            packing
                .store
                .put_record_if_absent(kind, b"orphan", &[1])
                .unwrap();
            let coding = CatalogCodingValidation {
                format_version: 1,
                scope: fixture.packing.manifest.scope,
                root: fixture.forests[0].clone(),
            };
            assert!(
                packing
                    .validate_coding(
                        coding,
                        manifest.policy,
                        |_| panic!("directory orphan fetched old forest"),
                        |_| panic!("directory orphan authorized old forest")
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn directory_index_rejects_corrupt_cursors_and_missing_completion_before_point_fetch() {
        let fixture = Fixture::new(12);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        let first = index.next_group(None).unwrap().unwrap();
        let id = first.group.range.group_id;
        let original = canonical_bytes(&first).unwrap();
        for mutation in 0..8 {
            let mut bad = first;
            match mutation {
                0 => bad.group.range.offset = u64::MAX,
                1 => bad.group.range.len = u32::MAX,
                2 => bad.group.range.part = mb_core::CATALOG_CODING_PARTS as u8,
                3 => bad.page.height = mb_core::CATALOG_MAX_HEIGHT + 1,
                4 => bad.page.hash = [0; 32],
                5 => bad.group.profile.data_shards = 0,
                6 => bad.group.added_at_event = 101,
                _ => bad.group.range.group_id = [0; 32],
            }
            let encoded = canonical_bytes(&bad).unwrap();
            index
                .packing
                .store
                .replace_record_if_value(GROUPS, &id, &original, &encoded)
                .unwrap();
            assert!(index.next_group(None).is_err());
            assert!(
                index
                    .read_group(id, |_| panic!("malformed cursor fetched pages"))
                    .is_err()
            );
            index
                .packing
                .store
                .replace_record_if_value(GROUPS, &id, &encoded, &original)
                .unwrap();
        }
        let marker = canonical_bytes(&index.manifest()).unwrap();
        index
            .packing
            .store
            .delete_record_if_value(COMPLETE, b"root", &marker)
            .unwrap();
        assert!(index.coverage(fixture.packing.sectors[0].id).is_err());
        assert!(index.next_group(None).is_err());
        assert!(
            index
                .read_group(id, |_| panic!("incomplete proof fetched pages"))
                .is_err()
        );
    }

    #[test]
    fn directory_join_spills_into_admitted_index_and_rebuilds_after_exhaustion() {
        let fixture = Fixture::new(768);
        let manifest = fixture.manifest(CatalogCodingCoveragePolicy::Current, Default::default());
        let limit = manifest.represented_work().unwrap();
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
        assert!(
            packing
                .store
                .with_record_transaction(|| build(
                    &packing,
                    manifest,
                    limit,
                    &mut |page| fixture.fetch(page),
                    &mut |_| Ok(CatalogCodingAuthorization::CurrentPlacement)
                ))
                .is_err()
        );
        assert_rollback(&packing);
        drop(packing);
        let index = fixture.build(8 * 1024 * 1024).unwrap();
        assert_eq!(fixture.root.summary.forests, 256);
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
        for position in [0, 384, 767] {
            assert!(
                index
                    .coverage(fixture.packing.sectors[position].id)
                    .unwrap()
                    .is_some()
            );
        }
        let expected = fixture.entries.last().unwrap();
        let mut fetched = 0;
        assert_eq!(
            index
                .read_group(expected.retained.group.id, |page| {
                    fetched += 1;
                    fixture.fetch(page)
                })
                .unwrap()
                .as_ref(),
            Some(expected)
        );
        assert_eq!(fetched, 1);
    }

    #[test]
    fn directory_join_structural_single_owner_admission_exceeds_old_combined_limits() {
        let fixture = Fixture::new(12);
        let mut manifest =
            fixture.manifest(CatalogCodingCoveragePolicy::Current, Default::default());
        // Necessary geometry from the actual allocator/codec audit, not an
        // upper bound or a materialized retained-data qualification. These
        // deliberately synthetic references cannot establish a completed index.
        let sources = (1_u64 << 40) / 65536;
        let sectors = (sources * 4).div_ceil(3);
        let groups = sectors.div_ceil(3);
        let descriptor_bytes = 7_046_430_806;
        let source_bytes = 4_596_957_192;
        let coding_bytes = 62_746_792_515;
        let profile = mb_core::PackingProfile {
            format_version: 1,
            sector_size: 65536,
            slot_size: 16384,
        };
        fn pages(bytes: u64) -> u64 {
            let mut level = bytes.div_ceil(mb_core::CATALOG_LEAF_BYTES as u64);
            let mut total = level;
            while level > 1 {
                level = level.div_ceil(mb_core::CATALOG_FANOUT as u64);
                total += level;
            }
            total
        }
        manifest.packing.descriptors.profile = profile;
        manifest.packing.descriptors.sectors = sectors;
        manifest.packing.descriptors.slots = sectors * 4;
        manifest.packing.descriptors.source_chunks = sources * 4;
        manifest.packing.descriptors.source_bytes = 1_u64 << 40;
        manifest.packing.descriptors.records.records = sectors * 2;
        manifest.packing.descriptors.records.page.byte_len = descriptor_bytes;
        manifest.packing.descriptors.records.page.height = 3;
        manifest.packing.descriptors.records.page.page_occurrences = pages(descriptor_bytes);
        manifest.packing.sources.profile = profile;
        manifest.packing.sources.sources = sources;
        manifest.packing.sources.chunks = sources * 4;
        manifest.packing.sources.ciphertext_bytes = 1_u64 << 40;
        manifest.packing.sources.records.records = sources * 2;
        manifest.packing.sources.records.page.byte_len = source_bytes;
        manifest.packing.sources.records.page.height = 3;
        manifest.packing.sources.records.page.page_occurrences = pages(source_bytes);
        manifest.coding.summary.coding.groups = groups;
        manifest.coding.summary.coding.information_roles = groups * 3;
        manifest.coding.summary.coding.parity_roles = groups * 2;
        manifest.coding.summary.coding.transcript_bytes = coding_bytes;
        manifest.coding.summary.coding.fragments = groups;
        manifest.coding.summary.evidence_bytes = coding_bytes;
        manifest.coding.summary.evidence_pages = pages(coding_bytes);
        let work = manifest.represented_work().unwrap();
        assert!(work.bytes > mb_core::CATALOG_CODING_MAX_BYTES);
        assert!(work.page_occurrences > mb_core::CATALOG_MAX_PAGE_OCCURRENCES);
        assert!(work.records > mb_core::CATALOG_MAX_RECORDS);
        manifest.validate(work).unwrap();
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes = mb_core::CATALOG_CODING_MAX_BYTES,
                1 => limit.page_occurrences = mb_core::CATALOG_MAX_PAGE_OCCURRENCES,
                _ => limit.records = mb_core::CATALOG_MAX_RECORDS,
            }
            assert!(manifest.validate(limit).is_err());
        }
    }
}

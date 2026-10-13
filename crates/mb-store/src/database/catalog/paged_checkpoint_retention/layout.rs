//! The two public layouts use the same custody operations. Every adapter
//! retains the original typed header and certificate; directory parts are
//! pinned before their readers fetch any evidence.

use super::super::checkpoint_body::Header;
use super::*;
use serde::de::DeserializeOwned;

pub(in crate::database::catalog) trait Layout:
    Header + DeserializeOwned
{
    type Certificate: Serialize + DeserializeOwned;
    const CERTIFICATE: &'static str;
    const JOURNAL: &'static str;
    const DEPENDENCIES: &'static str;
    const PIN_PREFIX: u8;
    const OTHER_JOURNAL: &'static str;
    fn guild_id(self) -> [u8; 32];
    fn parent(self) -> Option<[u8; 32]>;
    fn authority_root(self) -> mb_core::CatalogCheckpointAuthorityRoot;
    fn coding_root(self) -> mb_core::CatalogCodingDirectoryRoot;
    fn validate(self, budget: Work) -> Result<(), CatalogStoreError>;
    fn admit_capacity(
        self,
        policy: mb_core::CatalogCapacityPolicy,
    ) -> Result<(), CatalogStoreError>;
    fn validate_trust(
        self,
        trust: &PagedCheckpointTrust,
        budget: Work,
    ) -> Result<(), CatalogStoreError>;
    fn certificate_header(certificate: &Self::Certificate) -> Self;
    fn initial(self) -> Vec<Dependency>;
    fn walk_packing<P: Proof<Header = Self>>(
        self,
        control: &ControlStore,
        proof: &P,
        budget: Work,
        pin: &mut impl FnMut(Dependency) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError>;
}

macro_rules! header_facts {
    ($certificate:ty) => {
        type Certificate = $certificate;
        fn guild_id(self) -> [u8; 32] {
            self.guild_id
        }
        fn parent(self) -> Option<[u8; 32]> {
            self.parent
        }
        fn authority_root(self) -> mb_core::CatalogCheckpointAuthorityRoot {
            self.authority_root
        }
        fn coding_root(self) -> mb_core::CatalogCodingDirectoryRoot {
            self.coding
        }
        fn validate(self, budget: Work) -> Result<(), CatalogStoreError> {
            Ok(self.validate_header(budget)?)
        }
        fn validate_trust(
            self,
            trust: &PagedCheckpointTrust,
            budget: Work,
        ) -> Result<(), CatalogStoreError> {
            Ok(self.validate_trust(trust, budget)?)
        }
        fn certificate_header(certificate: &Self::Certificate) -> Self {
            certificate.checkpoint
        }
    };
}

impl Layout for PagedGuildCheckpoint {
    header_facts!(mb_core::QuorumPagedCheckpoint);
    const CERTIFICATE: &'static str = "catalog-paged-checkpoint-certificate-v1";
    const JOURNAL: &'static str = "catalog-paged-checkpoint-retention-v1";
    const DEPENDENCIES: &'static str = "catalog-paged-checkpoint-dependency-v1";
    const PIN_PREFIX: u8 = 4;
    const OTHER_JOURNAL: &'static str = "catalog-directory-checkpoint-retention-v1";
    fn admit_capacity(
        self,
        policy: mb_core::CatalogCapacityPolicy,
    ) -> Result<(), CatalogStoreError> {
        Ok(policy.admit_individual_checkpoint(self)?)
    }
    fn initial(self) -> Vec<Dependency> {
        dependencies(
            self.guild_id,
            [
                (CatalogSection::Checkpoint, self.authority_root.records.page),
                (CatalogSection::Packing, self.packed_sectors.records.page),
                (CatalogSection::Packing, self.packed_sources.records.page),
                (CatalogSection::Coding, self.coding.records.page),
            ],
        )
    }
    fn walk_packing<P: Proof<Header = Self>>(
        self,
        control: &ControlStore,
        proof: &P,
        _budget: Work,
        _pin: &mut impl FnMut(Dependency) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let scope = CatalogScope::Guild {
            guild_id: self.guild_id,
        };
        let mut fetch = |page| control.catalog_page(scope, CatalogSection::Packing, page);
        let mut sources = CatalogPackedSourceReader::new(scope, self.packed_sources)?;
        while unwrap_stream(sources.next_record(&mut fetch))?.is_some() {}
        let mut sectors = CatalogPackedSectorReader::new(scope, self.packed_sectors)?;
        while unwrap_stream(
            sectors.next_record_with_sources(&mut fetch, &mut |key| proof.source_id(key)),
        )?
        .is_some()
        {}
        Ok(())
    }
}

impl Layout for mb_core::PagedGuildCheckpointDirectory {
    header_facts!(mb_core::QuorumPagedCheckpointDirectory);
    const CERTIFICATE: &'static str = "catalog-directory-checkpoint-certificate-v1";
    const JOURNAL: &'static str = "catalog-directory-checkpoint-retention-v1";
    const DEPENDENCIES: &'static str = "catalog-directory-checkpoint-dependency-v1";
    const PIN_PREFIX: u8 = 6;
    const OTHER_JOURNAL: &'static str = "catalog-paged-checkpoint-retention-v1";
    fn admit_capacity(
        self,
        policy: mb_core::CatalogCapacityPolicy,
    ) -> Result<(), CatalogStoreError> {
        Ok(policy.admit_checkpoint(self)?)
    }
    fn initial(self) -> Vec<Dependency> {
        dependencies(
            self.guild_id,
            [
                (CatalogSection::Checkpoint, self.authority_root.records.page),
                (CatalogSection::Packing, self.packing.records.page),
                (CatalogSection::Coding, self.coding.records.page),
            ],
        )
    }
    fn walk_packing<P: Proof<Header = Self>>(
        self,
        control: &ControlStore,
        proof: &P,
        budget: Work,
        pin: &mut impl FnMut(Dependency) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let scope = CatalogScope::Guild {
            guild_id: self.guild_id,
        };
        let mut fetch = |page| control.catalog_page(scope, CatalogSection::Packing, page);
        let mut part = |part| {
            pin(Dependency {
                scope,
                section: CatalogSection::Packing,
                root: match part {
                    mb_core::CatalogPackingDirectoryRecord::Sources(part) => part.root.records.page,
                    mb_core::CatalogPackingDirectoryRecord::Sectors(part) => part.root.records.page,
                },
            })
        };
        let mut packing = mb_core::CatalogPackingDirectoryReader::new(scope, self.packing, budget)?;
        while unwrap_stream(packing.next_source_with_part(&mut fetch, &mut part))?.is_some() {}
        while unwrap_stream(packing.next_sector_with_part(
            &mut fetch,
            &mut |key| proof.source_id(key),
            &mut part,
        ))?
        .is_some()
        {}
        if !packing.is_complete() {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }
}

fn dependencies<const N: usize>(
    guild_id: [u8; 32],
    roots: [(CatalogSection, CatalogPageRef); N],
) -> Vec<Dependency> {
    roots
        .into_iter()
        .map(|(section, root)| Dependency {
            scope: CatalogScope::Guild { guild_id },
            section,
            root,
        })
        .collect()
}

pub(in crate::database::catalog) trait Proof {
    type Header: Layout;
    fn retention(
        &self,
        id: Uuid,
    ) -> Result<CatalogPagedCheckpointRetention<Self::Header>, CatalogStoreError>;
    fn certificate(&self) -> &<Self::Header as Layout>::Certificate;
    fn recheck(
        &self,
        read_trust: &mut impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError>;
    fn revision(
        &self,
        key: mb_core::CatalogCheckpointRevisionKey,
    ) -> Result<Option<R>, CatalogStoreError>;
    fn next_revision(
        &self,
        after: Option<mb_core::CatalogCheckpointRevisionKey>,
    ) -> Result<Option<R>, CatalogStoreError>;
    fn next_group(
        &self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError>;
    fn has_member(&self, holder: mb_core::NodeId) -> bool;
    fn source_id(&self, key: [u8; 32])
    -> Result<mb_core::CatalogPackedSourceId, CatalogStoreError>;
    fn read_group(
        &self,
        group: [u8; 32],
        budget: Work,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<Option<(mb_core::CatalogCodingEntry, Work)>, CatalogStoreError>;
}

macro_rules! proof {
    ($proof:ty, $header:ty) => {
        impl Proof for $proof {
            type Header = $header;
            fn retention(
                &self,
                id: Uuid,
            ) -> Result<CatalogPagedCheckpointRetention<Self::Header>, CatalogStoreError> {
                if !self.transition().has_certified_history_transition() {
                    return Err(DatabaseError::NotReady.into());
                }
                Ok(CatalogPagedCheckpointRetention {
                    id,
                    checkpoint: self.certificate().checkpoint,
                    certificate_hash: mb_core::canonical_hash_bounded(
                        self.certificate(),
                        mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
                    )?,
                    trust_hash: snapshot_hash(self.trust())?,
                    proof_work: self.transition().represented_work(),
                    budget: self.transition().budget(),
                })
            }
            fn certificate(&self) -> &<Self::Header as Layout>::Certificate {
                self.certificate()
            }
            fn recheck(
                &self,
                read_trust: &mut impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
            ) -> Result<(), CatalogStoreError> {
                self.recheck_header(read_trust)
            }
            fn revision(
                &self,
                key: mb_core::CatalogCheckpointRevisionKey,
            ) -> Result<Option<R>, CatalogStoreError> {
                self.index().revision(key)
            }
            fn next_revision(
                &self,
                after: Option<mb_core::CatalogCheckpointRevisionKey>,
            ) -> Result<Option<R>, CatalogStoreError> {
                self.index().next_revision(after)
            }
            fn next_group(
                &self,
                after: Option<[u8; 32]>,
            ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
                self.index().index().next_group_row(after)
            }
            fn has_member(&self, holder: mb_core::NodeId) -> bool {
                self.trust()
                    .members
                    .binary_search_by_key(&holder, |member| member.node_id)
                    .is_ok()
            }
            fn source_id(
                &self,
                key: [u8; 32],
            ) -> Result<mb_core::CatalogPackedSourceId, CatalogStoreError> {
                self.index().index().packing().source_id(key)
            }
            fn read_group(
                &self,
                group: [u8; 32],
                budget: Work,
                fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
            ) -> Result<Option<(mb_core::CatalogCodingEntry, Work)>, CatalogStoreError> {
                self.index()
                    .index()
                    .read_group_with_work_budget(group, budget, fetch)
            }
        }
    };
}
proof!(CatalogQuorumPagedCheckpointIndex, PagedGuildCheckpoint);
proof!(
    CatalogQuorumPagedCheckpointDirectoryIndex,
    mb_core::PagedGuildCheckpointDirectory
);

/// UUIDs also key the original private/payload backlinks. Reject a second
/// layout for the same ID, including permanently cancelled owners.
pub(in crate::database::catalog) fn require_layout<H: Layout>(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, H::OTHER_JOURNAL, id.as_bytes(), 8192)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

pub(in crate::database::catalog) fn validate_owner(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    macro_rules! check {
        ($header:ty) => {
            if let Some(record) =
                journal::read::<CatalogPagedCheckpointRetention<$header>>(connection, id)?
            {
                if record.state == CatalogPagedCheckpointRetentionState::Building
                    || record.roots == 0
                {
                    return Err(DatabaseError::Integrity.into());
                }
                owned_certificate(connection, record.retention)?;
                paged_checkpoint_revision::admitted_work(connection, record.retention)?;
                return Ok(());
            }
        };
    }
    check!(PagedGuildCheckpoint);
    check!(mb_core::PagedGuildCheckpointDirectory);
    Err(DatabaseError::Integrity.into())
}

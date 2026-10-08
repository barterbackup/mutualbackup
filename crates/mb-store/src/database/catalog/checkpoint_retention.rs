//! Durable local ownership of the logical roots embedded in authority records.
//! This is a retention journal, not a checkpoint certificate or activation.

use mb_core::{
    CatalogCheckpointAuthorityReader, CatalogCheckpointAuthorityRecord,
    CatalogCheckpointAuthorityRoot, CatalogStreamError, PagedRevisionSourceReader, WriterFence,
};

use super::retention_journal::{self as journal, Dependency};
use super::*;

const JOURNAL: &str = "catalog-checkpoint-retention-v1";
const JOURNAL_BYTES: usize = 2048;

/// The immutable descriptor for a local retention job. IDs never resume after
/// cancellation. All referenced public roots must already be staged locally;
/// their original intents may be retired after retention finishes successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointRetention {
    pub id: Uuid,
    pub guild_id: [u8; 32],
    pub authority: CatalogCheckpointAuthorityRoot,
}

impl CatalogCheckpointRetention {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        self.authority.validate()?;
        Ok(())
    }

    fn scope(self) -> CatalogScope {
        CatalogScope::Guild {
            guild_id: self.guild_id,
        }
    }
}

pub use journal::CatalogRetentionState as CatalogCheckpointRetentionState;

#[cfg(test)]
type JournalRecord = journal::JournalRecord<CatalogCheckpointRetention>;

impl journal::Retention for CatalogCheckpointRetention {
    const JOURNAL: &'static str = JOURNAL;
    const JOURNAL_BYTES: usize = JOURNAL_BYTES;
    const DEPENDENCIES: &'static str = "catalog-checkpoint-dependency-v1";
    const PIN_PREFIX: u8 = 1;

    fn id(self) -> Uuid {
        self.id
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        CatalogCheckpointRetention::validate(self)
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        Ok((
            self.authority.represented_bytes()?,
            self.authority.page_occurrences()?,
        ))
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        matches!((scope, section),
            (CatalogScope::Guild { guild_id }, CatalogSection::Checkpoint)
            | (CatalogScope::Dataset { guild_id, .. }, CatalogSection::SectorReferences)
            if guild_id == self.guild_id)
    }
}

#[cfg(test)]
fn dependencies(id: Uuid) -> String {
    journal::dependencies::<CatalogCheckpointRetention>(id)
}
#[cfg(test)]
fn pin_id(id: Uuid) -> [u8; 17] {
    journal::pin_id::<CatalogCheckpointRetention>(id)
}
fn read_journal(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<journal::JournalRecord<CatalogCheckpointRetention>>, CatalogStoreError> {
    journal::read(connection, id)
}
#[cfg(test)]
fn retain_root(
    connection: &Connection,
    retention: CatalogCheckpointRetention,
    dependency: Dependency,
) -> Result<(), CatalogStoreError> {
    journal::retain(connection, retention, dependency)
}

fn stream_error(error: CatalogStreamError<CatalogStoreError>) -> CatalogStoreError {
    match error {
        CatalogStreamError::Catalog(error) => error.into(),
        CatalogStreamError::Storage(error) => error,
    }
}

impl ControlStore {
    /// Acquire durable pins for the authority stream and every logical legacy
    /// envelope/source root, then publish this local journal after full typed
    /// EOF. Each pin is a short writer transaction; traversal holds no writer.
    /// Crash-interrupted Building jobs replay from the beginning with bounded
    /// memory. A failed traversal fences the job; cleanup remains incremental.
    ///
    /// This verifies signed records, legacy envelopes and source-record EOF
    /// including the declared bootstrap entry. Native anchors, source data and
    /// bootstrap ciphertext still require their existing independent owners.
    /// It does not certify membership, current writer fences, retained-prefix
    /// joins, unique revision IDs or evidence quorum, and activates no revision.
    pub fn retain_catalog_checkpoint_authority(
        &self,
        retention: CatalogCheckpointRetention,
    ) -> Result<(), CatalogStoreError> {
        retention.validate()?;
        let control = Dependency {
            scope: retention.scope(),
            section: CatalogSection::Checkpoint,
            root: retention.authority.records.page,
        };
        {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            if journal::begin(&transaction, retention)?
                == CatalogCheckpointRetentionState::Published
            {
                return Ok(());
            }
            journal::retain(&transaction, retention, control)?;
            transaction.commit()?;
        }
        let result = (|| {
            let mut reader =
                CatalogCheckpointAuthorityReader::new(retention.scope(), retention.authority)?;
            let mut fetch_control =
                |page| self.catalog_page(retention.scope(), CatalogSection::Checkpoint, page);
            while let Some(record) = reader
                .next_record(&mut fetch_control)
                .map_err(stream_error)?
            {
                let dependency = match &record {
                    CatalogCheckpointAuthorityRecord::LegacyRevision(revision) => {
                        Some(Dependency {
                            scope: retention.scope(),
                            section: CatalogSection::Checkpoint,
                            root: revision.body,
                        })
                    }
                    CatalogCheckpointAuthorityRecord::PagedRevision(revision) => Some(Dependency {
                        scope: revision.value.scope(),
                        section: CatalogSection::SectorReferences,
                        root: revision.value.sources.records.page,
                    }),
                    _ => None,
                };
                let Some(dependency) = dependency else {
                    continue;
                };
                {
                    let transaction = Transaction::new_unchecked(
                        &self.connection,
                        TransactionBehavior::Immediate,
                    )?;
                    journal::retain(&transaction, retention, dependency)?;
                    transaction.commit()?;
                }
                let mut fetch =
                    |page| self.catalog_page(dependency.scope, dependency.section, page);
                match record {
                    CatalogCheckpointAuthorityRecord::LegacyRevision(revision) => {
                        revision.read_signed(&mut fetch).map_err(stream_error)?;
                    }
                    CatalogCheckpointAuthorityRecord::PagedRevision(revision) => {
                        // This self-declared fence verifies signature/geometry
                        // only. Certified current-fence authority is external.
                        let body = &revision.value;
                        let fence = WriterFence {
                            owner: body.owner,
                            epoch: body.writer_epoch,
                            public_key: body.writer_public_key,
                        };
                        let mut sources = PagedRevisionSourceReader::new(
                            &revision,
                            retention.guild_id,
                            body.owner,
                            &fence,
                        )?;
                        while sources
                            .next_sector(&mut fetch)
                            .map_err(stream_error)?
                            .is_some()
                        {}
                    }
                    _ => unreachable!(),
                }
            }
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::publish(&transaction, retention)?;
            transaction.commit()?;
            Ok(())
        })();
        if result.is_err() {
            // A concurrent successful replay must not be retired by a failed
            // worker. Only fence a job that is still Building.
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::cancel_building(&transaction, retention)?;
            transaction.commit()?;
        }
        result
    }

    pub fn catalog_checkpoint_retention(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(CatalogCheckpointRetention, CatalogCheckpointRetentionState)>,
        CatalogStoreError,
    > {
        Ok(read_journal(&self.connection, id)?.map(|record| (record.retention, record.state)))
    }

    /// Fence further acquisition/publication before releasing any root. This
    /// local API must be guarded by current checkpoint ownership at activation.
    pub fn cancel_catalog_checkpoint_retention(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        journal::cancel::<CatalogCheckpointRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }

    /// Release at most one cancelled journal root. Parent links preserve each
    /// immutable byte-tree closure; ordinary bounded page GC reclaims it only
    /// after every other capture/checkpoint owner has released its references.
    pub fn release_catalog_checkpoint_root(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let released = journal::release::<CatalogCheckpointRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(released)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mb_core::{
        CatalogBuilder, CatalogCheckpointAuthorityBuilder, CatalogLegacyRevisionRef,
        CatalogSectorBuilder, CatalogSectorRecord, KeyMaterial, Member, PagedUserRevision,
        SectorRef, Seed, SignedRecord, USER_REVISION_DOMAIN, UserRevision, V1_CIPHER_PROFILE,
        V1_SECTOR_SIZE, merkle_zero_commitment,
    };

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        LegacySignature,
        Bootstrap,
    }

    struct Fixture {
        retention: CatalogCheckpointRetention,
        intents: Vec<CatalogIntent>,
        roots: Vec<Dependency>,
    }

    fn keys() -> KeyMaterial {
        KeyMaterial::from_seed(&Seed::from_bytes([177; 32]))
    }

    #[test]
    fn checkpoint_retention_v1_journal_and_pin_layout_remain_unchanged() {
        // Preserve enum imports as well as fully qualified state variants.
        use CatalogCheckpointRetentionState::*;
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 1, Fault::None);
        journal::assert_v1_layout(
            &store.connection,
            fixture.retention,
            fixture.retention.authority.records.page,
        );
        assert_eq!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap()
                .unwrap()
                .1,
            Cancelled
        );
        let pin = pin_id(fixture.retention.id);
        assert_eq!(pin[0], 1);
        assert_eq!(&pin[1..], fixture.retention.id.as_bytes());
        assert_eq!(
            dependencies(fixture.retention.id),
            format!(
                "catalog-checkpoint-dependency-v1/{}",
                fixture.retention.id.simple()
            )
        );
    }

    fn sector(index: u64) -> CatalogSectorRecord {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&index.to_be_bytes());
        CatalogSectorRecord {
            format_version: 1,
            sector: SectorRef {
                id,
                root: [14; 32],
                logical_len: 19,
            },
            commitment: merkle_zero_commitment(V1_SECTOR_SIZE as u32).unwrap(),
        }
    }

    fn fixture(store: &ControlStore, chains: u64, fault: Fault) -> Fixture {
        let owner = keys();
        let writer = SigningKey::from_bytes(&[178; 32]);
        let guild_id = [179; 32];
        let scope = CatalogScope::Guild { guild_id };
        let legacy_intent = CatalogIntent {
            id: Uuid::from_u128(1),
            scope,
            section: CatalogSection::Checkpoint,
        };
        let control_intent = CatalogIntent {
            id: Uuid::from_u128(2),
            ..legacy_intent
        };
        store.begin_catalog(legacy_intent).unwrap();
        store.begin_catalog(control_intent).unwrap();
        let mut intents = vec![legacy_intent, control_intent];
        let mut roots = Vec::new();
        let mut builder = CatalogCheckpointAuthorityBuilder::new(scope, 2, 1).unwrap();
        let mut control_sink =
            |page, bytes: Vec<u8>| store.stage_catalog_page(control_intent, page, &bytes);
        builder
            .push(
                &CatalogCheckpointAuthorityRecord::Member(Member {
                    node_id: owner.node_id(),
                    recovery_public_key: owner.recovery_public_key(),
                    failure_domain: "retention".into(),
                }),
                &mut control_sink,
            )
            .unwrap();
        builder
            .push(
                &CatalogCheckpointAuthorityRecord::WriterFence(WriterFence {
                    owner: owner.node_id(),
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }),
                &mut control_sink,
            )
            .unwrap();
        for index in 0..chains {
            let protected_root_id = Uuid::from_u128(u128::from(1000 + index));
            let metadata = sector(0);
            let mut legacy = UserRevision {
                format_version: 4,
                guild_id,
                protected_root_id,
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::from_u128(u128::from(10000 + index * 3)),
                owner: owner.node_id(),
                writer_epoch: 1,
                writer_public_key: writer.verifying_key().to_bytes(),
                writer_signature: Vec::new(),
                sequence: 1,
                parent: None,
                metadata_sectors: vec![metadata.sector.clone()],
                data_sectors: if index == 0 {
                    (1..1800).map(|id| sector(id).sector).collect()
                } else {
                    Vec::new()
                },
                sector_commitments: Some(vec![
                    metadata.commitment.clone();
                    if index == 0 { 1800 } else { 1 }
                ]),
            };
            legacy.sign_writer(&writer).unwrap();
            let legacy = SignedRecord::sign(USER_REVISION_DOMAIN, legacy, &owner).unwrap();
            let mut stored = legacy.clone();
            if index + 1 == chains && matches!(fault, Fault::LegacySignature) {
                stored.signature[0] ^= 1;
            }
            let mut bytes = CatalogBuilder::new(scope, CatalogSection::Checkpoint).unwrap();
            let mut sink =
                |page, bytes: Vec<u8>| store.stage_catalog_page(legacy_intent, page, &bytes);
            bytes
                .push(&canonical_bytes(&stored).unwrap(), &mut sink)
                .unwrap();
            let body = bytes.finish(&mut sink).unwrap();
            roots.push(Dependency {
                scope,
                section: CatalogSection::Checkpoint,
                root: body,
            });
            let reference = CatalogLegacyRevisionRef::from_signed(guild_id, &legacy, body).unwrap();
            builder
                .push(
                    &CatalogCheckpointAuthorityRecord::LegacyRevision(reference),
                    &mut control_sink,
                )
                .unwrap();

            let source_scope = CatalogScope::Dataset {
                guild_id,
                owner: owner.node_id(),
                protected_root_id,
            };
            let intent = CatalogIntent {
                id: Uuid::from_u128(u128::from(100 + index)),
                scope: source_scope,
                section: CatalogSection::SectorReferences,
            };
            store.begin_catalog(intent).unwrap();
            intents.push(intent);
            let mut sources = CatalogSectorBuilder::new(source_scope).unwrap();
            let mut sink = |page, bytes: Vec<u8>| store.stage_catalog_page(intent, page, &bytes);
            for id in 0..if index == 0 { 700 } else { 2 } {
                sources.push(&sector(id), &mut sink).unwrap();
            }
            let sources = sources.finish(&mut sink).unwrap();
            roots.push(Dependency {
                scope: source_scope,
                section: CatalogSection::SectorReferences,
                root: sources.records.page,
            });
            let mut parent = legacy.value.hash().unwrap();
            for sequence in 2..=3 {
                let metadata = if index + 1 == chains && matches!(fault, Fault::Bootstrap) {
                    sector(99999)
                } else {
                    metadata.clone()
                };
                let paged = PagedUserRevision {
                    format_version: 8,
                    guild_id,
                    protected_root_id,
                    cipher_profile: V1_CIPHER_PROFILE,
                    revision_id: Uuid::from_u128(u128::from(10000 + index * 3 + sequence - 1)),
                    owner: owner.node_id(),
                    writer_epoch: 1,
                    writer_public_key: writer.verifying_key().to_bytes(),
                    writer_signature: Vec::new(),
                    sequence,
                    parent: Some(parent),
                    metadata,
                    sources,
                }
                .sign(&writer, &owner)
                .unwrap();
                parent = paged.value.hash().unwrap();
                builder
                    .push(
                        &CatalogCheckpointAuthorityRecord::PagedRevision(paged),
                        &mut control_sink,
                    )
                    .unwrap();
            }
        }
        let authority = builder.finish(&mut control_sink).unwrap();
        roots.push(Dependency {
            scope,
            section: CatalogSection::Checkpoint,
            root: authority.records.page,
        });
        Fixture {
            // Deliberately share an ID with the control intent to prove that
            // the two owners' pin keys cannot alias.
            retention: CatalogCheckpointRetention {
                id: control_intent.id,
                guild_id,
                authority,
            },
            intents,
            roots,
        }
    }

    fn release_originals(store: &ControlStore, fixture: &Fixture) {
        for intent in &fixture.intents {
            store.cancel_catalog(*intent).unwrap();
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
    }

    fn assert_roots(store: &ControlStore, fixture: &Fixture, present: bool) {
        for dependency in &fixture.roots {
            assert_eq!(
                store
                    .catalog_page(dependency.scope, dependency.section, dependency.root)
                    .is_ok(),
                present
            );
        }
    }

    #[test]
    fn logical_checkpoint_roots_reopen_share_and_retire_beyond_fixed_bundle_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let mut store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = fixture(&store, 48, Fault::None);
        assert!(fixture.roots.len() > CATALOG_BUNDLE_ROOTS);
        assert!(fixture.roots[0].root.page_occurrences > 1);
        assert!(fixture.roots[1].root.page_occurrences > 1);
        store
            .retain_catalog_checkpoint_authority(fixture.retention)
            .unwrap();
        store
            .retain_catalog_checkpoint_authority(fixture.retention)
            .unwrap();
        let successor = CatalogCheckpointRetention {
            id: Uuid::from_u128(3),
            ..fixture.retention
        };
        store
            .retain_catalog_checkpoint_authority(successor)
            .unwrap();
        let record = read_journal(&store.connection, fixture.retention.id)
            .unwrap()
            .unwrap();
        // Two paged revisions per chain share one owned source root, while the
        // authority summary continues to count both traversal occurrences.
        assert_eq!(record.roots, 97);
        assert!(record.pages < fixture.retention.authority.page_occurrences().unwrap());
        release_originals(&store, &fixture);
        assert_roots(&store, &fixture, true);
        assert!(
            store
                .release_catalog_checkpoint_root(fixture.retention.id)
                .is_err()
        );
        drop(store);
        store = ControlStore::open(&path, &keys()).unwrap();
        assert_eq!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap(),
            Some((
                fixture.retention,
                CatalogCheckpointRetentionState::Published
            ))
        );
        store
            .cancel_catalog_checkpoint_retention(fixture.retention.id)
            .unwrap();
        for remaining in (0..97).rev() {
            assert!(
                store
                    .release_catalog_checkpoint_root(fixture.retention.id)
                    .unwrap()
            );
            assert_eq!(
                read_journal(&store.connection, fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .roots,
                remaining
            );
            if remaining == 48 {
                drop(store);
                store = ControlStore::open(&path, &keys()).unwrap();
            }
        }
        assert!(
            !store
                .release_catalog_checkpoint_root(fixture.retention.id)
                .unwrap()
        );
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, true);
        assert!(
            store
                .retain_catalog_checkpoint_authority(fixture.retention)
                .is_err()
        );
        store
            .cancel_catalog_checkpoint_retention(successor.id)
            .unwrap();
        while store.release_catalog_checkpoint_root(successor.id).unwrap() {}
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn interrupted_checkpoint_retention_replays_existing_pins_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = fixture(&store, 4, Fault::None);
        let transaction =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        insert_exact(
            &transaction,
            JOURNAL,
            fixture.retention.id.as_bytes(),
            &canonical_bytes(&JournalRecord {
                format_version: 1,
                retention: fixture.retention,
                state: CatalogCheckpointRetentionState::Building,
                roots: 0,
                bytes: 0,
                pages: 0,
            })
            .unwrap(),
        )
        .unwrap();
        retain_root(
            &transaction,
            fixture.retention,
            *fixture.roots.last().unwrap(),
        )
        .unwrap();
        retain_root(&transaction, fixture.retention, fixture.roots[0]).unwrap();
        transaction.commit().unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys()).unwrap();
        assert_eq!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap()
                .unwrap()
                .1,
            CatalogCheckpointRetentionState::Building
        );
        let mut substitution = fixture.retention;
        substitution.authority.generation += 1;
        assert!(
            store
                .retain_catalog_checkpoint_authority(substitution)
                .is_err()
        );
        assert_eq!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap()
                .unwrap()
                .1,
            CatalogCheckpointRetentionState::Building
        );
        store
            .retain_catalog_checkpoint_authority(fixture.retention)
            .unwrap();
        assert_eq!(
            read_journal(&store.connection, fixture.retention.id)
                .unwrap()
                .unwrap()
                .roots,
            9
        );
        release_originals(&store, &fixture);
        assert_roots(&store, &fixture, true);
    }

    #[test]
    fn full_legacy_and_source_eof_failures_fence_owned_roots_after_reopen() {
        for fault in [Fault::LegacySignature, Fault::Bootstrap] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("control.db");
            let store = ControlStore::open(&path, &keys()).unwrap();
            let fixture = fixture(&store, 4, fault);
            assert!(
                store
                    .retain_catalog_checkpoint_authority(fixture.retention)
                    .is_err()
            );
            assert_eq!(
                store
                    .catalog_checkpoint_retention(fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .1,
                CatalogCheckpointRetentionState::Cancelled
            );
            assert!(
                read_journal(&store.connection, fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .roots
                    >= 8
            );
            assert!(
                store
                    .retain_catalog_checkpoint_authority(fixture.retention)
                    .is_err()
            );
            drop(store);
            let store = ControlStore::open(&path, &keys()).unwrap();
            store
                .cancel_catalog_checkpoint_retention(fixture.retention.id)
                .unwrap();
            while store
                .release_catalog_checkpoint_root(fixture.retention.id)
                .unwrap()
            {}
            release_originals(&store, &fixture);
            assert_roots(&store, &fixture, false);
        }
    }

    #[test]
    fn corrupt_tail_and_ignored_journal_publication_never_publish_partial_retention() {
        for corrupt_tail in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("control.db");
            let store = ControlStore::open(&path, &keys()).unwrap();
            let fixture = fixture(&store, 2, Fault::None);
            if corrupt_tail {
                // Corrupt the final leaf of the first multi-page legacy body,
                // leaving its authenticated root/reference untouched.
                let dependency = fixture.roots[0];
                let mut reader = mb_core::CatalogReader::new(
                    dependency.scope,
                    dependency.section,
                    dependency.root,
                )
                .unwrap();
                let mut last = None;
                while reader
                    .next_leaf(&mut |page| {
                        let bytes =
                            store.catalog_page(dependency.scope, dependency.section, page)?;
                        if matches!(
                            page.verify_page(dependency.scope, dependency.section, &bytes)?,
                            CatalogPageContents::Leaf(_)
                        ) {
                            last = Some(page.hash);
                        }
                        Ok::<_, CatalogStoreError>(bytes)
                    })
                    .unwrap()
                    .is_some()
                {}
                store.connection.execute("UPDATE protocol_records SET bytes = zeroblob(length(bytes)) WHERE kind = ?1 AND record_id = ?2", params![PAGE, last.unwrap()]).unwrap();
            } else {
                let published = JournalRecord {
                    format_version: 1,
                    retention: fixture.retention,
                    state: CatalogCheckpointRetentionState::Published,
                    roots: fixture.roots.len() as u64,
                    bytes: fixture
                        .roots
                        .iter()
                        .map(|dependency| dependency.root.byte_len)
                        .sum(),
                    pages: fixture
                        .roots
                        .iter()
                        .map(|dependency| dependency.root.page_occurrences)
                        .sum(),
                };
                // Acquisition/count updates succeed, but the final completion
                // marker is ignored. It must not become visible as Published.
                store.connection.execute_batch(&format!(
                    "CREATE TEMP TRIGGER ignore_retention_publication BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-checkpoint-retention-v1' AND NEW.bytes=X'{}' BEGIN SELECT RAISE(IGNORE); END",
                    hex::encode(canonical_bytes(&published).unwrap()),
                )).unwrap();
            }
            assert!(
                store
                    .retain_catalog_checkpoint_authority(fixture.retention)
                    .is_err()
            );
            assert_eq!(
                store
                    .catalog_checkpoint_retention(fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .1,
                CatalogCheckpointRetentionState::Cancelled,
            );
            if !corrupt_tail {
                store
                    .connection
                    .execute_batch("DROP TRIGGER ignore_retention_publication")
                    .unwrap();
                let retry = CatalogCheckpointRetention {
                    id: Uuid::from_u128(3),
                    ..fixture.retention
                };
                store.retain_catalog_checkpoint_authority(retry).unwrap();
                while store
                    .release_catalog_checkpoint_root(fixture.retention.id)
                    .unwrap()
                {}
                release_originals(&store, &fixture);
                assert_roots(&store, &fixture, true);
            }
        }
    }

    #[test]
    fn ignored_acquisition_and_release_roll_back_root_pins_and_counters() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 1, Fault::None);
        store.connection.execute_batch("CREATE TEMP TRIGGER ignore_retention_count BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-checkpoint-retention-v1' BEGIN SELECT RAISE(IGNORE); END").unwrap();
        assert!(
            store
                .retain_catalog_checkpoint_authority(fixture.retention)
                .is_err()
        );
        assert!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap()
                .is_none()
        );
        assert!(
            candidate_hash(&store.connection, &dependencies(fixture.retention.id), &[])
                .unwrap()
                .is_none()
        );
        assert!(
            bounded_record(
                &store.connection,
                &pins(fixture.retention.authority.records.page.hash),
                &pin_id(fixture.retention.id),
                0
            )
            .unwrap()
            .is_none()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_retention_count")
            .unwrap();
        store
            .retain_catalog_checkpoint_authority(fixture.retention)
            .unwrap();
        release_originals(&store, &fixture);
        store
            .cancel_catalog_checkpoint_retention(fixture.retention.id)
            .unwrap();
        let before = read_journal(&store.connection, fixture.retention.id)
            .unwrap()
            .unwrap();
        store.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER ignore_retention_release BEFORE DELETE ON protocol_records WHEN OLD.kind='{}' BEGIN SELECT RAISE(IGNORE); END", dependencies(fixture.retention.id),
        )).unwrap();
        assert!(
            store
                .release_catalog_checkpoint_root(fixture.retention.id)
                .is_err()
        );
        assert_eq!(
            read_journal(&store.connection, fixture.retention.id).unwrap(),
            Some(before)
        );
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, true);
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_retention_release")
            .unwrap();
        while store
            .release_catalog_checkpoint_root(fixture.retention.id)
            .unwrap()
        {}
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn orphan_and_oversized_journals_and_foreign_roots_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 1, Fault::None);
        let control = *fixture.roots.last().unwrap();
        insert_exact(
            &store.connection,
            &dependencies(fixture.retention.id),
            &control.root.hash,
            &canonical_bytes(&control).unwrap(),
        )
        .unwrap();
        assert!(
            store
                .retain_catalog_checkpoint_authority(fixture.retention)
                .is_err()
        );
        assert!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap()
                .is_none()
        );
        store
            .connection
            .execute(
                "DELETE FROM protocol_records WHERE kind = ?1",
                [dependencies(fixture.retention.id)],
            )
            .unwrap();
        insert_exact(
            &store.connection,
            JOURNAL,
            fixture.retention.id.as_bytes(),
            &vec![0; JOURNAL_BYTES + 1],
        )
        .unwrap();
        assert!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .is_err()
        );
        store
            .connection
            .execute("DELETE FROM protocol_records WHERE kind = ?1", [JOURNAL])
            .unwrap();
        let mut foreign = fixture.retention;
        foreign.guild_id[0] ^= 1;
        assert!(store.retain_catalog_checkpoint_authority(foreign).is_err());
        assert!(
            store
                .catalog_checkpoint_retention(fixture.retention.id)
                .unwrap()
                .is_none()
        );
        store
            .retain_catalog_checkpoint_authority(fixture.retention)
            .unwrap();
        let transaction =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        let mut foreign_root = fixture.roots[1];
        foreign_root.scope = CatalogScope::Guild { guild_id: [1; 32] };
        foreign_root.section = CatalogSection::Checkpoint;
        assert!(retain_root(&transaction, fixture.retention, foreign_root).is_err());
        let mut private_root = fixture.roots[1];
        private_root.section = CatalogSection::FileMetadata;
        assert!(retain_root(&transaction, fixture.retention, private_root).is_err());
    }
}

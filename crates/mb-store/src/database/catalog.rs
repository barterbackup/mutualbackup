//! Local SQLCipher ownership of immutable catalog pages. Publication here is a
//! local catalog root, not a signed revision or a claim of remote protection.

use mb_core::{
    CATALOG_MAX_PAGE_OCCURRENCES, CATALOG_PAGE_BYTES, CatalogError, CatalogPageContents,
    CatalogPageRef, CatalogScope, CatalogSection, ModelError, canonical_bytes, decode_canonical,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::{ControlStore, DatabaseError};

mod bundle;
mod native_validation;
pub use bundle::{
    CATALOG_BUNDLE_DESCRIPTOR_BYTES, CATALOG_BUNDLE_ROOTS, CatalogBundle, CatalogBundleRoot,
    CatalogBundleState,
};
pub use native_validation::{
    CatalogNativeValidation, CatalogNativeValidationState, CatalogValidatedLink,
};

const INTENT: &str = "catalog-intent-v1";
const PAGE: &str = "catalog-page-v1";
const META: &str = "catalog-page-metadata-v1";
const GC: &str = "catalog-page-gc-v1";
const RECORD_BYTES: usize = 256;

#[derive(Debug, Error)]
pub enum CatalogStoreError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Page(#[from] CatalogError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl From<rusqlite::Error> for CatalogStoreError {
    fn from(error: rusqlite::Error) -> Self {
        DatabaseError::Sql(error).into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogIntent {
    pub id: Uuid,
    pub scope: CatalogScope,
    pub section: CatalogSection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogIntentState {
    Building,
    Published(CatalogPageRef),
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IntentRecord {
    format_version: u16,
    intent: CatalogIntent,
    state: CatalogIntentState,
    owned_pages: u64,
    owned_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PageMetadata {
    format_version: u16,
    scope: CatalogScope,
    section: CatalogSection,
    reference: CatalogPageRef,
}

fn owners(intent: CatalogIntent) -> String {
    format!("catalog-page-owner-v1/{}", intent.id.simple())
}

fn pins(hash: [u8; 32]) -> String {
    format!("catalog-page-pin-v1/{}", hex::encode(hash))
}

fn parents(hash: [u8; 32]) -> String {
    format!("catalog-page-parent-v1/{}", hex::encode(hash))
}

fn bounded_record(
    connection: &Connection,
    kind: &str,
    id: &[u8],
    limit: usize,
) -> Result<Option<Vec<u8>>, CatalogStoreError> {
    // Even a damaged row must not allocate an unbounded payload before bounds
    // are checked. The CASE is evaluated by SQLite before row materialization.
    let value: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(bytes) <= ?3 THEN bytes END
         FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![kind, id, limit as u64],
            |row| row.get(0),
        )
        .optional()?;
    match value {
        Some(None) => Err(DatabaseError::Integrity.into()),
        Some(Some(bytes)) => Ok(Some(bytes)),
        None => Ok(None),
    }
}

fn read_intent(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<IntentRecord, CatalogStoreError> {
    let bytes = bounded_record(connection, INTENT, intent.id.as_bytes(), RECORD_BYTES)?
        .ok_or(DatabaseError::Conflict)?;
    let record: IntentRecord = decode_canonical(&bytes)?;
    record.intent.scope.validate(record.intent.section)?;
    if record.format_version != 1
        || record.intent.id != intent.id
        || intent.id.is_nil()
        || record.owned_pages > CATALOG_MAX_PAGE_OCCURRENCES
        || record.owned_bytes < record.owned_pages
        || record.owned_bytes > record.owned_pages * CATALOG_PAGE_BYTES as u64
        || canonical_bytes(&record)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    if record.intent != intent {
        return Err(DatabaseError::Conflict.into());
    }
    if let CatalogIntentState::Published(root) = record.state {
        root.validate()?;
        if record.owned_pages == 0 {
            return Err(DatabaseError::Integrity.into());
        }
    }
    Ok(record)
}

fn write_intent(connection: &Connection, record: &IntentRecord) -> Result<(), CatalogStoreError> {
    let written = connection.execute(
        "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
        params![
            INTENT,
            record.intent.id.as_bytes(),
            canonical_bytes(record)?
        ],
    )?;
    if written != 1 {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn publish_root(
    connection: &Connection,
    intent: CatalogIntent,
    root: CatalogPageRef,
) -> Result<(), CatalogStoreError> {
    root.validate()?;
    let mut record = read_intent(connection, intent)?;
    if record.state != CatalogIntentState::Building
        && record.state != CatalogIntentState::Published(root)
    {
        return Err(DatabaseError::Conflict.into());
    }
    if bounded_record(connection, &owners(intent), &root.hash, 0)?.is_none()
        || bounded_record(connection, &pins(root.hash), intent.id.as_bytes(), 0)?.is_none()
    {
        return Err(DatabaseError::NotReady.into());
    }
    read_page(
        connection,
        PageMetadata {
            format_version: 1,
            scope: intent.scope,
            section: intent.section,
            reference: root,
        },
    )?;
    record.state = CatalogIntentState::Published(root);
    write_intent(connection, &record)
}

fn metadata(connection: &Connection, hash: [u8; 32]) -> Result<PageMetadata, CatalogStoreError> {
    let bytes =
        bounded_record(connection, META, &hash, RECORD_BYTES)?.ok_or(DatabaseError::NotReady)?;
    let page: PageMetadata = decode_canonical(&bytes)?;
    page.scope.validate(page.section)?;
    page.reference.validate()?;
    if page.format_version != 1 || page.reference.hash != hash || canonical_bytes(&page)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(page)
}

fn read_page(connection: &Connection, page: PageMetadata) -> Result<Vec<u8>, CatalogStoreError> {
    if metadata(connection, page.reference.hash)? != page {
        return Err(DatabaseError::Conflict.into());
    }
    let bytes = bounded_record(
        connection,
        PAGE,
        &page.reference.hash,
        page.reference.encoded_len as usize,
    )?
    .ok_or(DatabaseError::NotReady)?;
    page.reference
        .verify_page(page.scope, page.section, &bytes)?;
    Ok(bytes)
}

fn insert_exact(
    connection: &Connection,
    kind: &str,
    id: &[u8],
    bytes: &[u8],
) -> Result<(), CatalogStoreError> {
    let inserted = connection.execute(
        "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
         ON CONFLICT(kind, record_id) DO NOTHING",
        params![kind, id, bytes],
    )?;
    if inserted == 0 && bounded_record(connection, kind, id, bytes.len())?.as_deref() != Some(bytes)
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn unreferenced(connection: &Connection, hash: [u8; 32]) -> Result<bool, CatalogStoreError> {
    Ok(connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1 OR kind = ?2)",
        params![pins(hash), parents(hash)],
        |row| row.get(0),
    )?)
}

fn queue_unreferenced(connection: &Connection, hash: [u8; 32]) -> Result<(), CatalogStoreError> {
    if unreferenced(connection, hash)? {
        insert_exact(connection, GC, &hash, &[])?;
    }
    Ok(())
}

fn candidate_hash(
    connection: &Connection,
    kind: &str,
    excluded: &[u8],
) -> Result<Option<[u8; 32]>, CatalogStoreError> {
    let candidate: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(record_id) = 32 THEN record_id END
         FROM protocol_records WHERE kind = ?1 AND record_id != ?2 ORDER BY record_id LIMIT 1",
            params![kind, excluded],
            |row| row.get(0),
        )
        .optional()?;
    match candidate {
        None => Ok(None),
        Some(Some(hash)) => Ok(Some(hash.try_into().map_err(|_| DatabaseError::Integrity)?)),
        Some(None) => Err(DatabaseError::Integrity.into()),
    }
}

impl ControlStore {
    /// IDs are immutable; cancelled records remain as small fencing tombstones.
    /// Retirement of those tombstones needs a future authenticated generation
    /// floor, rather than allowing an old writer to recreate an intent.
    pub fn begin_catalog(
        &self,
        intent: CatalogIntent,
    ) -> Result<CatalogIntentState, CatalogStoreError> {
        intent.scope.validate(intent.section)?;
        if intent.id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if bounded_record(&transaction, INTENT, intent.id.as_bytes(), RECORD_BYTES)?.is_some() {
            let record = read_intent(&transaction, intent)?;
            if record.state == CatalogIntentState::Cancelled {
                return Err(DatabaseError::Conflict.into());
            }
            return Ok(record.state);
        }
        insert_exact(
            &transaction,
            INTENT,
            intent.id.as_bytes(),
            &canonical_bytes(&IntentRecord {
                format_version: 1,
                intent,
                state: CatalogIntentState::Building,
                owned_pages: 0,
                owned_bytes: 0,
            })?,
        )?;
        transaction.commit()?;
        Ok(CatalogIntentState::Building)
    }

    pub fn catalog_intent_state(
        &self,
        intent: CatalogIntent,
    ) -> Result<CatalogIntentState, CatalogStoreError> {
        Ok(read_intent(&self.connection, intent)?.state)
    }

    /// Store and pin one page atomically. Immediate children must already be
    /// durable and verified. Parent links preserve their full immutable closure.
    pub fn stage_catalog_page(
        &self,
        intent: CatalogIntent,
        reference: CatalogPageRef,
        bytes: &[u8],
    ) -> Result<(), CatalogStoreError> {
        let contents = reference.verify_page(intent.scope, intent.section, bytes)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut record = read_intent(&transaction, intent)?;
        if record.state != CatalogIntentState::Building {
            return Err(DatabaseError::Conflict.into());
        }
        let page = PageMetadata {
            format_version: 1,
            scope: intent.scope,
            section: intent.section,
            reference,
        };
        if let CatalogPageContents::Index(children) = &contents {
            for child in children {
                read_page(
                    &transaction,
                    PageMetadata {
                        reference: *child,
                        ..page
                    },
                )?;
            }
        }
        insert_exact(&transaction, PAGE, &reference.hash, bytes)?;
        insert_exact(
            &transaction,
            META,
            &reference.hash,
            &canonical_bytes(&page)?,
        )?;
        let owner_kind = owners(intent);
        if bounded_record(&transaction, &owner_kind, &reference.hash, 0)?.is_none() {
            if record.owned_pages == CATALOG_MAX_PAGE_OCCURRENCES {
                return Err(DatabaseError::CapacityExceeded.into());
            }
            insert_exact(&transaction, &owner_kind, &reference.hash, &[])?;
            record.owned_pages += 1;
            record.owned_bytes += bytes.len() as u64;
            write_intent(&transaction, &record)?;
        }
        insert_exact(
            &transaction,
            &pins(reference.hash),
            intent.id.as_bytes(),
            &[],
        )?;
        if let CatalogPageContents::Index(children) = contents {
            for child in children {
                insert_exact(&transaction, &parents(child.hash), &reference.hash, &[])?;
                transaction.execute(
                    "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                    params![GC, child.hash],
                )?;
            }
        }
        transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![GC, reference.hash],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Publish a local root only after its child-first durable closure exists.
    /// Surplus staged pins can then be released one at a time. This does not
    /// certify a signed revision, remote protection or freedom from bit rot.
    pub fn publish_catalog(
        &self,
        intent: CatalogIntent,
        root: CatalogPageRef,
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        publish_root(&transaction, intent, root)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically fence stale page writers/publication before dropping any pin.
    pub fn cancel_catalog(&self, intent: CatalogIntent) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut record = read_intent(&transaction, intent)?;
        bundle::require_unbundled(&transaction, intent)?;
        record.state = CatalogIntentState::Cancelled;
        write_intent(&transaction, &record)?;
        transaction.commit()?;
        Ok(())
    }

    /// Release one surplus/pending ownership record, preserving a published
    /// root. `false` means no eligible pins remain. Work is independent of the
    /// number of records in other captures or in the remainder of this catalog.
    pub fn release_catalog_pin(&self, intent: CatalogIntent) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut record = read_intent(&transaction, intent)?;
        let protected = match record.state {
            CatalogIntentState::Building => return Err(DatabaseError::Conflict.into()),
            CatalogIntentState::Published(root) => root.hash.to_vec(),
            CatalogIntentState::Cancelled => Vec::new(),
        };
        let owner_kind = owners(intent);
        let Some(hash) = candidate_hash(&transaction, &owner_kind, &protected)? else {
            return Ok(false);
        };
        let page = metadata(&transaction, hash)?;
        if page.scope != intent.scope
            || page.section != intent.section
            || bounded_record(&transaction, &owner_kind, &hash, 0)?.as_deref() != Some(&[])
            || bounded_record(&transaction, &pins(hash), intent.id.as_bytes(), 0)?.as_deref()
                != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        record.owned_pages = record
            .owned_pages
            .checked_sub(1)
            .ok_or(DatabaseError::Integrity)?;
        record.owned_bytes = record
            .owned_bytes
            .checked_sub(page.reference.encoded_len as u64)
            .ok_or(DatabaseError::Integrity)?;
        transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![owner_kind, hash],
        )?;
        transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![pins(hash), intent.id.as_bytes()],
        )?;
        write_intent(&transaction, &record)?;
        queue_unreferenced(&transaction, hash)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn catalog_page(
        &self,
        scope: CatalogScope,
        section: CatalogSection,
        reference: CatalogPageRef,
    ) -> Result<Vec<u8>, CatalogStoreError> {
        reference.validate()?;
        scope.validate(section)?;
        let transaction = self.connection.unchecked_transaction()?;
        let bytes = read_page(
            &transaction,
            PageMetadata {
                format_version: 1,
                scope,
                section,
                reference,
            },
        )?;
        transaction.commit()?;
        Ok(bytes)
    }

    /// Reclaim one queued, unreferenced page and its bounded outgoing edges.
    /// Shared pages survive via a pin or parent, even if another capture was
    /// cancelled. Child candidates are queued in this same durable transaction.
    pub fn collect_catalog_page(&self) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(hash) = candidate_hash(&transaction, GC, &[])? else {
            return Ok(false);
        };
        if bounded_record(&transaction, GC, &hash, 0)?.as_deref() != Some(&[]) {
            return Err(DatabaseError::Integrity.into());
        }
        if unreferenced(&transaction, hash)? {
            let page = metadata(&transaction, hash)?;
            let bytes = read_page(&transaction, page)?;
            if let CatalogPageContents::Index(children) =
                page.reference
                    .verify_page(page.scope, page.section, &bytes)?
            {
                for child in children {
                    transaction.execute(
                        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                        params![parents(child.hash), hash],
                    )?;
                    queue_unreferenced(&transaction, child.hash)?;
                }
            }
            transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![PAGE, hash],
            )?;
            transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![META, hash],
            )?;
        }
        transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![GC, hash],
        )?;
        transaction.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use mb_core::{CATALOG_LEAF_BYTES, CatalogBuilder, CatalogReader, KeyMaterial, NodeId, Seed};

    use super::*;

    fn intent(id: u8) -> CatalogIntent {
        CatalogIntent {
            id: Uuid::from_bytes([id; 16]),
            scope: CatalogScope::Dataset {
                guild_id: [1; 32],
                owner: NodeId([2; 32]),
                protected_root_id: Uuid::from_bytes([3; 16]),
            },
            section: CatalogSection::GitGraph,
        }
    }

    type EncodedPages = Vec<(CatalogPageRef, Vec<u8>)>;

    fn graph() -> (Vec<u8>, CatalogPageRef, EncodedPages) {
        let bytes = [
            vec![1; CATALOG_LEAF_BYTES],
            vec![2; CATALOG_LEAF_BYTES],
            vec![3; 17],
        ]
        .concat();
        let mut pages = Vec::new();
        let mut sink = |reference, encoded| {
            pages.push((reference, encoded));
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(intent(1).scope, intent(1).section).unwrap();
        builder.push(&bytes, &mut sink).unwrap();
        let root = builder.finish(&mut sink).unwrap();
        (bytes, root, pages)
    }

    fn read(store: &ControlStore, operation: CatalogIntent, root: CatalogPageRef) -> Vec<u8> {
        let mut reader = CatalogReader::new(operation.scope, operation.section, root).unwrap();
        let mut bytes = Vec::new();
        let mut fetch =
            |reference| store.catalog_page(operation.scope, operation.section, reference);
        while let Some(leaf) = reader.next_leaf(&mut fetch).unwrap() {
            bytes.extend(leaf);
        }
        bytes
    }

    #[test]
    fn catalog_ownership_reopens_at_each_stage_publication_and_cleanup_boundary() {
        let (bytes, root, pages) = graph();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([91; 32]));
        for stopped in 0..=pages.len() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open(&path, &keys).unwrap();
            let operation = intent(10);
            assert_eq!(
                store.begin_catalog(operation).unwrap(),
                CatalogIntentState::Building
            );
            for (reference, encoded) in &pages[..stopped] {
                store
                    .stage_catalog_page(operation, *reference, encoded)
                    .unwrap();
            }
            assert_eq!(
                store.catalog_intent_state(operation).unwrap(),
                CatalogIntentState::Building
            );
            if stopped < pages.len() {
                assert!(store.publish_catalog(operation, root).is_err());
            }
            drop(store);
            let store = ControlStore::open(&path, &keys).unwrap();
            assert_eq!(
                store.begin_catalog(operation).unwrap(),
                CatalogIntentState::Building
            );
            for (reference, encoded) in &pages {
                store
                    .stage_catalog_page(operation, *reference, encoded)
                    .unwrap();
            }
            store.publish_catalog(operation, root).unwrap();
            drop(store);
            let mut store = ControlStore::open(&path, &keys).unwrap();
            assert_eq!(
                store.begin_catalog(operation).unwrap(),
                CatalogIntentState::Published(root)
            );
            store.publish_catalog(operation, root).unwrap();
            assert!(
                store
                    .stage_catalog_page(operation, pages[0].0, &pages[0].1)
                    .is_err()
            );
            assert_eq!(read(&store, operation, root), bytes);
            while store.release_catalog_pin(operation).unwrap() {
                drop(store);
                store = ControlStore::open(&path, &keys).unwrap();
                assert_eq!(read(&store, operation, root), bytes);
                assert!(!store.collect_catalog_page().unwrap());
            }
            store.cancel_catalog(operation).unwrap();
            drop(store);
            let mut store = ControlStore::open(&path, &keys).unwrap();
            while store.release_catalog_pin(operation).unwrap() {
                drop(store);
                store = ControlStore::open(&path, &keys).unwrap();
            }
            while store.collect_catalog_page().unwrap() {
                drop(store);
                store = ControlStore::open(&path, &keys).unwrap();
            }
            assert!(
                store
                    .catalog_page(operation.scope, operation.section, root)
                    .is_err()
            );
            assert!(store.records(PAGE).unwrap().is_empty());
            assert!(store.begin_catalog(operation).is_err());
        }
    }

    #[test]
    fn catalog_shared_closures_survive_cancelled_and_replaced_owners() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([92; 32]));
        let path = temp.path().join("control.db");
        let store = ControlStore::open(&path, &keys).unwrap();
        let (bytes, root, pages) = graph();
        let first = intent(11);
        let successor = intent(12);
        store.begin_catalog(first).unwrap();
        for (reference, encoded) in &pages {
            store
                .stage_catalog_page(first, *reference, encoded)
                .unwrap();
        }
        store.publish_catalog(first, root).unwrap();
        store.begin_catalog(successor).unwrap();
        let (_, encoded) = pages.last().unwrap();
        store.stage_catalog_page(successor, root, encoded).unwrap();
        store.cancel_catalog(first).unwrap();
        assert!(store.publish_catalog(first, root).is_err());
        assert!(store.stage_catalog_page(first, root, encoded).is_err());
        while store.release_catalog_pin(first).unwrap() {}
        assert!(!store.collect_catalog_page().unwrap());
        assert_eq!(store.records(PAGE).unwrap().len(), pages.len());
        assert_eq!(
            store.catalog_intent_state(successor).unwrap(),
            CatalogIntentState::Building
        );
        assert_eq!(read(&store, successor, root), bytes);
        store.publish_catalog(successor, root).unwrap();
        drop(store);
        let mut store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(read(&store, successor, root), bytes);
        store.cancel_catalog(first).unwrap();
        assert!(!store.release_catalog_pin(first).unwrap());
        assert!(!store.collect_catalog_page().unwrap());
        store.cancel_catalog(successor).unwrap();
        while store.release_catalog_pin(successor).unwrap() {}
        let mut collected = 0;
        while store.collect_catalog_page().unwrap() {
            collected += 1;
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
        }
        assert_eq!(collected, pages.len());
        assert!(store.records(PAGE).unwrap().is_empty());
        assert!(store.records(META).unwrap().is_empty());
        assert!(
            store
                .records_with_kind_prefix("catalog-page-parent-v1/")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn catalog_rejects_unready_children_corruption_and_conflicting_intent_scope() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([93; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let operation = intent(13);
        store.begin_catalog(operation).unwrap();
        let (_, root, pages) = graph();
        let (_, root_bytes) = pages.last().unwrap();
        assert!(
            store
                .stage_catalog_page(operation, root, root_bytes)
                .is_err()
        );
        assert!(store.records(PAGE).unwrap().is_empty());
        assert_eq!(
            read_intent(&store.connection, operation)
                .unwrap()
                .owned_pages,
            0
        );
        let mut conflict = operation;
        conflict.section = CatalogSection::FileMetadata;
        assert!(store.begin_catalog(conflict).is_err());
        assert!(
            store
                .stage_catalog_page(conflict, pages[0].0, &pages[0].1)
                .is_err()
        );
        assert!(store.release_catalog_pin(operation).is_err());
        for (reference, encoded) in &pages[..pages.len() - 1] {
            store
                .stage_catalog_page(operation, *reference, encoded)
                .unwrap();
        }
        let (leaf, original) = &pages[0];
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        store.put_record(PAGE, &leaf.hash, &corrupt).unwrap();
        assert!(
            store
                .stage_catalog_page(operation, root, root_bytes)
                .is_err()
        );
        assert!(
            store
                .catalog_page(operation.scope, operation.section, *leaf)
                .is_err()
        );
        assert_eq!(
            store.get_record(PAGE, &leaf.hash).unwrap().unwrap(),
            corrupt
        );
        store.put_record(PAGE, &leaf.hash, original).unwrap();
        store
            .stage_catalog_page(operation, root, root_bytes)
            .unwrap();
        store
            .put_record(PAGE, &root.hash, &vec![0; CATALOG_PAGE_BYTES + 1])
            .unwrap();
        assert!(store.publish_catalog(operation, root).is_err());
        assert_eq!(
            store.catalog_intent_state(operation).unwrap(),
            CatalogIntentState::Building
        );
        store.put_record(PAGE, &root.hash, root_bytes).unwrap();
        store.publish_catalog(operation, root).unwrap();
        let mut bad = root;
        bad.byte_len += 1;
        assert!(store.publish_catalog(operation, bad).is_err());
        assert_eq!(
            store.catalog_intent_state(operation).unwrap(),
            CatalogIntentState::Published(root)
        );
    }

    #[test]
    fn catalog_sql_failure_rolls_back_page_ownership_and_gc_edges() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([94; 32]));
        let path = temp.path().join("control.db");
        let store = ControlStore::open(&path, &keys).unwrap();
        let (_, root, pages) = graph();
        let operation = intent(14);
        store.begin_catalog(operation).unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER reject_pin BEFORE INSERT ON protocol_records
            WHEN NEW.kind GLOB 'catalog-page-pin-v1/*'
            BEGIN SELECT RAISE(ABORT, 'injected pin failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .stage_catalog_page(operation, pages[0].0, &pages[0].1)
                .is_err()
        );
        assert!(store.records(PAGE).unwrap().is_empty());
        assert!(store.records(META).unwrap().is_empty());
        assert_eq!(
            read_intent(&store.connection, operation)
                .unwrap()
                .owned_pages,
            0
        );
        store
            .connection
            .execute_batch("DROP TRIGGER reject_pin;")
            .unwrap();
        for (reference, encoded) in &pages {
            store
                .stage_catalog_page(operation, *reference, encoded)
                .unwrap();
        }
        store.publish_catalog(operation, root).unwrap();
        store.cancel_catalog(operation).unwrap();
        while store.release_catalog_pin(operation).unwrap() {}
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER reject_page_delete BEFORE DELETE ON protocol_records
             WHEN OLD.kind = 'catalog-page-v1'
             BEGIN SELECT RAISE(ABORT, 'injected GC failure'); END;",
            )
            .unwrap();
        assert!(store.collect_catalog_page().is_err());
        assert_eq!(store.records(PAGE).unwrap().len(), pages.len());
        assert_eq!(store.records(GC).unwrap().len(), 1);
        assert_eq!(
            store
                .records_with_kind_prefix("catalog-page-parent-v1/")
                .unwrap()
                .len(),
            pages.len() - 1
        );
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        while store.collect_catalog_page().unwrap() {}
        assert!(store.records(PAGE).unwrap().is_empty());
        assert!(store.records(GC).unwrap().is_empty());
    }
}

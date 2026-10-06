//! Page ownership for live local sector recipes, published with their source
//! record. Retirement visits one indexed recipe per step and never scans a
//! catalog's closure or materializes unrelated source records.

use super::*;

const PIN: &str = "catalog-source-pin-v1";
const SNAPSHOT: &str = "catalog-source-recipe-v1";
const LINK: &str = "catalog-source-intent-link-v1";
const CURSOR: &str = "catalog-source-sweep-v1";
const CURSOR_KEY: &[u8] = b"cursor";
pub const CATALOG_SECTOR_RECIPE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogSourceSweep {
    Idle,
    Retained([u8; 32]),
    Retired([u8; 32]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSectorSource {
    pub intent: CatalogIntent,
    pub page: CatalogPageRef,
    pub recipe: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourcePin {
    format_version: u16,
    intent: CatalogIntent,
    page: CatalogPageRef,
}

pub(super) fn require_unlinked_source(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, LINK, intent.id.as_bytes(), 32)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn delete_exact(connection: &Connection, kind: &str, key: &[u8]) -> Result<(), CatalogStoreError> {
    if connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
        params![kind, key],
    )? != 1
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

impl ControlStore {
    /// Return a bounded source descriptor only while its exact live recipe is
    /// still pinned. Repair must recheck ownership in its writer transaction.
    pub fn catalog_sector_source(
        &self,
        sector_id: [u8; 32],
    ) -> Result<Option<CatalogSectorSource>, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let source = read_source(&transaction, sector_id)?;
        transaction.commit()?;
        Ok(source)
    }

    /// Replace a damaged or missing payload for an existing pinned page.
    /// The caller authenticates recovered ciphertext and its sector reference;
    /// this transaction rechecks the exact recipe, pin, immutable page metadata
    /// and child links. It changes only the payload, preserving source lifetime.
    pub fn repair_catalog_sector_page(
        &self,
        sector_id: [u8; 32],
        expected_recipe: &[u8],
        encoded: &[u8],
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let source = read_source(&transaction, sector_id)?.ok_or(DatabaseError::Conflict)?;
        if source.recipe != expected_recipe {
            return Err(DatabaseError::Conflict.into());
        }
        let contents =
            source
                .page
                .verify_page(source.intent.scope, source.intent.section, encoded)?;
        let expected = PageMetadata {
            format_version: 1,
            scope: source.intent.scope,
            section: source.intent.section,
            reference: source.page,
        };
        if metadata(&transaction, source.page.hash)? != expected {
            return Err(DatabaseError::Integrity.into());
        }
        if let CatalogPageContents::Index(children) = contents {
            for child in children {
                if metadata(&transaction, child.hash)?
                    != (PageMetadata {
                        reference: child,
                        ..expected
                    })
                    || bounded_record(&transaction, &parents(child.hash), &source.page.hash, 0)?
                        .as_deref()
                        != Some(&[])
                {
                    return Err(DatabaseError::Integrity.into());
                }
            }
        }
        if transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![PAGE, source.page.hash, encoded],
        )? != 1
        {
            return Err(DatabaseError::Conflict.into());
        }
        transaction.commit()?;
        Ok(())
    }

    /// Publish one private page's source recipe and its immutable root pin in
    /// one writer transaction. The caller verifies sector address/encryption.
    /// This dedicated intent must own exactly this one page; existing parents
    /// retain its children. Existing incompatible source records are preserved.
    pub fn publish_catalog_sector_recipe(
        &self,
        intent: CatalogIntent,
        page: CatalogPageRef,
        sector_id: [u8; 32],
        recipe: &[u8],
    ) -> Result<(), CatalogStoreError> {
        if !intent.section.is_private()
            || recipe.is_empty()
            || recipe.len() > CATALOG_SECTOR_RECIPE_BYTES
        {
            return Err(DatabaseError::Conflict.into());
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = read_intent(&transaction, intent)?;
        if record.owned_pages != 1 || record.owned_bytes != u64::from(page.encoded_len) {
            return Err(DatabaseError::Conflict.into());
        }
        // Source intents cannot be members of a descriptor bundle. Its root
        // pin has a separate lifetime tied to the exact local-sector record.
        if bounded_record(&transaction, bundle::LINK, intent.id.as_bytes(), 16)?.is_some() {
            return Err(DatabaseError::Conflict.into());
        }
        let pin = canonical_bytes(&SourcePin {
            format_version: 1,
            intent,
            page,
        })?;
        if let Some(existing) = bounded_record(&transaction, LINK, intent.id.as_bytes(), 32)?
            && existing != sector_id
        {
            return Err(DatabaseError::Conflict.into());
        }
        publish_root(&transaction, intent, page)?;
        insert_exact(&transaction, PIN, &sector_id, &pin)?;
        insert_exact(&transaction, SNAPSHOT, &sector_id, recipe)?;
        insert_exact(&transaction, LINK, intent.id.as_bytes(), &sector_id)?;
        insert_exact(&transaction, "local-sector", &sector_id, recipe)?;
        transaction.commit()?;
        Ok(())
    }

    /// Inspect one source pin using an indexed cursor. Its page remains pinned
    /// while the exact published recipe exists. Once the recipe is deleted or
    /// replaced, fence the dedicated intent and release its one pin atomically.
    /// Old intent IDs remain cancelled tombstones and cannot be resurrected.
    pub fn sweep_catalog_source_pin(&self) -> Result<CatalogSourceSweep, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let cursor = bounded_record(&transaction, CURSOR, CURSOR_KEY, 32)?.unwrap_or_default();
        if !cursor.is_empty() && cursor.len() != 32 {
            return Err(DatabaseError::Integrity.into());
        }
        let next = |after: &[u8]| -> Result<Option<[u8; 32]>, CatalogStoreError> {
            let candidate: Option<Option<Vec<u8>>> = transaction.query_row(
                "SELECT CASE WHEN length(record_id) = 32 THEN record_id END
                 FROM protocol_records WHERE kind = ?1 AND record_id > ?2 ORDER BY record_id LIMIT 1",
                params![PIN, after], |row| row.get(0),
            ).optional()?;
            match candidate {
                None => Ok(None),
                Some(Some(id)) => Ok(Some(id.try_into().map_err(|_| DatabaseError::Integrity)?)),
                Some(None) => Err(DatabaseError::Integrity.into()),
            }
        };
        let Some(id) = next(&cursor)?.or(next(&[])?) else {
            return Ok(CatalogSourceSweep::Idle);
        };
        let pin_bytes = bounded_record(&transaction, PIN, &id, RECORD_BYTES)?
            .ok_or(DatabaseError::Integrity)?;
        let pin: SourcePin = decode_canonical(&pin_bytes)?;
        if pin.format_version != 1
            || canonical_bytes(&pin)? != pin_bytes
            || !pin.intent.section.is_private()
        {
            return Err(DatabaseError::Integrity.into());
        }
        let snapshot = bounded_record(&transaction, SNAPSHOT, &id, CATALOG_SECTOR_RECIPE_BYTES)?
            .ok_or(DatabaseError::Integrity)?;
        if snapshot.is_empty()
            || bounded_record(&transaction, LINK, pin.intent.id.as_bytes(), 32)?.as_deref()
                != Some(&id)
        {
            return Err(DatabaseError::Integrity.into());
        }
        let mut record = read_intent(&transaction, pin.intent)?;
        if record.state != CatalogIntentState::Published(pin.page)
            || record.owned_pages != 1
            || record.owned_bytes != u64::from(pin.page.encoded_len)
            || bounded_record(&transaction, &owners(pin.intent), &pin.page.hash, 0)?.as_deref()
                != Some(&[])
            || bounded_record(
                &transaction,
                &pins(pin.page.hash),
                pin.intent.id.as_bytes(),
                0,
            )?
            .as_deref()
                != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        let retained: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = 'local-sector' AND record_id = ?1 AND bytes = ?2)",
            params![id, snapshot], |row| row.get(0),
        )?;
        let outcome = if retained {
            CatalogSourceSweep::Retained(id)
        } else {
            // Checking row counts makes SQL IGNORE faults roll the entire
            // cancellation and ownership release back, including source links.
            record.state = CatalogIntentState::Cancelled;
            record.owned_pages = 0;
            record.owned_bytes = 0;
            write_intent(&transaction, &record)?;
            delete_exact(&transaction, &owners(pin.intent), &pin.page.hash)?;
            delete_exact(&transaction, &pins(pin.page.hash), pin.intent.id.as_bytes())?;
            delete_exact(&transaction, LINK, pin.intent.id.as_bytes())?;
            delete_exact(&transaction, SNAPSHOT, &id)?;
            delete_exact(&transaction, PIN, &id)?;
            queue_unreferenced(&transaction, pin.page.hash)?;
            CatalogSourceSweep::Retired(id)
        };
        let written = transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![CURSOR, CURSOR_KEY, id],
        )?;
        if written != 1 {
            return Err(DatabaseError::Conflict.into());
        }
        transaction.commit()?;
        Ok(outcome)
    }
}

fn read_source(
    connection: &Connection,
    id: [u8; 32],
) -> Result<Option<CatalogSectorSource>, CatalogStoreError> {
    let Some(pin_bytes) = bounded_record(connection, PIN, &id, RECORD_BYTES)? else {
        return Ok(None);
    };
    let pin: SourcePin = decode_canonical(&pin_bytes)?;
    if pin.format_version != 1
        || canonical_bytes(&pin)? != pin_bytes
        || !pin.intent.section.is_private()
    {
        return Err(DatabaseError::Integrity.into());
    }
    pin.page.validate()?;
    let recipe = bounded_record(connection, SNAPSHOT, &id, CATALOG_SECTOR_RECIPE_BYTES)?
        .ok_or(DatabaseError::Integrity)?;
    let record = read_intent(connection, pin.intent)?;
    if recipe.is_empty()
        || bounded_record(connection, LINK, pin.intent.id.as_bytes(), 32)?.as_deref() != Some(&id)
        || record.state != CatalogIntentState::Published(pin.page)
        || record.owned_pages != 1
        || record.owned_bytes != u64::from(pin.page.encoded_len)
        || bounded_record(connection, &owners(pin.intent), &pin.page.hash, 0)?.as_deref()
            != Some(&[])
        || bounded_record(
            connection,
            &pins(pin.page.hash),
            pin.intent.id.as_bytes(),
            0,
        )?
        .as_deref()
            != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    let retained: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = 'local-sector' AND record_id = ?1 AND bytes = ?2)",
        params![id, recipe], |row| row.get(0),
    )?;
    Ok(retained.then_some(CatalogSectorSource {
        intent: pin.intent,
        page: pin.page,
        recipe,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{CATALOG_LEAF_BYTES, CatalogBuilder, NodeId};

    fn operation(id: u8) -> CatalogIntent {
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

    fn stage(store: &ControlStore, intent: CatalogIntent, bytes: &[u8]) -> CatalogPageRef {
        store.begin_catalog(intent).unwrap();
        let mut sink = |page, encoded: Vec<u8>| store.stage_catalog_page(intent, page, &encoded);
        let mut builder = CatalogBuilder::new(intent.scope, intent.section).unwrap();
        builder.push(bytes, &mut sink).unwrap();
        builder.finish(&mut sink).unwrap()
    }

    #[test]
    fn catalog_source_repair_restores_corrupt_and_missing_payload_across_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[6; 32]).unwrap();
        let source = operation(7);
        let page = stage(&store, source, b"private paths");
        let encoded = store
            .catalog_page(source.scope, source.section, page)
            .unwrap();
        let id = [8; 32];
        let recipe = b"bounded source recipe";
        store
            .publish_catalog_sector_recipe(source, page, id, recipe)
            .unwrap();
        for missing in [false, true] {
            if missing {
                store.delete_record(PAGE, &page.hash).unwrap();
            } else {
                store
                    .put_record(PAGE, &page.hash, &vec![9; CATALOG_PAGE_BYTES * 2])
                    .unwrap();
            }
            assert!(
                store
                    .catalog_page(source.scope, source.section, page)
                    .is_err()
            );
            let descriptor = store.catalog_sector_source(id).unwrap().unwrap();
            assert_eq!(
                descriptor,
                CatalogSectorSource {
                    intent: source,
                    page,
                    recipe: recipe.to_vec()
                }
            );
            store
                .repair_catalog_sector_page(id, recipe, &encoded)
                .unwrap();
            assert_eq!(
                store
                    .catalog_page(source.scope, source.section, page)
                    .unwrap(),
                encoded
            );
            assert_eq!(
                store.get_record("local-sector", &id).unwrap().unwrap(),
                recipe
            );
            assert_eq!(
                store.sweep_catalog_source_pin().unwrap(),
                CatalogSourceSweep::Retained(id)
            );
        }
        drop(store);
        let store = ControlStore::open_with_key(&path, &[6; 32]).unwrap();
        assert_eq!(
            store
                .catalog_page(source.scope, source.section, page)
                .unwrap(),
            encoded
        );
        assert!(store.cancel_catalog(source).is_err());
        assert!(!store.collect_catalog_page().unwrap());
    }

    #[test]
    fn catalog_source_repair_fences_recipe_changes_ignored_sql_and_retired_sources() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[5; 32]).unwrap();
        let source = operation(8);
        let page = stage(&store, source, b"private paths");
        let encoded = store
            .catalog_page(source.scope, source.section, page)
            .unwrap();
        let id = [9; 32];
        let recipe = b"bounded source recipe";
        store
            .publish_catalog_sector_recipe(source, page, id, recipe)
            .unwrap();
        let damaged = vec![0; encoded.len()];
        store.put_record(PAGE, &page.hash, &damaged).unwrap();
        assert!(
            store
                .repair_catalog_sector_page(id, b"another recipe", &encoded)
                .is_err()
        );
        assert!(
            store
                .repair_catalog_sector_page(id, recipe, &damaged)
                .is_err()
        );
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER ignore_page_repair BEFORE UPDATE ON protocol_records
             WHEN NEW.kind = 'catalog-page-v1' BEGIN SELECT RAISE(IGNORE); END;",
            )
            .unwrap();
        assert!(
            store
                .repair_catalog_sector_page(id, recipe, &encoded)
                .is_err()
        );
        assert_eq!(
            store.get_record(PAGE, &page.hash).unwrap().unwrap(),
            damaged
        );
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_page_repair")
            .unwrap();
        // Simulate a writer replacing the recipe after the repair descriptor
        // was read. The replacement may be large: equality stays inside SQL.
        store
            .put_record("local-sector", &id, &vec![1; CATALOG_PAGE_BYTES])
            .unwrap();
        assert!(store.catalog_sector_source(id).unwrap().is_none());
        assert!(
            store
                .repair_catalog_sector_page(id, recipe, &encoded)
                .is_err()
        );
        assert_eq!(
            store.get_record(PAGE, &page.hash).unwrap().unwrap(),
            damaged
        );
        store.put_record("local-sector", &id, recipe).unwrap();
        drop(store);
        let store = ControlStore::open_with_key(&path, &[5; 32]).unwrap();
        store
            .repair_catalog_sector_page(id, recipe, &encoded)
            .unwrap();
        store.delete_record("local-sector", &id).unwrap();
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retired(id)
        );
        while store.collect_catalog_page().unwrap() {}
        assert!(
            store
                .repair_catalog_sector_page(id, recipe, &encoded)
                .is_err()
        );
        assert!(store.catalog_sector_source(id).unwrap().is_none());
        assert!(
            store
                .catalog_page(source.scope, source.section, page)
                .is_err()
        );
        assert!(store.begin_catalog(source).is_err());
    }

    #[test]
    fn catalog_source_pin_preserves_page_closure_through_owner_cancellation_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let original = operation(1);
        let root = stage(&store, original, &vec![9; CATALOG_LEAF_BYTES * 2 + 1]);
        store.publish_catalog(original, root).unwrap();
        let page = store
            .catalog_page(original.scope, original.section, root)
            .unwrap();
        let source = operation(2);
        store.begin_catalog(source).unwrap();
        store.stage_catalog_page(source, root, &page).unwrap();
        store
            .publish_catalog_sector_recipe(source, root, [4; 32], b"bounded source recipe")
            .unwrap();
        store
            .publish_catalog_sector_recipe(source, root, [4; 32], b"bounded source recipe")
            .unwrap();
        assert!(store.cancel_catalog(source).is_err());
        assert!(
            store
                .publish_catalog_bundle(&CatalogBundle {
                    id: Uuid::from_bytes([8; 16]),
                    scope: source.scope,
                    roots: vec![CatalogBundleRoot {
                        intent: source,
                        root
                    }],
                    descriptor: vec![1]
                })
                .is_err()
        );
        store.cancel_catalog(original).unwrap();
        while store.release_catalog_pin(original).unwrap() {}
        while store.collect_catalog_page().unwrap() {}
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retained([4; 32])
        );
        let mut reader = mb_core::CatalogReader::new(source.scope, source.section, root).unwrap();
        let mut decoded = vec![];
        while let Some(leaf) = reader
            .next_leaf(&mut |reference| store.catalog_page(source.scope, source.section, reference))
            .unwrap()
        {
            decoded.extend(leaf);
        }
        assert_eq!(decoded, vec![9; CATALOG_LEAF_BYTES * 2 + 1]);
        store.delete_record("local-sector", &[4; 32]).unwrap();
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retired([4; 32])
        );
        assert_eq!(
            store.catalog_intent_state(source).unwrap(),
            CatalogIntentState::Cancelled
        );
        assert!(store.begin_catalog(source).is_err());
        assert!(
            store
                .publish_catalog_sector_recipe(source, root, [4; 32], b"bounded source recipe")
                .is_err()
        );
        drop(store);
        let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
        while store.collect_catalog_page().unwrap() {}
        assert!(
            store
                .catalog_page(source.scope, source.section, root)
                .is_err()
        );
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Idle
        );
    }

    #[test]
    fn catalog_source_pin_cursor_retires_only_one_deleted_or_replaced_recipe_per_step() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let mut sources = vec![];
        for id in 1..=3 {
            let intent = operation(id);
            let page = stage(&store, intent, b"shared page");
            store
                .publish_catalog_sector_recipe(intent, page, [id; 32], &[id])
                .unwrap();
            sources.push((intent, page));
        }
        store.delete_record("local-sector", &[2; 32]).unwrap();
        // A large replacement Inline recipe is compared by SQLite; it is never
        // materialized by the bounded pin sweeper.
        store
            .put_record("local-sector", &[3; 32], &vec![8; 64 * 1024])
            .unwrap();
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retained([1; 32])
        );
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retired([2; 32])
        );
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retired([3; 32])
        );
        assert_eq!(
            store.sweep_catalog_source_pin().unwrap(),
            CatalogSourceSweep::Retained([1; 32])
        );
        while store.collect_catalog_page().unwrap() {}
        assert!(
            store
                .catalog_page(sources[0].0.scope, sources[0].0.section, sources[0].1)
                .is_ok()
        );
        assert_eq!(
            store
                .get_record("local-sector", &[3; 32])
                .unwrap()
                .unwrap()
                .len(),
            64 * 1024
        );
    }

    #[test]
    fn catalog_source_pin_sql_faults_roll_back_publication_and_retirement() {
        let temp = tempfile::tempdir().unwrap();
        for (index, predicate) in [
            "NEW.kind = 'local-sector'",
            "NEW.kind = 'catalog-source-recipe-v1'",
            "NEW.kind = 'catalog-source-intent-link-v1'",
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp.path().join(format!("control-{index}.db"));
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let intent = operation(1);
            let page = stage(&store, intent, b"protected source page");
            store.connection.execute_batch(&format!("CREATE TRIGGER source_fault BEFORE INSERT ON protocol_records WHEN {predicate} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                store
                    .publish_catalog_sector_recipe(intent, page, [1; 32], b"recipe")
                    .is_err()
            );
            assert_eq!(
                store.catalog_intent_state(intent).unwrap(),
                CatalogIntentState::Building
            );
            for kind in [PIN, SNAPSHOT, LINK, "local-sector"] {
                assert!(store.records(kind).unwrap().is_empty());
            }
            store
                .connection
                .execute_batch("DROP TRIGGER source_fault")
                .unwrap();
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            store
                .publish_catalog_sector_recipe(intent, page, [1; 32], b"recipe")
                .unwrap();
            store.delete_record("local-sector", &[1; 32]).unwrap();
            store.connection.execute_batch("CREATE TRIGGER source_fault BEFORE DELETE ON protocol_records WHEN OLD.kind LIKE 'catalog-page-pin-v1/%' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
            assert!(store.sweep_catalog_source_pin().is_err());
            assert_eq!(
                store.catalog_intent_state(intent).unwrap(),
                CatalogIntentState::Published(page)
            );
            assert!(store.get_record(PIN, &[1; 32]).unwrap().is_some());
            assert!(
                store
                    .catalog_page(intent.scope, intent.section, page)
                    .is_ok()
            );
            store
                .connection
                .execute_batch("DROP TRIGGER source_fault")
                .unwrap();
            drop(store);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                store.sweep_catalog_source_pin().unwrap(),
                CatalogSourceSweep::Retired([1; 32])
            );
            assert!(store.collect_catalog_page().unwrap());
        }
    }
}

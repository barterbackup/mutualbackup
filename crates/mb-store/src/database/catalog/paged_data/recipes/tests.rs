use super::*;

fn fixture(store: &ControlStore) -> (CatalogBundle, Vec<u8>, CatalogSectorRecord) {
    let (bundle, bytes) = paged_revision::tests::fixture(store, 1, None);
    let signed = PagedUserRevision::decode_signed(&bundle.descriptor).unwrap();
    let mut reader = mb_core::CatalogSectorReader::new(bundle.scope, signed.value.sources).unwrap();
    let mut source = None;
    while let Some(record) = reader
        .next_sector(&mut |page| {
            store.catalog_page(bundle.scope, CatalogSection::SectorReferences, page)
        })
        .unwrap()
    {
        if record.sector.id != signed.value.metadata.sector.id {
            source = Some(record)
        }
    }
    (bundle, bytes, source.unwrap())
}

fn publish(
    store: &ControlStore,
    bundle: &CatalogBundle,
    bytes: &[u8],
    source: &CatalogSectorRecord,
    anchor: Uuid,
    recipe: &[u8],
) -> Result<(), CatalogStoreError> {
    store.publish_paged_revision_catalog_checked(bundle, bytes, |view| {
        view.bind_data_source(source, anchor, recipe)
    })
}

fn source(
    store: &ControlStore,
    bundle: &CatalogBundle,
    source: &CatalogSectorRecord,
) -> PagedCatalogDataSource {
    store
        .paged_revision_data_source(bundle.id, source.sector.id)
        .unwrap()
        .unwrap()
}

fn record(
    store: &ControlStore,
    bundle: &CatalogBundle,
    source: &CatalogSectorRecord,
) -> SharedDataSourceRecord {
    let bytes = store
        .get_record(&sources(bundle.id), &source.sector.id)
        .unwrap()
        .unwrap();
    assert!(bytes.len() <= PAGED_DATA_SHARED_BINDING_BYTES);
    shared_record(&bytes).unwrap().unwrap()
}

#[test]
fn shared_data_recipes_bound_retained_history_and_survive_last_owner_cleanup_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let recipe = vec![91; PAGED_DATA_RECIPE_BYTES];
    let anchor = Uuid::new_v4();
    let mut bundles = Vec::new();
    let mut identity = None;
    for _ in 0..32 {
        let (bundle, bytes, reference) = fixture(&store);
        publish(&store, &bundle, &bytes, &reference, anchor, &recipe).unwrap();
        assert_eq!(source(&store, &bundle, &reference).recipe, recipe);
        assert_eq!(source(&store, &bundle, &reference).generation, 0);
        let binding = record(&store, &bundle, &reference);
        assert_eq!(*identity.get_or_insert(binding.recipe), binding.recipe);
        bundles.push((bundle, bytes, reference));
    }
    let key = identity.unwrap();
    assert_eq!(store.records(RECIPE).unwrap().len(), 1);
    let encoded = store.get_record(RECIPE, &key).unwrap().unwrap();
    assert!(encoded.len() <= RECORD_LIMIT);
    assert_eq!(
        load(&store.connection, key).unwrap().unwrap().references,
        32
    );
    assert_eq!(anchor_count(&store.connection, anchor).unwrap(), Some(32));
    let dense_sources = (1_u64 << 40) / mb_core::V1_SECTOR_SIZE as u64;
    assert_eq!(
        dense_sources * 32 * PAGED_DATA_RECIPE_BYTES as u64,
        4_u64 << 40
    );
    let shared_values = dense_sources * RECORD_LIMIT as u64
        + dense_sources * 32 * PAGED_DATA_SHARED_BINDING_BYTES as u64;
    assert!(shared_values < 512_u64 << 30);
    // This is encoded-value arithmetic, not SQL/WAL or dense-data qualification.
    for (bundle, _, reference) in &bundles[..31] {
        store.cancel_paged_revision_catalog(bundle.id).unwrap();
        assert!(store.release_paged_revision_data_source(bundle.id).unwrap());
        assert!(
            store
                .paged_revision_data_source(bundle.id, reference.sector.id)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(load(&store.connection, key).unwrap().unwrap().references, 1);
    drop(store);
    let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    let (last, bytes, reference) = &bundles[31];
    assert_eq!(source(&store, last, reference).recipe, recipe);
    publish(&store, last, bytes, reference, anchor, &recipe).unwrap();
    assert_eq!(load(&store.connection, key).unwrap().unwrap().references, 1);
    store.cancel_paged_revision_catalog(last.id).unwrap();
    assert!(store.release_paged_revision_data_source(last.id).unwrap());
    assert!(store.records(RECIPE).unwrap().is_empty());
    assert!(store.records(&owners(key)).unwrap().is_empty());
    assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
}

#[test]
fn shared_data_recipes_keep_repair_generations_and_physical_pins_independent() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let mut items = Vec::new();
    for _ in 0..3 {
        let (bundle, bytes, reference) = fixture(&store);
        publish(&store, &bundle, &bytes, &reference, a, b"original").unwrap();
        items.push(source(&store, &bundle, &reference));
    }
    let original = items[0].clone();
    let moved = store
        .replace_paged_revision_data_source_checked(&original, b, b"replacement", |_| {
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
    assert_eq!(moved.generation, 1);
    assert_eq!(
        store
            .paged_revision_data_source(items[1].catalog.bundle.id, items[1].source.sector.id)
            .unwrap(),
        Some(items[1].clone())
    );
    assert_eq!(anchor_count(&store.connection, a).unwrap(), Some(2));
    assert_eq!(anchor_count(&store.connection, b).unwrap(), Some(1));
    let joined = store
        .replace_paged_revision_data_source_checked(&items[2], b, b"replacement", |_| {
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
    assert_eq!(joined.generation, 1);
    assert_eq!(store.records(RECIPE).unwrap().len(), 2);
    assert!(
        store
            .replace_paged_revision_data_source_checked(&original, a, b"stale", |_| Ok::<
                _,
                CatalogStoreError,
            >(
                ()
            ))
            .is_err()
    );
    assert_eq!(
        store
            .replace_paged_revision_data_source_checked(&original, b, b"replacement", |_| Ok::<
                _,
                CatalogStoreError,
            >(
                ()
            ))
            .unwrap(),
        moved
    );
    assert_eq!(anchor_count(&store.connection, a).unwrap(), Some(1));
    assert_eq!(anchor_count(&store.connection, b).unwrap(), Some(2));
    for item in [items[1].clone(), moved, joined] {
        store
            .cancel_paged_revision_catalog(item.catalog.bundle.id)
            .unwrap();
        assert!(
            store
                .release_paged_revision_data_source(item.catalog.bundle.id)
                .unwrap()
        );
    }
    assert!(store.records(RECIPE).unwrap().is_empty());
    assert!(store.paged_data_anchor_ids().unwrap().is_empty());
}

#[test]
fn shared_data_recipes_reject_sql_faults_without_partial_publication_or_cleanup() {
    for statement in [
        "CREATE TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-paged-data-recipe-v1' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind GLOB 'catalog-paged-data-recipe-owner-v1/*' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind GLOB 'catalog-paged-data-source-v1/*' BEGIN SELECT RAISE(IGNORE); END",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let (bundle, bytes, reference) = fixture(&store);
        let anchor = Uuid::new_v4();
        store.connection.execute_batch(statement).unwrap();
        assert!(publish(&store, &bundle, &bytes, &reference, anchor, b"source").is_err());
        assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
        assert!(store.records(RECIPE).unwrap().is_empty());
        assert!(store.paged_data_anchor_ids().unwrap().is_empty());
        let count: u64 = store.connection.query_row("SELECT count(*) FROM protocol_records WHERE kind GLOB 'catalog-paged-data-recipe-owner-v1/*'", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (first, bytes, reference) = fixture(&store);
    let anchor = Uuid::new_v4();
    publish(&store, &first, &bytes, &reference, anchor, b"source").unwrap();
    let binding = record(&store, &first, &reference);
    for statement in [
        "CREATE TRIGGER fault BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-paged-data-recipe-v1' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER fault AFTER UPDATE ON protocol_records WHEN NEW.kind = 'catalog-paged-data-recipe-v1' BEGIN UPDATE protocol_records SET bytes = OLD.bytes WHERE kind = NEW.kind AND record_id = NEW.record_id; END",
    ] {
        let (next, bytes, _) = fixture(&store);
        store.connection.execute_batch(statement).unwrap();
        assert!(publish(&store, &next, &bytes, &reference, anchor, b"source").is_err());
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
        assert!(store.catalog_bundle(next.id).unwrap().is_none());
        assert_eq!(
            load(&store.connection, binding.recipe)
                .unwrap()
                .unwrap()
                .references,
            1
        );
        assert_eq!(anchor_count(&store.connection, anchor).unwrap(), Some(1));
    }
    store.cancel_paged_revision_catalog(first.id).unwrap();
    for predicate in [
        "OLD.kind = 'catalog-paged-data-recipe-v1'",
        "OLD.kind GLOB 'catalog-paged-data-recipe-owner-v1/*'",
    ] {
        store.connection.execute_batch(&format!("CREATE TRIGGER fault BEFORE DELETE ON protocol_records WHEN {predicate} BEGIN SELECT RAISE(IGNORE); END")).unwrap();
        assert!(store.release_paged_revision_data_source(first.id).is_err());
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
        assert!(
            store
                .get_record(&sources(first.id), &reference.sector.id)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            load(&store.connection, binding.recipe)
                .unwrap()
                .unwrap()
                .references,
            1
        );
        assert_eq!(anchor_count(&store.connection, anchor).unwrap(), Some(1));
    }
    assert!(store.release_paged_revision_data_source(first.id).unwrap());
}

#[test]
fn shared_data_recipes_preserve_legacy_bytes_and_reject_corrupt_and_missing_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bytes, reference) = fixture(&store);
    let anchor = Uuid::new_v4();
    publish(&store, &bundle, &bytes, &reference, anchor, b"source").unwrap();
    let binding = record(&store, &bundle, &reference);
    let original = source(&store, &bundle, &reference);
    let recipe = load(&store.connection, binding.recipe).unwrap().unwrap();
    let saved = store.get_record(RECIPE, &binding.recipe).unwrap().unwrap();
    for changed in [
        Recipe {
            references: 0,
            ..recipe.clone()
        },
        Recipe {
            references: 2,
            ..recipe.clone()
        },
        Recipe {
            bytes: vec![0; PAGED_DATA_RECIPE_BYTES + 1],
            ..recipe.clone()
        },
    ] {
        store
            .put_record(RECIPE, &binding.recipe, &canonical_bytes(&changed).unwrap())
            .unwrap();
        assert!(
            store
                .paged_revision_data_source(bundle.id, reference.sector.id)
                .is_err()
        );
        assert!(publish(&store, &bundle, &bytes, &reference, anchor, b"source").is_err());
        store.put_record(RECIPE, &binding.recipe, &saved).unwrap();
    }
    store.delete_record(RECIPE, &binding.recipe).unwrap();
    assert!(
        store
            .paged_revision_data_source(bundle.id, reference.sector.id)
            .is_err()
    );
    store.put_record(RECIPE, &binding.recipe, &saved).unwrap();
    let row = store
        .get_record(&sources(bundle.id), &reference.sector.id)
        .unwrap()
        .unwrap();
    let missing = SharedDataSourceRecord {
        recipe: [0; 32],
        ..binding.clone()
    };
    store
        .put_record(
            &sources(bundle.id),
            &reference.sector.id,
            &canonical_bytes(&missing).unwrap(),
        )
        .unwrap();
    assert!(
        store
            .paged_revision_data_source(bundle.id, reference.sector.id)
            .is_err()
    );
    store
        .put_record(&sources(bundle.id), &reference.sector.id, &row)
        .unwrap();
    make_inline_for_test(&store, &original);
    let legacy = canonical_bytes(&(1_u16, &reference, anchor, b"source".to_vec())).unwrap();
    store
        .put_record(&sources(bundle.id), &reference.sector.id, &legacy)
        .unwrap();
    assert_eq!(source(&store, &bundle, &reference), original);
    publish(&store, &bundle, &bytes, &reference, anchor, b"source").unwrap();
    assert_eq!(
        store
            .get_record(&sources(bundle.id), &reference.sector.id)
            .unwrap(),
        Some(legacy)
    );
    assert!(store.records(RECIPE).unwrap().is_empty());
    // An enormous vector declaration with no bytes must reject before allocating.
    let mut malformed =
        canonical_bytes(&(1_u16, recipe.scope, &recipe.source, recipe.anchor)).unwrap();
    malformed.extend_from_slice(&[255, 255, 255, 255, 255, 255, 255, 255, 255, 1]);
    assert!(
        std::panic::catch_unwind(|| decode_canonical::<Recipe>(&malformed))
            .unwrap()
            .is_err()
    );
}

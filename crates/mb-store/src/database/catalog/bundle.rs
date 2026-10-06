//! Atomic local publication/cancellation of bounded multi-stream descriptors.
//! This journal supplies durable ownership, not signed protocol authority.

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::*;

const BUNDLE: &str = "catalog-bundle-v1";
pub(super) const LINK: &str = "catalog-intent-bundle-v1";
const BUNDLE_RECORD_BYTES: usize = 8 * 1024;
pub const CATALOG_BUNDLE_ROOTS: usize = 16;
pub const CATALOG_BUNDLE_DESCRIPTOR_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogBundleRoot {
    pub intent: CatalogIntent,
    pub root: CatalogPageRef,
}

/// Each root has its own existing intent and retains its immutable closure.
/// The caller must verify that its typed descriptor references precisely these
/// roots. SQLCipher protects the local bytes; protocol signing remains external.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogBundle {
    pub id: Uuid,
    pub scope: CatalogScope,
    #[serde(deserialize_with = "decode_roots")]
    pub roots: Vec<CatalogBundleRoot>,
    #[serde(deserialize_with = "decode_descriptor")]
    pub descriptor: Vec<u8>,
}

impl CatalogBundle {
    pub fn validate(&self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil()
            || self.roots.is_empty()
            || self.roots.len() > CATALOG_BUNDLE_ROOTS
            || self.descriptor.is_empty()
            || self.descriptor.len() > CATALOG_BUNDLE_DESCRIPTOR_BYTES
        {
            return Err(DatabaseError::Integrity.into());
        }
        for (index, member) in self.roots.iter().enumerate() {
            member.intent.scope.validate(member.intent.section)?;
            member.root.validate()?;
            if member.intent.id.is_nil()
                || member.intent.scope != self.scope
                || self.roots[..index]
                    .iter()
                    .any(|previous| previous.intent.id == member.intent.id)
            {
                return Err(DatabaseError::Conflict.into());
            }
        }
        Ok(())
    }
}

fn decode_bounded<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
    limit: usize,
) -> Result<Vec<T>, D::Error> {
    struct Bounded<T>(usize, std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {} bundle elements", self.0)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > self.0) {
                return Err(serde::de::Error::custom(
                    "oversized catalog bundle collection",
                ));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.0));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.0 {
                    return Err(serde::de::Error::custom(
                        "oversized catalog bundle collection",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    decoder.deserialize_seq(Bounded(limit, std::marker::PhantomData))
}
fn decode_roots<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<CatalogBundleRoot>, D::Error> {
    decode_bounded(decoder, CATALOG_BUNDLE_ROOTS)
}
fn decode_descriptor<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decode_bounded(decoder, CATALOG_BUNDLE_DESCRIPTOR_BYTES)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogBundleState {
    Published,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BundleRecord {
    format_version: u16,
    bundle: CatalogBundle,
    state: CatalogBundleState,
}

fn read_bundle(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<BundleRecord>, CatalogStoreError> {
    if id.is_nil() {
        return Err(DatabaseError::Conflict.into());
    }
    let Some(bytes) = bounded_record(connection, BUNDLE, id.as_bytes(), BUNDLE_RECORD_BYTES)?
    else {
        return Ok(None);
    };
    let record: BundleRecord = decode_canonical(&bytes)?;
    record.bundle.validate()?;
    if record.format_version != 1 || record.bundle.id != id || canonical_bytes(&record)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

fn require_link(
    connection: &Connection,
    intent: CatalogIntent,
    bundle_id: Uuid,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, LINK, intent.id.as_bytes(), 16)?.as_deref()
        != Some(bundle_id.as_bytes())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn require_unbundled(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    super::source::require_unlinked_source(connection, intent)?;
    if bounded_record(connection, LINK, intent.id.as_bytes(), 16)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

pub(super) fn publish_bundle(
    connection: &Connection,
    bundle: &CatalogBundle,
) -> Result<(), CatalogStoreError> {
    bundle.validate()?;
    let existing = read_bundle(connection, bundle.id)?;
    if existing.as_ref().is_some_and(|record| {
        record.state != CatalogBundleState::Published || record.bundle != *bundle
    }) {
        return Err(DatabaseError::Conflict.into());
    }
    for member in &bundle.roots {
        super::source::require_unlinked_source(connection, member.intent)?;
        if existing.is_some() {
            require_link(connection, member.intent, bundle.id)?;
        } else if bounded_record(connection, LINK, member.intent.id.as_bytes(), 16)?.is_some() {
            return Err(DatabaseError::Conflict.into());
        }
        publish_root(connection, member.intent, member.root)?;
        insert_exact(
            connection,
            LINK,
            member.intent.id.as_bytes(),
            bundle.id.as_bytes(),
        )?;
    }
    let record = BundleRecord {
        format_version: 1,
        bundle: bundle.clone(),
        state: CatalogBundleState::Published,
    };
    let bytes = canonical_bytes(&record)?;
    if bytes.len() > BUNDLE_RECORD_BYTES {
        return Err(DatabaseError::Integrity.into());
    }
    insert_exact(connection, BUNDLE, bundle.id.as_bytes(), &bytes)?;
    Ok(())
}

pub(super) fn bundle_snapshot(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<(CatalogBundle, CatalogBundleState)>, CatalogStoreError> {
    let Some(record) = read_bundle(connection, id)? else {
        return Ok(None);
    };
    for member in &record.bundle.roots {
        let intent = read_intent(connection, member.intent)?;
        match record.state {
            CatalogBundleState::Published => {
                require_link(connection, member.intent, id)?;
                if intent.state != CatalogIntentState::Published(member.root) {
                    return Err(DatabaseError::Integrity.into());
                }
            }
            CatalogBundleState::Cancelled if intent.state != CatalogIntentState::Cancelled => {
                return Err(DatabaseError::Integrity.into());
            }
            CatalogBundleState::Cancelled => require_unbundled(connection, member.intent)?,
        }
    }
    Ok(Some((record.bundle, record.state)))
}

pub(super) fn cancel_bundle(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    let mut record = read_bundle(connection, id)?.ok_or(DatabaseError::NotReady)?;
    if record.state == CatalogBundleState::Cancelled {
        return Ok(());
    }
    for member in &record.bundle.roots {
        require_link(connection, member.intent, id)?;
        let mut intent = read_intent(connection, member.intent)?;
        if intent.state != CatalogIntentState::Published(member.root) {
            return Err(DatabaseError::Integrity.into());
        }
        intent.state = CatalogIntentState::Cancelled;
        write_intent(connection, &intent)?;
        let removed = connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![LINK, member.intent.id.as_bytes(), id.as_bytes()],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict.into());
        }
    }
    record.state = CatalogBundleState::Cancelled;
    let written = connection.execute(
        "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
        params![BUNDLE, id.as_bytes(), canonical_bytes(&record)?],
    )?;
    if written != 1 {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

impl ControlStore {
    /// Publish all root pins and the immutable descriptor in one writer
    /// transaction. Retries must match every byte; cancelled IDs never resume.
    pub fn publish_catalog_bundle(&self, bundle: &CatalogBundle) -> Result<(), CatalogStoreError> {
        bundle.validate()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        publish_bundle(&transaction, bundle)?;
        transaction.commit()?;
        Ok(())
    }

    /// Read a consistent local publication snapshot. Page corruption discovered
    /// later by traversal still blocks the affected operation; this is not a
    /// bit-rot certificate or a remote protection claim.
    pub fn catalog_bundle(
        &self,
        id: Uuid,
    ) -> Result<Option<(CatalogBundle, CatalogBundleState)>, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let snapshot = bundle_snapshot(&transaction, id)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Fence every member before bounded pin/page cleanup can start. Individual
    /// cancellation of a published member is rejected while its link exists.
    pub fn cancel_catalog_bundle(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        super::native_validation::require_unpublished_validation(&transaction, id)?;
        cancel_bundle(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{CATALOG_LEAF_BYTES, CatalogBuilder, CatalogReader, KeyMaterial, NodeId, Seed};

    type Pages = Vec<(CatalogPageRef, Vec<u8>)>;
    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }
    fn intent(id: u8) -> CatalogIntent {
        CatalogIntent {
            id: Uuid::from_bytes([id; 16]),
            scope: scope(),
            section: CatalogSection::GitGraph,
        }
    }
    fn graph(marker: u8) -> (Vec<u8>, CatalogPageRef, Pages) {
        let bytes = vec![marker; CATALOG_LEAF_BYTES * 2 + 17];
        let mut pages = Vec::new();
        let mut sink = |reference, encoded| {
            pages.push((reference, encoded));
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        builder.push(&bytes, &mut sink).unwrap();
        (bytes, builder.finish(&mut sink).unwrap(), pages)
    }
    fn stage(store: &ControlStore, id: u8) -> (CatalogBundle, Vec<Pages>) {
        let mut bundle = CatalogBundle {
            id: Uuid::from_bytes([id; 16]),
            scope: scope(),
            roots: Vec::new(),
            descriptor: b"opaque caller-validated descriptor".to_vec(),
        };
        let mut graphs = Vec::new();
        for index in 0..3 {
            let member = intent(id + index + 1);
            let (_, root, pages) = graph(index + 1);
            store.begin_catalog(member).unwrap();
            for (reference, encoded) in &pages {
                store
                    .stage_catalog_page(member, *reference, encoded)
                    .unwrap();
            }
            bundle.roots.push(CatalogBundleRoot {
                intent: member,
                root,
            });
            graphs.push(pages);
        }
        (bundle, graphs)
    }
    fn read(store: &ControlStore, member: CatalogBundleRoot) -> Vec<u8> {
        let mut reader =
            CatalogReader::new(member.intent.scope, member.intent.section, member.root).unwrap();
        let mut bytes = Vec::new();
        while let Some(leaf) = reader
            .next_leaf(&mut |reference| {
                store.catalog_page(member.intent.scope, member.intent.section, reference)
            })
            .unwrap()
        {
            bytes.extend(leaf);
        }
        bytes
    }
    fn published(store: &ControlStore, bundle: &CatalogBundle) {
        assert_eq!(
            store.catalog_bundle(bundle.id).unwrap(),
            Some((bundle.clone(), CatalogBundleState::Published))
        );
        for member in &bundle.roots {
            assert_eq!(
                store.catalog_intent_state(member.intent).unwrap(),
                CatalogIntentState::Published(member.root)
            );
        }
    }
    fn building(store: &ControlStore, bundle: &CatalogBundle) {
        assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
        for member in &bundle.roots {
            assert_eq!(
                store.catalog_intent_state(member.intent).unwrap(),
                CatalogIntentState::Building
            );
            assert!(
                bounded_record(&store.connection, LINK, member.intent.id.as_bytes(), 16)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn catalog_bundle_reopens_publication_pin_release_cancellation_and_each_gc_step() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([101; 32]));
        let path = directory.path().join("control.db");
        let mut store = ControlStore::open(&path, &keys).unwrap();
        let (bundle, graphs) = stage(&store, 10);
        drop(store);
        store = ControlStore::open(&path, &keys).unwrap();
        building(&store, &bundle);
        store.publish_catalog_bundle(&bundle).unwrap();
        drop(store);
        store = ControlStore::open(&path, &keys).unwrap();
        published(&store, &bundle);
        store.publish_catalog_bundle(&bundle).unwrap();
        for (index, member) in bundle.roots.iter().enumerate() {
            assert!(store.cancel_catalog(member.intent).is_err());
            assert_eq!(read(&store, *member), graph(index as u8 + 1).0);
            while store.release_catalog_pin(member.intent).unwrap() {
                drop(store);
                store = ControlStore::open(&path, &keys).unwrap();
                published(&store, &bundle);
                assert!(!store.collect_catalog_page().unwrap());
            }
        }
        store.cancel_catalog_bundle(bundle.id).unwrap();
        drop(store);
        store = ControlStore::open(&path, &keys).unwrap();
        store.cancel_catalog_bundle(bundle.id).unwrap();
        assert_eq!(
            store.catalog_bundle(bundle.id).unwrap(),
            Some((bundle.clone(), CatalogBundleState::Cancelled))
        );
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        for (index, member) in bundle.roots.iter().enumerate() {
            assert_eq!(
                store.catalog_intent_state(member.intent).unwrap(),
                CatalogIntentState::Cancelled
            );
            assert!(store.publish_catalog(member.intent, member.root).is_err());
            let (_, encoded) = graphs[index].last().unwrap();
            assert!(
                store
                    .stage_catalog_page(member.intent, member.root, encoded)
                    .is_err()
            );
            while store.release_catalog_pin(member.intent).unwrap() {
                drop(store);
                store = ControlStore::open(&path, &keys).unwrap();
            }
        }
        let mut collected = 0;
        while store.collect_catalog_page().unwrap() {
            collected += 1;
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
            assert_eq!(
                store.catalog_bundle(bundle.id).unwrap().unwrap().1,
                CatalogBundleState::Cancelled
            );
        }
        assert_eq!(collected, 9); // Three unique pages per repeated-leaf tree.
        assert!(store.records(PAGE).unwrap().is_empty());
    }

    #[test]
    fn catalog_bundle_pending_and_published_successors_retain_shared_stream_closures() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([102; 32]));
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys).unwrap();
        let (first, graphs) = stage(&store, 20);
        store.publish_catalog_bundle(&first).unwrap();
        let mut successor = CatalogBundle {
            id: Uuid::from_bytes([30; 16]),
            scope: scope(),
            roots: Vec::new(),
            descriptor: b"successor descriptor".to_vec(),
        };
        for (index, member) in first.roots.iter().enumerate() {
            let next = intent(31 + index as u8);
            store.begin_catalog(next).unwrap();
            store
                .stage_catalog_page(next, member.root, &graphs[index].last().unwrap().1)
                .unwrap();
            successor.roots.push(CatalogBundleRoot {
                intent: next,
                root: member.root,
            });
            while store.release_catalog_pin(member.intent).unwrap() {}
        }
        store.cancel_catalog_bundle(first.id).unwrap();
        for member in &first.roots {
            while store.release_catalog_pin(member.intent).unwrap() {}
        }
        assert!(!store.collect_catalog_page().unwrap());
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        building(&store, &successor);
        for (index, member) in successor.roots.iter().enumerate() {
            assert_eq!(read(&store, *member), graph(index as u8 + 1).0);
        }
        store.publish_catalog_bundle(&successor).unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        published(&store, &successor);
        let mut conflict = successor.clone();
        conflict.id = Uuid::from_bytes([40; 16]);
        assert!(store.publish_catalog_bundle(&conflict).is_err());
        assert!(store.catalog_bundle(conflict.id).unwrap().is_none());
        let mut conflict = successor.clone();
        conflict.descriptor.push(0);
        assert!(store.publish_catalog_bundle(&conflict).is_err());
        published(&store, &successor);
        store.cancel_catalog_bundle(successor.id).unwrap();
        for member in &successor.roots {
            while store.release_catalog_pin(member.intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        assert!(store.records(PAGE).unwrap().is_empty());
    }

    #[test]
    fn catalog_bundle_sql_abort_and_ignored_writes_roll_back_every_member_transition() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([103; 32]));
        let path = directory.path().join("control.db");
        let mut store = ControlStore::open(&path, &keys).unwrap();
        let (bundle, _) = stage(&store, 50);
        let second_id = hex::encode(bundle.roots[1].intent.id.as_bytes());
        for statement in [
            format!(
                "CREATE TEMP TRIGGER fail BEFORE UPDATE OF bytes ON protocol_records WHEN OLD.kind = '{INTENT}' AND OLD.record_id = x'{second_id}' BEGIN SELECT RAISE(ABORT, 'injected'); END"
            ),
            format!(
                "CREATE TEMP TRIGGER fail BEFORE UPDATE OF bytes ON protocol_records WHEN OLD.kind = '{INTENT}' AND OLD.record_id = x'{second_id}' BEGIN SELECT RAISE(IGNORE); END"
            ),
            format!(
                "CREATE TEMP TRIGGER fail BEFORE INSERT ON protocol_records WHEN NEW.kind = '{BUNDLE}' BEGIN SELECT RAISE(ABORT, 'injected'); END"
            ),
        ] {
            store.connection.execute_batch(&statement).unwrap();
            assert!(store.publish_catalog_bundle(&bundle).is_err());
            building(&store, &bundle);
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
            building(&store, &bundle);
        }
        store.publish_catalog_bundle(&bundle).unwrap();
        for statement in [
            format!(
                "CREATE TEMP TRIGGER fail BEFORE UPDATE OF bytes ON protocol_records WHEN OLD.kind = '{INTENT}' AND OLD.record_id = x'{second_id}' BEGIN SELECT RAISE(IGNORE); END"
            ),
            format!(
                "CREATE TEMP TRIGGER fail BEFORE DELETE ON protocol_records WHEN OLD.kind = '{LINK}' BEGIN SELECT RAISE(IGNORE); END"
            ),
            format!(
                "CREATE TEMP TRIGGER fail BEFORE UPDATE OF bytes ON protocol_records WHEN OLD.kind = '{BUNDLE}' BEGIN SELECT RAISE(IGNORE); END"
            ),
        ] {
            store.connection.execute_batch(&statement).unwrap();
            assert!(store.cancel_catalog_bundle(bundle.id).is_err());
            published(&store, &bundle);
            for member in &bundle.roots {
                assert!(store.cancel_catalog(member.intent).is_err());
            }
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
            published(&store, &bundle);
        }
        store.cancel_catalog_bundle(bundle.id).unwrap();
        assert_eq!(
            store.catalog_bundle(bundle.id).unwrap().unwrap().1,
            CatalogBundleState::Cancelled
        );
    }

    #[test]
    fn catalog_bundle_bounds_scope_missing_roots_and_corruption_fail_closed() {
        struct Declared;
        impl<'de> SeqAccess<'de> for Declared {
            type Error = serde::de::value::Error;
            fn size_hint(&self) -> Option<usize> {
                Some(usize::MAX)
            }
            fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
                &mut self,
                _: T,
            ) -> Result<Option<T::Value>, Self::Error> {
                panic!("oversized declaration must reject before allocating elements")
            }
        }
        assert!(decode_roots(serde::de::value::SeqAccessDeserializer::new(Declared)).is_err());
        assert!(decode_descriptor(serde::de::value::SeqAccessDeserializer::new(Declared)).is_err());
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([104; 32]));
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys).unwrap();
        let (bundle, _) = stage(&store, 60);
        let mut invalid = bundle.clone();
        invalid.roots[2].root.hash = [99; 32];
        assert!(store.publish_catalog_bundle(&invalid).is_err());
        building(&store, &bundle);
        let mut invalid = bundle.clone();
        invalid.roots.push(invalid.roots[0]);
        assert!(invalid.validate().is_err());
        let mut invalid = bundle.clone();
        invalid.roots[0].intent.scope = CatalogScope::Guild { guild_id: [1; 32] };
        assert!(invalid.validate().is_err());
        let mut invalid = bundle.clone();
        invalid
            .descriptor
            .resize(CATALOG_BUNDLE_DESCRIPTOR_BYTES + 1, 0);
        assert!(store.publish_catalog_bundle(&invalid).is_err());
        let mut maximum = bundle.clone();
        maximum
            .descriptor
            .resize(CATALOG_BUNDLE_DESCRIPTOR_BYTES, 0);
        maximum.roots = (0..CATALOG_BUNDLE_ROOTS)
            .map(|index| CatalogBundleRoot {
                intent: intent(100 + index as u8),
                root: bundle.roots[0].root,
            })
            .collect();
        maximum.validate().unwrap();
        assert!(
            canonical_bytes(&BundleRecord {
                format_version: 1,
                bundle: maximum.clone(),
                state: CatalogBundleState::Published
            })
            .unwrap()
            .len()
                <= BUNDLE_RECORD_BYTES
        );
        maximum.roots.push(CatalogBundleRoot {
            intent: intent(120),
            root: bundle.roots[0].root,
        });
        assert!(maximum.validate().is_err());
        store.publish_catalog_bundle(&bundle).unwrap();
        let original = bounded_record(
            &store.connection,
            BUNDLE,
            bundle.id.as_bytes(),
            BUNDLE_RECORD_BYTES,
        )
        .unwrap()
        .unwrap();
        store
            .put_record(
                BUNDLE,
                bundle.id.as_bytes(),
                &vec![0; BUNDLE_RECORD_BYTES + 1],
            )
            .unwrap();
        assert!(store.catalog_bundle(bundle.id).is_err());
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        assert!(store.cancel_catalog_bundle(bundle.id).is_err());
        for member in &bundle.roots {
            assert_eq!(
                store.catalog_intent_state(member.intent).unwrap(),
                CatalogIntentState::Published(member.root)
            );
        }
        store
            .put_record(BUNDLE, bundle.id.as_bytes(), &original)
            .unwrap();
        published(&store, &bundle);
    }
}

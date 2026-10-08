//! Shared bounded root ownership. Policy-specific walkers and activation guards
//! remain with their callers; persisted version-one layouts stay unchanged.

use serde::de::DeserializeOwned;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogRetentionState {
    Building,
    Published,
    Cancelled,
}

pub(super) trait Retention: Copy + Eq + Serialize + DeserializeOwned {
    const JOURNAL: &'static str;
    const JOURNAL_BYTES: usize;
    const DEPENDENCIES: &'static str;
    const PIN_PREFIX: u8;

    fn id(self) -> Uuid;
    fn validate(self) -> Result<(), CatalogStoreError>;
    fn work(self) -> Result<(u64, u64), CatalogStoreError>;
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct JournalRecord<R> {
    pub(super) format_version: u16,
    pub(super) retention: R,
    pub(super) state: CatalogRetentionState,
    pub(super) roots: u64,
    pub(super) bytes: u64,
    pub(super) pages: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Dependency {
    pub(super) scope: CatalogScope,
    pub(super) section: CatalogSection,
    pub(super) root: CatalogPageRef,
}

impl Dependency {
    pub(super) fn validate(self, retention: impl Retention) -> Result<(), CatalogStoreError> {
        self.scope.validate(self.section)?;
        self.root.validate()?;
        if !retention.allows(self.scope, self.section) {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    pub(super) fn page(self) -> PageMetadata {
        PageMetadata {
            format_version: 1,
            scope: self.scope,
            section: self.section,
            reference: self.root,
        }
    }
}

pub(super) fn dependencies<R: Retention>(id: Uuid) -> String {
    format!("{}/{}", R::DEPENDENCIES, id.simple())
}

pub(super) fn pin_id<R: Retention>(id: Uuid) -> [u8; 17] {
    // Capture IDs are 16 bytes; each retention policy has a distinct prefix.
    let mut key = [0; 17];
    key[0] = R::PIN_PREFIX;
    key[1..].copy_from_slice(id.as_bytes());
    key
}

pub(super) fn read<R: Retention>(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<JournalRecord<R>>, CatalogStoreError> {
    if id.is_nil() {
        return Err(DatabaseError::Conflict.into());
    }
    let Some(bytes) = bounded_record(connection, R::JOURNAL, id.as_bytes(), R::JOURNAL_BYTES)?
    else {
        return Ok(None);
    };
    let record: JournalRecord<R> = decode_canonical(&bytes)?;
    record.retention.validate()?;
    let (represented_bytes, pages) = record.retention.work()?;
    if record.format_version != 1
        || record.retention.id() != id
        || record.roots > record.pages
        || record.pages > pages
        || record.bytes > represented_bytes
        || (record.roots == 0) != (record.pages == 0)
        || (record.roots == 0) != (record.bytes == 0)
        || record.state == CatalogRetentionState::Published && record.roots == 0
        || canonical_bytes(&record)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

pub(super) fn require<R: Retention>(
    connection: &Connection,
    retention: R,
) -> Result<JournalRecord<R>, CatalogStoreError> {
    let record = read(connection, retention.id())?.ok_or(DatabaseError::NotReady)?;
    if record.retention != retention {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(record)
}

pub(super) fn write<R: Retention>(
    connection: &Connection,
    previous: JournalRecord<R>,
    next: JournalRecord<R>,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    if bytes.len() > R::JOURNAL_BYTES {
        return Err(DatabaseError::Integrity.into());
    }
    let written = connection.execute(
        "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?4",
        params![
            R::JOURNAL,
            previous.retention.id().as_bytes(),
            bytes,
            canonical_bytes(&previous)?
        ],
    )?;
    if written != 1 || read(connection, previous.retention.id())? != Some(next) {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

/// The caller owns a short transaction and pins initial roots before commit.
pub(super) fn begin<R: Retention>(
    connection: &Connection,
    retention: R,
) -> Result<CatalogRetentionState, CatalogStoreError> {
    retention.validate()?;
    match read::<R>(connection, retention.id())? {
        Some(record)
            if record.retention != retention
                || record.state == CatalogRetentionState::Cancelled =>
        {
            Err(DatabaseError::Conflict.into())
        }
        Some(record) => Ok(record.state),
        None => {
            let orphan: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
                [dependencies::<R>(retention.id())],
                |row| row.get(0),
            )?;
            if orphan {
                return Err(DatabaseError::Integrity.into());
            }
            let record = JournalRecord {
                format_version: 1,
                retention,
                state: CatalogRetentionState::Building,
                roots: 0,
                bytes: 0,
                pages: 0,
            };
            let bytes = canonical_bytes(&record)?;
            if bytes.len() > R::JOURNAL_BYTES {
                return Err(DatabaseError::Integrity.into());
            }
            insert_exact(connection, R::JOURNAL, retention.id().as_bytes(), &bytes)?;
            if read(connection, retention.id())? != Some(record) {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(record.state)
        }
    }
}

pub(super) fn retain<R: Retention>(
    connection: &Connection,
    retention: R,
    dependency: Dependency,
) -> Result<(), CatalogStoreError> {
    dependency.validate(retention)?;
    let previous = require(connection, retention)?;
    if previous.state != CatalogRetentionState::Building {
        return Err(DatabaseError::Conflict.into());
    }
    read_page(connection, dependency.page())?;
    let kind = dependencies::<R>(retention.id());
    let pin = pin_id::<R>(retention.id());
    let bytes = canonical_bytes(&dependency)?;
    if let Some(existing) = bounded_record(connection, &kind, &dependency.root.hash, RECORD_BYTES)?
    {
        if existing != bytes
            || bounded_record(connection, &pins(dependency.root.hash), &pin, 0)?.as_deref()
                != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(());
    }
    let mut next = previous;
    next.roots = next
        .roots
        .checked_add(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    next.bytes = next
        .bytes
        .checked_add(dependency.root.byte_len)
        .ok_or(DatabaseError::CapacityExceeded)?;
    next.pages = next
        .pages
        .checked_add(dependency.root.page_occurrences)
        .ok_or(DatabaseError::CapacityExceeded)?;
    let (represented_bytes, pages) = retention.work()?;
    if next.pages > pages || next.bytes > represented_bytes {
        return Err(DatabaseError::CapacityExceeded.into());
    }
    insert_exact(connection, &kind, &dependency.root.hash, &bytes)?;
    insert_exact(connection, &pins(dependency.root.hash), &pin, &[])?;
    if bounded_record(connection, &kind, &dependency.root.hash, RECORD_BYTES)?.as_deref()
        != Some(bytes.as_slice())
        || bounded_record(connection, &pins(dependency.root.hash), &pin, 0)?.as_deref() != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
        params![GC, dependency.root.hash],
    )?;
    write(connection, previous, next)
}

pub(super) fn publish<R: Retention>(
    connection: &Connection,
    retention: R,
) -> Result<(), CatalogStoreError> {
    let previous = require(connection, retention)?;
    if previous.state != CatalogRetentionState::Building {
        return Err(DatabaseError::Conflict.into());
    }
    let mut next = previous;
    next.state = CatalogRetentionState::Published;
    write(connection, previous, next)
}

/// A failed worker must never cancel another worker's successful publication.
pub(super) fn cancel_building<R: Retention>(
    connection: &Connection,
    retention: R,
) -> Result<(), CatalogStoreError> {
    let previous = require(connection, retention)?;
    if previous.state == CatalogRetentionState::Building {
        let mut next = previous;
        next.state = CatalogRetentionState::Cancelled;
        write(connection, previous, next)?;
    }
    Ok(())
}

pub(super) fn cancel<R: Retention>(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    let previous = read::<R>(connection, id)?.ok_or(DatabaseError::NotReady)?;
    if previous.state != CatalogRetentionState::Cancelled {
        let mut next = previous;
        next.state = CatalogRetentionState::Cancelled;
        write(connection, previous, next)?;
    }
    Ok(())
}

/// Release one cancelled root. The caller commits dependency, pin and counter
/// changes atomically, then ordinary bounded page GC follows byte-tree edges.
pub(super) fn release<R: Retention>(
    connection: &Connection,
    id: Uuid,
) -> Result<bool, CatalogStoreError> {
    let previous = read::<R>(connection, id)?.ok_or(DatabaseError::NotReady)?;
    if previous.state != CatalogRetentionState::Cancelled {
        return Err(DatabaseError::Conflict.into());
    }
    let kind = dependencies::<R>(id);
    let Some(hash) = candidate_hash(connection, &kind, &[])? else {
        if previous.roots != 0 {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(false);
    };
    let bytes =
        bounded_record(connection, &kind, &hash, RECORD_BYTES)?.ok_or(DatabaseError::Integrity)?;
    let dependency: Dependency = decode_canonical(&bytes)?;
    dependency.validate(previous.retention)?;
    let pin = pin_id::<R>(id);
    if dependency.root.hash != hash
        || canonical_bytes(&dependency)? != bytes
        || metadata(connection, hash)? != dependency.page()
        || bounded_record(connection, &pins(hash), &pin, 0)?.as_deref() != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    let mut next = previous;
    next.roots = next.roots.checked_sub(1).ok_or(DatabaseError::Integrity)?;
    next.bytes = next
        .bytes
        .checked_sub(dependency.root.byte_len)
        .ok_or(DatabaseError::Integrity)?;
    next.pages = next
        .pages
        .checked_sub(dependency.root.page_occurrences)
        .ok_or(DatabaseError::Integrity)?;
    let removed = connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
        params![kind, hash, bytes],
    )?;
    let unpinned = connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
        params![pins(hash), pin, &[] as &[u8]],
    )?;
    if removed != 1 || unpinned != 1 {
        return Err(DatabaseError::Conflict.into());
    }
    write(connection, previous, next)?;
    queue_unreferenced(connection, hash)?;
    Ok(true)
}

#[cfg(test)]
pub(super) fn assert_v1_layout<R: Retention>(
    connection: &Connection,
    retention: R,
    root: CatalogPageRef,
) {
    // Independent copies of the original enums/field order, retained solely
    // to prove pre-refactor persisted rows still reopen byte-for-byte.
    #[derive(Serialize)]
    enum OriginalState {
        Building,
        Published,
        Cancelled,
    }
    #[derive(Serialize)]
    struct OriginalRecord<R> {
        format_version: u16,
        retention: R,
        state: OriginalState,
        roots: u64,
        bytes: u64,
        pages: u64,
    }
    for (old, state) in [
        (OriginalState::Building, CatalogRetentionState::Building),
        (OriginalState::Published, CatalogRetentionState::Published),
        (OriginalState::Cancelled, CatalogRetentionState::Cancelled),
    ] {
        let bytes = canonical_bytes(&OriginalRecord {
            format_version: 1,
            retention,
            state: old,
            roots: 1,
            bytes: root.byte_len,
            pages: root.page_occurrences,
        })
        .unwrap();
        let expected = JournalRecord {
            format_version: 1,
            retention,
            state,
            roots: 1,
            bytes: root.byte_len,
            pages: root.page_occurrences,
        };
        assert_eq!(canonical_bytes(&expected).unwrap(), bytes);
        connection.execute("INSERT OR REPLACE INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)", params![R::JOURNAL, retention.id().as_bytes(), bytes]).unwrap();
        let read = read::<R>(connection, retention.id()).unwrap().unwrap();
        assert!(read == expected);
    }
}

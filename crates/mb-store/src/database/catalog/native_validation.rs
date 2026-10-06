//! Disk-backed joins derived from verified native/source catalog streams.
//! Atomic completion supplies local validation evidence, not signed authority.

use mb_core::{
    CATALOG_MAX_RECORDS, CATALOG_MAX_STREAM_BYTES, CATALOG_SECTOR_RECORD_BYTES, CatalogFileEvent,
    CatalogFileKind, CatalogFileRecipeRecord, CatalogFileStat, CatalogNativeFileReader,
    CatalogNativeFileRoot, CatalogSectorReader, CatalogSectorRecord, CatalogSectorRoot,
    CatalogStreamError, SectorId,
};

use super::*;

const VALIDATION: &str = "catalog-native-validation-v1";
const VALIDATION_BYTES: usize = 2048;
const LINK_BYTES: usize = 128;
const BUNDLE_LINK: &str = "catalog-native-bundle-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogNativeValidation {
    pub id: Uuid,
    pub scope: CatalogScope,
    pub files: CatalogNativeFileRoot,
    pub sources: CatalogSectorRoot,
}

impl CatalogNativeValidation {
    pub fn validate(self) -> Result<(), CatalogStoreError> {
        self.scope.validate(CatalogSection::FileMetadata)?;
        self.files.validate()?;
        self.sources.validate()?;
        if self.id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        let pages = [
            self.files.namespace.records.page,
            self.files.recipes.records.page,
            self.sources.records.page,
        ];
        if pages.iter().map(|page| page.byte_len).sum::<u64>() > CATALOG_MAX_STREAM_BYTES
            || pages.iter().map(|page| page.page_occurrences).sum::<u64>()
                > CATALOG_MAX_PAGE_OCCURRENCES
        {
            return Err(CatalogError::Bounds.into());
        }
        Ok(())
    }

    /// Namespace/recipe/source roles, bound to this validation identity. Every
    /// stream retains its own durable intent; the validation ID is the bundle ID.
    pub fn as_local_bundle(
        self,
        intents: [CatalogIntent; 3],
    ) -> Result<CatalogBundle, CatalogStoreError> {
        self.validate()?;
        let expected_sections = [
            CatalogSection::FileMetadata,
            CatalogSection::FileMetadata,
            CatalogSection::SectorReferences,
        ];
        let roots = [
            self.files.namespace.records.page,
            self.files.recipes.records.page,
            self.sources.records.page,
        ];
        for (intent, expected) in intents.iter().zip(expected_sections) {
            if intent.scope != self.scope || intent.section != expected {
                return Err(DatabaseError::Conflict.into());
            }
        }
        let bundle = CatalogBundle {
            id: self.id,
            scope: self.scope,
            roots: intents
                .into_iter()
                .zip(roots)
                .map(|(intent, root)| CatalogBundleRoot { intent, root })
                .collect(),
            descriptor: canonical_bytes(&self)?,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogNativeValidationState {
    Verified,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ValidationRecord {
    format_version: u16,
    manifest: CatalogNativeValidation,
    state: CatalogNativeValidationState,
}

/// A group derived from validated entries and their exact recipe identities.
/// The primary key names the first file recipe encountered in component order;
/// it may follow an alias in the namespace. Restore uses this key to locate the
/// payload, rather than assuming the alias already has a restored predecessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogValidatedLink {
    pub format_version: u16,
    pub link_group: u64,
    pub stat: CatalogFileStat,
    pub logical_len: u64,
    pub primary_file_key: Option<u64>,
    pub recipe_hash: Option<[u8; 32]>,
}

fn sources(id: Uuid) -> String {
    format!("catalog-validation-source-v1/{}", id.simple())
}
fn links(id: Uuid) -> String {
    format!("catalog-validation-link-v1/{}", id.simple())
}
fn unresolved(id: Uuid) -> String {
    format!("catalog-validation-unresolved-v1/{}", id.simple())
}

fn read_validation(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<ValidationRecord>, CatalogStoreError> {
    if id.is_nil() {
        return Err(DatabaseError::Conflict.into());
    }
    let Some(bytes) = bounded_record(connection, VALIDATION, id.as_bytes(), VALIDATION_BYTES)?
    else {
        return Ok(None);
    };
    let record: ValidationRecord = decode_canonical(&bytes)?;
    record.manifest.validate()?;
    if record.format_version != 1 || record.manifest.id != id || canonical_bytes(&record)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

fn require_verified(
    connection: &Connection,
    id: Uuid,
) -> Result<ValidationRecord, CatalogStoreError> {
    let record = read_validation(connection, id)?.ok_or(DatabaseError::NotReady)?;
    if record.state != CatalogNativeValidationState::Verified {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(record)
}

pub(super) fn verified_manifest(
    connection: &Connection,
    id: Uuid,
) -> Result<CatalogNativeValidation, CatalogStoreError> {
    Ok(require_verified(connection, id)?.manifest)
}

pub(super) fn validation_snapshot(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<(CatalogNativeValidation, CatalogNativeValidationState)>, CatalogStoreError> {
    Ok(read_validation(connection, id)?.map(|record| (record.manifest, record.state)))
}

pub(super) fn link_publication(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    require_verified(connection, id)?;
    insert_exact(connection, BUNDLE_LINK, id.as_bytes(), id.as_bytes())
}

pub(super) fn require_publication_link(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, BUNDLE_LINK, id.as_bytes(), 16)?.as_deref() != Some(id.as_bytes())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn cancel_linked_publication(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    require_publication_link(connection, id)?;
    cancel_validation(connection, id)?;
    if connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?2",
        params![BUNDLE_LINK, id.as_bytes()],
    )? != 1
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

pub(super) fn source_record(
    connection: &Connection,
    id: Uuid,
    sector: SectorId,
) -> Result<Option<CatalogSectorRecord>, CatalogStoreError> {
    require_verified(connection, id)?;
    let record = bounded_record(
        connection,
        &sources(id),
        &sector,
        CATALOG_SECTOR_RECORD_BYTES,
    )?
    .map(|bytes| CatalogSectorRecord::decode(&bytes))
    .transpose()?;
    if record
        .as_ref()
        .is_some_and(|record| record.sector.id != sector)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(record)
}

/// A published native bundle must cancel its validation and roots together.
pub(super) fn require_unpublished_validation(
    connection: &Connection,
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, BUNDLE_LINK, id.as_bytes(), 16)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn cancel_validation(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    let mut record = read_validation(connection, id)?.ok_or(DatabaseError::NotReady)?;
    if record.state != CatalogNativeValidationState::Cancelled {
        record.state = CatalogNativeValidationState::Cancelled;
        let written = connection.execute(
            "UPDATE protocol_records SET bytes = ?2 WHERE kind = ?1 AND record_id = ?3",
            params![VALIDATION, canonical_bytes(&record)?, id.as_bytes()],
        )?;
        if written != 1 {
            return Err(DatabaseError::Conflict.into());
        }
    }
    Ok(())
}

fn native_snapshot(
    connection: &Connection,
    id: Uuid,
    expected_scope: CatalogScope,
) -> Result<Option<(CatalogNativeValidation, CatalogBundleState)>, CatalogStoreError> {
    expected_scope.validate(CatalogSection::FileMetadata)?;
    let Some((bundle, state)) = super::bundle::bundle_snapshot(connection, id)? else {
        if bounded_record(connection, BUNDLE_LINK, id.as_bytes(), 16)?.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    if bundle.scope != expected_scope
        || bundle.roots.len() != 3
        || bundle.descriptor.len() > VALIDATION_BYTES
    {
        return Err(DatabaseError::Conflict.into());
    }
    let manifest: CatalogNativeValidation = decode_canonical(&bundle.descriptor)?;
    let intents = [
        bundle.roots[0].intent,
        bundle.roots[1].intent,
        bundle.roots[2].intent,
    ];
    if manifest.as_local_bundle(intents)? != bundle {
        return Err(DatabaseError::Integrity.into());
    }
    let validation = read_validation(connection, id)?.ok_or(DatabaseError::Integrity)?;
    if validation.manifest != manifest {
        return Err(DatabaseError::Integrity.into());
    }
    match state {
        CatalogBundleState::Published => {
            if validation.state != CatalogNativeValidationState::Verified
                || bounded_record(connection, BUNDLE_LINK, id.as_bytes(), 16)?.as_deref()
                    != Some(id.as_bytes())
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        CatalogBundleState::Cancelled => {
            if validation.state != CatalogNativeValidationState::Cancelled {
                return Err(DatabaseError::Integrity.into());
            }
            require_unpublished_validation(connection, id)?;
        }
    }
    Ok(Some((manifest, state)))
}

fn read_link(
    connection: &Connection,
    id: Uuid,
    group: u64,
) -> Result<Option<CatalogValidatedLink>, CatalogStoreError> {
    let Some(bytes) = bounded_record(connection, &links(id), &group.to_be_bytes(), LINK_BYTES)?
    else {
        return Ok(None);
    };
    let record: CatalogValidatedLink = decode_canonical(&bytes)?;
    record.stat.validate()?;
    if record.format_version != 1
        || record.link_group != group
        || record.primary_file_key.is_some() != record.recipe_hash.is_some()
        || record
            .primary_file_key
            .is_some_and(|key| key >= CATALOG_MAX_RECORDS)
        || canonical_bytes(&record)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

fn merge_link(
    connection: &Connection,
    id: Uuid,
    proposed: CatalogValidatedLink,
) -> Result<(), CatalogStoreError> {
    let key = proposed.link_group.to_be_bytes();
    match read_link(connection, id, proposed.link_group)? {
        None => {
            insert_exact(connection, &links(id), &key, &canonical_bytes(&proposed)?)?;
            if proposed.primary_file_key.is_none() {
                insert_exact(connection, &unresolved(id), &key, &[])?;
            }
        }
        Some(existing) => {
            if existing.stat != proposed.stat
                || existing.logical_len != proposed.logical_len
                || existing.recipe_hash.is_some()
                    && proposed.recipe_hash.is_some()
                    && existing.recipe_hash != proposed.recipe_hash
            {
                return Err(DatabaseError::Conflict.into());
            }
            if existing.primary_file_key.is_none() && proposed.primary_file_key.is_some() {
                let written = connection.execute(
                    "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
                    params![links(id), key, canonical_bytes(&proposed)?],
                )?;
                if written != 1 {
                    return Err(DatabaseError::Conflict.into());
                }
                let removed = connection.execute(
                    "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                    params![unresolved(id), key],
                )?;
                if removed != 1 {
                    return Err(DatabaseError::Integrity.into());
                }
            }
        }
    }
    Ok(())
}

fn unwrap_stream<T>(
    result: Result<T, CatalogStreamError<CatalogStoreError>>,
) -> Result<T, CatalogStoreError> {
    result.map_err(|error| match error {
        CatalogStreamError::Catalog(error) => error.into(),
        CatalogStreamError::Storage(error) => error,
    })
}

struct ActiveFile {
    key: u64,
    stat: CatalogFileStat,
    logical_len: u64,
    group: Option<u64>,
    hash: blake3::Hasher,
}

fn finish_file(
    connection: &Connection,
    id: Uuid,
    file: Option<ActiveFile>,
) -> Result<(), CatalogStoreError> {
    if let Some(file) = file
        && let Some(group) = file.group
    {
        merge_link(
            connection,
            id,
            CatalogValidatedLink {
                format_version: 1,
                link_group: group,
                stat: file.stat,
                logical_len: file.logical_len,
                primary_file_key: Some(file.key),
                recipe_hash: Some(*file.hash.finalize().as_bytes()),
            },
        )?;
    }
    Ok(())
}

impl ControlStore {
    /// Atomically bind a completed native validation to exactly its namespace,
    /// recipe and source roots and their retained pins. This is local durable
    /// publication; protocol signing and ciphertext protection remain external.
    pub fn publish_native_file_catalog(
        &self,
        manifest: CatalogNativeValidation,
        intents: [CatalogIntent; 3],
    ) -> Result<(), CatalogStoreError> {
        let bundle = manifest.as_local_bundle(intents)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if require_verified(&transaction, manifest.id)?.manifest != manifest {
            return Err(DatabaseError::Conflict.into());
        }
        super::bundle::publish_bundle(&transaction, &bundle)?;
        insert_exact(
            &transaction,
            BUNDLE_LINK,
            manifest.id.as_bytes(),
            manifest.id.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Consistent typed publication/validation snapshot. Traversal and recovery
    /// still check actual page/ciphertext bytes; this is not a bitrot certificate.
    pub fn native_file_catalog(
        &self,
        id: Uuid,
        expected_scope: CatalogScope,
    ) -> Result<Option<(CatalogNativeValidation, CatalogBundleState)>, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let snapshot = native_snapshot(&transaction, id, expected_scope)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Fence the validation index and every member intent in one transaction
    /// before bounded index/pin/page cleanup. Individual cancellation is blocked.
    pub fn cancel_native_file_catalog(
        &self,
        id: Uuid,
        expected_scope: CatalogScope,
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (_, state) =
            native_snapshot(&transaction, id, expected_scope)?.ok_or(DatabaseError::NotReady)?;
        if state != CatalogBundleState::Cancelled {
            cancel_validation(&transaction, id)?;
            super::bundle::cancel_bundle(&transaction, id)?;
            let removed = transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![BUNDLE_LINK, id.as_bytes(), id.as_bytes()],
            )?;
            if removed != 1 {
                return Err(DatabaseError::Conflict.into());
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Derive disk-backed source/group lookup rows from the three verified
    /// streams. A single writer transaction commits only after authenticated
    /// EOFs, exact recipe/source joins, matching group attributes/recipes and
    /// resolution of every alias. Errors and process loss roll back all rows.
    /// Memory holds bounded readers, one current file/hash and one SQL row.
    /// Callers must authenticate both root descriptors before this local check;
    /// no ciphertext, signed authority, page retention or capacity is certified.
    pub fn validate_native_file_catalog(
        &self,
        manifest: CatalogNativeValidation,
    ) -> Result<(), CatalogStoreError> {
        manifest.validate()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some(existing) = read_validation(&transaction, manifest.id)? {
            if existing.manifest != manifest
                || existing.state != CatalogNativeValidationState::Verified
            {
                return Err(DatabaseError::Conflict.into());
            }
            transaction.commit()?;
            return Ok(());
        }
        // Orphan rows cannot be adopted as evidence for a different root.
        let source_kind = sources(manifest.id);
        let link_kind = links(manifest.id);
        let unresolved_kind = unresolved(manifest.id);
        let present: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1, ?2, ?3))",
            params![source_kind, link_kind, unresolved_kind],
            |row| row.get(0),
        )?;
        if present {
            return Err(DatabaseError::Integrity.into());
        }
        let mut reader = CatalogSectorReader::new(manifest.scope, manifest.sources)?;
        let mut fetch_source = |reference| {
            read_page(
                &transaction,
                PageMetadata {
                    format_version: 1,
                    scope: manifest.scope,
                    section: CatalogSection::SectorReferences,
                    reference,
                },
            )
        };
        while let Some(source) = unwrap_stream(reader.next_sector(&mut fetch_source))? {
            insert_exact(
                &transaction,
                &source_kind,
                &source.sector.id,
                &canonical_bytes(&source)?,
            )?;
        }
        let mut reader = CatalogNativeFileReader::new(manifest.scope, manifest.files)?;
        let mut fetch_file = |reference| {
            read_page(
                &transaction,
                PageMetadata {
                    format_version: 1,
                    scope: manifest.scope,
                    section: CatalogSection::FileMetadata,
                    reference,
                },
            )
        };
        let mut active: Option<ActiveFile> = None;
        while let Some(event) = unwrap_stream(reader.next_event(&mut fetch_file))? {
            match event {
                CatalogFileEvent::Entry(entry) => {
                    finish_file(&transaction, manifest.id, active.take())?;
                    match entry.kind {
                        CatalogFileKind::Directory => {}
                        CatalogFileKind::File {
                            file_key,
                            logical_len,
                            link_group,
                        } => {
                            active = Some(ActiveFile {
                                key: file_key,
                                stat: entry.stat,
                                logical_len,
                                group: link_group,
                                hash: blake3::Hasher::new_derive_key(
                                    "mutualbackup native file recipe identity v1",
                                ),
                            });
                        }
                        CatalogFileKind::HardLink {
                            logical_len,
                            link_group,
                        } => {
                            merge_link(
                                &transaction,
                                manifest.id,
                                CatalogValidatedLink {
                                    format_version: 1,
                                    link_group,
                                    stat: entry.stat,
                                    logical_len,
                                    primary_file_key: None,
                                    recipe_hash: None,
                                },
                            )?;
                        }
                    }
                }
                CatalogFileEvent::Recipe(record) => {
                    let current = active.as_mut().ok_or(DatabaseError::Integrity)?;
                    let bytes = match &record {
                        CatalogFileRecipeRecord::File {
                            format_version,
                            logical_len,
                            extents,
                            sectors,
                            ..
                        } => {
                            // File ordinal differs across duplicate legacy primaries.
                            // Excluding it preserves comparison of exact recipes.
                            canonical_bytes(&(*format_version, *logical_len, *extents, *sectors))?
                        }
                        CatalogFileRecipeRecord::Extent { .. } => canonical_bytes(&record)?,
                        CatalogFileRecipeRecord::Sectors { references, .. } => {
                            for reference in references {
                                let bytes = bounded_record(
                                    &transaction,
                                    &source_kind,
                                    &reference.id,
                                    CATALOG_SECTOR_RECORD_BYTES,
                                )?
                                .ok_or(DatabaseError::NotReady)?;
                                let source = CatalogSectorRecord::decode(&bytes)?;
                                if source.sector != *reference {
                                    return Err(DatabaseError::Conflict.into());
                                }
                            }
                            canonical_bytes(&record)?
                        }
                    };
                    current.hash.update(&(bytes.len() as u32).to_be_bytes());
                    current.hash.update(&bytes);
                }
            }
        }
        finish_file(&transaction, manifest.id, active)?;
        let pending: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
            params![unresolved_kind],
            |row| row.get(0),
        )?;
        if pending {
            return Err(DatabaseError::NotReady.into());
        }
        let record = ValidationRecord {
            format_version: 1,
            manifest,
            state: CatalogNativeValidationState::Verified,
        };
        insert_exact(
            &transaction,
            VALIDATION,
            manifest.id.as_bytes(),
            &canonical_bytes(&record)?,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn native_file_catalog_validation(
        &self,
        id: Uuid,
    ) -> Result<Option<(CatalogNativeValidation, CatalogNativeValidationState)>, CatalogStoreError>
    {
        Ok(read_validation(&self.connection, id)?.map(|record| (record.manifest, record.state)))
    }

    pub fn native_file_catalog_source(
        &self,
        id: Uuid,
        sector: SectorId,
    ) -> Result<Option<CatalogSectorRecord>, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        require_verified(&transaction, id)?;
        let record = bounded_record(
            &transaction,
            &sources(id),
            &sector,
            CATALOG_SECTOR_RECORD_BYTES,
        )?
        .map(|bytes| CatalogSectorRecord::decode(&bytes))
        .transpose()?;
        if record
            .as_ref()
            .is_some_and(|record| record.sector.id != sector)
        {
            return Err(DatabaseError::Integrity.into());
        }
        transaction.commit()?;
        Ok(record)
    }

    pub fn native_file_catalog_link(
        &self,
        id: Uuid,
        group: u64,
    ) -> Result<Option<CatalogValidatedLink>, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let validation = require_verified(&transaction, id)?;
        let record = read_link(&transaction, id, group)?;
        if record.as_ref().is_some_and(|record| {
            record
                .primary_file_key
                .is_none_or(|key| key >= validation.manifest.files.namespace.records.records)
        }) {
            return Err(DatabaseError::Integrity.into());
        }
        transaction.commit()?;
        Ok(record)
    }

    /// Fence lookups and stale validation retries before bounded index cleanup.
    pub fn cancel_native_file_catalog_validation(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        require_unpublished_validation(&transaction, id)?;
        cancel_validation(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }

    /// Delete one cancelled index row per transaction. Fencing journals remain
    /// until a future authenticated generation-floor retirement policy exists.
    pub fn release_native_file_validation_record(
        &self,
        id: Uuid,
    ) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if read_validation(&transaction, id)?
            .ok_or(DatabaseError::NotReady)?
            .state
            != CatalogNativeValidationState::Cancelled
        {
            return Err(DatabaseError::Conflict.into());
        }
        for kind in [sources(id), links(id), unresolved(id)] {
            let key: Option<Option<Vec<u8>>> = transaction
                .query_row(
                    "SELECT CASE WHEN length(record_id) <= 32 THEN record_id END
                 FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
                    params![kind],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(key) = key {
                let key = key.ok_or(DatabaseError::Integrity)?;
                let removed = transaction.execute(
                    "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                    params![kind, key],
                )?;
                if removed != 1 {
                    return Err(DatabaseError::Conflict.into());
                }
                transaction.commit()?;
                return Ok(true);
            }
        }
        transaction.commit()?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use mb_core::{
        CatalogFileBuilder, CatalogFileExtent, CatalogFileRecipeBuilder, CatalogFileRecord,
        CatalogSectorBuilder, KeyMaterial, NodeId, SectorRef, Seed, V1_SECTOR_SIZE,
        merkle_zero_commitment,
    };

    use super::*;

    const STAT: CatalogFileStat = CatalogFileStat {
        mode: 0o640,
        modified_secs: -4,
        modified_nanos: 2,
    };

    type Recipe = (u64, u64, Vec<(u64, Vec<SectorRef>)>);

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn entry(path: &[u8], kind: CatalogFileKind) -> CatalogFileRecord {
        CatalogFileRecord {
            format_version: 1,
            path: path.to_vec(),
            stat: STAT,
            kind,
        }
    }

    fn source(index: u32) -> CatalogSectorRecord {
        let mut id = [4; 32];
        id[..4].copy_from_slice(&index.to_be_bytes());
        CatalogSectorRecord {
            format_version: 1,
            sector: SectorRef {
                id,
                root: [5; 32],
                logical_len: 3,
            },
            commitment: merkle_zero_commitment(V1_SECTOR_SIZE as u32).unwrap(),
        }
    }

    fn stage_owned(
        store: &ControlStore,
        entries: &[CatalogFileRecord],
        recipes: &[Recipe],
        source_records: &[CatalogSectorRecord],
    ) -> (CatalogNativeValidation, [CatalogIntent; 3]) {
        let intents = [
            CatalogSection::FileMetadata,
            CatalogSection::FileMetadata,
            CatalogSection::SectorReferences,
        ]
        .map(|section| CatalogIntent {
            id: Uuid::new_v4(),
            scope: scope(),
            section,
        });
        for intent in intents {
            store.begin_catalog(intent).unwrap();
        }
        let mut namespace = CatalogFileBuilder::new(scope(), STAT).unwrap();
        let mut sink =
            |reference, bytes: Vec<u8>| store.stage_catalog_page(intents[0], reference, &bytes);
        for entry in entries {
            namespace.push(entry, &mut sink).unwrap();
        }
        let namespace = namespace.finish(&mut sink).unwrap();
        let mut payload = CatalogFileRecipeBuilder::new(scope()).unwrap();
        let mut sink =
            |reference, bytes: Vec<u8>| store.stage_catalog_page(intents[1], reference, &bytes);
        for (key, len, extents) in recipes {
            payload
                .push_file(
                    *key,
                    *len,
                    extents.iter().map(|(offset, sectors)| CatalogFileExtent {
                        offset: *offset,
                        logical_len: sectors
                            .iter()
                            .map(|reference| u64::from(reference.logical_len))
                            .sum(),
                        sectors,
                    }),
                    &mut sink,
                )
                .unwrap();
        }
        let recipes = payload.finish(&mut sink).unwrap();
        let mut sources = CatalogSectorBuilder::new(scope()).unwrap();
        let mut sink =
            |reference, bytes: Vec<u8>| store.stage_catalog_page(intents[2], reference, &bytes);
        for source in source_records {
            sources.push(source, &mut sink).unwrap();
        }
        let sources = sources.finish(&mut sink).unwrap();
        let manifest = CatalogNativeValidation {
            id: Uuid::new_v4(),
            scope: scope(),
            files: CatalogNativeFileRoot {
                format_version: 1,
                namespace,
                recipes,
            },
            sources,
        };
        (manifest, intents)
    }

    fn stage(
        store: &ControlStore,
        entries: &[CatalogFileRecord],
        recipes: &[Recipe],
        source_records: &[CatalogSectorRecord],
    ) -> CatalogNativeValidation {
        stage_owned(store, entries, recipes, source_records).0
    }

    fn fixture_owned(store: &ControlStore) -> (CatalogNativeValidation, [CatalogIntent; 3]) {
        let sector = source(1).sector;
        stage_owned(
            store,
            &[
                entry(
                    b"a-alias",
                    CatalogFileKind::HardLink {
                        logical_len: 10,
                        link_group: 7,
                    },
                ),
                entry(
                    b"b-primary",
                    CatalogFileKind::File {
                        file_key: 1,
                        logical_len: 10,
                        link_group: Some(7),
                    },
                ),
                entry(
                    b"c-primary",
                    CatalogFileKind::File {
                        file_key: 2,
                        logical_len: 10,
                        link_group: Some(7),
                    },
                ),
                entry(
                    b"d-alias",
                    CatalogFileKind::HardLink {
                        logical_len: 10,
                        link_group: 7,
                    },
                ),
                entry(
                    b"e-empty",
                    CatalogFileKind::File {
                        file_key: 4,
                        logical_len: 0,
                        link_group: None,
                    },
                ),
            ],
            &[
                (1, 10, vec![(2, vec![sector.clone()])]),
                (2, 10, vec![(2, vec![sector.clone()])]),
                (4, 0, vec![]),
            ],
            &[source(1)],
        )
    }

    fn fixture(store: &ControlStore) -> CatalogNativeValidation {
        fixture_owned(store).0
    }

    fn assert_no_index(store: &ControlStore, manifest: CatalogNativeValidation) {
        assert!(
            store
                .native_file_catalog_validation(manifest.id)
                .unwrap()
                .is_none()
        );
        for kind in [
            sources(manifest.id),
            links(manifest.id),
            unresolved(manifest.id),
        ] {
            assert!(store.records(&kind).unwrap().is_empty());
        }
    }

    #[test]
    fn catalog_native_validation_reopens_forward_aliases_duplicate_primaries_and_fenced_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        let manifest = fixture(&store);
        assert!(
            store
                .native_file_catalog_source(manifest.id, source(1).sector.id)
                .is_err()
        );
        store.validate_native_file_catalog(manifest).unwrap();
        store.validate_native_file_catalog(manifest).unwrap();
        assert!(
            store
                .release_native_file_validation_record(manifest.id)
                .is_err()
        );
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store.native_file_catalog_validation(manifest.id).unwrap(),
            Some((manifest, CatalogNativeValidationState::Verified))
        );
        assert_eq!(
            store
                .native_file_catalog_source(manifest.id, source(1).sector.id)
                .unwrap(),
            Some(source(1))
        );
        assert!(
            store
                .native_file_catalog_source(manifest.id, [0; 32])
                .unwrap()
                .is_none()
        );
        let link = store
            .native_file_catalog_link(manifest.id, 7)
            .unwrap()
            .unwrap();
        assert_eq!(link.primary_file_key, Some(1));
        assert_eq!((link.stat, link.logical_len), (STAT, 10));
        assert!(link.recipe_hash.is_some());
        assert!(
            store
                .native_file_catalog_link(manifest.id, 8)
                .unwrap()
                .is_none()
        );
        let changed = CatalogNativeValidation {
            sources: CatalogSectorRoot {
                logical_bytes: manifest.sources.logical_bytes + 1,
                ..manifest.sources
            },
            ..manifest
        };
        assert!(store.validate_native_file_catalog(changed).is_err());
        store
            .cancel_native_file_catalog_validation(manifest.id)
            .unwrap();
        drop(store);
        let mut store = ControlStore::open(&path, &keys).unwrap();
        store
            .cancel_native_file_catalog_validation(manifest.id)
            .unwrap();
        assert!(
            store
                .native_file_catalog_source(manifest.id, source(1).sector.id)
                .is_err()
        );
        assert!(store.native_file_catalog_link(manifest.id, 7).is_err());
        assert!(store.validate_native_file_catalog(manifest).is_err());
        let mut removed = 0;
        while store
            .release_native_file_validation_record(manifest.id)
            .unwrap()
        {
            removed += 1;
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
        }
        assert_eq!(removed, 2);
        assert_eq!(
            store.native_file_catalog_validation(manifest.id).unwrap(),
            Some((manifest, CatalogNativeValidationState::Cancelled))
        );
        assert!(store.validate_native_file_catalog(manifest).is_err());
        // Cancelling validation does not cancel or reclaim the owned source pages.
        store
            .catalog_page(
                manifest.scope,
                CatalogSection::SectorReferences,
                manifest.sources.records.page,
            )
            .unwrap();
    }

    #[test]
    fn catalog_native_validation_rejects_unresolved_conflicting_aliases_and_recipe_identities() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(directory.path().join("control.db"), &keys).unwrap();
        let sector = source(1).sector;
        let mut alias = entry(
            b"a",
            CatalogFileKind::HardLink {
                logical_len: 10,
                link_group: 7,
            },
        );
        for mismatch in 0..4 {
            let primary = entry(
                b"b",
                CatalogFileKind::File {
                    file_key: 1,
                    logical_len: 10,
                    link_group: Some(7),
                },
            );
            match mismatch {
                0 => alias.stat.mode += 1,
                1 => {
                    alias.stat = STAT;
                    alias.stat.modified_secs -= 1;
                }
                2 => {
                    alias.stat = STAT;
                    alias.stat.modified_nanos += 1;
                }
                _ => {
                    alias.stat = STAT;
                    alias.kind = CatalogFileKind::HardLink {
                        logical_len: 11,
                        link_group: 7,
                    };
                }
            }
            let manifest = stage(
                &store,
                &[alias.clone(), primary],
                &[(1, 10, vec![(2, vec![sector.clone()])])],
                &[source(1)],
            );
            assert!(store.validate_native_file_catalog(manifest).is_err());
            assert_no_index(&store, manifest);
        }
        let manifest = stage(
            &store,
            &[entry(
                b"a",
                CatalogFileKind::HardLink {
                    logical_len: 0,
                    link_group: 9,
                },
            )],
            &[],
            &[],
        );
        assert!(store.validate_native_file_catalog(manifest).is_err());
        assert_no_index(&store, manifest);
        // Same group and attributes but different sparse offset is a conflicting
        // exact recipe even though the represented source and length match.
        let entries = [
            entry(
                b"a",
                CatalogFileKind::File {
                    file_key: 0,
                    logical_len: 10,
                    link_group: Some(7),
                },
            ),
            entry(
                b"b",
                CatalogFileKind::File {
                    file_key: 1,
                    logical_len: 10,
                    link_group: Some(7),
                },
            ),
        ];
        let manifest = stage(
            &store,
            &entries,
            &[
                (0, 10, vec![(2, vec![sector.clone()])]),
                (1, 10, vec![(3, vec![sector.clone()])]),
            ],
            &[source(1)],
        );
        assert!(store.validate_native_file_catalog(manifest).is_err());
        assert_no_index(&store, manifest);
        // A valid unlinked empty file does not provide a primary for an alias.
        let manifest = stage(
            &store,
            &[
                entry(
                    b"a",
                    CatalogFileKind::HardLink {
                        logical_len: 0,
                        link_group: 9,
                    },
                ),
                entry(
                    b"b",
                    CatalogFileKind::File {
                        file_key: 1,
                        logical_len: 0,
                        link_group: None,
                    },
                ),
            ],
            &[(1, 0, vec![])],
            &[],
        );
        assert!(store.validate_native_file_catalog(manifest).is_err());
        assert_no_index(&store, manifest);
    }

    #[test]
    fn catalog_native_validation_joins_exact_signed_source_references_and_bounds_cached_rows() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(directory.path().join("control.db"), &keys).unwrap();
        for changed in [
            SectorRef {
                root: [6; 32],
                ..source(1).sector
            },
            SectorRef {
                logical_len: 2,
                ..source(1).sector
            },
            source(2).sector,
        ] {
            let manifest = stage(
                &store,
                &[entry(
                    b"a",
                    CatalogFileKind::File {
                        file_key: 0,
                        logical_len: 10,
                        link_group: None,
                    },
                )],
                &[(0, 10, vec![(2, vec![changed])])],
                &[source(1)],
            );
            assert!(store.validate_native_file_catalog(manifest).is_err());
            assert_no_index(&store, manifest);
        }
        let manifest = fixture(&store);
        let wrong_summary = CatalogNativeValidation {
            id: Uuid::new_v4(),
            sources: CatalogSectorRoot {
                logical_bytes: manifest.sources.logical_bytes + 1,
                ..manifest.sources
            },
            ..manifest
        };
        assert!(store.validate_native_file_catalog(wrong_summary).is_err());
        assert_no_index(&store, wrong_summary);
        store.validate_native_file_catalog(manifest).unwrap();
        let original_link = store
            .native_file_catalog_link(manifest.id, 7)
            .unwrap()
            .unwrap();
        let wrong_key = CatalogValidatedLink {
            primary_file_key: Some(manifest.files.namespace.records.records),
            ..original_link
        };
        store
            .put_record(
                &links(manifest.id),
                &7_u64.to_be_bytes(),
                &canonical_bytes(&wrong_key).unwrap(),
            )
            .unwrap();
        assert!(store.native_file_catalog_link(manifest.id, 7).is_err());
        store
            .put_record(
                &links(manifest.id),
                &7_u64.to_be_bytes(),
                &canonical_bytes(&original_link).unwrap(),
            )
            .unwrap();
        store
            .put_record(
                &sources(manifest.id),
                &source(1).sector.id,
                &canonical_bytes(&source(2)).unwrap(),
            )
            .unwrap();
        assert!(
            store
                .native_file_catalog_source(manifest.id, source(1).sector.id)
                .is_err()
        );
        store
            .put_record(
                &sources(manifest.id),
                &source(1).sector.id,
                &[0; CATALOG_SECTOR_RECORD_BYTES + 1],
            )
            .unwrap();
        assert!(
            store
                .native_file_catalog_source(manifest.id, source(1).sector.id)
                .is_err()
        );
        store
            .put_record(
                &links(manifest.id),
                &7_u64.to_be_bytes(),
                &[0; LINK_BYTES + 1],
            )
            .unwrap();
        assert!(store.native_file_catalog_link(manifest.id, 7).is_err());
        store
            .put_record(
                VALIDATION,
                manifest.id.as_bytes(),
                &[0; VALIDATION_BYTES + 1],
            )
            .unwrap();
        assert!(store.native_file_catalog_validation(manifest.id).is_err());
        assert!(
            store
                .cancel_native_file_catalog_validation(manifest.id)
                .is_err()
        );
    }

    #[test]
    fn catalog_native_validation_sql_abort_and_ignored_updates_roll_back_every_join() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys).unwrap();
        let manifest = fixture(&store);
        for trigger in [
            "CREATE TEMP TRIGGER fail_validation BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-native-validation-v1' BEGIN SELECT RAISE(ABORT, 'injected'); END",
            "CREATE TEMP TRIGGER fail_validation BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-native-validation-v1' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_validation BEFORE UPDATE ON protocol_records WHEN NEW.kind LIKE 'catalog-validation-link-v1/%' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_validation BEFORE DELETE ON protocol_records WHEN OLD.kind LIKE 'catalog-validation-unresolved-v1/%' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_validation BEFORE INSERT ON protocol_records WHEN NEW.kind LIKE 'catalog-validation-source-v1/%' BEGIN SELECT RAISE(IGNORE); END",
        ] {
            store.connection.execute_batch(trigger).unwrap();
            assert!(store.validate_native_file_catalog(manifest).is_err());
            assert_no_index(&store, manifest);
            store
                .connection
                .execute_batch("DROP TRIGGER fail_validation")
                .unwrap();
        }
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        store.validate_native_file_catalog(manifest).unwrap();
        store.connection.execute_batch("CREATE TEMP TRIGGER fail_cancel BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-native-validation-v1' BEGIN SELECT RAISE(IGNORE); END").unwrap();
        assert!(
            store
                .cancel_native_file_catalog_validation(manifest.id)
                .is_err()
        );
        assert_eq!(
            store
                .native_file_catalog_validation(manifest.id)
                .unwrap()
                .unwrap()
                .1,
            CatalogNativeValidationState::Verified
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fail_cancel")
            .unwrap();
        store
            .cancel_native_file_catalog_validation(manifest.id)
            .unwrap();
        store.connection.execute_batch("CREATE TEMP TRIGGER fail_cleanup BEFORE DELETE ON protocol_records WHEN OLD.kind LIKE 'catalog-validation-source-v1/%' BEGIN SELECT RAISE(IGNORE); END").unwrap();
        assert!(
            store
                .release_native_file_validation_record(manifest.id)
                .is_err()
        );
        assert_eq!(store.records(&sources(manifest.id)).unwrap().len(), 1);
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        while store
            .release_native_file_validation_record(manifest.id)
            .unwrap()
        {}
        assert!(store.records(&sources(manifest.id)).unwrap().is_empty());
    }

    #[test]
    fn catalog_native_validation_uses_indexed_sources_and_groups_across_many_pages() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        let records: Vec<_> = (0..3200).map(source).collect();
        let mut entries = Vec::new();
        let mut recipes = Vec::new();
        for index in 0..3200 {
            entries.push(entry(
                format!("alias-{index:04}").as_bytes(),
                CatalogFileKind::HardLink {
                    logical_len: 10,
                    link_group: index,
                },
            ));
        }
        for (index, record) in records.iter().enumerate() {
            let key = entries.len() as u64;
            entries.push(entry(
                format!("file-{index:04}").as_bytes(),
                CatalogFileKind::File {
                    file_key: key,
                    logical_len: 10,
                    link_group: Some(index as u64),
                },
            ));
            recipes.push((
                key,
                10,
                vec![(2, vec![record.sector.clone(), record.sector.clone()])],
            ));
        }
        let manifest = stage(&store, &entries, &recipes, &records);
        assert!(manifest.files.namespace.records.page.height > 0);
        assert!(manifest.files.recipes.records.page.height > 0);
        assert!(manifest.sources.records.page.height > 0);
        store.validate_native_file_catalog(manifest).unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        for index in [0, 127, 128, 1599, 3199] {
            assert_eq!(
                store
                    .native_file_catalog_source(manifest.id, source(index).sector.id)
                    .unwrap(),
                Some(source(index))
            );
            let link = store
                .native_file_catalog_link(manifest.id, index as u64)
                .unwrap()
                .unwrap();
            assert_eq!(link.primary_file_key, Some(3200 + index as u64));
            assert_eq!(link.logical_len, 10);
        }
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM protocol_records WHERE kind = ?1",
                    params![sources(manifest.id)],
                    |row| row.get::<_, u64>(0)
                )
                .unwrap(),
            3200
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM protocol_records WHERE kind = ?1",
                    params![links(manifest.id)],
                    |row| row.get::<_, u64>(0)
                )
                .unwrap(),
            3200
        );
        assert!(store.records(&unresolved(manifest.id)).unwrap().is_empty());
    }

    #[test]
    fn catalog_native_publication_reopens_exact_roles_and_cancels_index_and_roots_together() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        let (manifest, intents) = fixture_owned(&store);
        assert!(
            store
                .publish_native_file_catalog(manifest, intents)
                .is_err()
        );
        assert!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap()
                .is_none()
        );
        store.validate_native_file_catalog(manifest).unwrap();
        store
            .publish_native_file_catalog(manifest, intents)
            .unwrap();
        store
            .publish_native_file_catalog(manifest, intents)
            .unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap(),
            Some((manifest, CatalogBundleState::Published))
        );
        let bundle = manifest.as_local_bundle(intents).unwrap();
        assert_eq!(
            store.catalog_bundle(manifest.id).unwrap(),
            Some((bundle.clone(), CatalogBundleState::Published))
        );
        for member in &bundle.roots {
            assert_eq!(
                store.catalog_intent_state(member.intent).unwrap(),
                CatalogIntentState::Published(member.root)
            );
            assert!(store.cancel_catalog(member.intent).is_err());
            assert!(!store.release_catalog_pin(member.intent).unwrap());
        }
        assert!(store.cancel_catalog_bundle(manifest.id).is_err());
        assert!(
            store
                .cancel_native_file_catalog_validation(manifest.id)
                .is_err()
        );
        let wrong_scope = CatalogScope::Dataset {
            guild_id: [9; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        };
        assert!(store.native_file_catalog(manifest.id, wrong_scope).is_err());
        assert!(
            store
                .cancel_native_file_catalog(manifest.id, wrong_scope)
                .is_err()
        );
        store
            .cancel_native_file_catalog(manifest.id, manifest.scope)
            .unwrap();
        drop(store);
        let mut store = ControlStore::open(&path, &keys).unwrap();
        store
            .cancel_native_file_catalog(manifest.id, manifest.scope)
            .unwrap();
        assert_eq!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap(),
            Some((manifest, CatalogBundleState::Cancelled))
        );
        assert!(
            store
                .native_file_catalog_source(manifest.id, source(1).sector.id)
                .is_err()
        );
        assert!(store.native_file_catalog_link(manifest.id, 7).is_err());
        assert!(store.validate_native_file_catalog(manifest).is_err());
        assert!(
            store
                .publish_native_file_catalog(manifest, intents)
                .is_err()
        );
        for intent in intents {
            assert_eq!(
                store.catalog_intent_state(intent).unwrap(),
                CatalogIntentState::Cancelled
            );
            assert!(
                store
                    .stage_catalog_page(intent, bundle.roots[0].root, b"stale")
                    .is_err()
            );
            while store.release_catalog_pin(intent).unwrap() {
                drop(store);
                store = ControlStore::open(&path, &keys).unwrap();
            }
        }
        let mut removed = 0;
        while store
            .release_native_file_validation_record(manifest.id)
            .unwrap()
        {
            removed += 1;
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
        }
        assert_eq!(removed, 2);
        while store.collect_catalog_page().unwrap() {
            drop(store);
            store = ControlStore::open(&path, &keys).unwrap();
        }
        assert!(store.records(PAGE).unwrap().is_empty());
        assert_eq!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap(),
            Some((manifest, CatalogBundleState::Cancelled))
        );
        assert!(
            store
                .publish_native_file_catalog(manifest, intents)
                .is_err()
        );
    }

    #[test]
    fn catalog_native_publication_rejects_manifest_role_ownership_and_untyped_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(directory.path().join("control.db"), &keys).unwrap();
        let (manifest, intents) = fixture_owned(&store);
        store.validate_native_file_catalog(manifest).unwrap();
        let mut changed = intents;
        changed[2].section = CatalogSection::FileMetadata;
        assert!(manifest.as_local_bundle(changed).is_err());
        let mut changed = intents;
        changed[0].scope = CatalogScope::Guild { guild_id: [1; 32] };
        assert!(manifest.as_local_bundle(changed).is_err());
        let mut changed = intents;
        changed[1] = changed[0];
        assert!(manifest.as_local_bundle(changed).is_err());
        let mut changed = intents;
        changed.swap(0, 1);
        assert!(
            store
                .publish_native_file_catalog(manifest, changed)
                .is_err()
        );
        assert!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap()
                .is_none()
        );
        for intent in intents {
            assert_eq!(
                store.catalog_intent_state(intent).unwrap(),
                CatalogIntentState::Building
            );
        }
        // The generic opaque API can retain the correct trees in an arbitrary
        // role order. Typed loading rejects a descriptor/manifest substitution.
        let mut substituted = manifest.as_local_bundle(intents).unwrap();
        substituted.roots.swap(0, 1);
        store.publish_catalog_bundle(&substituted).unwrap();
        assert!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .is_err()
        );
        assert!(
            store
                .publish_native_file_catalog(manifest, intents)
                .is_err()
        );
        store.cancel_catalog_bundle(manifest.id).unwrap();
        store
            .cancel_native_file_catalog_validation(manifest.id)
            .unwrap();
    }

    #[test]
    fn catalog_native_publication_sql_failures_roll_back_the_joint_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        let (manifest, intents) = fixture_owned(&store);
        store.validate_native_file_catalog(manifest).unwrap();
        for trigger in [
            "CREATE TEMP TRIGGER fail_native BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-native-bundle-v1' BEGIN SELECT RAISE(ABORT, 'injected'); END",
            "CREATE TEMP TRIGGER fail_native BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-native-bundle-v1' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_native BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-intent-v1' BEGIN SELECT RAISE(IGNORE); END",
        ] {
            store.connection.execute_batch(trigger).unwrap();
            assert!(
                store
                    .publish_native_file_catalog(manifest, intents)
                    .is_err()
            );
            assert!(
                store
                    .native_file_catalog(manifest.id, manifest.scope)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                store
                    .native_file_catalog_validation(manifest.id)
                    .unwrap()
                    .unwrap()
                    .1,
                CatalogNativeValidationState::Verified
            );
            for intent in intents {
                assert_eq!(
                    store.catalog_intent_state(intent).unwrap(),
                    CatalogIntentState::Building
                );
            }
            store
                .connection
                .execute_batch("DROP TRIGGER fail_native")
                .unwrap();
        }
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        store
            .publish_native_file_catalog(manifest, intents)
            .unwrap();
        for trigger in [
            "CREATE TEMP TRIGGER fail_native BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-native-validation-v1' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_native BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-intent-v1' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_native BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-bundle-v1' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER fail_native BEFORE DELETE ON protocol_records WHEN OLD.kind = 'catalog-native-bundle-v1' BEGIN SELECT RAISE(IGNORE); END",
        ] {
            store.connection.execute_batch(trigger).unwrap();
            assert!(
                store
                    .cancel_native_file_catalog(manifest.id, manifest.scope)
                    .is_err()
            );
            assert_eq!(
                store
                    .native_file_catalog(manifest.id, manifest.scope)
                    .unwrap(),
                Some((manifest, CatalogBundleState::Published))
            );
            assert_eq!(
                store
                    .native_file_catalog_validation(manifest.id)
                    .unwrap()
                    .unwrap()
                    .1,
                CatalogNativeValidationState::Verified
            );
            assert_eq!(
                store
                    .native_file_catalog_source(manifest.id, source(1).sector.id)
                    .unwrap(),
                Some(source(1))
            );
            for member in manifest.as_local_bundle(intents).unwrap().roots {
                assert_eq!(
                    store.catalog_intent_state(member.intent).unwrap(),
                    CatalogIntentState::Published(member.root)
                );
            }
            store
                .connection
                .execute_batch("DROP TRIGGER fail_native")
                .unwrap();
        }
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        store
            .cancel_native_file_catalog(manifest.id, manifest.scope)
            .unwrap();
        assert_eq!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap(),
            Some((manifest, CatalogBundleState::Cancelled))
        );
    }
}

//! Dataset and aggregate guild encoded-page credits. These share the original
//! page/reservation writer and charge every stored page until actual final GC.
//! SQL/WAL, source/payload allocation and traversal require enclosing policies.

use super::*;

const POLICY: &str = "catalog-page-scope-quota-v1";
const ENABLED: &str = "catalog-page-scope-quota-enabled-v1";
const USAGE: &str = "catalog-page-scope-usage-v1";
const SCOPE: &str = "catalog-page-scope-v1";
const PAGE_CHARGE: &str = "catalog-page-scope-charge-v1";
const LOAN: &str = "catalog-page-scope-loan-v1";

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Policy {
    version: u8,
    dataset: CatalogStorageQuota,
    guild: CatalogStorageQuota,
}

impl Policy {
    fn quota(self, scope: CatalogScope) -> CatalogStorageQuota {
        match scope {
            CatalogScope::Dataset { .. } => self.dataset,
            CatalogScope::Guild { .. } => self.guild,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Counts {
    stored_page_bytes: u64,
    stored_pages: u64,
    reserved_page_bytes: u64,
    reserved_pages: u64,
    open_reservations: u32,
}

impl Counts {
    fn covers(self, other: Self) -> bool {
        self.stored_page_bytes >= other.stored_page_bytes
            && self.stored_pages >= other.stored_pages
            && self.reserved_page_bytes >= other.reserved_page_bytes
            && self.reserved_pages >= other.reserved_pages
            && self.open_reservations >= other.open_reservations
    }

    fn usage(self, quota: CatalogStorageQuota) -> CatalogStorageUsage {
        CatalogStorageUsage {
            quota,
            stored_page_bytes: self.stored_page_bytes,
            stored_pages: self.stored_pages,
            reserved_page_bytes: self.reserved_page_bytes,
            reserved_pages: self.reserved_pages,
            open_reservations: self.open_reservations,
        }
    }

    fn from_usage(usage: CatalogStorageUsage) -> Self {
        Self {
            stored_page_bytes: usage.stored_page_bytes,
            stored_pages: usage.stored_pages,
            reserved_page_bytes: usage.reserved_page_bytes,
            reserved_pages: usage.reserved_pages,
            open_reservations: usage.open_reservations,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Usage {
    version: u8,
    scope: CatalogScope,
    counts: Counts,
}

fn scope_key(scope: CatalogScope) -> Result<[u8; 32], CatalogStoreError> {
    scope.validate(match scope {
        CatalogScope::Dataset { .. } => CatalogSection::FileMetadata,
        CatalogScope::Guild { .. } => CatalogSection::Checkpoint,
    })?;
    let mut hash = blake3::Hasher::new_derive_key("mutualbackup encoded page quota scope v1");
    hash.update(&canonical_bytes(&scope)?);
    Ok(*hash.finalize().as_bytes())
}

fn guild_scope(scope: CatalogScope) -> CatalogScope {
    let guild_id = match scope {
        CatalogScope::Dataset { guild_id, .. } | CatalogScope::Guild { guild_id } => guild_id,
    };
    CatalogScope::Guild { guild_id }
}

fn members(scope: CatalogScope) -> Result<String, CatalogStoreError> {
    Ok(format!(
        "catalog-page-quota-member-v1/{}",
        hex::encode(scope_key(scope)?)
    ))
}

fn policy(connection: &Connection) -> Result<Option<Policy>, CatalogStoreError> {
    match (
        bounded_record(connection, ENABLED, KEY, 1)?.as_deref(),
        bounded_record(connection, POLICY, KEY, RECORD_BYTES)?,
    ) {
        (None, None) => {
            let stale: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1, ?2, ?3, ?4)
                 OR kind GLOB 'catalog-page-quota-member-v1/*')",
                params![USAGE, SCOPE, PAGE_CHARGE, LOAN],
                |row| row.get(0),
            )?;
            if stale {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(None)
        }
        (Some([1]), Some(bytes)) => {
            let policy: Policy = decode(&bytes)?;
            if policy.version != 1 {
                return Err(DatabaseError::Integrity.into());
            }
            policy.dataset.validate()?;
            policy.guild.validate()?;
            Ok(Some(policy))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

pub(super) fn require_global_policy(
    connection: &Connection,
    global_present: bool,
) -> Result<(), CatalogStoreError> {
    if policy(connection)?.is_some() && !global_present {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn usage(
    connection: &Connection,
    scope: CatalogScope,
    policy: Policy,
) -> Result<Option<Usage>, CatalogStoreError> {
    let key = scope_key(scope)?;
    match (
        bounded_record(connection, SCOPE, &key, 1)?.as_deref(),
        bounded_record(connection, USAGE, &key, RECORD_BYTES)?,
    ) {
        (None, None) => {
            let stale: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
                [members(scope)?],
                |row| row.get(0),
            )?;
            if stale {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(None)
        }
        (Some([1]), Some(bytes)) => {
            let usage: Usage = decode(&bytes)?;
            if usage.version != 1 || usage.scope != scope {
                return Err(DatabaseError::Integrity.into());
            }
            usage.counts.usage(policy.quota(scope)).validate()?;
            Ok(Some(usage))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn ensure(
    connection: &Connection,
    scope: CatalogScope,
    policy: Policy,
) -> Result<Usage, CatalogStoreError> {
    if let Some(usage) = usage(connection, scope, policy)? {
        return Ok(usage);
    }
    let record = Usage {
        version: 1,
        scope,
        counts: Counts::default(),
    };
    let key = scope_key(scope)?;
    insert_exact(connection, SCOPE, &key, &[1])?;
    insert_exact(connection, USAGE, &key, &canonical_bytes(&record)?)?;
    if usage(connection, scope, policy)? != Some(record) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(record)
}

fn each_scope(
    scope: CatalogScope,
    mut operation: impl FnMut(CatalogScope) -> Result<(), CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    operation(scope)?;
    if matches!(scope, CatalogScope::Dataset { .. }) {
        operation(guild_scope(scope))?;
    }
    Ok(())
}

fn change(
    connection: &Connection,
    scope: CatalogScope,
    policy: Policy,
    create: bool,
    mut operation: impl FnMut(&mut Counts) -> Result<(), CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    each_scope(scope, |scope| {
        if create {
            ensure(connection, scope, policy)?
        } else {
            usage(connection, scope, policy)?.ok_or(DatabaseError::Integrity)?
        };
        Ok(())
    })?;
    require_totals(connection, scope, policy, true)?;
    each_scope(scope, |scope| {
        let mut record = usage(connection, scope, policy)?.ok_or(DatabaseError::Integrity)?;
        operation(&mut record.counts)?;
        record.counts.usage(policy.quota(scope)).validate()?;
        replace(connection, USAGE, &scope_key(scope)?, &record)?;
        if usage(connection, scope, policy)? != Some(record) {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    })?;
    require_totals(connection, scope, policy, false)
}

fn require_totals(
    connection: &Connection,
    scope: CatalogScope,
    policy: Policy,
    check_global: bool,
) -> Result<(), CatalogStoreError> {
    let guild = usage(connection, guild_scope(scope), policy)?
        .ok_or(DatabaseError::Integrity)?
        .counts;
    if matches!(scope, CatalogScope::Dataset { .. }) {
        let dataset = usage(connection, scope, policy)?
            .ok_or(DatabaseError::Integrity)?
            .counts;
        if !guild.covers(dataset) {
            return Err(DatabaseError::Integrity.into());
        }
    }
    if check_global
        && !Counts::from_usage(ledger(connection)?.ok_or(DatabaseError::Integrity)?.usage)
            .covers(guild)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn member_key(tag: u8, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(id.len() + 1);
    key.push(tag);
    key.extend(id);
    key
}

fn register_member(
    connection: &Connection,
    scope: CatalogScope,
    tag: u8,
    id: &[u8],
) -> Result<(), CatalogStoreError> {
    each_scope(scope, |scope| {
        let kind = members(scope)?;
        let key = member_key(tag, id);
        insert_exact(connection, &kind, &key, &[])?;
        if bounded_record(connection, &kind, &key, 0)?.as_deref() != Some(&[]) {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    })
}

fn require_member(
    connection: &Connection,
    scope: CatalogScope,
    policy: Policy,
    tag: u8,
    id: &[u8],
) -> Result<(), CatalogStoreError> {
    each_scope(scope, |scope| {
        if usage(connection, scope, policy)?.is_none()
            || bounded_record(connection, &members(scope)?, &member_key(tag, id), 0)?.as_deref()
                != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    })?;
    require_totals(connection, scope, policy, false)
}

fn require_loan(
    connection: &Connection,
    record: Reservation,
    policy: Policy,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, LOAN, record.intent.id.as_bytes(), RECORD_BYTES)?.as_deref()
        != Some(canonical_bytes(&(1_u8, record.intent, record.original))?.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    require_member(
        connection,
        record.intent.scope,
        policy,
        1,
        record.intent.id.as_bytes(),
    )?;
    require_totals(connection, record.intent.scope, policy, true)?;
    if !record.closed {
        each_scope(record.intent.scope, |scope| {
            let counts = usage(connection, scope, policy)?
                .ok_or(DatabaseError::Integrity)?
                .counts;
            if counts.open_reservations == 0
                || counts.reserved_page_bytes < record.remaining.page_bytes
                || counts.reserved_pages < record.remaining.pages
            {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(())
        })?;
    }
    Ok(())
}

pub(super) fn require_reservation(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(());
    };
    ledger(connection)?.ok_or(DatabaseError::Integrity)?;
    if let Some(record) = reservation(connection, intent)? {
        require_loan(connection, record, policy)?;
    } else if bounded_record(connection, LOAN, intent.id.as_bytes(), RECORD_BYTES)?.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn adopt_loan(
    connection: &Connection,
    record: Reservation,
    policy: Policy,
) -> Result<(), CatalogStoreError> {
    change(connection, record.intent.scope, policy, true, |counts| {
        if !record.closed {
            counts.reserved_page_bytes = counts
                .reserved_page_bytes
                .checked_add(record.remaining.page_bytes)
                .ok_or(DatabaseError::CapacityExceeded)?;
            counts.reserved_pages = counts
                .reserved_pages
                .checked_add(record.remaining.pages)
                .ok_or(DatabaseError::CapacityExceeded)?;
            counts.open_reservations = counts
                .open_reservations
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?;
        }
        Ok(())
    })?;
    insert_exact(
        connection,
        LOAN,
        record.intent.id.as_bytes(),
        &canonical_bytes(&(1_u8, record.intent, record.original))?,
    )?;
    register_member(
        connection,
        record.intent.scope,
        1,
        record.intent.id.as_bytes(),
    )?;
    require_loan(connection, record, policy)
}

pub(super) fn reserve(
    connection: &Connection,
    record: Reservation,
) -> Result<(), CatalogStoreError> {
    if let Some(policy) = policy(connection)? {
        if bounded_record(connection, LOAN, record.intent.id.as_bytes(), RECORD_BYTES)?.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        adopt_loan(connection, record, policy)?;
    }
    Ok(())
}

fn charge_page(connection: &Connection, page: PageMetadata) -> Result<(), CatalogStoreError> {
    insert_exact(
        connection,
        PAGE_CHARGE,
        &page.reference.hash,
        &canonical_bytes(&page)?,
    )?;
    register_member(connection, page.scope, 0, &page.reference.hash)
}

fn require_page(
    connection: &Connection,
    page: PageMetadata,
    policy: Policy,
) -> Result<(), CatalogStoreError> {
    if bounded_record(connection, PAGE_CHARGE, &page.reference.hash, RECORD_BYTES)?.as_deref()
        != Some(canonical_bytes(&page)?.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    require_member(connection, page.scope, policy, 0, &page.reference.hash)
}

pub(super) fn stage(
    connection: &Connection,
    record: Reservation,
    reference: CatalogPageRef,
    bytes: u64,
) -> Result<(), CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(());
    };
    require_loan(connection, record, policy)?;
    let page = PageMetadata {
        format_version: 1,
        scope: record.intent.scope,
        section: record.intent.section,
        reference,
    };
    if bounded_record(connection, PAGE, &reference.hash, CATALOG_PAGE_BYTES)?.is_some() {
        return require_page(connection, page, policy);
    }
    if bounded_record(connection, PAGE_CHARGE, &reference.hash, RECORD_BYTES)?.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    change(connection, page.scope, policy, false, |counts| {
        counts.reserved_page_bytes = counts
            .reserved_page_bytes
            .checked_sub(bytes)
            .ok_or(DatabaseError::Integrity)?;
        counts.reserved_pages = counts
            .reserved_pages
            .checked_sub(1)
            .ok_or(DatabaseError::Integrity)?;
        counts.stored_page_bytes = counts
            .stored_page_bytes
            .checked_add(bytes)
            .ok_or(DatabaseError::CapacityExceeded)?;
        counts.stored_pages = counts
            .stored_pages
            .checked_add(1)
            .ok_or(DatabaseError::CapacityExceeded)?;
        Ok(())
    })?;
    charge_page(connection, page)?;
    require_page(connection, page, policy)
}

pub(super) fn close(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(());
    };
    require_reservation(connection, intent)?;
    let Some(record) = reservation(connection, intent)? else {
        return Ok(());
    };
    if record.closed {
        return Ok(());
    }
    change(connection, intent.scope, policy, false, |counts| {
        counts.reserved_page_bytes = counts
            .reserved_page_bytes
            .checked_sub(record.remaining.page_bytes)
            .ok_or(DatabaseError::Integrity)?;
        counts.reserved_pages = counts
            .reserved_pages
            .checked_sub(record.remaining.pages)
            .ok_or(DatabaseError::Integrity)?;
        counts.open_reservations = counts
            .open_reservations
            .checked_sub(1)
            .ok_or(DatabaseError::Integrity)?;
        Ok(())
    })
}

fn delete_exact(connection: &Connection, kind: &str, key: &[u8]) -> Result<(), CatalogStoreError> {
    if connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
        params![kind, key],
    )? != 1
        || bounded_record(connection, kind, key, RECORD_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn collect(
    connection: &Connection,
    page: PageMetadata,
    bytes: u64,
) -> Result<(), CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(());
    };
    require_page(connection, page, policy)?;
    change(connection, page.scope, policy, false, |counts| {
        counts.stored_page_bytes = counts
            .stored_page_bytes
            .checked_sub(bytes)
            .ok_or(DatabaseError::Integrity)?;
        counts.stored_pages = counts
            .stored_pages
            .checked_sub(1)
            .ok_or(DatabaseError::Integrity)?;
        Ok(())
    })?;
    delete_exact(connection, PAGE_CHARGE, &page.reference.hash)?;
    each_scope(page.scope, |scope| {
        delete_exact(
            connection,
            &members(scope)?,
            &member_key(0, &page.reference.hash),
        )
    })
}

fn adopt(
    connection: &Connection,
    policy: Policy,
    global: CatalogStorageUsage,
) -> Result<(), CatalogStoreError> {
    let orphan_metadata: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records AS metadata WHERE metadata.kind = ?1
         AND NOT EXISTS(SELECT 1 FROM protocol_records AS page WHERE page.kind = ?2
         AND page.record_id = metadata.record_id))",
        params![META, PAGE],
        |row| row.get(0),
    )?;
    if orphan_metadata {
        return Err(DatabaseError::Integrity.into());
    }
    let mut total = Counts::default();
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(record_id) = 32 THEN record_id END,
         CASE WHEN length(bytes) BETWEEN 1 AND ?2 THEN bytes END
         FROM protocol_records WHERE kind = ?1 ORDER BY record_id",
    )?;
    let mut rows = statement.query(params![PAGE, CATALOG_PAGE_BYTES])?;
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(0)?
            .ok_or(DatabaseError::Integrity)?;
        let bytes: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(1)?
            .ok_or(DatabaseError::Integrity)?;
        let page = metadata(
            connection,
            key.try_into().map_err(|_| DatabaseError::Integrity)?,
        )?;
        page.reference
            .verify_page(page.scope, page.section, &bytes)?;
        change(connection, page.scope, policy, true, |counts| {
            counts.stored_page_bytes = counts
                .stored_page_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(DatabaseError::CapacityExceeded)?;
            counts.stored_pages = counts
                .stored_pages
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?;
            Ok(())
        })?;
        charge_page(connection, page)?;
        require_page(connection, page, policy)?;
        total.stored_page_bytes = total
            .stored_page_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(DatabaseError::CapacityExceeded)?;
        total.stored_pages = total
            .stored_pages
            .checked_add(1)
            .ok_or(DatabaseError::CapacityExceeded)?;
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(record_id) = 16 THEN record_id END,
         CASE WHEN length(bytes) BETWEEN 1 AND ?2 THEN bytes END
         FROM protocol_records WHERE kind = ?1 ORDER BY record_id",
    )?;
    let mut rows = statement.query(params![RESERVATION, RECORD_BYTES])?;
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(0)?
            .ok_or(DatabaseError::Integrity)?;
        let bytes: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(1)?
            .ok_or(DatabaseError::Integrity)?;
        let record: Reservation = decode(&bytes)?;
        let state = read_intent(connection, record.intent)?.state;
        if key != record.intent.id.as_bytes()
            || reservation(connection, record.intent)? != Some(record)
            || record.closed == (state == CatalogIntentState::Building)
        {
            return Err(DatabaseError::Integrity.into());
        }
        adopt_loan(connection, record, policy)?;
        if !record.closed {
            total.reserved_page_bytes = total
                .reserved_page_bytes
                .checked_add(record.remaining.page_bytes)
                .ok_or(DatabaseError::CapacityExceeded)?;
            total.reserved_pages = total
                .reserved_pages
                .checked_add(record.remaining.pages)
                .ok_or(DatabaseError::CapacityExceeded)?;
            total.open_reservations = total
                .open_reservations
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?;
        }
    }
    if total != Counts::from_usage(global) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

impl ControlStore {
    /// Add one retained encoded-page limit per dataset and one aggregate limit
    /// per guild. Guild totals include public packing/coding/checkpoint pages
    /// and every dataset's private/source pages. The original store limit still
    /// applies. Initial enablement authenticates one bounded page/loan at a time
    /// under their writer; all shared, cancelled and pending data stays charged.
    /// Later changes are grow-only and do not rescan retained catalogs.
    /// These quotas do not authorize a checkpoint or admit SQL/WAL/payload work.
    pub fn configure_catalog_scoped_storage_quotas(
        &self,
        dataset: CatalogStorageQuota,
        guild: CatalogStorageQuota,
    ) -> Result<(), CatalogStoreError> {
        dataset.validate()?;
        guild.validate()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let global = ledger(&transaction)?.ok_or(DatabaseError::NotReady)?.usage;
        let new = Policy {
            version: 1,
            dataset,
            guild,
        };
        if let Some(previous) = policy(&transaction)? {
            for (before, after) in [(previous.dataset, dataset), (previous.guild, guild)] {
                if after.page_bytes < before.page_bytes
                    || after.pages < before.pages
                    || after.open_reservations < before.open_reservations
                {
                    return Err(DatabaseError::CapacityExceeded.into());
                }
            }
            replace(&transaction, POLICY, KEY, &new)?;
        } else {
            insert_exact(&transaction, POLICY, KEY, &canonical_bytes(&new)?)?;
            insert_exact(&transaction, ENABLED, KEY, &[1])?;
            if policy(&transaction)? != Some(new) {
                return Err(DatabaseError::Integrity.into());
            }
            adopt(&transaction, new, global)?;
        }
        if policy(&transaction)? != Some(new) {
            return Err(DatabaseError::Integrity.into());
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn catalog_dataset_storage_usage(
        &self,
        scope: CatalogScope,
    ) -> Result<Option<CatalogStorageUsage>, CatalogStoreError> {
        if !matches!(scope, CatalogScope::Dataset { .. }) {
            return Err(DatabaseError::Conflict.into());
        }
        self.scoped_storage_usage(scope)
    }

    pub fn catalog_guild_storage_usage(
        &self,
        guild_id: [u8; 32],
    ) -> Result<Option<CatalogStorageUsage>, CatalogStoreError> {
        self.scoped_storage_usage(CatalogScope::Guild { guild_id })
    }

    fn scoped_storage_usage(
        &self,
        scope: CatalogScope,
    ) -> Result<Option<CatalogStorageUsage>, CatalogStoreError> {
        scope_key(scope)?;
        let snapshot = self.read_snapshot()?;
        let result = if let Some(policy) = policy(&snapshot)? {
            ledger(&snapshot)?.ok_or(DatabaseError::Integrity)?;
            Some(
                usage(&snapshot, scope, policy)?
                    .map_or(Counts::default(), |usage| usage.counts)
                    .usage(policy.quota(scope)),
            )
        } else {
            None
        };
        snapshot.commit()?;
        Ok(result)
    }
}

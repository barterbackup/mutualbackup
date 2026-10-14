//! Independent public custody for a fully proven predecessor. Copy one root
//! per writer transaction; never inherit private or READY payload ownership.
use super::super::packing_validation::unwrap_stream;
use super::super::retention_journal::{self as journal, Dependency, Retention};
use super::*;

const RECORD: &str = "catalog-checkpoint-ancestry-v1";
const GUARD: &str = "catalog-checkpoint-ancestry-guard-v1";
type BoundedDependencyRow = (Option<Vec<u8>>, Option<Vec<u8>>);
const ARCHIVE_BYTES: usize = mb_core::PAGED_QUORUM_CHECKPOINT_BYTES + 32768;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Receipt {
    Individual(CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpoint>),
    Directory(CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpointDirectory>),
}
impl Retention for Receipt {
    const JOURNAL: &'static str = "catalog-checkpoint-ancestry-retention-v1";
    const JOURNAL_BYTES: usize = 8192;
    const DEPENDENCIES: &'static str = "catalog-checkpoint-ancestry-dependency-v1";
    const PIN_PREFIX: u8 = 7;
    fn id(self) -> Uuid {
        match self {
            Self::Individual(r) => r.id,
            Self::Directory(r) => r.id,
        }
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        match self {
            Self::Individual(r) => r.validate(),
            Self::Directory(r) => r.validate(),
        }
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        match self {
            Self::Individual(r) => r.work(),
            Self::Directory(r) => r.work(),
        }
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        match self {
            Self::Individual(r) => r.allows(scope, section),
            Self::Directory(r) => r.allows(scope, section),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Archive {
    format_version: u16,
    receipt: Receipt,
    certificate: CatalogPublicCheckpoint,
    source_roots: u64,
    source_bytes: u64,
    source_pages: u64,
    after: Option<[u8; 32]>,
    state: CatalogPagedCheckpointRetentionState,
    roots: u64,
    bytes: u64,
    pages: u64,
}
fn read(cx: &Connection, id: Uuid) -> Result<Option<Archive>, CatalogStoreError> {
    let bytes = bounded_record(cx, RECORD, id.as_bytes(), ARCHIVE_BYTES)?;
    if bytes != bounded_record(cx, GUARD, id.as_bytes(), ARCHIVE_BYTES)? {
        return Err(DatabaseError::Integrity.into());
    }
    let Some(bytes) = bytes else { return Ok(None) };
    let a: Archive = decode_canonical(&bytes)?;
    let j = journal::require(cx, a.receipt)?;
    let (header_hash, trust, budget, proof) = match a.receipt {
        Receipt::Individual(r) => (r.checkpoint.hash()?, r.trust_hash, r.budget, r.proof_work),
        Receipt::Directory(r) => (r.checkpoint.hash()?, r.trust_hash, r.budget, r.proof_work),
    };
    let cert_hash = match a.receipt {
        Receipt::Individual(r) => r.certificate_hash,
        Receipt::Directory(r) => r.certificate_hash,
    };
    if a.format_version != 1
        || a.receipt.id() != id
        || a.certificate.hash()? != header_hash
        || canonical_bytes(&a)? != bytes
        || (j.state, j.roots, j.bytes, j.pages) != (a.state, a.roots, a.bytes, a.pages)
        || a.source_roots == 0
        || a.source_roots > a.source_pages
        || a.roots > a.source_roots
        || a.bytes > a.source_bytes
        || a.pages > a.source_pages
        || (a.state != CatalogPagedCheckpointRetentionState::Cancelled
            && (a.roots == 0) != a.after.is_none())
    {
        return Err(DatabaseError::Integrity.into());
    }
    let original_hash = match &a.certificate {
        CatalogPublicCheckpoint::Individual(c) => {
            mb_core::canonical_hash_bounded(c, mb_core::PAGED_QUORUM_CHECKPOINT_BYTES)?
        }
        CatalogPublicCheckpoint::Directory(c) => {
            mb_core::canonical_hash_bounded(c, mb_core::PAGED_QUORUM_CHECKPOINT_BYTES)?
        }
    };
    if original_hash != cert_hash || trust == [0; 32] {
        return Err(DatabaseError::Integrity.into());
    }
    budget.remaining_after(
        proof
            .checked_add(a.certificate.work()?)?
            .checked_add(archive_work(a.source_roots)?)?,
    )?;
    if a.state == CatalogPagedCheckpointRetentionState::Published
        && (a.roots, a.bytes, a.pages) != (a.source_roots, a.source_bytes, a.source_pages)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(a))
}
fn archive_work(roots: u64) -> Result<Work, CatalogStoreError> {
    Ok(Work {
        bytes: (ARCHIVE_BYTES as u64)
            .checked_mul(4)
            .and_then(|n| roots.checked_mul(2048).and_then(|r| n.checked_add(r)))
            .ok_or(DatabaseError::CapacityExceeded)?,
        records: roots
            .checked_mul(2)
            .and_then(|n| n.checked_add(4))
            .ok_or(DatabaseError::CapacityExceeded)?,
        page_occurrences: 0,
    })
}
fn write(cx: &Connection, old: &Archive, next: &Archive) -> Result<(), CatalogStoreError> {
    let before = canonical_bytes(old)?;
    let bytes = canonical_bytes(next)?;
    if bytes.len() > ARCHIVE_BYTES {
        return Err(DatabaseError::CapacityExceeded.into());
    }
    for kind in [RECORD, GUARD] {
        if cx.execute(
            "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
            params![kind, old.receipt.id().as_bytes(), bytes, before],
        )? != 1
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    if read(cx, old.receipt.id())?.as_ref() != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn source(cx: &Connection, id: Uuid) -> Result<Archive, CatalogStoreError> {
    macro_rules! owner {
        ($header:ty,$variant:ident) => {
            if let Some(j) = journal::read::<CatalogPagedCheckpointRetention<$header>>(cx, id)? {
                if j.state != CatalogPagedCheckpointRetentionState::Published {
                    return Err(DatabaseError::Conflict.into());
                }
                let certificate = paged_checkpoint_retention::owned_certificate(cx, j.retention)?;
                return Ok(Archive {
                    format_version: 1,
                    receipt: Receipt::$variant(j.retention),
                    certificate: CatalogPublicCheckpoint::$variant(certificate),
                    source_roots: j.roots,
                    source_bytes: j.bytes,
                    source_pages: j.pages,
                    after: None,
                    state: CatalogPagedCheckpointRetentionState::Building,
                    roots: 0,
                    bytes: 0,
                    pages: 0,
                });
            }
        };
    }
    owner!(mb_core::PagedGuildCheckpoint, Individual);
    owner!(mb_core::PagedGuildCheckpointDirectory, Directory);
    Err(DatabaseError::NotReady.into())
}
fn check_source(cx: &Connection, a: &Archive) -> Result<String, CatalogStoreError> {
    let expected = source(cx, a.receipt.id())?;
    if (
        expected.receipt,
        &expected.certificate,
        expected.source_roots,
        expected.source_bytes,
        expected.source_pages,
    ) != (
        a.receipt,
        &a.certificate,
        a.source_roots,
        a.source_bytes,
        a.source_pages,
    ) {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(match a.receipt {
        Receipt::Individual(r) => journal::dependencies::<
            CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpoint>,
        >(r.id),
        Receipt::Directory(r) => journal::dependencies::<
            CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpointDirectory>,
        >(r.id),
    })
}
pub(super) fn require_published(
    cx: &Connection,
    tip: CatalogCheckpointRecoveryTip,
) -> Result<(), CatalogStoreError> {
    let a = read(cx, tip.owner)?.ok_or(DatabaseError::NotReady)?;
    if a.state != CatalogPagedCheckpointRetentionState::Published
        || a.certificate.guild_id() != tip.guild_id
        || a.certificate.layout() != tip.layout
        || a.certificate.generation() != tip.generation
        || a.certificate.hash()? != tip.hash
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
pub(super) fn certificate(
    cx: &Connection,
    id: Uuid,
) -> Result<Option<CatalogPublicCheckpoint>, CatalogStoreError> {
    Ok(read(cx, id)?
        .filter(|a| a.state == CatalogPagedCheckpointRetentionState::Published)
        .map(|a| a.certificate))
}
const LINK: &str = "catalog-checkpoint-ancestry-link-v1";
const LINK_GUARD: &str = "catalog-checkpoint-ancestry-link-guard-v1";
pub(super) fn link_parent(
    cx: &Connection,
    child: Uuid,
    parent: CatalogCheckpointRecoveryTip,
) -> Result<(), CatalogStoreError> {
    require_published(cx, parent)?;
    let bytes = canonical_bytes(&parent)?;
    for kind in [LINK, LINK_GUARD] {
        insert_exact(cx, kind, child.as_bytes(), &bytes)?;
    }
    if parent_for(cx, child)? != Some(parent) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn parent_for(
    cx: &Connection,
    child: Uuid,
) -> Result<Option<CatalogCheckpointRecoveryTip>, CatalogStoreError> {
    let bytes = bounded_record(cx, LINK, child.as_bytes(), 1024)?;
    if bytes != bounded_record(cx, LINK_GUARD, child.as_bytes(), 1024)? {
        return Err(DatabaseError::Integrity.into());
    }
    let Some(bytes) = bytes else { return Ok(None) };
    let parent: CatalogCheckpointRecoveryTip = decode_canonical(&bytes)?;
    if canonical_bytes(&parent)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    require_published(cx, parent)?;
    Ok(Some(parent))
}
pub(super) fn check_parent(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
) -> Result<(), CatalogStoreError> {
    let parent = parent_for(cx, spec.id)?;
    if parent.map(|p| (p.generation, p.hash)) != spec.certificate.previous_identity()
        || parent.is_some_and(|p| p.guild_id != spec.certificate.guild_id() || p.owner == spec.id)
    {
        return Err(DatabaseError::NotReady.into());
    }
    Ok(())
}
pub(super) fn recovery_source(
    cx: &Connection,
    id: Uuid,
    original: bool,
) -> Result<Option<CatalogCheckpointRecoverySource>, CatalogStoreError> {
    let (a, archived) = if original {
        (source(cx, id)?, false)
    } else {
        let Some(a) = read(cx, id)? else {
            return Ok(None);
        };
        if a.state != CatalogPagedCheckpointRetentionState::Published {
            return Ok(None);
        }
        (a, true)
    };
    let parent = parent_for(cx, id)?;
    if parent.map(|p| (p.generation, p.hash)) != a.certificate.previous_identity()
        || parent.is_some_and(|p| p.guild_id != a.certificate.guild_id() || p.owner == id)
    {
        return Err(DatabaseError::Integrity.into());
    }
    let (trust_hash, proof_work, budget) = match a.receipt {
        Receipt::Individual(r) => (r.trust_hash, r.proof_work, r.budget),
        Receipt::Directory(r) => (r.trust_hash, r.proof_work, r.budget),
    };
    Ok(Some(CatalogCheckpointRecoverySource {
        owner: id,
        certificate: a.certificate,
        trust_hash,
        proof_work,
        budget,
        parent,
        archived,
    }))
}
impl ControlStore {
    /// Begin independent predecessor custody from a published full-proof owner.
    /// The original owner must remain published until the copy reaches EOF.
    pub fn begin_checkpoint_ancestry_archive(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some(a) = read(&tx, id)? {
            if a.state == CatalogPagedCheckpointRetentionState::Cancelled {
                return Err(DatabaseError::Conflict.into());
            }
            if a.state == CatalogPagedCheckpointRetentionState::Building {
                check_source(&tx, &a)?;
            }
            tx.commit()?;
            return Ok(());
        }
        let a = source(&tx, id)?;
        let budget = match a.receipt {
            Receipt::Individual(r) => r.budget,
            Receipt::Directory(r) => r.budget,
        };
        let proof = match a.receipt {
            Receipt::Individual(r) => r.proof_work,
            Receipt::Directory(r) => r.proof_work,
        };
        budget.remaining_after(
            proof
                .checked_add(a.certificate.work()?)?
                .checked_add(archive_work(a.source_roots)?)?,
        )?;
        journal::begin(&tx, a.receipt)?;
        let bytes = canonical_bytes(&a)?;
        for kind in [RECORD, GUARD] {
            insert_exact(&tx, kind, id.as_bytes(), &bytes)?;
        }
        if read(&tx, id)?.as_ref() != Some(&a) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(())
    }
    /// Copy at most one public root, or publish at authenticated EOF. Returns
    /// true while another bounded step is needed; interruption is resumable.
    pub fn advance_checkpoint_ancestry_archive(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let a = read(&tx, id)?.ok_or(DatabaseError::NotReady)?;
        if a.state == CatalogPagedCheckpointRetentionState::Published {
            tx.commit()?;
            return Ok(false);
        }
        if a.state != CatalogPagedCheckpointRetentionState::Building {
            return Err(DatabaseError::Conflict.into());
        }
        let kind = check_source(&tx, &a)?;
        let row:Option<BoundedDependencyRow>=tx.query_row("SELECT CASE WHEN length(record_id)=32 THEN record_id END, CASE WHEN length(bytes)<=?3 THEN bytes END FROM protocol_records WHERE kind=?1 AND (?2 IS NULL OR record_id>?2) ORDER BY record_id LIMIT 1",params![kind,a.after.map(|h|h.to_vec()),RECORD_BYTES],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let mut next = a.clone();
        if let Some((key, bytes)) = row {
            let key: [u8; 32] = key
                .ok_or(DatabaseError::Integrity)?
                .try_into()
                .map_err(|_| DatabaseError::Integrity)?;
            let bytes = bytes.ok_or(DatabaseError::Integrity)?;
            let dep: Dependency = decode_canonical(&bytes)?;
            let source_pin = match a.receipt {
                Receipt::Individual(r) => journal::pin_id::<
                    CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpoint>,
                >(r.id),
                Receipt::Directory(r) => journal::pin_id::<
                    CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpointDirectory>,
                >(r.id),
            };
            if dep.root.hash != key
                || canonical_bytes(&dep)? != bytes
                || bounded_record(&tx, &pins(key), &source_pin, 0)?.as_deref() != Some(&[])
            {
                return Err(DatabaseError::Integrity.into());
            }
            journal::retain(&tx, a.receipt, dep)?;
            next.after = Some(key);
        } else {
            if (a.roots, a.bytes, a.pages) != (a.source_roots, a.source_bytes, a.source_pages) {
                return Err(DatabaseError::Integrity.into());
            }
            journal::publish(&tx, a.receipt)?;
        }
        let j = journal::require(&tx, a.receipt)?;
        next.state = j.state;
        next.roots = j.roots;
        next.bytes = j.bytes;
        next.pages = j.pages;
        check_source(&tx, &a)?;
        write(&tx, &a, &next)?;
        tx.commit()?;
        Ok(next.state != CatalogPagedCheckpointRetentionState::Published)
    }
    /// Read an independently owned original certificate after source retirement.
    pub fn checkpoint_ancestry_certificate(
        &self,
        id: Uuid,
    ) -> Result<Option<CatalogPublicCheckpoint>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let value = certificate(&tx, id)?;
        tx.commit()?;
        Ok(value)
    }
    /// Serve only a proven path through a public root held by this archive.
    pub fn checkpoint_ancestry_page(
        &self,
        id: Uuid,
        path: &mb_core::CatalogPagePath,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        path.validate()?;
        let tx = self.read_snapshot()?;
        let Some(a) = read(&tx, id)? else {
            tx.commit()?;
            return Ok(None);
        };
        if a.state != CatalogPagedCheckpointRetentionState::Published {
            tx.commit()?;
            return Ok(None);
        }
        let dep = Dependency {
            scope: path.scope,
            section: path.section,
            root: path.pages[0],
        };
        dep.validate(a.receipt)?;
        if bounded_record(
            &tx,
            &journal::dependencies::<Receipt>(id),
            &dep.root.hash,
            RECORD_BYTES,
        )?
        .as_deref()
            != Some(canonical_bytes(&dep)?.as_slice())
            || bounded_record(
                &tx,
                &pins(dep.root.hash),
                &journal::pin_id::<Receipt>(id),
                0,
            )?
            .as_deref()
                != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        let value = unwrap_stream(path.read(&mut |reference| {
            read_page(
                &tx,
                PageMetadata {
                    format_version: 1,
                    scope: path.scope,
                    section: path.section,
                    reference,
                },
            )
        }))?;
        tx.commit()?;
        Ok(Some(value))
    }

    /// Cancellation is fenced while recovery progress can need this generation.
    pub fn cancel_checkpoint_ancestry_archive(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let a = read(&tx, id)?.ok_or(DatabaseError::NotReady)?;
        if recovery_tip::read(&tx)?.is_some_and(|tip| {
            tip.guild_id == a.certificate.guild_id() && tip.generation >= a.certificate.generation()
        }) {
            return Err(DatabaseError::Conflict.into());
        }
        journal::cancel::<Receipt>(&tx, id)?;
        let next = Archive {
            state: CatalogPagedCheckpointRetentionState::Cancelled,
            ..a.clone()
        };
        write(&tx, &a, &next)?;
        tx.commit()?;
        Ok(())
    }
    pub fn release_checkpoint_ancestry_archive_step(
        &self,
        id: Uuid,
    ) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let a = read(&tx, id)?.ok_or(DatabaseError::NotReady)?;
        if a.state != CatalogPagedCheckpointRetentionState::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let changed = journal::release::<Receipt>(&tx, id)?;
        let j = journal::require(&tx, a.receipt)?;
        let next = Archive {
            roots: j.roots,
            bytes: j.bytes,
            pages: j.pages,
            ..a.clone()
        };
        write(&tx, &a, &next)?;
        tx.commit()?;
        Ok(changed)
    }
}

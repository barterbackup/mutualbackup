//! Checkpoint filesystem work outside the SQL writer, then publish by exact
//! attempt/generation CAS. This journal never authorizes source data or pins.
use super::*;
use crate::{
    ANCHOR_DISCOVERY_CHECKPOINT_BYTES, AnchorAreaDiscovery, AnchorAreaDiscoveryStep, AnchorError,
    StableAnchorAreaLocator,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const ANCHOR_DISCOVERY_JOURNAL_KIND: &str = "anchor-area-discovery-v1";
const MAX_JOBS: usize = 32;
const JOURNAL_BYTES: usize = ANCHOR_DISCOVERY_CHECKPOINT_BYTES + 64;
const FENCE_KIND: &str = "anchor-area-discovery-fence-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorDiscoveryJobStatus {
    pub area_id: Uuid,
    pub journal_bytes: u64,
    pub attempt: Option<Uuid>,
    pub generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorDiscoveryJobPage {
    pub jobs: Vec<AnchorDiscoveryJobStatus>,
    pub next_after: Option<Uuid>,
}

#[derive(Serialize, Deserialize)]
struct Location(#[serde(with = "crate::raw_path_bytes")] PathBuf);

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u8,
    attempt: Uuid,
    generation: u64,
    cursor: Vec<u8>,
}

impl ControlStore {
    /// Inspect one bounded page without opening any source or changing progress.
    /// An unreadable journal still appears, so operators can reset it explicitly.
    pub fn anchor_discovery_jobs(
        &self,
        after: Option<Uuid>,
    ) -> Result<AnchorDiscoveryJobPage, DatabaseError> {
        let mut statement = self.connection.prepare(
            "SELECT CASE WHEN length(record_id) = 16 THEN record_id END, length(bytes), CASE WHEN length(bytes) <= ?3 THEN bytes END
             FROM protocol_records WHERE kind = ?1 AND record_id > ?2
             ORDER BY record_id LIMIT ?4")?;
        let mut rows = statement.query(params![
            ANCHOR_DISCOVERY_JOURNAL_KIND,
            after.map(|id| id.as_bytes().to_vec()).unwrap_or_default(),
            JOURNAL_BYTES as i64,
            (MAX_JOBS + 1) as i64
        ])?;
        let mut jobs = Vec::new();
        let mut next_after = None;
        while let Some(row) = rows.next()? {
            if jobs.len() == MAX_JOBS {
                next_after = jobs
                    .last()
                    .map(|job: &AnchorDiscoveryJobStatus| job.area_id);
                break;
            }
            let key: Vec<u8> = row
                .get::<_, Option<Vec<u8>>>(0)?
                .ok_or(DatabaseError::Integrity)?;
            let area_id = Uuid::from_slice(&key).map_err(|_| DatabaseError::Integrity)?;
            let size: i64 = row.get(1)?;
            let journal = row.get::<_, Option<Vec<u8>>>(2)?.and_then(|bytes| {
                let journal: Journal = mb_core::decode_canonical(&bytes).ok()?;
                (journal.version == 1
                    && !journal.attempt.is_nil()
                    && mb_core::canonical_bytes_bounded(&journal, JOURNAL_BYTES).ok()? == bytes)
                    .then_some(journal)
            });
            jobs.push(AnchorDiscoveryJobStatus {
                area_id,
                journal_bytes: u64::try_from(size).map_err(|_| DatabaseError::Integrity)?,
                attempt: journal.as_ref().map(|job| job.attempt),
                generation: journal.map(|job| job.generation),
            });
        }
        Ok(AnchorDiscoveryJobPage { jobs, next_after })
    }

    /// Explicitly abandon current assistance and release its quota slot. The
    /// durable epoch invalidates work started before this reset, including a
    /// publisher that originally observed no journal. No source/pin is touched.
    pub fn reset_anchor_area_discovery(&self, area_id: Uuid) -> Result<bool, DatabaseError> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let existed: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1 AND record_id = ?2)",
            params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes()],
            |row| row.get(0),
        )?;
        Self::rotate_discovery_fence(&transaction, area_id)?;
        let removed = transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes()],
        )?;
        if removed != usize::from(existed) {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit()?;
        Ok(existed)
    }

    fn rotate_discovery_fence(
        transaction: &rusqlite::Transaction<'_>,
        area_id: Uuid,
    ) -> Result<Vec<u8>, DatabaseError> {
        let fence = Uuid::new_v4().as_bytes().to_vec();
        if transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
            ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![FENCE_KIND, area_id.as_bytes(), &fence],
        )? != 1
        {
            return Err(DatabaseError::Conflict);
        }
        Ok(fence)
    }

    fn discovery_fence(&self, area_id: Uuid) -> Result<Vec<u8>, DatabaseError> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let existing: Option<Option<Vec<u8>>> = transaction.query_row("SELECT CASE WHEN length(bytes) = 16 THEN bytes END FROM protocol_records WHERE kind = ?1 AND record_id = ?2", params![FENCE_KIND, area_id.as_bytes()], |row| row.get(0)).optional()?;
        let fence = match existing {
            Some(Some(bytes)) if Uuid::from_slice(&bytes).is_ok_and(|id| !id.is_nil()) => bytes,
            Some(_) => return Err(DatabaseError::Integrity),
            None => Self::rotate_discovery_fence(&transaction, area_id)?,
        };
        transaction.commit()?;
        Ok(fence)
    }

    /// Bounded local assistance shared by capture, serving and cleanup.
    pub fn anchor_area_location_hint(&self, area_id: Uuid) -> anyhow::Result<Option<PathBuf>> {
        Ok(self
            .get_record_bounded("anchor-area-location", area_id.as_bytes(), 4_112)?
            .and_then(|bytes| mb_core::decode_canonical::<Location>(&bytes).ok())
            .map(|path| path.0)
            .filter(|path| path.as_os_str().as_encoded_bytes().len() <= 4_096))
    }

    /// Resolve assistance without authorizing source contents or publication.
    pub fn resolve_anchor_area_location(
        &self,
        area: &StableAnchorAreaLocator,
    ) -> anyhow::Result<PathBuf> {
        let hint = self.anchor_area_location_hint(area.area_id)?;
        if let Some(path) = area.known_path(hint.as_deref()) {
            return Ok(path);
        }
        if !self.is_read_only()? {
            match self.advance_anchor_area_discovery(area) {
                Ok(AnchorAreaDiscoveryStep::Found(path)) => return Ok(path),
                Ok(AnchorAreaDiscoveryStep::Pending) => {
                    return Err(AnchorError::AnchorAreaDiscoveryPending.into());
                }
                Ok(AnchorAreaDiscoveryStep::Missing) => {
                    return Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()).into());
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<AnchorError>(),
                        Some(AnchorError::UnsupportedSourceOperation(
                            "persistent anchor directory cookies"
                        ))
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(crate::anchor::resolve_anchor_area_with_hint(
            area,
            hint.as_deref(),
        )?)
    }

    /// Complete assistance only after the caller's native operation validates
    /// its own authority. Read-only inspection never changes local records.
    pub fn remember_anchor_area_location(
        &self,
        area_id: Uuid,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        if self.is_read_only()? {
            return Ok(());
        }
        if path.as_os_str().as_encoded_bytes().len() > 4_096 {
            return Err(AnchorError::AnchorAreaDiscoveryLimit.into());
        }
        if self.anchor_area_location_hint(area_id)?.as_deref() == Some(path)
            && self
                .get_record_bounded(
                    ANCHOR_DISCOVERY_JOURNAL_KIND,
                    area_id.as_bytes(),
                    JOURNAL_BYTES,
                )?
                .is_none()
        {
            return Ok(());
        }
        let bytes = mb_core::canonical_bytes_bounded(&Location(path.to_path_buf()), 4_112)?;
        Ok(self.finish_anchor_area_discovery(area_id, &bytes)?)
    }

    /// Advance one durable relocation job. Pending work survives process/cache
    /// loss. A stale writer returns Pending and never overwrites newer progress.
    pub fn advance_anchor_area_discovery(
        &self,
        area: &StableAnchorAreaLocator,
    ) -> anyhow::Result<AnchorAreaDiscoveryStep> {
        let fence = self.discovery_fence(area.area_id)?;
        let expected = self.get_record_bounded(
            ANCHOR_DISCOVERY_JOURNAL_KIND,
            area.area_id.as_bytes(),
            JOURNAL_BYTES,
        )?;
        let (attempt, generation, mut discovery) = if let Some(bytes) = &expected {
            let journal: Journal = mb_core::decode_canonical(bytes)?;
            if journal.version != 1
                || journal.attempt.is_nil()
                || mb_core::canonical_bytes_bounded(&journal, JOURNAL_BYTES)? != *bytes
            {
                return Err(DatabaseError::Integrity.into());
            }
            let generation = journal
                .generation
                .checked_add(1)
                .ok_or(DatabaseError::Conflict)?;
            let resumed = match AnchorAreaDiscovery::resume(area, &journal.cursor) {
                Ok(discovery) => discovery,
                Err(AnchorError::SourceChanged(_)) => AnchorAreaDiscovery::start(area)?,
                Err(error) => return Err(error.into()),
            };
            (journal.attempt, generation, resumed)
        } else {
            (Uuid::new_v4(), 0, AnchorAreaDiscovery::start(area)?)
        };
        let mut step = match discovery.advance() {
            Ok(step) => step,
            Err(AnchorError::SourceChanged(_)) => {
                discovery = AnchorAreaDiscovery::start(area)?;
                AnchorAreaDiscoveryStep::Pending
            }
            Err(error) => return Err(error.into()),
        };
        let next = if step == AnchorAreaDiscoveryStep::Missing {
            None
        } else {
            let cursor = match discovery.checkpoint() {
                Ok(cursor) => cursor,
                Err(AnchorError::SourceChanged(_)) => {
                    // Persist a fresh cursor rather than stale directory cookies.
                    discovery = AnchorAreaDiscovery::start(area)?;
                    step = AnchorAreaDiscoveryStep::Pending;
                    discovery.checkpoint()?
                }
                Err(error) => return Err(error.into()),
            };
            Some(mb_core::canonical_bytes_bounded(
                &Journal {
                    version: 1,
                    attempt,
                    generation,
                    cursor,
                },
                JOURNAL_BYTES,
            )?)
        };
        if !self.commit_anchor_discovery_fenced(
            area.area_id,
            expected.as_deref(),
            next.as_deref(),
            Some(&fence),
        )? {
            return Ok(AnchorAreaDiscoveryStep::Pending);
        }
        Ok(step)
    }

    #[cfg(test)]
    fn commit_anchor_discovery(
        &self,
        area_id: Uuid,
        expected: Option<&[u8]>,
        next: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        self.commit_anchor_discovery_fenced(area_id, expected, next, None)
    }

    fn commit_anchor_discovery_fenced(
        &self,
        area_id: Uuid,
        expected: Option<&[u8]>,
        next: Option<&[u8]>,
        fence: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if let Some(expected_fence) = fence {
            let current: Option<Option<Vec<u8>>> = transaction.query_row("SELECT CASE WHEN length(bytes) = 16 THEN bytes END FROM protocol_records WHERE kind = ?1 AND record_id = ?2", params![FENCE_KIND, area_id.as_bytes()], |row| row.get(0)).optional()?;
            if current.as_ref().and_then(Option::as_deref) != Some(expected_fence) {
                return Ok(false);
            }
        }
        let actual = transaction.query_row(
            "SELECT CASE WHEN length(bytes) <= ?3 THEN bytes END FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes(), JOURNAL_BYTES as i64],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ).optional()?;
        if actual.as_ref().is_some_and(Option::is_none) {
            return Err(DatabaseError::Integrity.into());
        }
        if actual.as_ref().and_then(Option::as_deref) != expected {
            return Ok(false);
        }
        match next {
            Some(next) if expected.is_some() => {
                if transaction.execute("UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?4",
                    params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes(), next, expected])? != 1 { return Err(DatabaseError::Conflict.into()); }
            }
            Some(next) => {
                let count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM (SELECT 1 FROM protocol_records WHERE kind = ?1 LIMIT ?2)",
                    params![ANCHOR_DISCOVERY_JOURNAL_KIND, MAX_JOBS as i64], |row| row.get(0))?;
                if count >= MAX_JOBS as i64 { return Err(AnchorError::AnchorAreaDiscoveryLimit.into()); }
                if transaction.execute("INSERT INTO protocol_records (kind, record_id, bytes) VALUES (?1, ?2, ?3)",
                    params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes(), next])? != 1 { return Err(DatabaseError::Conflict.into()); }
            }
            None => {
                let removed = transaction.execute("DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                    params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes(), expected])?;
                if removed != usize::from(expected.is_some()) { return Err(DatabaseError::Conflict.into()); }
                Self::rotate_discovery_fence(&transaction, area_id)?;
            }
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Publish an already authenticated location and retire its assistance
    /// cursor atomically. Neither an ignored hint nor ignored cleanup may commit.
    pub fn finish_anchor_area_discovery(
        &self,
        area_id: Uuid,
        hint: &[u8],
    ) -> Result<(), DatabaseError> {
        if hint.len() > 4_112 {
            return Err(DatabaseError::Integrity);
        }
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let had_job: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1 AND record_id = ?2)",
            params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes()],
            |row| row.get(0),
        )?;
        Self::rotate_discovery_fence(&transaction, area_id)?;
        if transaction.execute("INSERT INTO protocol_records (kind, record_id, bytes) VALUES ('anchor-area-location', ?1, ?2)
            ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![area_id.as_bytes(), hint])? != 1 { return Err(DatabaseError::Conflict); }
        let removed = transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![ANCHOR_DISCOVERY_JOURNAL_KIND, area_id.as_bytes()],
        )?;
        if removed != usize::from(had_job) {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn discovery_status_pages_unreadable_jobs_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[8; 32]).unwrap();
        let attempt = Uuid::new_v4();
        let valid = mb_core::canonical_bytes(&Journal {
            version: 1,
            attempt,
            generation: 7,
            cursor: vec![],
        })
        .unwrap();
        // Include over-quota imported state so listing must expose every page.
        for n in 1..=34 {
            let bytes = match n {
                2 => vec![0; JOURNAL_BYTES + 1],
                3 => b"corrupt".to_vec(),
                _ => valid.clone(),
            };
            store
                .put_record(
                    ANCHOR_DISCOVERY_JOURNAL_KIND,
                    Uuid::from_u128(n).as_bytes(),
                    &bytes,
                )
                .unwrap();
        }
        drop(store);
        let original = fs::read(&path).unwrap();
        let store = ControlStore::open_existing_read_only_with_key(&path, &[8; 32]).unwrap();
        let first = store.anchor_discovery_jobs(None).unwrap();
        assert_eq!(first.jobs.len(), MAX_JOBS);
        assert_eq!(first.next_after, Some(Uuid::from_u128(32)));
        assert_eq!(first.jobs[0].attempt, Some(attempt));
        assert_eq!(first.jobs[0].generation, Some(7));
        assert_eq!(first.jobs[1].journal_bytes, (JOURNAL_BYTES + 1) as u64);
        assert_eq!(first.jobs[1].attempt, None);
        assert_eq!(first.jobs[2].generation, None);
        let second = store.anchor_discovery_jobs(first.next_after).unwrap();
        assert_eq!(
            second
                .jobs
                .iter()
                .map(|job| job.area_id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(33), Uuid::from_u128(34)]
        );
        assert_eq!(second.next_after, None);
        assert!(
            store
                .reset_anchor_area_discovery(Uuid::from_u128(2))
                .is_err()
        );
        drop(store);
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn discovery_reset_fences_absence_aba_and_old_progress_across_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let old = ControlStore::open_with_key(&path, &[8; 32]).unwrap();
        let area = Uuid::new_v4();
        let original_fence = old.discovery_fence(area).unwrap();
        let current = ControlStore::open_existing_with_key(&path, &[8; 32]).unwrap();
        assert!(
            current
                .commit_anchor_discovery_fenced(
                    area,
                    None,
                    Some(b"old progress"),
                    Some(&original_fence)
                )
                .unwrap()
        );
        assert!(current.reset_anchor_area_discovery(area).unwrap());
        drop(current);
        let current = ControlStore::open_existing_with_key(&path, &[8; 32]).unwrap();
        // Absence is the same as the stale publisher originally saw; its epoch isn't.
        assert!(
            !old.commit_anchor_discovery_fenced(
                area,
                None,
                Some(b"resurrected"),
                Some(&original_fence)
            )
            .unwrap()
        );
        assert!(
            !old.commit_anchor_discovery_fenced(
                area,
                Some(b"old progress"),
                Some(b"stale"),
                Some(&original_fence)
            )
            .unwrap()
        );
        let fresh_fence = current.discovery_fence(area).unwrap();
        assert_ne!(fresh_fence, original_fence);
        assert!(
            current
                .commit_anchor_discovery_fenced(area, None, Some(b"fresh"), Some(&fresh_fence))
                .unwrap()
        );
        current
            .finish_anchor_area_discovery(area, b"verified hint")
            .unwrap();
        assert!(
            !old.commit_anchor_discovery_fenced(
                area,
                None,
                Some(b"late completion"),
                Some(&fresh_fence)
            )
            .unwrap()
        );
        let completed_fence = current.discovery_fence(area).unwrap();
        assert!(!current.reset_anchor_area_discovery(area).unwrap());
        assert!(
            !old.commit_anchor_discovery_fenced(
                area,
                None,
                Some(b"late absence"),
                Some(&completed_fence)
            )
            .unwrap()
        );
        assert_eq!(
            current
                .get_record("anchor-area-location", area.as_bytes())
                .unwrap()
                .unwrap(),
            b"verified hint"
        );
        assert!(current.anchor_discovery_jobs(None).unwrap().jobs.is_empty());
    }

    #[test]
    fn discovery_reset_releases_quota_and_rolls_back_ignored_writes() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[8; 32]).unwrap();
        let area = Uuid::from_u128(1);
        let fence = store.discovery_fence(area).unwrap();
        for n in 1..=MAX_JOBS {
            assert!(
                store
                    .commit_anchor_discovery(Uuid::from_u128(n as u128), None, Some(b"unreadable"))
                    .unwrap()
            );
        }
        let next = Uuid::from_u128(100);
        assert!(
            store
                .commit_anchor_discovery(next, None, Some(b"new"))
                .is_err()
        );
        store
            .put_record("anchor-area-location", area.as_bytes(), b"saved hint")
            .unwrap();
        store
            .put_record("physical-pin", area.as_bytes(), b"preserved pin")
            .unwrap();
        for trigger in [
            "CREATE TEMP TRIGGER deny_reset BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'anchor-area-discovery-fence-v1' BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TEMP TRIGGER deny_reset BEFORE DELETE ON protocol_records WHEN OLD.kind = 'anchor-area-discovery-v1' BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            store.connection.execute_batch(trigger).unwrap();
            assert!(store.reset_anchor_area_discovery(area).is_err());
            assert_eq!(store.discovery_fence(area).unwrap(), fence);
            assert_eq!(
                store
                    .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, area.as_bytes())
                    .unwrap()
                    .unwrap(),
                b"unreadable"
            );
            store
                .connection
                .execute_batch("DROP TRIGGER deny_reset")
                .unwrap();
        }
        assert!(store.reset_anchor_area_discovery(area).unwrap());
        assert!(
            store
                .commit_anchor_discovery(next, None, Some(b"new"))
                .unwrap()
        );
        assert_eq!(
            store.anchor_discovery_jobs(None).unwrap().jobs.len(),
            MAX_JOBS
        );
        assert_eq!(
            store
                .get_record("anchor-area-location", area.as_bytes())
                .unwrap()
                .unwrap(),
            b"saved hint"
        );
        assert_eq!(
            store
                .get_record("physical-pin", area.as_bytes())
                .unwrap()
                .unwrap(),
            b"preserved pin"
        );
        // Explicit reset also repairs malformed assistance fences, without loading them.
        store
            .put_record(FENCE_KIND, area.as_bytes(), &vec![0; JOURNAL_BYTES + 1])
            .unwrap();
        assert!(store.discovery_fence(area).is_err());
        assert!(!store.reset_anchor_area_discovery(area).unwrap());
        assert_eq!(store.discovery_fence(area).unwrap().len(), 16);
    }

    #[test]
    fn anchor_discovery_cursor_survives_fresh_processes() {
        if let Some(input) = std::env::var_os("MB_ANCHOR_DISCOVERY_CHILD") {
            let input = PathBuf::from(input);
            let area: StableAnchorAreaLocator =
                mb_core::decode_canonical(&fs::read(&input).unwrap()).unwrap();
            let state = input.parent().unwrap();
            let store =
                ControlStore::open_existing_with_key(state.join("control.db"), &[8; 32]).unwrap();
            let status = match store.advance_anchor_area_discovery(&area).unwrap() {
                AnchorAreaDiscoveryStep::Pending => "pending",
                AnchorAreaDiscoveryStep::Found(path) => {
                    assert_eq!(
                        path,
                        area.volume_root_hint.join(".mutualbackup-anchors-target")
                    );
                    "found"
                }
                other => panic!("{other:?}"),
            };
            fs::write(state.join("status"), status).unwrap();
            return;
        }
        process_fixture(None);
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn anchor_discovery_btrfs_cursor_survives_fresh_processes() {
        let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").unwrap();
        process_fixture(Some(Path::new(&root)));
    }

    fn process_fixture(root: Option<&Path>) {
        let temp = match root {
            Some(root) => tempfile::tempdir_in(root).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let scan = temp.path().join("scan");
        let state = temp.path().join("state");
        fs::create_dir(&scan).unwrap();
        fs::create_dir(&state).unwrap();
        let area = StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            filesystem_id: crate::filesystem_identity(&scan).unwrap().stable_id,
            path_hint: scan.join("old-area"),
            volume_root_hint: scan.clone(),
        };
        for n in 0..6_000 {
            fs::write(scan.join(format!("entry-{n}")), []).unwrap();
        }
        let target = scan.join(".mutualbackup-anchors-target");
        fs::create_dir(&target).unwrap();
        fs::write(
            target.join(".mutualbackup-anchor-area-v1"),
            format!("mutualbackup-anchor-area-v1\n{}\n", area.area_id),
        )
        .unwrap();
        let input = state.join("input");
        fs::write(&input, mb_core::canonical_bytes(&area).unwrap()).unwrap();
        drop(ControlStore::open_with_key(state.join("control.db"), &[8; 32]).unwrap());
        let mut previous: Option<(Uuid, u64, Vec<u8>)> = None;
        let mut completed = false;
        for _ in 0..30 {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "database::anchor_discovery::tests::anchor_discovery_cursor_survives_fresh_processes", "--test-threads=1"])
                .env("MB_ANCHOR_DISCOVERY_CHILD", &input).output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let store =
                ControlStore::open_existing_read_only_with_key(state.join("control.db"), &[8; 32])
                    .unwrap();
            let bytes = store
                .get_record_bounded(
                    ANCHOR_DISCOVERY_JOURNAL_KIND,
                    area.area_id.as_bytes(),
                    JOURNAL_BYTES,
                )
                .unwrap()
                .unwrap();
            let journal: Journal = mb_core::decode_canonical(&bytes).unwrap();
            if let Some((attempt, generation, cursor)) = &previous {
                assert_eq!(journal.attempt, *attempt);
                assert!(journal.generation > *generation);
                assert_ne!(&journal.cursor, cursor);
            }
            if fs::read_to_string(state.join("status")).unwrap() == "found" {
                let mut reopened = AnchorAreaDiscovery::resume(&area, &journal.cursor).unwrap();
                assert_eq!(
                    reopened.advance().unwrap(),
                    AnchorAreaDiscoveryStep::Found(target.clone())
                );
                completed = true;
                break;
            }
            previous = Some((journal.attempt, journal.generation, journal.cursor));
        }
        assert!(completed && previous.is_some());
        let store =
            ControlStore::open_existing_with_key(state.join("control.db"), &[8; 32]).unwrap();
        store
            .finish_anchor_area_discovery(area.area_id, b"verified location")
            .unwrap();
        assert!(
            store
                .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, area.area_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_record("anchor-area-location", area.area_id.as_bytes())
                .unwrap()
                .unwrap(),
            b"verified location"
        );
    }

    #[test]
    fn anchor_discovery_missing_corrupt_oversized_and_overflowing_jobs_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[8; 32]).unwrap();
        let area = StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            filesystem_id: 0,
            path_hint: temp.path().join("missing"),
            volume_root_hint: temp.path().to_path_buf(),
        };
        let mut missing = false;
        for _ in 0..20 {
            if store.advance_anchor_area_discovery(&area).unwrap()
                == AnchorAreaDiscoveryStep::Missing
            {
                missing = true;
                break;
            }
        }
        assert!(missing);
        assert!(
            store
                .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, area.area_id.as_bytes())
                .unwrap()
                .is_none()
        );
        let cursor = AnchorAreaDiscovery::start(&area)
            .unwrap()
            .checkpoint()
            .unwrap();
        let invalid = [
            mb_core::canonical_bytes(&Journal {
                version: 2,
                attempt: Uuid::new_v4(),
                generation: 0,
                cursor: cursor.clone(),
            })
            .unwrap(),
            mb_core::canonical_bytes(&Journal {
                version: 1,
                attempt: Uuid::nil(),
                generation: 0,
                cursor: cursor.clone(),
            })
            .unwrap(),
            mb_core::canonical_bytes(&Journal {
                version: 1,
                attempt: Uuid::new_v4(),
                generation: u64::MAX,
                cursor,
            })
            .unwrap(),
            vec![0; JOURNAL_BYTES + 1],
        ];
        for bytes in invalid {
            store
                .put_record(
                    ANCHOR_DISCOVERY_JOURNAL_KIND,
                    area.area_id.as_bytes(),
                    &bytes,
                )
                .unwrap();
            assert!(store.advance_anchor_area_discovery(&area).is_err());
            assert_eq!(
                store
                    .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, area.area_id.as_bytes())
                    .unwrap()
                    .unwrap(),
                bytes
            );
        }
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn anchor_discovery_btrfs_source_loss_retires_missing_job() {
        let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").unwrap();
        let temp = tempfile::tempdir_in(root).unwrap();
        let scan = temp.path().join("scan");
        let state = temp.path().join("state");
        fs::create_dir(&scan).unwrap();
        fs::create_dir(&state).unwrap();
        let area = StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            filesystem_id: crate::filesystem_identity(&scan).unwrap().stable_id,
            path_hint: scan.join("old-area"),
            volume_root_hint: scan.clone(),
        };
        let target = scan.join(".mutualbackup-anchors-target");
        fs::create_dir(&target).unwrap();
        fs::write(
            target.join(".mutualbackup-anchor-area-v1"),
            format!("mutualbackup-anchor-area-v1\n{}\n", area.area_id),
        )
        .unwrap();
        let store = ControlStore::open_with_key(state.join("control.db"), &[8; 32]).unwrap();
        let mut found = false;
        for _ in 0..30 {
            if store.advance_anchor_area_discovery(&area).unwrap()
                == AnchorAreaDiscoveryStep::Found(target.clone())
            {
                found = true;
                break;
            }
        }
        assert!(found);
        fs::remove_dir_all(target).unwrap();
        let mut missing = false;
        for _ in 0..30 {
            if store.advance_anchor_area_discovery(&area).unwrap()
                == AnchorAreaDiscoveryStep::Missing
            {
                missing = true;
                break;
            }
        }
        assert!(missing);
        assert!(
            store
                .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, area.area_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_record("anchor-area-location", area.area_id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn anchor_discovery_cas_quota_faults_and_atomic_hint_completion() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[8; 32]).unwrap();
        let id = Uuid::new_v4();
        assert!(
            store
                .commit_anchor_discovery(id, None, Some(b"one"))
                .unwrap()
        );
        assert!(
            store
                .commit_anchor_discovery(id, Some(b"one"), Some(b"two"))
                .unwrap()
        );
        assert!(
            !store
                .commit_anchor_discovery(id, Some(b"one"), Some(b"stale"))
                .unwrap()
        );
        assert!(!store.commit_anchor_discovery(id, None, None).unwrap());
        for n in 1..MAX_JOBS {
            assert!(
                store
                    .commit_anchor_discovery(Uuid::from_u128(n as u128), None, Some(b"pending"))
                    .unwrap()
            );
        }
        assert!(
            store
                .commit_anchor_discovery(Uuid::new_v4(), None, Some(b"excess"))
                .is_err()
        );
        let original_fence = store.discovery_fence(id).unwrap();
        for target in ["hint", "cleanup"] {
            let trigger = if target == "hint" {
                "CREATE TEMP TRIGGER deny_discovery BEFORE INSERT ON protocol_records WHEN NEW.kind = 'anchor-area-location' BEGIN SELECT RAISE(IGNORE); END;"
            } else {
                "CREATE TEMP TRIGGER deny_discovery BEFORE DELETE ON protocol_records WHEN OLD.kind = 'anchor-area-discovery-v1' BEGIN SELECT RAISE(IGNORE); END;"
            };
            store.connection.execute_batch(trigger).unwrap();
            assert!(store.finish_anchor_area_discovery(id, b"location").is_err());
            assert_eq!(store.discovery_fence(id).unwrap(), original_fence);
            assert_eq!(
                store
                    .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, id.as_bytes())
                    .unwrap()
                    .unwrap(),
                b"two"
            );
            assert!(
                store
                    .get_record("anchor-area-location", id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            store
                .connection
                .execute_batch("DROP TRIGGER deny_discovery")
                .unwrap();
        }
        store.finish_anchor_area_discovery(id, b"location").unwrap();
        assert!(
            store
                .get_record(ANCHOR_DISCOVERY_JOURNAL_KIND, id.as_bytes())
                .unwrap()
                .is_none()
        );
    }
}

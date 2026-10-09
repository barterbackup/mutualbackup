use super::*;
use mb_core::canonical_bytes_bounded;
use std::os::unix::fs::MetadataExt;

pub const ANCHOR_DISCOVERY_CHECKPOINT_BYTES: usize = 576 * 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnchorAreaDiscoveryStep {
    Pending,
    Found(PathBuf),
    Missing,
}

/// Local, bounded discovery state. A checkpoint is location assistance, never
/// source authority. Reopen revalidates every retained directory before seeking.
pub struct AnchorAreaDiscovery {
    area: StableAnchorAreaLocator,
    scan: Scan,
    found: Option<(NativeFileId, PathBuf)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct DirectoryStamp {
    identity: NativeFileId,
    modified: (i64, i64),
    changed: (i64, i64),
    len: u64,
}

impl DirectoryStamp {
    pub(super) fn read(directory: &PinnedDirectory) -> Result<Self, AnchorError> {
        let metadata = directory.as_file().metadata()?;
        Ok(Self {
            identity: directory.identity()?,
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            len: metadata.len(),
        })
    }
}

impl Frame {
    pub(super) fn verify_unchanged(&self) -> Result<(), AnchorError> {
        if DirectoryStamp::read(&self.directory)? != self.stamp {
            return Err(AnchorError::SourceChanged(self.path.clone()));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SavedFrame {
    #[serde(with = "raw_path_bytes")]
    path: PathBuf,
    stamp: DirectoryStamp,
    cookie: i64,
}

#[derive(Serialize, Deserialize)]
struct SavedCandidate {
    identity: NativeFileId,
    #[serde(with = "raw_path_bytes")]
    path: PathBuf,
}

impl From<&(NativeFileId, PathBuf)> for SavedCandidate {
    fn from((identity, path): &(NativeFileId, PathBuf)) -> Self {
        Self {
            identity: *identity,
            path: path.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    version: u8,
    area: StableAnchorAreaLocator,
    #[serde(with = "raw_path_bytes_vec")]
    roots: Vec<PathBuf>,
    next_root: usize,
    frames: Vec<SavedFrame>,
    candidate: Option<SavedCandidate>,
    found: Option<SavedCandidate>,
}

impl AnchorAreaDiscovery {
    /// Check the saved cursor's wire structure without touching its paths.
    pub(crate) fn validate_preserved_checkpoint(
        area_id: Uuid,
        bytes: &[u8],
    ) -> Result<(), AnchorError> {
        if bytes.len() > ANCHOR_DISCOVERY_CHECKPOINT_BYTES {
            return Err(AnchorError::AnchorAreaDiscoveryLimit);
        }
        let saved: Checkpoint = decode_canonical(bytes).map_err(|_| AnchorError::UnsafePath)?;
        if saved.version != 1
            || saved.area.area_id != area_id
            || saved.frames.len() > MAX_DEPTH
            || saved.roots.len() > MAX_ROOTS
            || saved.roots.first() != Some(&saved.area.volume_root_hint)
            || saved.next_root > saved.roots.len()
            || (!saved.frames.is_empty() && saved.found.is_some())
            || canonical_bytes_bounded(&saved, ANCHOR_DISCOVERY_CHECKPOINT_BYTES)
                .map_err(|_| AnchorError::UnsafePath)?
                != bytes
        {
            return Err(AnchorError::UnsafePath);
        }
        check_path(&saved.area.path_hint)?;
        check_path(&saved.area.volume_root_hint)?;
        for root in &saved.roots {
            check_path(root)?;
        }
        let active_root = saved
            .next_root
            .checked_sub(1)
            .and_then(|index| saved.roots.get(index));
        let mut parent = active_root.map(PathBuf::as_path);
        for (index, frame) in saved.frames.iter().enumerate() {
            check_path(&frame.path)?;
            if frame.cookie < 0
                || frame.stamp.identity.filesystem_id != saved.area.filesystem_id
                || if index == 0 {
                    Some(frame.path.as_path()) != parent
                } else {
                    frame.path.parent() != parent
                }
            {
                return Err(AnchorError::UnsafePath);
            }
            parent = Some(&frame.path);
        }
        for candidate in [&saved.candidate, &saved.found].into_iter().flatten() {
            check_path(&candidate.path)?;
            if candidate.identity.filesystem_id != saved.area.filesystem_id
                || !active_root.is_some_and(|root| candidate.path.starts_with(root))
            {
                return Err(AnchorError::UnsafePath);
            }
        }
        Ok(())
    }

    pub fn start(area: &StableAnchorAreaLocator) -> Result<Self, AnchorError> {
        check_path(&area.path_hint)?;
        check_path(&area.volume_root_hint)?;
        Ok(Self {
            area: area.clone(),
            scan: Scan::new(roots(area)?),
            found: None,
        })
    }

    pub fn resume(area: &StableAnchorAreaLocator, bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > ANCHOR_DISCOVERY_CHECKPOINT_BYTES {
            return Err(AnchorError::AnchorAreaDiscoveryLimit);
        }
        let saved: Checkpoint = decode_canonical(bytes).map_err(|_| AnchorError::UnsafePath)?;
        if &saved.area != area {
            return Err(AnchorError::SourceChanged(area.path_hint.clone()));
        }
        if saved.version != 1
            || saved.frames.len() > MAX_DEPTH
            || saved.roots.len() > MAX_ROOTS
            || canonical_bytes_bounded(&saved, ANCHOR_DISCOVERY_CHECKPOINT_BYTES)
                .map_err(|_| AnchorError::UnsafePath)?
                != bytes
        {
            return Err(AnchorError::UnsafePath);
        }
        if saved.roots.first() != Some(&area.volume_root_hint)
            || saved.next_root > saved.roots.len()
        {
            return Err(AnchorError::UnsafePath);
        }
        for root in &saved.roots {
            check_path(root)?;
        }
        let active_root = saved
            .next_root
            .checked_sub(1)
            .and_then(|index| saved.roots.get(index))
            .cloned();
        if !saved.frames.is_empty() && saved.found.is_some() {
            return Err(AnchorError::UnsafePath);
        }
        for candidate in [&saved.candidate, &saved.found].into_iter().flatten() {
            check_path(&candidate.path)?;
            if candidate.identity.filesystem_id != area.filesystem_id
                || !active_root
                    .as_ref()
                    .is_some_and(|root| candidate.path.starts_with(root))
            {
                return Err(AnchorError::UnsafePath);
            }
        }
        let mut scan = Scan::new(saved.roots);
        scan.next_root = saved.next_root;
        for frame in saved.frames {
            check_path(&frame.path)?;
            if frame.cookie < 0 || frame.stamp.identity.filesystem_id != area.filesystem_id {
                return Err(AnchorError::UnsafePath);
            }
            let directory = if let Some(parent) = scan.stack.last() {
                if frame.path.parent() != Some(parent.path.as_path()) {
                    return Err(AnchorError::UnsafePath);
                }
                let name = frame.path.file_name().ok_or(AnchorError::UnsafePath)?;
                parent
                    .directory
                    .open_child_directory(Path::new(name))
                    .map_err(|error| reopen_error(error, &frame.path))?
                    .ok_or_else(|| AnchorError::SourceChanged(frame.path.clone()))?
            } else {
                if active_root.as_ref() != Some(&frame.path) {
                    return Err(AnchorError::UnsafePath);
                }
                PinnedDirectory::open(&frame.path)
                    .map_err(|error| reopen_error(error, &frame.path))?
            };
            if stable_filesystem_id_for_file(directory.as_file())? != area.filesystem_id
                || DirectoryStamp::read(&directory)? != frame.stamp
            {
                return Err(AnchorError::SourceChanged(frame.path));
            }
            require_persistent_cookies(&directory)?;
            let mut restored = Frame::open(directory, frame.path, &scan.open_frames)?;
            restored.stamp = frame.stamp;
            restored.verify_unchanged()?;
            restored.entries.seek(frame.cookie)?;
            scan.stack.push(restored);
        }
        scan.candidate = saved
            .candidate
            .map(|candidate| (candidate.identity, candidate.path));
        Ok(Self {
            area: area.clone(),
            scan,
            found: saved
                .found
                .map(|candidate| (candidate.identity, candidate.path)),
        })
    }

    pub fn advance(&mut self) -> Result<AnchorAreaDiscoveryStep, AnchorError> {
        if let Some((identity, path)) = &self.found {
            let current = PinnedDirectory::open(path).map_err(|error| reopen_error(error, path))?;
            if current.identity()? != *identity
                || marked_id(&current, path) != Some(self.area.area_id)
            {
                return Err(AnchorError::SourceChanged(path.clone()));
            }
            return Ok(AnchorAreaDiscoveryStep::Found(path.clone()));
        }
        match self
            .scan
            .advance(&self.area, STEPS_PER_LOOKUP, LOOKUP_TIME)?
        {
            Some(path) => {
                let directory =
                    PinnedDirectory::open(&path).map_err(|error| reopen_error(error, &path))?;
                if directory.filesystem_id != self.area.filesystem_id
                    || marked_id(&directory, &path) != Some(self.area.area_id)
                {
                    return Err(AnchorError::SourceChanged(path));
                }
                self.found = Some((directory.identity()?, path.clone()));
                Ok(AnchorAreaDiscoveryStep::Found(path))
            }
            None if self.scan.finished() => {
                // Preserve completed work across unrelated mount-table changes.
                // Before claiming absence, enqueue any newly visible roots.
                for root in roots(&self.area)? {
                    if !self.scan.roots.contains(&root) {
                        if self.scan.roots.len() == MAX_ROOTS {
                            return Err(AnchorError::AnchorAreaDiscoveryLimit);
                        }
                        self.scan.roots.push(root);
                    }
                }
                if self.scan.finished() {
                    Ok(AnchorAreaDiscoveryStep::Missing)
                } else {
                    Ok(AnchorAreaDiscoveryStep::Pending)
                }
            }
            None => Ok(AnchorAreaDiscoveryStep::Pending),
        }
    }

    pub fn checkpoint(&self) -> Result<Vec<u8>, AnchorError> {
        let mut frames = Vec::with_capacity(self.scan.stack.len());
        for frame in &self.scan.stack {
            require_persistent_cookies(&frame.directory)?;
            frame.verify_unchanged()?;
            frames.push(SavedFrame {
                path: frame.path.clone(),
                stamp: frame.stamp,
                cookie: frame.entries.cookie(),
            });
        }
        let saved = Checkpoint {
            version: 1,
            area: self.area.clone(),
            roots: self.scan.roots.clone(),
            next_root: self.scan.next_root,
            frames,
            candidate: self.scan.candidate.as_ref().map(Into::into),
            found: self.found.as_ref().map(Into::into),
        };
        canonical_bytes_bounded(&saved, ANCHOR_DISCOVERY_CHECKPOINT_BYTES)
            .map_err(|_| AnchorError::AnchorAreaDiscoveryLimit)
    }
}

fn require_persistent_cookies(directory: &PinnedDirectory) -> Result<(), AnchorError> {
    // Enabled only for the Linux Btrfs implementation and the ext4 host used by
    // ordinary tests. Other native platforms/filesystems need their own gate.
    if !matches!(
        filesystem_type_for_file(directory.as_file())?,
        0x9123_683e | 0xef53
    ) {
        return Err(AnchorError::UnsupportedSourceOperation(
            "persistent anchor directory cookies",
        ));
    }
    Ok(())
}

pub(super) fn reopen_error(error: AnchorError, path: &Path) -> AnchorError {
    match &error {
        AnchorError::Io(io)
            if io.kind() == std::io::ErrorKind::NotFound
                || matches!(
                    io.raw_os_error(),
                    Some(libc::EXDEV | libc::ELOOP | libc::ENOTDIR)
                ) =>
        {
            AnchorError::SourceChanged(path.to_path_buf())
        }
        AnchorError::UnsupportedObject(_) => AnchorError::SourceChanged(path.to_path_buf()),
        _ => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_reopen_restarts_namespace_changes_and_preserves_other_io_errors() {
        let temp = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        let path = temp.path().join(format!("{AREA_PREFIX}-candidate"));
        fs::create_dir(&path).unwrap();
        write_anchor_area_marker(&path, area.area_id).unwrap();
        // Keep the old inode allocated while testing replacement identities.
        let original = PinnedDirectory::open(&path).unwrap();
        let identity = original.identity().unwrap();
        for replacement in ["missing", "file", "symlink", "inode", "marker"] {
            if fs::symlink_metadata(&path).is_ok() {
                if path.is_dir() && !path.is_symlink() {
                    fs::remove_dir_all(&path).unwrap();
                } else {
                    fs::remove_file(&path).unwrap();
                }
            }
            match replacement {
                "missing" => {}
                "file" => fs::write(&path, []).unwrap(),
                "symlink" => std::os::unix::fs::symlink(temp.path(), &path).unwrap(),
                _ => {
                    fs::create_dir(&path).unwrap();
                    write_anchor_area_marker(
                        &path,
                        if replacement == "marker" {
                            Uuid::new_v4()
                        } else {
                            area.area_id
                        },
                    )
                    .unwrap();
                }
            }
            let mut scan = Scan::new(vec![]);
            scan.candidate = Some((identity, path.clone()));
            assert!(
                matches!(
                    scan.advance(&area, 1, Duration::from_secs(1)),
                    Err(AnchorError::SourceChanged(changed)) if changed == path
                ),
                "{replacement}"
            );
        }
        for code in [libc::EACCES, libc::EIO, libc::EMFILE] {
            assert!(matches!(
                reopen_error(AnchorError::Io(std::io::Error::from_raw_os_error(code)), &path),
                AnchorError::Io(error) if error.raw_os_error() == Some(code)
            ));
        }
    }

    #[test]
    fn durable_scan_rediscovers_candidate_moved_inside_completed_subtree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scan");
        fs::create_dir(&root).unwrap();
        for name in ["first", "second"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        // Use the filesystem's enumeration order rather than assuming sorted names.
        let directory = PinnedDirectory::open(&root).unwrap();
        let mut entries = directory::DirectoryEntries::new(&directory).unwrap();
        let mut parents = Vec::new();
        while let Some(entry) = entries.next().unwrap() {
            if entry.name != "." && entry.name != ".." {
                parents.push(root.join(entry.name));
            }
        }
        let completed = &parents[0];
        let pending = &parents[1];
        let original = completed.join(format!("{AREA_PREFIX}-original"));
        fs::create_dir(&original).unwrap();
        let area = fixture(&root);
        write_anchor_area_marker(&original, area.area_id).unwrap();
        for n in 0..6_000 {
            fs::write(pending.join(format!("entry-{n}")), []).unwrap();
        }
        let mut discovery = AnchorAreaDiscovery::start(&area).unwrap();
        for _ in 0..100 {
            assert_eq!(
                discovery
                    .scan
                    .advance(&area, 1, Duration::from_secs(1))
                    .unwrap(),
                None
            );
            if discovery.scan.candidate.is_some()
                && discovery
                    .scan
                    .stack
                    .last()
                    .is_some_and(|frame| &frame.path == pending)
            {
                break;
            }
        }
        assert_eq!(discovery.scan.candidate.as_ref().unwrap().1, original);
        assert_eq!(&discovery.scan.stack.last().unwrap().path, pending);
        let cursor = discovery.checkpoint().unwrap();
        drop(discovery);
        let database = temp.path().join("control.db");
        let store = crate::ControlStore::open_with_key(&database, &[8; 32]).unwrap();
        let attempt = Uuid::new_v4();
        let journal = canonical_bytes(&(1_u8, attempt, 0_u64, &cursor)).unwrap();
        store
            .put_record(
                crate::ANCHOR_DISCOVERY_JOURNAL_KIND,
                area.area_id.as_bytes(),
                &journal,
            )
            .unwrap();
        drop(store);
        let moved = completed.join(format!("{AREA_PREFIX}-moved"));
        fs::rename(&original, &moved).unwrap();
        // No saved directory frame changed: only an already finished subtree did.
        let mut resumed = AnchorAreaDiscovery::resume(&area, &cursor).unwrap();
        assert!(matches!(
            resumed.scan.advance(&area, 10_000, Duration::from_secs(10)),
            Err(AnchorError::SourceChanged(path)) if path == original
        ));
        drop(resumed);
        let mut found = None;
        for _ in 0..30 {
            // Every retry loses process-local handles and reopens durable state.
            let store = crate::ControlStore::open_existing_with_key(&database, &[8; 32]).unwrap();
            match store.advance_anchor_area_discovery(&area).unwrap() {
                AnchorAreaDiscoveryStep::Found(path) => {
                    found = Some(path);
                    break;
                }
                AnchorAreaDiscoveryStep::Pending => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(found, Some(moved));
    }

    fn fixture(root: &Path) -> StableAnchorAreaLocator {
        StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            filesystem_id: filesystem_identity(root).unwrap().stable_id,
            path_hint: root.join("old-area"),
            volume_root_hint: root.to_path_buf(),
        }
    }

    #[test]
    #[ignore = "requires two phases around an externally remounted Btrfs filesystem"]
    fn checkpoint_btrfs_cursor_survives_external_remount() {
        #[derive(Serialize, Deserialize)]
        struct Remount {
            root: PathBuf,
            area: StableAnchorAreaLocator,
            cursor: Vec<u8>,
            target: PathBuf,
        }
        let root = PathBuf::from(std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").unwrap());
        let record =
            PathBuf::from(std::env::var_os("MUTUALBACKUP_DISCOVERY_REMOUNT_RECORD").unwrap());
        if record.exists() {
            let bytes = fs::read(&record).unwrap();
            assert!(bytes.len() <= ANCHOR_DISCOVERY_CHECKPOINT_BYTES + 16_384);
            let state: Remount = decode_canonical(&bytes).unwrap();
            assert!(state.root.starts_with(&root));
            let mut discovery = AnchorAreaDiscovery::resume(&state.area, &state.cursor).unwrap();
            assert_eq!(discovery.checkpoint().unwrap(), state.cursor);
            let mut found = None;
            for _ in 0..30 {
                match discovery.advance().unwrap() {
                    AnchorAreaDiscoveryStep::Found(path) => {
                        found = Some(path);
                        break;
                    }
                    AnchorAreaDiscoveryStep::Pending => {
                        let checkpoint = discovery.checkpoint().unwrap();
                        drop(discovery);
                        discovery = AnchorAreaDiscovery::resume(&state.area, &checkpoint).unwrap();
                    }
                    other => panic!("{other:?}"),
                }
            }
            assert_eq!(found, Some(state.target));
            drop(discovery);
            fs::remove_dir_all(state.root).unwrap();
            fs::remove_file(record).unwrap();
        } else {
            let temp = tempfile::tempdir_in(root).unwrap();
            let scan = temp.path().join("scan");
            fs::create_dir(&scan).unwrap();
            let area = fixture(&scan);
            for n in 0..6_000 {
                fs::write(scan.join(format!("entry-{n}")), []).unwrap();
            }
            let target = scan.join(format!("{AREA_PREFIX}-target"));
            fs::create_dir(&target).unwrap();
            write_anchor_area_marker(&target, area.area_id).unwrap();
            let mut discovery = AnchorAreaDiscovery::start(&area).unwrap();
            assert!(
                discovery
                    .scan
                    .advance(&area, 50, Duration::from_secs(1))
                    .unwrap()
                    .is_none()
            );
            let cursor = discovery.checkpoint().unwrap();
            drop(discovery);
            let root = temp.keep();
            let bytes = canonical_bytes_bounded(
                &Remount {
                    root,
                    area,
                    cursor,
                    target,
                },
                ANCHOR_DISCOVERY_CHECKPOINT_BYTES + 16_384,
            )
            .unwrap();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(record)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs filesystem and bind mounts"]
    fn checkpoint_scan_fences_nested_subvolumes_and_mounts() {
        let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").unwrap();
        let temp = tempfile::tempdir_in(root).unwrap();
        let scan_root = temp.path().join("scan");
        let external = temp.path().join("external");
        fs::create_dir(&scan_root).unwrap();
        fs::create_dir(&external).unwrap();
        let area = fixture(&scan_root);
        let nested = scan_root.join("nested");
        let output = std::process::Command::new("btrfs")
            .args(["subvolume", "create"])
            .arg(&nested)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for parent in [&nested, &external] {
            let marked = parent.join(format!("{AREA_PREFIX}-foreign"));
            fs::create_dir(&marked).unwrap();
            write_anchor_area_marker(&marked, area.area_id).unwrap();
        }
        assert_ne!(
            filesystem_identity(&nested).unwrap().stable_id,
            area.filesystem_id
        );
        let mount = scan_root.join("mounted");
        fs::create_dir(&mount).unwrap();
        let output = std::process::Command::new("sudo")
            .args(["-n", "mount", "--bind"])
            .arg(&external)
            .arg(&mount)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = (|| -> Result<Option<PathBuf>, AnchorError> {
            let mut scan = Scan::new(vec![scan_root.clone()]);
            for _ in 0..100 {
                let found = scan.advance(&area, 100, Duration::from_secs(1))?;
                if found.is_some() || scan.finished() {
                    return Ok(found);
                }
            }
            Err(AnchorError::AnchorAreaDiscoveryLimit)
        })();
        let unmount = std::process::Command::new("sudo")
            .args(["-n", "umount"])
            .arg(&mount)
            .output()
            .unwrap();
        let delete = std::process::Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(&nested)
            .output()
            .unwrap();
        assert!(
            unmount.status.success(),
            "{}",
            String::from_utf8_lossy(&unmount.stderr)
        );
        assert!(
            delete.status.success(),
            "{}",
            String::from_utf8_lossy(&delete.stderr)
        );
        assert_eq!(result.unwrap(), None);
        let target = scan_root.join(format!("{AREA_PREFIX}-target"));
        fs::create_dir(&target).unwrap();
        write_anchor_area_marker(&target, area.area_id).unwrap();
        let mut scan = Scan::new(vec![scan_root]);
        assert_eq!(
            scan.advance(&area, 100, Duration::from_secs(1)).unwrap(),
            Some(target)
        );
    }

    #[test]
    fn checkpoint_reopens_buffered_directory_cookies_without_restarting_wide_scan() {
        let temp = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        for n in 0..5_000 {
            fs::write(temp.path().join(format!("entry-{n}")), []).unwrap();
        }
        let target = temp.path().join(format!("{AREA_PREFIX}-target"));
        fs::create_dir(&target).unwrap();
        write_anchor_area_marker(&target, area.area_id).unwrap();
        let mut discovery = AnchorAreaDiscovery::start(&area).unwrap();
        assert!(
            discovery
                .scan
                .advance(&area, 50, Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        let mut previous = discovery.checkpoint().unwrap();
        drop(discovery);
        let mut found = None;
        for _ in 0..20 {
            let mut resumed = AnchorAreaDiscovery::resume(&area, &previous).unwrap();
            match resumed.advance().unwrap() {
                AnchorAreaDiscoveryStep::Found(path) => {
                    found = Some(path);
                    let saved = resumed.checkpoint().unwrap();
                    let mut reopened = AnchorAreaDiscovery::resume(&area, &saved).unwrap();
                    assert_eq!(
                        reopened.advance().unwrap(),
                        AnchorAreaDiscoveryStep::Found(target.clone())
                    );
                    break;
                }
                AnchorAreaDiscoveryStep::Pending => {
                    let next = resumed.checkpoint().unwrap();
                    assert_ne!(next, previous);
                    previous = next;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(found, Some(target));
    }

    #[test]
    fn checkpoint_rejects_directory_changes_replacement_and_invalid_cookies() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scan");
        fs::create_dir(&root).unwrap();
        let area = fixture(&root);
        let mut discovery = AnchorAreaDiscovery::start(&area).unwrap();
        discovery
            .scan
            .advance(&area, 1, Duration::from_secs(1))
            .unwrap();
        let saved = discovery.checkpoint().unwrap();
        drop(discovery);
        let mut corrupt: Checkpoint = decode_canonical(&saved).unwrap();
        corrupt.frames[0].cookie = -1;
        let bytes = canonical_bytes_bounded(&corrupt, ANCHOR_DISCOVERY_CHECKPOINT_BYTES).unwrap();
        assert!(matches!(
            AnchorAreaDiscovery::resume(&area, &bytes),
            Err(AnchorError::UnsafePath)
        ));
        corrupt.frames[0].cookie = 0;
        corrupt.version = 2;
        let bytes = canonical_bytes_bounded(&corrupt, ANCHOR_DISCOVERY_CHECKPOINT_BYTES).unwrap();
        assert!(matches!(
            AnchorAreaDiscovery::resume(&area, &bytes),
            Err(AnchorError::UnsafePath)
        ));
        assert!(matches!(
            AnchorAreaDiscovery::resume(&area, &vec![0; ANCHOR_DISCOVERY_CHECKPOINT_BYTES + 1]),
            Err(AnchorError::AnchorAreaDiscoveryLimit)
        ));
        fs::write(root.join("new-name"), []).unwrap();
        assert!(matches!(
            AnchorAreaDiscovery::resume(&area, &saved),
            Err(AnchorError::SourceChanged(_))
        ));
        fs::rename(&root, temp.path().join("replaced")).unwrap();
        fs::create_dir(&root).unwrap();
        assert!(matches!(
            AnchorAreaDiscovery::resume(&area, &saved),
            Err(AnchorError::SourceChanged(_))
        ));
    }
}

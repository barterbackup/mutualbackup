//! Bounded, process-local relocation discovery. A pending scan never establishes
//! absence. Callers may retry it or supply a durable catalog location hint.
use super::*;
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
mod checkpoint;
#[cfg(target_os = "linux")]
mod directory;
#[cfg(target_os = "linux")]
pub use checkpoint::{
    ANCHOR_DISCOVERY_CHECKPOINT_BYTES, AnchorAreaDiscovery, AnchorAreaDiscoveryStep,
};

const INDEX_ENTRIES: usize = 32;
const STEPS_PER_LOOKUP: usize = 2_048;
const LOOKUP_TIME: Duration = Duration::from_millis(25);
const MISSING_RETRY: Duration = Duration::from_secs(60);
const MAX_ROOTS: usize = 256;
const MAX_MOUNTINFO_BYTES: usize = 256 * 1_024;
const MAX_DEPTH: usize = 64;
// Each frame owns one pinned directory and one streaming directory iterator.
const MAX_OPEN_FRAMES: usize = 64;

type IndexKey = (Uuid, u64, PathBuf);
type Index = BTreeMap<IndexKey, Arc<Mutex<State>>>;
static INDEX: OnceLock<Mutex<Index>> = OnceLock::new();

pub(super) fn cached(area: &StableAnchorAreaLocator) -> Option<PathBuf> {
    let key = (
        area.area_id,
        area.filesystem_id,
        area.volume_root_hint.clone(),
    );
    let state = INDEX.get()?.lock().ok()?.get(&key).cloned()?;
    let state = state.try_lock().ok()?;
    let State::Resolved(path) = &*state else {
        return None;
    };
    if validate_stable_anchor_area(path, area.area_id).is_ok()
        && filesystem_identity(path).is_ok_and(|identity| identity.stable_id == area.filesystem_id)
    {
        Some(path.clone())
    } else {
        None
    }
}

#[derive(Default)]
enum State {
    #[default]
    New,
    Scanning(Scan),
    Resolved(PathBuf),
    Missing(Instant),
}

pub(super) fn resolve(area: &StableAnchorAreaLocator) -> Result<PathBuf, AnchorError> {
    check_path(&area.volume_root_hint)?;
    let key = (
        area.area_id,
        area.filesystem_id,
        area.volume_root_hint.clone(),
    );
    let (state, evicted) = {
        let mut index = INDEX
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| AnchorError::AnchorAreaIndexUnavailable)?;
        if let Some(state) = index.get(&key) {
            (Arc::clone(state), None)
        } else {
            let evicted = if index.len() == INDEX_ENTRIES {
                // Eviction drops cursors/handles, but never while another lookup
                // is using them. No filesystem operation runs under this lock.
                let victim = index
                    .iter()
                    .find_map(|(key, state)| (Arc::strong_count(state) == 1).then(|| key.clone()))
                    .ok_or(AnchorError::AnchorAreaDiscoveryLimit)?;
                index.remove(&victim)
            } else {
                None
            };
            let state = Arc::new(Mutex::new(State::New));
            index.insert(key, Arc::clone(&state));
            (state, evicted)
        }
    };
    drop(evicted);
    let mut state = match state.try_lock() {
        Ok(state) => state,
        Err(TryLockError::WouldBlock) => return Err(AnchorError::AnchorAreaDiscoveryPending),
        Err(TryLockError::Poisoned(_)) => return Err(AnchorError::AnchorAreaIndexUnavailable),
    };
    match &*state {
        State::Resolved(path)
            if validate_stable_anchor_area(path, area.area_id).is_ok()
                && filesystem_identity(path).is_ok_and(|id| id.stable_id == area.filesystem_id) =>
        {
            return Ok(path.clone());
        }
        State::Missing(until) if Instant::now() < *until => {
            return Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()));
        }
        State::Scanning(_) => {}
        _ => *state = State::New,
    }
    if matches!(*state, State::New) {
        *state = State::Scanning(Scan::new(roots(area)?));
    }
    let State::Scanning(scan) = &mut *state else {
        unreachable!()
    };
    match scan.advance(area, STEPS_PER_LOOKUP, LOOKUP_TIME) {
        Ok(Some(path)) => {
            *state = State::Resolved(path.clone());
            Ok(path)
        }
        Ok(None) if scan.finished() => {
            *state = State::Missing(Instant::now() + MISSING_RETRY);
            Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()))
        }
        Ok(None) => Err(AnchorError::AnchorAreaDiscoveryPending),
        Err(error) => {
            // Errors/limits are never cached as absence. Drop pinned handles so
            // failed discovery cannot exhaust the process descriptor budget.
            *state = State::New;
            Err(error)
        }
    }
}

fn check_path(path: &Path) -> Result<(), AnchorError> {
    if path.as_os_str().as_encoded_bytes().len() > MAX_RELATIVE_PATH_BYTES {
        return Err(AnchorError::AnchorAreaDiscoveryLimit);
    }
    Ok(())
}

pub(super) fn roots(area: &StableAnchorAreaLocator) -> Result<Vec<PathBuf>, AnchorError> {
    let mut roots = vec![area.volume_root_hint.clone()];
    #[cfg(target_os = "linux")]
    {
        let mut contents = String::new();
        File::open("/proc/self/mountinfo")?
            .take((MAX_MOUNTINFO_BYTES + 1) as u64)
            .read_to_string(&mut contents)?;
        if contents.len() > MAX_MOUNTINFO_BYTES {
            return Err(AnchorError::AnchorAreaDiscoveryLimit);
        }
        append_mount_roots(&contents, &mut roots)?;
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
fn append_mount_roots(contents: &str, roots: &mut Vec<PathBuf>) -> Result<(), AnchorError> {
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(path) = fields.nth(4) else { continue };
        if !fields.any(|field| field == "-") {
            continue;
        }
        let Some(filesystem) = fields.next() else {
            continue;
        };
        if !is_data_filesystem(filesystem) {
            continue;
        }
        let Some(path) = decode_mount_path(path) else {
            continue;
        };
        check_path(&path)?;
        if !roots.contains(&path) {
            if roots.len() == MAX_ROOTS {
                return Err(AnchorError::AnchorAreaDiscoveryLimit);
            }
            roots.push(path);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
static OPEN_FRAMES: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

#[cfg(target_os = "linux")]
struct Frame {
    directory: PinnedDirectory,
    entries: directory::DirectoryEntries,
    path: PathBuf,
    stamp: checkpoint::DirectoryStamp,
    open_frames: Arc<AtomicUsize>,
}

#[cfg(target_os = "linux")]
impl Frame {
    fn open(
        directory: PinnedDirectory,
        path: PathBuf,
        open_frames: &Arc<AtomicUsize>,
    ) -> Result<Self, AnchorError> {
        check_path(&path)?;
        let stamp = checkpoint::DirectoryStamp::read(&directory)?;
        let mut count = open_frames.load(Ordering::Acquire);
        loop {
            if count >= MAX_OPEN_FRAMES {
                return Err(AnchorError::AnchorAreaDiscoveryLimit);
            }
            match open_frames.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        match directory::DirectoryEntries::new(&directory) {
            Ok(entries) => Ok(Self {
                directory,
                entries,
                path,
                stamp,
                open_frames: Arc::clone(open_frames),
            }),
            Err(error) => {
                open_frames.fetch_sub(1, Ordering::AcqRel);
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Frame {
    fn drop(&mut self) {
        self.open_frames.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Scan {
    roots: Vec<PathBuf>,
    next_root: usize,
    #[cfg(target_os = "linux")]
    stack: Vec<Frame>,
    #[cfg(target_os = "linux")]
    open_frames: Arc<AtomicUsize>,
    candidate: Option<(NativeFileId, PathBuf)>,
}

impl Scan {
    fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            next_root: 0,
            #[cfg(target_os = "linux")]
            stack: Vec::new(),
            #[cfg(target_os = "linux")]
            open_frames: Arc::clone(OPEN_FRAMES.get_or_init(Default::default)),
            candidate: None,
        }
    }

    fn finished(&self) -> bool {
        #[cfg(target_os = "linux")]
        if !self.stack.is_empty() {
            return false;
        }
        self.next_root == self.roots.len() && self.candidate.is_none()
    }

    #[cfg(not(target_os = "linux"))]
    fn advance(
        &mut self,
        _: &StableAnchorAreaLocator,
        _: usize,
        _: Duration,
    ) -> Result<Option<PathBuf>, AnchorError> {
        Err(AnchorError::UnsupportedSourceOperation(
            "anchor relocation discovery",
        ))
    }

    #[cfg(target_os = "linux")]
    fn advance(
        &mut self,
        area: &StableAnchorAreaLocator,
        steps: usize,
        duration: Duration,
    ) -> Result<Option<PathBuf>, AnchorError> {
        let started = Instant::now();
        for step in 0..steps {
            if step > 0 && started.elapsed() >= duration {
                break;
            }
            if self.stack.is_empty() {
                if let Some((identity, path)) = self.candidate.take() {
                    let actual = PinnedDirectory::open(&path)
                        .map_err(|error| checkpoint::reopen_error(error, &path))?;
                    if actual.identity()? != identity
                        || marked_id(&actual, &path) != Some(area.area_id)
                    {
                        return Err(AnchorError::SourceChanged(path));
                    }
                    return Ok(Some(path));
                }
                let Some(root) = self.roots.get(self.next_root).cloned() else {
                    return Ok(None);
                };
                self.next_root += 1;
                check_path(&root)?;
                let directory = match PinnedDirectory::open(&root) {
                    Ok(directory) => directory,
                    Err(AnchorError::Io(error))
                        if ignorable(&error)
                            || matches!(
                                error.raw_os_error(),
                                Some(libc::ELOOP | libc::ENOTDIR)
                            ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if directory.filesystem_id != area.filesystem_id {
                    continue;
                }
                if root
                    .file_name()
                    .is_some_and(|name| name.as_bytes().starts_with(AREA_PREFIX.as_bytes()))
                {
                    if marked_id(&directory, &root) == Some(area.area_id) {
                        self.candidate = Some((directory.identity()?, root));
                    }
                    continue;
                }
                self.stack
                    .push(Frame::open(directory, root, &self.open_frames)?);
                continue;
            }
            let frame = self.stack.last_mut().expect("nonempty stack");
            let entry = match frame.entries.next() {
                Ok(entry) => entry,
                Err(AnchorError::Io(error)) if ignorable(&error) => continue,
                Err(error) => return Err(error),
            };
            let Some(entry) = entry else {
                frame.verify_unchanged()?;
                self.stack.pop();
                continue;
            };
            if !entry.may_be_directory || entry.name == "." || entry.name == ".." {
                continue;
            }
            let name = entry.name;
            let path = frame.path.join(&name);
            check_path(&path)?;
            let directory = match frame.directory.open_child_directory(Path::new(&name)) {
                Ok(Some(directory)) => directory,
                Ok(None) => continue,
                Err(AnchorError::Io(error))
                    if ignorable(&error)
                        || matches!(
                            error.raw_os_error(),
                            Some(libc::EXDEV | libc::ELOOP | libc::ENOTDIR)
                        ) =>
                {
                    continue;
                }
                Err(AnchorError::UnsupportedObject(_)) => continue,
                Err(error) => return Err(error),
            };
            // Btrfs subvolumes also have distinct stable identities even when
            // reached without crossing a mount. Do not inherit the parent's
            // identity until the actual pinned child has been checked.
            if stable_filesystem_id_for_file(directory.as_file())? != area.filesystem_id {
                continue;
            }
            if name.as_bytes().starts_with(AREA_PREFIX.as_bytes()) {
                // Never descend into payloads, even for a different/invalid area.
                if marked_id(&directory, &path) != Some(area.area_id) {
                    continue;
                }
                let identity = directory.identity()?;
                if self
                    .candidate
                    .as_ref()
                    .is_some_and(|(other, _)| *other != identity)
                {
                    return Err(AnchorError::AnchorAreaCollision(path));
                }
                self.candidate = Some((identity, path));
                continue;
            }
            if self.stack.len() == MAX_DEPTH {
                return Err(AnchorError::AnchorAreaDiscoveryLimit);
            }
            self.stack
                .push(Frame::open(directory, path, &self.open_frames)?);
        }
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn ignorable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
    )
}

#[cfg(target_os = "linux")]
fn marked_id(directory: &PinnedDirectory, path: &Path) -> Option<Uuid> {
    directory
        .open_child_file(AREA_MARKER)
        .ok()
        .flatten()
        .and_then(|file| read_area_marker_contents(file, path).ok())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> StableAnchorAreaLocator {
        StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            path_hint: root.join("gone"),
            filesystem_id: filesystem_identity(root).unwrap().stable_id,
            volume_root_hint: root.to_path_buf(),
        }
    }

    fn marked(root: &Path, name: &str, id: Uuid) -> PathBuf {
        let path = root.join(format!("{AREA_PREFIX}-{name}"));
        fs::create_dir(&path).unwrap();
        write_anchor_area_marker(&path, id).unwrap();
        path
    }

    fn complete(
        scan: &mut Scan,
        area: &StableAnchorAreaLocator,
    ) -> Result<Option<PathBuf>, AnchorError> {
        for _ in 0..10_000 {
            let found = scan.advance(area, 1, Duration::from_secs(1))?;
            if found.is_some() || scan.finished() {
                return Ok(found);
            }
        }
        panic!("incremental scan did not finish");
    }

    #[test]
    fn discovery_resumes_large_directory_and_fences_late_ambiguity() {
        let temp = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        for i in 0..200 {
            fs::write(temp.path().join(format!("file-{i}")), []).unwrap();
        }
        let moved = marked(temp.path(), "moved", area.area_id);
        // Payload descendants are not scanned.
        fs::create_dir_all(moved.join("nested/a/b/c")).unwrap();
        let mut scan = Scan::new(vec![temp.path().to_path_buf()]);
        assert_eq!(
            scan.advance(&area, 1, Duration::from_secs(1)).unwrap(),
            None
        );
        assert!(!scan.finished());
        assert_eq!(scan.stack.len(), 1);
        assert_eq!(complete(&mut scan, &area).unwrap(), Some(moved));

        marked(temp.path(), "duplicate", area.area_id);
        let mut scan = Scan::new(vec![temp.path().to_path_buf()]);
        assert!(matches!(
            complete(&mut scan, &area),
            Err(AnchorError::AnchorAreaCollision(_))
        ));
    }

    #[test]
    fn discovery_does_not_report_pending_work_as_absence_or_follow_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        let moved = marked(outside.path(), "outside", area.area_id);
        symlink(&moved, temp.path().join(format!("{AREA_PREFIX}-link"))).unwrap();
        for i in 0..10 {
            fs::write(temp.path().join(format!("file-{i}")), []).unwrap();
        }
        let mut scan = Scan::new(vec![temp.path().to_path_buf()]);
        assert_eq!(
            scan.advance(&area, 2, Duration::from_secs(1)).unwrap(),
            None
        );
        assert!(!scan.finished());
        assert_eq!(complete(&mut scan, &area).unwrap(), None);
        assert!(scan.finished());
        let mut wrong_volume = area.clone();
        wrong_volume.filesystem_id ^= 1;
        let mut scan = Scan::new(vec![outside.path().to_path_buf()]);
        assert_eq!(complete(&mut scan, &wrong_volume).unwrap(), None);

        let regular = temp.path().join("file-0");
        let link = temp.path().join(format!("{AREA_PREFIX}-link"));
        let mut scan = Scan::new(vec![regular, link, moved.clone()]);
        // Stale non-directory/symlink roots are skipped. A marked root itself
        // is a candidate, but only the following advance can publish it.
        assert_eq!(
            scan.advance(&area, 3, Duration::from_secs(1)).unwrap(),
            None
        );
        assert!(!scan.finished());
        assert_eq!(complete(&mut scan, &area).unwrap(), Some(moved));
    }

    #[test]
    fn discovery_returns_explicit_limits_instead_of_incomplete_absence() {
        let temp = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        let mut deepest = temp.path().to_path_buf();
        for _ in 0..MAX_DEPTH {
            deepest.push("d");
            fs::create_dir(&deepest).unwrap();
        }
        let mut scan = Scan::new(vec![temp.path().to_path_buf()]);
        // This deliberately saturates the frame budget. Give the fixture its
        // own pool so parallel tests keep exercising the production pool.
        scan.open_frames = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            complete(&mut scan, &area),
            Err(AnchorError::AnchorAreaDiscoveryLimit)
        ));
        assert!(check_path(&PathBuf::from("x".repeat(MAX_RELATIVE_PATH_BYTES + 1))).is_err());
        let mounts = (0..=MAX_ROOTS)
            .map(|i| format!("1 0 0:0 / /mount-{i} rw - ext4 none rw\n"))
            .collect::<String>();
        assert!(matches!(
            append_mount_roots(&mounts, &mut Vec::new()),
            Err(AnchorError::AnchorAreaDiscoveryLimit)
        ));
    }

    #[test]
    fn discovery_shared_frame_budget_releases_capacity_when_scans_drop() {
        let temp = tempfile::tempdir().unwrap();
        let pool = Arc::new(AtomicUsize::new(0));
        let mut first = Scan::new(vec![]);
        let mut second = Scan::new(vec![]);
        // Separate scans retain the same process-level budget in production.
        assert!(Arc::ptr_eq(&first.open_frames, &second.open_frames));
        first.open_frames = Arc::clone(&pool);
        second.open_frames = Arc::clone(&pool);
        let open = || {
            Frame::open(
                PinnedDirectory::open(temp.path()).unwrap(),
                temp.path().to_path_buf(),
                &pool,
            )
        };
        for _ in 0..MAX_OPEN_FRAMES / 2 {
            first.stack.push(open().unwrap());
            second.stack.push(open().unwrap());
        }
        assert_eq!(pool.load(Ordering::Acquire), MAX_OPEN_FRAMES);
        assert!(matches!(open(), Err(AnchorError::AnchorAreaDiscoveryLimit)));
        assert_eq!(pool.load(Ordering::Acquire), MAX_OPEN_FRAMES);
        drop(first);
        assert_eq!(pool.load(Ordering::Acquire), MAX_OPEN_FRAMES / 2);
        for _ in 0..MAX_OPEN_FRAMES / 2 {
            second.stack.push(open().unwrap());
        }
        assert!(matches!(open(), Err(AnchorError::AnchorAreaDiscoveryLimit)));
        drop(second);
        assert_eq!(pool.load(Ordering::Acquire), 0);
        drop(open().unwrap());
        assert_eq!(pool.load(Ordering::Acquire), 0);
    }

    #[test]
    fn discovery_busy_area_does_not_block_unrelated_lookup_and_reuses_resolved_hint() {
        let temp = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        let key = (
            area.area_id,
            area.filesystem_id,
            area.volume_root_hint.clone(),
        );
        let state = Arc::new(Mutex::new(State::New));
        INDEX
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(key.clone(), Arc::clone(&state));
        let held = state.lock().unwrap();
        assert!(matches!(
            resolve(&area),
            Err(AnchorError::AnchorAreaDiscoveryPending)
        ));
        let second = fixture(temp.path());
        let moved = marked(temp.path(), "second", second.area_id);
        let second_key = (
            second.area_id,
            second.filesystem_id,
            second.volume_root_hint.clone(),
        );
        INDEX.get().unwrap().lock().unwrap().insert(
            second_key.clone(),
            Arc::new(Mutex::new(State::Scanning(Scan::new(vec![
                temp.path().to_path_buf(),
            ])))),
        );
        let mut found = None;
        for _ in 0..100 {
            match resolve(&second) {
                Ok(path) => {
                    found = Some(path);
                    break;
                }
                Err(AnchorError::AnchorAreaDiscoveryPending) => {}
                Err(error) => panic!("{error}"),
            }
        }
        assert_eq!(found, Some(moved.clone()));
        assert_eq!(resolve(&second).unwrap(), moved);
        drop(held);
        let mut index = INDEX.get().unwrap().lock().unwrap();
        index.remove(&key);
        index.remove(&second_key);
    }

    #[test]
    fn discovery_candidate_path_replacement_is_rejected_after_pinned_walk() {
        let temp = tempfile::tempdir().unwrap();
        let area = fixture(temp.path());
        let moved = marked(temp.path(), "moved", area.area_id);
        let mut scan = Scan::new(vec![temp.path().to_path_buf()]);
        for _ in 0..10 {
            scan.advance(&area, 1, Duration::from_secs(1)).unwrap();
            if scan.candidate.is_some() {
                break;
            }
        }
        assert!(scan.candidate.is_some());
        fs::rename(&moved, temp.path().join("renamed")).unwrap();
        fs::create_dir(&moved).unwrap();
        write_anchor_area_marker(&moved, area.area_id).unwrap();
        assert!(matches!(
            complete(&mut scan, &area),
            Err(AnchorError::SourceChanged(_))
        ));
    }
}

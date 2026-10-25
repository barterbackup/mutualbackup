//! Opt-in, bounded diagnostics for the unchanged first-coverage test deadline.
//! No seed, payload or protocol evidence bytes enter this trace.
use crate::Node;
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_EVENTS: usize = 65_536;
type Registry = BTreeMap<usize, (Weak<Inner>, usize)>;
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

#[derive(Clone, Serialize)]
struct Event {
    at_us: u64,
    job: u64,
    node: usize,
    phase: &'static str,
    operation: &'static str,
    file: Option<&'static str>,
    line: Option<u32>,
    panicking: bool,
}
#[derive(Default)]
struct Events {
    dropped: u64,
    entries: VecDeque<Event>,
}
struct Inner {
    started: Instant,
    sequence: AtomicU64,
    events: Mutex<Events>,
}

pub(super) struct Session {
    inner: Arc<Inner>,
    nodes: Vec<usize>,
    directory: PathBuf,
    offline_spare: bool,
    checkpoint: [u8; 32],
    attempt: [u8; 16],
    unix_started_ms: u128,
}

impl Session {
    pub(super) fn start(
        nodes: &[Arc<Mutex<Node>>],
        offline_spare: bool,
        checkpoint: [u8; 32],
        attempt: [u8; 16],
    ) -> Option<Self> {
        let directory = PathBuf::from(std::env::var_os("MB_COVERAGE_TRACE_DIRECTORY")?);
        assert!(
            directory.is_dir(),
            "coverage trace directory must already exist"
        );
        let inner = Arc::new(Inner {
            started: Instant::now(),
            sequence: AtomicU64::new(1),
            events: Mutex::new(Events::default()),
        });
        let ids: Vec<_> = nodes
            .iter()
            .map(|node| Arc::as_ptr(node) as usize)
            .collect();
        let mut registry = REGISTRY
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap();
        for (index, id) in ids.iter().enumerate() {
            assert!(
                !registry.contains_key(id),
                "node already belongs to a coverage trace"
            );
            registry.insert(*id, (Arc::downgrade(&inner), index));
        }
        Some(Self {
            inner,
            nodes: ids,
            directory,
            offline_spare,
            checkpoint,
            attempt,
            unix_started_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        })
    }

    pub(super) fn save(&self, outcome: &str) -> std::io::Result<PathBuf> {
        let events = self.inner.events.lock().unwrap();
        let report = serde_json::json!({
            "format_version": 1, "offline_spare": self.offline_spare,
            "checkpoint": hex::encode(self.checkpoint), "attempt": hex::encode(self.attempt),
            "unix_started_ms": self.unix_started_ms, "elapsed_us": self.inner.started.elapsed().as_micros(),
            "outcome": outcome, "dropped": events.dropped, "events": events.entries,
        });
        let path = self
            .directory
            .join(format!("coverage-{}.json", uuid::Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        serde_json::to_writer(&mut file, &report)?;
        use std::io::Write;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(path)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let mut registry = REGISTRY.get().unwrap().lock().unwrap();
        let expected = Arc::downgrade(&self.inner);
        for id in &self.nodes {
            if registry
                .get(id)
                .is_some_and(|(inner, _)| inner.ptr_eq(&expected))
            {
                registry.remove(id);
            }
        }
    }
}

pub(super) struct Job {
    inner: Arc<Inner>,
    id: u64,
    node: usize,
    operation: &'static str,
    source: Option<&'static std::panic::Location<'static>>,
}
impl Job {
    pub(super) fn queued(
        node: &Arc<Mutex<Node>>,
        operation: &'static str,
        source: Option<&'static std::panic::Location<'static>>,
    ) -> Option<Self> {
        let (inner, index) = {
            let registry = REGISTRY.get()?.lock().unwrap();
            let (inner, index) = registry.get(&(Arc::as_ptr(node) as usize))?;
            (inner.upgrade()?, *index)
        };
        let id = inner.sequence.fetch_add(1, Ordering::Relaxed);
        let job = Self {
            inner,
            id,
            node: index,
            operation,
            source,
        };
        job.phase("queued");
        Some(job)
    }
    pub(super) fn phase(&self, phase: &'static str) {
        let event = Event {
            at_us: self.inner.started.elapsed().as_micros().try_into().unwrap(),
            job: self.id,
            node: self.node,
            phase,
            operation: self.operation,
            file: self.source.map(|s| s.file()),
            line: self.source.map(|s| s.line()),
            panicking: std::thread::panicking(),
        };
        let mut events = self.inner.events.lock().unwrap();
        if events.entries.len() == MAX_EVENTS {
            events.entries.pop_front();
            events.dropped += 1;
        }
        events.entries.push_back(event);
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        self.phase("done");
    }
}

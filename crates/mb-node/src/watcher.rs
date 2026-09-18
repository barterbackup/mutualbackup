use std::collections::BTreeMap;
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use mb_store::filesystem_identity;
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecursiveMode, Watcher};

use crate::{Node, ProtectedRoot};

const WATCH_RETRY_MIN: Duration = Duration::from_secs(1);
const WATCH_RETRY_MAX: Duration = Duration::from_secs(60);
const WATCH_EVENT_CAPACITY: usize = 256;
const WATCH_ROOT_HEALTH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WatchedRootIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

pub async fn run_root_watcher(node: Arc<Mutex<Node>>) -> Result<()> {
    run_root_watcher_inner(node, None).await
}

#[cfg(test)]
pub(crate) async fn run_root_watcher_ready(
    node: Arc<Mutex<Node>>,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    run_root_watcher_inner(node, Some(ready)).await
}

async fn run_root_watcher_inner(
    node: Arc<Mutex<Node>>,
    mut ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let mut retry_delay = WATCH_RETRY_MIN;
    loop {
        let roots = match node_blocking(node.clone(), |node| node.protected_roots()).await {
            Ok(roots) => roots,
            Err(error) => {
                tracing::error!(%error, "cannot inspect protected root; watcher will retry");
                tokio::time::sleep(retry_delay).await;
                retry_delay = next_retry_delay(retry_delay);
                continue;
            }
        };
        if roots.is_empty() {
            retry_delay = WATCH_RETRY_MIN;
            tokio::time::sleep(WATCH_RETRY_MIN).await;
            continue;
        }
        match watch_once(node.clone(), &roots, &mut ready).await {
            Ok(()) => tracing::warn!("filesystem watcher stopped; restarting"),
            Err(error) => tracing::warn!(
                %error,
                "a protected root is unavailable; peer service remains online and watcher will retry"
            ),
        }
        for root in &roots {
            mark_dirty(
                node.clone(),
                root.root_id,
                "protected root watcher unavailable; reconciliation required",
                false,
            )
            .await;
        }
        tokio::time::sleep(retry_delay).await;
        retry_delay = next_retry_delay(retry_delay);
    }
}

async fn watch_once(
    node: Arc<Mutex<Node>>,
    roots: &[ProtectedRoot],
    ready: &mut Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(WATCH_EVENT_CAPACITY);
    let watcher_failure = Arc::new(Mutex::new(None::<String>));
    let callback_failure = watcher_failure.clone();
    let watched_paths = roots
        .iter()
        .map(|root| (root.root_id, root.path.clone()))
        .collect::<Vec<_>>();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        match event {
            Ok(event) if !event_requires_reconciliation(&event.kind) => return,
            Ok(event) => {
                for (root_id, root_path) in &watched_paths {
                    if event.paths.iter().any(|path| path.starts_with(root_path)) {
                        let _ = sender.try_send(*root_id);
                    }
                }
                return;
            }
            Err(error) => {
                if let Ok(mut failure) = callback_failure.lock() {
                    *failure = Some(error.to_string());
                }
            }
        }
        // One pending notification per root is sufficient: events are hints which
        // trigger a full reconciliation, not an authoritative change journal.
        // Watcher errors are retained separately so a full event queue cannot hide
        // them.
        for (root_id, _) in &watched_paths {
            let _ = sender.try_send(*root_id);
        }
    })
    .context("cannot create recursive filesystem watcher")?;
    let mut opened = BTreeMap::new();
    let mut unavailable = BTreeMap::<uuid::Uuid, (tokio::time::Instant, Duration)>::new();
    for root in roots {
        match attach_watched_root(&mut watcher, root) {
            Ok((handle, identity)) => {
                // Attach the watch before advancing the dirty generation.
                // Events during reconciliation remain queued, so capture
                // cannot miss a change between the full scan and readiness.
                persist_dirty(
                    node.clone(),
                    root.root_id,
                    "startup or watcher restart reconciliation required",
                    false,
                )
                .await?;
                opened.insert(root.root_id, (root.clone(), handle, identity));
            }
            Err(error) => {
                tracing::warn!(
                    root = %root.path.display(),
                    %error,
                    "protected root watch is unavailable; healthy roots remain watched"
                );
                mark_dirty(
                    node.clone(),
                    root.root_id,
                    "protected root watcher unavailable; reconciliation required",
                    false,
                )
                .await;
                unavailable.insert(
                    root.root_id,
                    (
                        tokio::time::Instant::now() + WATCH_RETRY_MIN,
                        WATCH_RETRY_MIN,
                    ),
                );
            }
        }
    }
    if let Some(ready) = ready.take() {
        let _ = ready.send(());
    }
    let mut health = tokio::time::interval(WATCH_ROOT_HEALTH_INTERVAL);
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    health.tick().await;
    loop {
        if let Some(error) = watcher_failure
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem watcher error state is poisoned"))?
            .take()
        {
            anyhow::bail!("filesystem watcher reported an error: {error}");
        }
        tokio::select! {
            signal = receiver.recv() => match signal {
                Some(root_id) => {
                    mark_dirty(
                        node.clone(),
                        root_id,
                        "filesystem changed; reconciliation required",
                        true,
                    )
                    .await;
                }
                None => anyhow::bail!("filesystem watcher callback stopped"),
            },
            _ = health.tick() => {
                let current_roots = node_blocking(node.clone(), |node| node.protected_roots()).await?;
                if current_roots != roots {
                    anyhow::bail!("protected-root configuration changed");
                }
                let failed = opened
                    .iter()
                    .filter_map(|(root_id, (root, _handle, expected))| {
                        match watched_root_identity(root) {
                            Ok(current) if current == *expected => None,
                            Ok(_) => Some((*root_id, "protected root was replaced or remounted".to_owned())),
                            Err(error) => Some((*root_id, format!("protected root health check failed: {error:#}"))),
                        }
                    })
                    .collect::<Vec<_>>();
                for (root_id, error) in failed {
                    let (root, _handle, _expected) = opened
                        .remove(&root_id)
                        .expect("failed watched root must still be tracked");
                    let _ = watcher.unwatch(&root.path);
                    tracing::warn!(root = %root.path.display(), %error, "protected root watch became unavailable");
                    mark_dirty(
                        node.clone(),
                        root_id,
                        "protected root watcher unavailable; reconciliation required",
                        false,
                    )
                    .await;
                    unavailable.insert(
                        root_id,
                        (tokio::time::Instant::now() + WATCH_RETRY_MIN, WATCH_RETRY_MIN),
                    );
                }
                let now = tokio::time::Instant::now();
                for root in roots {
                    if opened.contains_key(&root.root_id)
                        || unavailable
                            .get(&root.root_id)
                            .is_some_and(|(retry_at, _)| *retry_at > now)
                    {
                        continue;
                    }
                    match attach_watched_root(&mut watcher, root) {
                        Ok((handle, identity)) => {
                            persist_dirty(
                                node.clone(),
                                root.root_id,
                                "protected root watcher restored; reconciliation required",
                                false,
                            )
                            .await?;
                            opened.insert(root.root_id, (root.clone(), handle, identity));
                            unavailable.remove(&root.root_id);
                        }
                        Err(error) => {
                            let delay = unavailable
                                .get(&root.root_id)
                                .map(|(_, delay)| next_retry_delay(*delay))
                                .unwrap_or(WATCH_RETRY_MIN);
                            tracing::debug!(root = %root.path.display(), %error, ?delay, "protected root watch retry deferred");
                            unavailable.insert(root.root_id, (now + delay, delay));
                        }
                    }
                }
            }
        }
    }
}

fn attach_watched_root(
    watcher: &mut notify::RecommendedWatcher,
    root: &ProtectedRoot,
) -> Result<(File, WatchedRootIdentity)> {
    let opened = open_watched_root(root)?;
    watcher
        .watch(&root.path, RecursiveMode::Recursive)
        .with_context(|| format!("cannot watch protected root {}", root.path.display()))?;
    Ok(opened)
}

fn event_requires_reconciliation(kind: &EventKind) -> bool {
    !matches!(
        kind,
        EventKind::Access(
            AccessKind::Read | AccessKind::Open(_) | AccessKind::Close(AccessMode::Read)
        )
    )
}

fn open_watched_root(root: &ProtectedRoot) -> Result<(File, WatchedRootIdentity)> {
    use std::os::unix::fs::MetadataExt;

    let handle = File::open(&root.path)?;
    let held = handle.metadata()?;
    let identity = watched_root_identity(root)?;
    if !held.is_dir() || held.dev() != identity.device || held.ino() != identity.inode {
        anyhow::bail!("protected root changed while its watcher was being attached");
    }
    Ok((handle, identity))
}

fn watched_root_identity(root: &ProtectedRoot) -> Result<WatchedRootIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(&root.path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("protected root is not a safe directory");
    }
    let filesystem = filesystem_identity(&root.path)?;
    if !root.matches_identity(filesystem, metadata.ino()) {
        anyhow::bail!("protected root identity changed");
    }
    Ok(WatchedRootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount_id: filesystem.mount_id,
    })
}

async fn mark_dirty(
    node: Arc<Mutex<Node>>,
    root_id: uuid::Uuid,
    reason: &'static str,
    changed: bool,
) {
    if let Err(error) = persist_dirty(node, root_id, reason, changed).await {
        tracing::error!(%error, "cannot persist protected-root dirty state");
    }
}

async fn persist_dirty(
    node: Arc<Mutex<Node>>,
    root_id: uuid::Uuid,
    reason: &'static str,
    changed: bool,
) -> Result<()> {
    node_blocking(node, move |node| {
        if changed {
            node.mark_root_changed(root_id, reason)
        } else {
            node.mark_root_dirty(root_id, reason)
        }
    })
    .await
}

fn next_retry_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(WATCH_RETRY_MAX)
}

async fn node_blocking<T, F>(node: Arc<Mutex<Node>>, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut Node) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut node = node
            .lock()
            .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?;
        operation(&mut node)
    })
    .await
    .context("filesystem watcher worker failed")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn watcher_retry_is_bounded() {
        assert_eq!(
            next_retry_delay(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(next_retry_delay(Duration::from_secs(32)), WATCH_RETRY_MAX);
        assert_eq!(next_retry_delay(WATCH_RETRY_MAX), WATCH_RETRY_MAX);
    }

    #[test]
    fn watcher_ignores_reads_but_not_close_after_write() {
        assert!(!event_requires_reconciliation(&EventKind::Access(
            AccessKind::Open(AccessMode::Any)
        )));
        assert!(!event_requires_reconciliation(&EventKind::Access(
            AccessKind::Read
        )));
        assert!(!event_requires_reconciliation(&EventKind::Access(
            AccessKind::Close(AccessMode::Read)
        )));
        assert!(event_requires_reconciliation(&EventKind::Access(
            AccessKind::Close(AccessMode::Write)
        )));
        assert!(event_requires_reconciliation(&EventKind::Modify(
            notify::event::ModifyKind::Any
        )));
    }

    #[test]
    fn root_identity_detects_directory_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("root");
        std::fs::create_dir(&path).unwrap();
        let filesystem = filesystem_identity(&path).unwrap();
        let root = ProtectedRoot {
            format_version: 3,
            root_id: uuid::Uuid::new_v4(),
            path: path.clone(),
            filesystem_id: filesystem.stable_id,
            root_inode: std::fs::symlink_metadata(&path).unwrap().ino(),
        };
        let (_held_root, before) = open_watched_root(&root).unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(watched_root_identity(&root).is_err());
        assert_eq!(before.inode, root.root_inode);
    }

    #[tokio::test]
    async fn unavailable_root_does_not_block_healthy_root_watch() {
        let temp = tempfile::tempdir().unwrap();
        let missing_path = temp.path().join("missing");
        let healthy_path = temp.path().join("healthy");
        std::fs::create_dir(&missing_path).unwrap();
        std::fs::create_dir(&healthy_path).unwrap();
        let missing_filesystem = filesystem_identity(&missing_path).unwrap();
        let healthy_filesystem = filesystem_identity(&healthy_path).unwrap();
        let missing_inode = std::fs::metadata(&missing_path).unwrap().ino();
        let healthy_inode = std::fs::metadata(&healthy_path).unwrap().ino();
        let missing_id = uuid::Uuid::from_bytes([1; 16]);
        let healthy_id = uuid::Uuid::from_bytes([2; 16]);
        let mut node = Node::open(
            temp.path().join("state"),
            mb_core::Seed::from_bytes([91; 32]),
        )
        .unwrap();
        node.install_test_protected_root(ProtectedRoot {
            format_version: 3,
            root_id: missing_id,
            path: missing_path.clone(),
            filesystem_id: missing_filesystem.stable_id,
            root_inode: missing_inode,
        })
        .unwrap();
        node.install_test_protected_root(ProtectedRoot {
            format_version: 3,
            root_id: healthy_id,
            path: healthy_path.clone(),
            filesystem_id: healthy_filesystem.stable_id,
            root_inode: healthy_inode,
        })
        .unwrap();
        std::fs::remove_dir_all(&missing_path).unwrap();
        let node = Arc::new(Mutex::new(node));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let watcher = tokio::spawn(run_root_watcher_ready(node.clone(), ready_tx));
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap();

        std::fs::write(healthy_path.join("changed"), b"changed").unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let sequence = node
                    .lock()
                    .unwrap()
                    .test_root_change_sequence(healthy_id)
                    .unwrap();
                if sequence >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            node.lock()
                .unwrap()
                .test_root_change_sequence(missing_id)
                .unwrap(),
            1
        );
        watcher.abort();
    }
}

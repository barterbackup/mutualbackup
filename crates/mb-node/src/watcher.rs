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
    let opened = roots
        .iter()
        .map(|root| {
            open_watched_root(root).map(|(handle, identity)| (root.clone(), handle, identity))
        })
        .collect::<Result<Vec<_>>>()?;
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
    for root in roots {
        watcher
            .watch(&root.path, RecursiveMode::Recursive)
            .with_context(|| format!("cannot watch protected root {}", root.path.display()))?;
    }
    // Attach every watch before advancing the dirty generation. Events which
    // arrive during reconciliation remain queued, so a capture started after
    // readiness cannot miss a change between the full scan and watcher setup.
    for root in roots {
        persist_dirty(
            node.clone(),
            root.root_id,
            "startup or watcher restart reconciliation required",
            false,
        )
        .await?;
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
                for (root, _handle, expected) in &opened {
                    let current = watched_root_identity(root)
                        .context("protected root health check failed")?;
                    if current != *expected {
                        anyhow::bail!("protected root was removed, replaced, or remounted");
                    }
                }
                let current_roots = node_blocking(node.clone(), |node| node.protected_roots()).await?;
                if current_roots != roots {
                    anyhow::bail!("protected-root configuration changed");
                }
            }
        }
    }
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
}

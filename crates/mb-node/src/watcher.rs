use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use mb_store::filesystem_identity;
use notify::{RecursiveMode, Watcher};

use crate::{Node, ProtectedRoot};

const WATCH_RETRY_MIN: Duration = Duration::from_secs(1);
const WATCH_RETRY_MAX: Duration = Duration::from_secs(60);
const WATCH_EVENT_CAPACITY: usize = 1;
const WATCH_ROOT_HEALTH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WatchedRootIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

pub async fn run_root_watcher(node: Arc<Mutex<Node>>) -> Result<()> {
    let mut retry_delay = WATCH_RETRY_MIN;
    loop {
        let root = match node_blocking(node.clone(), |node| node.protected_root()).await {
            Ok(root) => root,
            Err(error) => {
                tracing::error!(%error, "cannot inspect protected root; watcher will retry");
                tokio::time::sleep(retry_delay).await;
                retry_delay = next_retry_delay(retry_delay);
                continue;
            }
        };
        let Some(root) = root else {
            retry_delay = WATCH_RETRY_MIN;
            tokio::time::sleep(WATCH_RETRY_MIN).await;
            continue;
        };
        mark_dirty(
            node.clone(),
            "startup or watcher restart reconciliation required",
        )
        .await;

        match watch_once(node.clone(), &root).await {
            Ok(()) => tracing::warn!(
                root = %root.path.display(),
                "filesystem watcher stopped; restarting"
            ),
            Err(error) => tracing::warn!(
                root = %root.path.display(),
                %error,
                "protected root is unavailable; peer service remains online and watcher will retry"
            ),
        }
        mark_dirty(
            node.clone(),
            "protected root watcher unavailable; reconciliation required",
        )
        .await;
        tokio::time::sleep(retry_delay).await;
        retry_delay = next_retry_delay(retry_delay);
    }
}

async fn watch_once(node: Arc<Mutex<Node>>, root: &ProtectedRoot) -> Result<()> {
    let expected = watched_root_identity(root)?;
    let (sender, mut receiver) = tokio::sync::mpsc::channel(WATCH_EVENT_CAPACITY);
    let watcher_failure = Arc::new(Mutex::new(None::<String>));
    let callback_failure = watcher_failure.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if let Err(error) = event
            && let Ok(mut failure) = callback_failure.lock()
        {
            *failure = Some(error.to_string());
        }
        // One pending notification is sufficient: events are hints which trigger a
        // full reconciliation, not an authoritative change journal. Watcher errors
        // are retained separately so a full event queue cannot hide them.
        let _ = sender.try_send(());
    })
    .context("cannot create recursive filesystem watcher")?;
    watcher
        .watch(&root.path, RecursiveMode::Recursive)
        .with_context(|| format!("cannot watch protected root {}", root.path.display()))?;
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
                Some(()) => {
                    mark_dirty(node.clone(), "filesystem changed; reconciliation required").await;
                }
                None => anyhow::bail!("filesystem watcher callback stopped"),
            },
            _ = health.tick() => {
                let current = watched_root_identity(root)
                    .context("protected root health check failed")?;
                if current != expected {
                    anyhow::bail!("protected root was removed, replaced, or remounted");
                }
            }
        }
    }
}

fn watched_root_identity(root: &ProtectedRoot) -> Result<WatchedRootIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(&root.path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("protected root is not a safe directory");
    }
    let filesystem = filesystem_identity(&root.path)?;
    if filesystem.device != root.filesystem_device
        || filesystem.mount_id != root.filesystem_mount_id
    {
        anyhow::bail!("protected root filesystem identity changed");
    }
    Ok(WatchedRootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount_id: filesystem.mount_id,
    })
}

async fn mark_dirty(node: Arc<Mutex<Node>>, reason: &'static str) {
    if let Err(error) = node_blocking(node, move |node| node.mark_root_dirty(reason)).await {
        tracing::error!(%error, "cannot persist protected-root dirty state");
    }
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
    fn root_identity_detects_directory_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("root");
        std::fs::create_dir(&path).unwrap();
        let filesystem = filesystem_identity(&path).unwrap();
        let root = ProtectedRoot {
            format_version: 2,
            root_id: uuid::Uuid::new_v4(),
            path: path.clone(),
            filesystem_device: filesystem.device,
            filesystem_mount_id: filesystem.mount_id,
        };
        let before = watched_root_identity(&root).unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let after = watched_root_identity(&root).unwrap();
        assert_ne!(before, after);
    }
}

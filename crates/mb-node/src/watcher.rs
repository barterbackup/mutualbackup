use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};

use crate::Node;

const WATCH_RETRY_MIN: Duration = Duration::from_secs(1);
const WATCH_RETRY_MAX: Duration = Duration::from_secs(60);
const WATCH_EVENT_CAPACITY: usize = 1;

pub async fn run_root_watcher(node: Arc<Mutex<Node>>) -> Result<()> {
    let mut retry_delay = WATCH_RETRY_MIN;
    loop {
        let root = match node_blocking(node.clone(), |node| {
            node.protected_root().map(|root| root.map(|root| root.path))
        })
        .await
        {
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
                root = %root.display(),
                "filesystem watcher stopped; restarting"
            ),
            Err(error) => tracing::warn!(
                root = %root.display(),
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

async fn watch_once(node: Arc<Mutex<Node>>, root: &std::path::Path) -> Result<()> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(WATCH_EVENT_CAPACITY);
    let mut watcher = notify::recommended_watcher(move |_event| {
        // One pending notification is sufficient: events are hints which trigger a
        // full reconciliation, not an authoritative change journal.
        let _ = sender.try_send(());
    })
    .context("cannot create recursive filesystem watcher")?;
    watcher
        .watch(root, RecursiveMode::Recursive)
        .with_context(|| format!("cannot watch protected root {}", root.display()))?;
    while receiver.recv().await.is_some() {
        mark_dirty(node.clone(), "filesystem changed; reconciliation required").await;
    }
    Ok(())
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
}

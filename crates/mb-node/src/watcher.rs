use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};

use crate::Node;

pub async fn run_root_watcher(node: Arc<Mutex<Node>>) -> Result<()> {
    loop {
        let root = node_blocking(node.clone(), |node| {
            node.protected_root().map(|root| root.map(|root| root.path))
        })
        .await?;
        let Some(root) = root else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        node_blocking(node.clone(), |node| {
            node.mark_root_dirty("startup reconciliation required")
        })
        .await?;

        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = sender.send(event);
        })
        .context("cannot create recursive filesystem watcher")?;
        watcher
            .watch(&root, RecursiveMode::Recursive)
            .with_context(|| format!("cannot watch protected root {}", root.display()))?;
        while let Some(event) = receiver.recv().await {
            let reason = match event {
                Ok(event) => format!("filesystem event: {:?}", event.kind),
                Err(error) => format!("filesystem watcher error or overflow: {error}"),
            };
            node_blocking(node.clone(), move |node| node.mark_root_dirty(&reason)).await?;
        }
        tracing::warn!(root = %root.display(), "filesystem watcher stopped; restarting");
    }
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

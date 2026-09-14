use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::control::{query_local_backup_job, submit_local_backup};
use crate::node::AutomaticBackupPoll;
use crate::{BackupJobState, Node, P2pClient};

pub async fn run_automatic_backups(node: Arc<Mutex<Node>>, p2p: P2pClient) -> Result<()> {
    loop {
        let poll = node_blocking(node.clone(), |node| {
            node.poll_automatic_backup(unix_seconds())
        })
        .await?;
        match poll {
            AutomaticBackupPoll::Idle => {}
            AutomaticBackupPoll::InFlight(revision_id) => {
                match query_local_backup_job(node.clone(), &p2p, revision_id).await {
                    Ok(job) if job.state == BackupJobState::Committed => {
                        node_blocking(node.clone(), move |node| {
                            node.automatic_backup_finished(Some(revision_id), true, None)
                        })
                        .await?;
                    }
                    Ok(job) if job.state == BackupJobState::Failed => {
                        let error = job
                            .error
                            .unwrap_or_else(|| "automatic backup failed".into());
                        node_blocking(node.clone(), move |node| {
                            node.automatic_backup_finished(Some(revision_id), false, Some(&error))
                        })
                        .await?;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%revision_id, %error, "automatic backup status check deferred");
                    }
                }
            }
            AutomaticBackupPoll::Start { estimated_bytes } => {
                match submit_local_backup(node.clone(), &p2p, false).await {
                    Ok(job) => {
                        let revision_id = job.descriptor.revision_id;
                        node_blocking(node.clone(), move |node| {
                            node.automatic_backup_submitted(revision_id)
                        })
                        .await?;
                        tracing::info!(
                            %revision_id,
                            estimated_bytes,
                            "automatic backup submitted after full reconciliation"
                        );
                    }
                    Err(error) => {
                        let message = format!("{error:#}");
                        tracing::warn!(%error, "automatic backup submission deferred");
                        node_blocking(node.clone(), move |node| {
                            node.automatic_backup_finished(None, false, Some(&message))
                        })
                        .await?;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn run_periodic_audits(
    node: Arc<Mutex<Node>>,
    p2p: P2pClient,
    interval: Duration,
) -> Result<()> {
    let interval_seconds = interval.as_secs();
    anyhow::ensure!(
        interval_seconds > 0,
        "audit interval must be greater than zero"
    );
    loop {
        let now = unix_seconds();
        let due = node_blocking(node.clone(), move |node| {
            node.guild_audit_due(now, interval_seconds)
        })
        .await?;
        if due {
            let reports = node_blocking(node.clone(), |node| node.scrub_storage()).await?;
            let corrupt = reports
                .iter()
                .map(|report| report.corrupt_objects.len())
                .sum::<usize>();
            if corrupt > 0 {
                tracing::warn!(
                    corrupt,
                    "periodic storage scrub found corrupt parity objects"
                );
            }
            match crate::audit_guild(node.clone(), &p2p, true).await {
                Ok(report) => tracing::info!(
                    state = ?report.state,
                    groups = report.checked_groups,
                    unavailable = report.assigned_shards_unavailable,
                    repaired = report.assigned_shards_repaired,
                    emergency = report.emergency_copies_created,
                    emergency_removed = report.emergency_copies_removed,
                    "periodic guild audit completed"
                ),
                Err(error) => tracing::warn!(%error, "periodic guild audit deferred"),
            }
        }
        tokio::time::sleep(Duration::from_secs(interval_seconds.min(60))).await;
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
    .context("automatic-backup worker failed")?
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

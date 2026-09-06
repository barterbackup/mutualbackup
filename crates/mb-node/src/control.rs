use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as SyncUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use mb_core::NodeId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use crate::Node;

const MAX_LOCAL_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectedRoot {
    pub format_version: u16,
    pub root_id: Uuid,
    pub path: PathBuf,
    pub filesystem_device: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub format_version: u16,
    pub node_id: NodeId,
    pub data_dir: PathBuf,
    pub protected_root: Option<ProtectedRoot>,
    pub checkpoint_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LocalRequest {
    Status,
    AddRoot { path: PathBuf },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LocalResponse {
    Status(NodeStatus),
    RootAdded(ProtectedRoot),
    Error(String),
}

pub async fn serve_local_control(node: Arc<Mutex<Node>>, socket_path: &Path) -> Result<()> {
    let parent = socket_path
        .parent()
        .context("control socket must have a parent directory")?;
    let parent_existed = parent.exists();
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "cannot create control socket directory {}",
            parent.display()
        )
    })?;
    if !parent_existed {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("control socket directory must be private and owned by the daemon user");
    }
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket() {
            bail!(
                "refusing to replace non-socket control path {}",
                socket_path.display()
            );
        }
        match SyncUnixStream::connect(socket_path) {
            Ok(_) => bail!("another daemon is already listening on the control socket"),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(socket_path).with_context(|| {
                    format!("cannot remove stale socket {}", socket_path.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot verify stale socket {}", socket_path.display())
                });
            }
        }
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("cannot bind control socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(socket_path)?;
    let _cleanup = SocketCleanup {
        path: socket_path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(node, stream).await {
                tracing::warn!(%error, "local control request failed");
            }
        });
    }
}

pub async fn local_control_call(
    socket_path: &Path,
    request: &LocalRequest,
) -> Result<LocalResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("cannot connect to daemon at {}", socket_path.display()))?;
    write_frame(&mut stream, request).await?;
    let response: LocalResponse = read_frame(&mut stream).await?;
    if let LocalResponse::Error(message) = &response {
        bail!("daemon rejected request: {message}");
    }
    Ok(response)
}

async fn handle_connection(node: Arc<Mutex<Node>>, mut stream: UnixStream) -> Result<()> {
    let request: LocalRequest = read_frame(&mut stream).await?;
    let response = tokio::task::spawn_blocking(move || {
        let mut node = node
            .lock()
            .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?;
        match request {
            LocalRequest::Status => node.status().map(LocalResponse::Status),
            LocalRequest::AddRoot { path } => {
                node.add_protected_root(&path).map(LocalResponse::RootAdded)
            }
        }
    })
    .await
    .context("local control worker failed")?
    .unwrap_or_else(|error| LocalResponse::Error(format!("{error:#}")));
    write_frame(&mut stream, &response).await
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_LOCAL_FRAME_BYTES {
        bail!("local control frame exceeds size limit");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_LOCAL_FRAME_BYTES {
        bail!("local control frame exceeds size limit");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_protocol_round_trips() {
        let request = LocalRequest::AddRoot {
            path: PathBuf::from("/var/lib/data"),
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: LocalRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            decoded,
            LocalRequest::AddRoot { path } if path == Path::new("/var/lib/data")
        ));
    }
}

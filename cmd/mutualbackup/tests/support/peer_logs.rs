//! Preserve fixture daemon diagnostics across successful cleanup and panics.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const LOG_NAMES: &[&str] = &[
    "p0.log",
    "p1.log",
    "p2.log",
    "p3.log",
    "p4.log",
    "recovered.log",
    "storage-recovered.log",
    "outsider.log",
    "recovered-p1.log",
];

pub(super) struct PeerLogArchive {
    run_root: PathBuf,
    destination: Option<PathBuf>,
    finished: bool,
}

impl PeerLogArchive {
    pub(super) fn from_environment(run_root: &Path) -> io::Result<Self> {
        let archive_root = std::env::var_os("MUTUALBACKUP_TEST_LOG_ROOT").map(PathBuf::from);
        Self::new(run_root, archive_root.as_deref())
    }

    fn new(run_root: &Path, archive_root: Option<&Path>) -> io::Result<Self> {
        let destination = if let Some(root) = archive_root {
            DirBuilder::new().recursive(true).mode(0o700).create(root)?;
            if !fs::symlink_metadata(root)?.file_type().is_dir() {
                return Err(io::Error::other("peer log archive must be a directory"));
            }
            let root = root.canonicalize()?;
            if root.starts_with(run_root.canonicalize()?) {
                return Err(io::Error::other(
                    "peer log archive must be outside the fixture",
                ));
            }
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            let prefix = run_root.file_name().unwrap_or_default().to_string_lossy();
            Some(
                tempfile::Builder::new()
                    .prefix(&format!("{prefix}-"))
                    .permissions(fs::Permissions::from_mode(0o700))
                    .tempdir_in(root)?
                    .keep(),
            )
        } else {
            None
        };
        Ok(Self {
            run_root: run_root.to_owned(),
            destination,
            finished: false,
        })
    }

    /// Call after stopping daemons, before removing any fixture directories.
    /// A failed copy leaves the original fixture intact for diagnosis.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if let Some(destination) = &self.destination {
            for name in LOG_NAMES {
                let source = self.run_root.join(name);
                let metadata = match fs::symlink_metadata(&source) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                if !metadata.file_type().is_file() {
                    continue;
                }
                let mut input = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(source)?;
                if !input.metadata()?.is_file() {
                    continue;
                }
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(destination.join(name))?;
                io::copy(&mut input, &mut output)?;
                output.sync_all()?;
            }
            File::open(destination)?.sync_all()?;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for PeerLogArchive {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!(
                "could not archive peer logs from {}: {error}",
                self.run_root.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn archives_only_named_regular_daemon_logs_before_successful_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("process-success");
        fs::create_dir(&run).unwrap();
        fs::write(run.join("p0.log"), b"peer diagnostics\n").unwrap();
        fs::write(run.join("private.log"), b"unrelated secret").unwrap();
        fs::create_dir(run.join("source")).unwrap();
        fs::write(run.join("source/p1.log"), b"protected payload").unwrap();
        symlink("source/p1.log", run.join("p1.log")).unwrap();
        fs::create_dir(run.join("p2.log")).unwrap();
        let archive_root = temp.path().join("artifacts");
        let mut archive = PeerLogArchive::new(&run, Some(&archive_root)).unwrap();
        let destination = archive.destination.clone().unwrap();
        archive.finish().unwrap();
        fs::remove_dir_all(&run).unwrap();
        drop(archive);
        assert_eq!(
            fs::read(destination.join("p0.log")).unwrap(),
            b"peer diagnostics\n"
        );
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
        for directory in [&archive_root, &destination] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(destination.join("p0.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn archives_peer_logs_on_fixture_failure_without_removing_originals() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("process-failure");
        fs::create_dir(&run).unwrap();
        fs::write(run.join("recovered.log"), b"failed retry diagnostics").unwrap();
        let archive_root = temp.path().join("artifacts");
        let result = std::panic::catch_unwind(|| {
            let _archive = PeerLogArchive::new(&run, Some(&archive_root)).unwrap();
            panic!("fixture failed");
        });
        assert!(result.is_err());
        let destination = fs::read_dir(archive_root)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::read(destination.join("recovered.log")).unwrap(),
            b"failed retry diagnostics"
        );
        assert_eq!(
            fs::read(run.join("recovered.log")).unwrap(),
            b"failed retry diagnostics"
        );
    }

    #[test]
    fn refuses_archive_inside_fixture_and_preserves_logs_when_copy_fails() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("process-copy-error");
        fs::create_dir(&run).unwrap();
        assert!(PeerLogArchive::new(&run, Some(&run.join("artifacts"))).is_err());
        fs::write(run.join("p0.log"), b"original diagnostics").unwrap();
        let archive_root = temp.path().join("artifacts");
        let mut archive = PeerLogArchive::new(&run, Some(&archive_root)).unwrap();
        fs::remove_dir(archive.destination.as_ref().unwrap()).unwrap();
        assert!(archive.finish().is_err());
        assert_eq!(
            fs::read(run.join("p0.log")).unwrap(),
            b"original diagnostics"
        );
    }
}

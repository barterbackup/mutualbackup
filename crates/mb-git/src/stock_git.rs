//! Find ordinary Git when the user has installed `mutualgit` as `git` on PATH.
//!
//! Packed-object streaming uses `git cat-file --batch`. Running the first
//! `git` on PATH would recurse into our own CLI when its optional alias is
//! installed ahead of stock Git.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::process::Command;

pub(crate) fn executable() -> io::Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    executable_in(&path)
}

fn executable_in(path: &OsStr) -> io::Result<PathBuf> {
    for directory in std::env::split_paths(path) {
        let candidate = directory.join("git");
        let Ok(output) = Command::new(&candidate).arg("--version").output() else {
            continue;
        };
        if output.status.success() && output.stdout.starts_with(b"git version ") {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "stock Git is required for raw object streaming; install ordinary Git on the daemon's PATH (the mutualgit alias cannot replace it)",
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn skips_mutualgit_alias_ahead_of_stock_git() {
        let alias_dir = tempfile::tempdir().unwrap();
        let alias = alias_dir.path().join("git");
        fs::write(&alias, b"#!/bin/sh\nprintf 'mutualgit 0.1.0\\n'\n").unwrap();
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o755)).unwrap();
        let stock_dir = tempfile::tempdir().unwrap();
        let stock = stock_dir.path().join("git");
        fs::write(&stock, b"#!/bin/sh\nprintf 'git version 2.55.0\\n'\n").unwrap();
        fs::set_permissions(&stock, fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([alias_dir.path(), stock_dir.path()]).unwrap();
        assert_eq!(executable_in(&path).unwrap(), stock);
    }

    #[test]
    fn missing_dependency_reports_how_to_supply_ordinary_git() {
        let empty = tempfile::tempdir().unwrap();
        let error = executable_in(empty.path().as_os_str()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("daemon's PATH"));
    }
}

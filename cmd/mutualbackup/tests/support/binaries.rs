//! Select one complete installed candidate, or the ordinary Cargo programs.
//! An explicit candidate never falls back to a program from another build.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const PROGRAMS: [(&str, &str); 4] = [
    ("mutualbackup", env!("CARGO_BIN_EXE_mutualbackup")),
    ("mutualbackupd", env!("CARGO_BIN_EXE_mutualbackupd")),
    ("mutualgit", env!("CARGO_BIN_EXE_mutualgit")),
    (
        "git-remote-mutualbackup",
        env!("CARGO_BIN_EXE_git-remote-mutualbackup"),
    ),
];

pub fn program(name: &str) -> &'static Path {
    static SELECTED: OnceLock<[PathBuf; 4]> = OnceLock::new();
    let programs = SELECTED.get_or_init(|| {
        select(std::env::var_os("MUTUALBACKUP_TEST_BIN_DIR").as_deref())
            .unwrap_or_else(|error| panic!("invalid process-test candidate: {error}"))
    });
    let index = PROGRAMS
        .iter()
        .position(|(candidate, _)| *candidate == name)
        .expect("unknown process-test program");
    &programs[index]
}

fn select(directory: Option<&OsStr>) -> Result<[PathBuf; 4], String> {
    use std::os::unix::fs::PermissionsExt;

    let directory = directory.map(Path::new);
    if let Some(directory) = directory
        && (!directory.is_absolute() || !directory.is_dir())
    {
        return Err(format!(
            "MUTUALBACKUP_TEST_BIN_DIR must name an absolute installed bin directory: {}",
            directory.display()
        ));
    }
    let programs = PROGRAMS.map(|(name, built)| match directory {
        Some(directory) => directory.join(name),
        None => PathBuf::from(built),
    });
    for program in &programs {
        let metadata = std::fs::metadata(program)
            .map_err(|error| format!("{}: {error}", program.display()))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!(
                "candidate is not executable: {}",
                program.display()
            ));
        }
    }
    Ok(programs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn candidate(root: &Path) {
        for (name, _) in PROGRAMS {
            let file = root.join(name);
            std::fs::write(&file, b"#!/bin/sh\nprintf 'installed-candidate\\n'\n").unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn installed_selection_executes_only_the_candidate_including_symlinked_raw_paths() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"candidate-\xff".to_vec()));
        std::fs::create_dir(&directory).unwrap();
        candidate(&directory);
        let link = temp.path().join("installed");
        symlink(&directory, &link).unwrap();
        for program in select(Some(link.as_os_str())).unwrap() {
            assert!(program.starts_with(&link));
            let output = std::process::Command::new(program).output().unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, b"installed-candidate\n");
        }
    }

    #[test]
    fn incomplete_or_unexecutable_candidate_cannot_mix_in_cargo_programs() {
        let temp = tempfile::tempdir().unwrap();
        candidate(temp.path());
        let helper = temp.path().join("git-remote-mutualbackup");
        std::fs::remove_file(&helper).unwrap();
        assert!(
            select(Some(temp.path().as_os_str()))
                .unwrap_err()
                .contains("git-remote-mutualbackup")
        );
        candidate(temp.path());
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            select(Some(temp.path().as_os_str()))
                .unwrap_err()
                .contains("not executable")
        );
        assert!(select(Some(OsStr::new(""))).is_err());
        assert!(select(Some(OsStr::new("relative/bin"))).is_err());
    }
}

//! Raw-byte Git diffs over committed anchors, the staged index, and a pinned
//! worktree. Libgit2 computes hunks from buffers; no Git filters or checkout
//! conversion are involved. Input and output caps bound this first frontend.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use git2::{DiffOptions, ObjectType, Oid, Patch};
use mb_store::{AnchorError, ControlStore, PinnedReadDirectory};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::GitWorktreeScope;
use crate::stage::{
    GitIndexEntry, StageError, anchors_for_oid, indexed_anchor_manifest, stage_path_key,
    staged_entries_for_scope,
};
use crate::status::{StatusError, committed_files_for_scope};

const MAX_DIFF_FILE_BYTES: u64 = 16 * 1024 * 1024;
// The local control socket currently has a 1 MiB JSON frame; a byte array can
// expand to four JSON bytes per payload byte. Keep a conservative envelope.
const MAX_DIFF_OUTPUT_BYTES: usize = 192 * 1024;
type DiffFile = (Vec<u8>, u32, [u8; 20]);

#[derive(Debug, Error)]
pub enum DiffError {
    #[error("Git stage error: {0}")]
    Stage(#[from] StageError),
    #[error("Git history read error: {0}")]
    Status(#[from] StatusError),
    #[error("native source path or anchor error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("working-tree read error: {0}")]
    Io(#[from] std::io::Error),
    #[error("libgit2 could not generate the raw-byte diff: {0}")]
    Git(#[from] git2::Error),
    #[error("a Git blob has no verified native anchor")]
    MissingAnchor,
    #[error("a file or diff output exceeds the bounded local diff limit")]
    TooLarge,
    #[error("the working file changed while the diff was read")]
    SourceChanged,
    #[error("the committed or staged file has an unsupported Git mode")]
    UnsupportedMode,
    #[error("the working file has different bytes under the staged Git object ID")]
    OidCollision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitDiff {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub cached: bool,
    pub patch: Vec<u8>,
}

fn read_anchor(
    control: &ControlStore,
    repository_id: Uuid,
    oid: [u8; 20],
    selected_anchor: Option<Uuid>,
) -> Result<Vec<u8>, DiffError> {
    let anchors = anchors_for_oid(control, repository_id, Oid::from_bytes(&oid)?)?;
    let anchor = anchors
        .into_iter()
        .find(|anchor| selected_anchor.is_none_or(|id| anchor.anchor_id == id))
        .ok_or(DiffError::MissingAnchor)?;
    if anchor.logical_len > MAX_DIFF_FILE_BYTES {
        return Err(DiffError::TooLarge);
    }
    let (mut file, _) = crate::catalog_anchor::open(control, &anchor).map_err(StageError::from)?;
    let mut bytes = Vec::with_capacity(anchor.logical_len as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != anchor.logical_len {
        return Err(DiffError::SourceChanged);
    }
    Ok(bytes)
}

fn fingerprint(metadata: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn read_worktree(
    root: &PinnedReadDirectory,
    path: &[u8],
    expected: &GitIndexEntry,
    expected_hash: [u8; 32],
    expected_len: u64,
) -> Result<Option<DiffFile>, DiffError> {
    let relative = PathBuf::from(OsString::from_vec(path.to_vec()));
    stage_path_key(&relative)?;
    let mut parent = root.try_clone()?;
    let mut components = relative.components().peekable();
    let mut leaf = None;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(StageError::UnsafePath.into());
        };
        if components.peek().is_some() {
            let Some(next) = parent.open_child_directory(name)? else {
                return Ok(None);
            };
            parent = next;
        } else {
            leaf = Some(name);
        }
    }
    let leaf = leaf.ok_or(StageError::UnsafePath)?;
    match parent.read_child_symlink(leaf) {
        Ok(Some(bytes)) => {
            if bytes.len() as u64 == expected_len
                && blake3::hash(&bytes).as_bytes() == &expected_hash
            {
                return Ok(Some((Vec::new(), 0o120000, expected.oid)));
            }
            let oid: [u8; 20] = Oid::hash_object(ObjectType::Blob, &bytes)?
                .as_bytes()
                .try_into()
                .expect("SHA-1 OID");
            if oid == expected.oid {
                return Err(DiffError::OidCollision);
            }
            return Ok(Some((bytes, 0o120000, oid)));
        }
        Ok(None) => return Ok(None),
        Err(AnchorError::UnsupportedObject(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let Some(mut file) = parent.open_child_file(leaf)? else {
        return Ok(None);
    };
    read_worktree_file(&mut file, expected, expected_hash, expected_len).map(Some)
}

fn read_worktree_file(
    file: &mut File,
    expected: &GitIndexEntry,
    expected_hash: [u8; 32],
    expected_len: u64,
) -> Result<DiffFile, DiffError> {
    let before = file.metadata()?;
    let mode = if before.mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    };
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if fingerprint(&before) != fingerprint(&file.metadata()?) {
        return Err(DiffError::SourceChanged);
    }
    if before.len() == expected_len && hasher.finalize().as_bytes() == &expected_hash {
        return Ok((Vec::new(), mode, expected.oid));
    }
    if before.len() > MAX_DIFF_FILE_BYTES {
        return Err(DiffError::TooLarge);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(MAX_DIFF_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DIFF_FILE_BYTES
        || bytes.len() as u64 != before.len()
        || fingerprint(&before) != fingerprint(&file.metadata()?)
    {
        return Err(DiffError::SourceChanged);
    }
    let oid: [u8; 20] = Oid::hash_object(ObjectType::Blob, &bytes)?
        .as_bytes()
        .try_into()
        .expect("SHA-1 OID");
    if oid == expected.oid {
        return Err(DiffError::OidCollision);
    }
    Ok((bytes, mode, oid))
}

fn append_bounded(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DiffError> {
    if output.len().saturating_add(bytes.len()) > MAX_DIFF_OUTPUT_BYTES {
        return Err(DiffError::TooLarge);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn quote_git_path(prefix: &[u8], path: &[u8]) -> Vec<u8> {
    let bytes = [prefix, path].concat();
    if bytes
        .iter()
        .all(|byte| matches!(byte, b'!'..=b'~') && !matches!(byte, b'"' | b'\\'))
    {
        return bytes;
    }
    let mut quoted = vec![b'"'];
    for byte in bytes {
        match byte {
            b'"' | b'\\' => quoted.extend([b'\\', byte]),
            b'\n' => quoted.extend_from_slice(b"\\n"),
            b'\t' => quoted.extend_from_slice(b"\\t"),
            0x20..=0x7e => quoted.push(byte),
            _ => quoted.extend(format!("\\{byte:03o}").as_bytes()),
        }
    }
    quoted.push(b'"');
    quoted
}

fn append_patch(
    output: &mut Vec<u8>,
    path: &[u8],
    old: Option<DiffFile>,
    new: Option<DiffFile>,
) -> Result<(), DiffError> {
    let old_mode = old.as_ref().map(|(_, mode, _)| *mode);
    let new_mode = new.as_ref().map(|(_, mode, _)| *mode);
    if old_mode.is_some_and(|mode| !matches!(mode, 0o100644 | 0o100755 | 0o120000))
        || new_mode.is_some_and(|mode| !matches!(mode, 0o100644 | 0o100755 | 0o120000))
    {
        return Err(DiffError::UnsupportedMode);
    }
    let old_oid = old.as_ref().map_or([0; 20], |(_, _, oid)| *oid);
    let new_oid = new.as_ref().map_or([0; 20], |(_, _, oid)| *oid);
    if old_oid == new_oid && old_mode == new_mode {
        return Ok(());
    }
    let old_path = quote_git_path(b"a/", path);
    let new_path = quote_git_path(b"b/", path);
    append_bounded(output, b"diff --git ")?;
    append_bounded(output, &old_path)?;
    append_bounded(output, b" ")?;
    append_bounded(output, &new_path)?;
    append_bounded(output, b"\n")?;
    match (old_mode, new_mode) {
        (None, Some(mode)) => {
            append_bounded(output, format!("new file mode {mode:06o}\n").as_bytes())?
        }
        (Some(mode), None) => {
            append_bounded(output, format!("deleted file mode {mode:06o}\n").as_bytes())?
        }
        (Some(old), Some(new)) if old != new => {
            append_bounded(
                output,
                format!("old mode {old:06o}\nnew mode {new:06o}\n").as_bytes(),
            )?;
        }
        _ => {}
    }
    let old_git_oid = Oid::from_bytes(&old_oid)?;
    let new_git_oid = Oid::from_bytes(&new_oid)?;
    let mode_suffix = if old_mode == new_mode {
        old_mode.map_or(String::new(), |mode| format!(" {mode:06o}"))
    } else {
        String::new()
    };
    append_bounded(
        output,
        format!("index {old_git_oid}..{new_git_oid}{mode_suffix}\n").as_bytes(),
    )?;
    let old_bytes = old
        .as_ref()
        .map_or(&[][..], |(bytes, _, _)| bytes.as_slice());
    let new_bytes = new
        .as_ref()
        .map_or(&[][..], |(bytes, _, _)| bytes.as_slice());
    if old_bytes == new_bytes {
        return Ok(());
    }
    let path = Path::new(std::ffi::OsStr::from_bytes(path));
    let mut options = DiffOptions::new();
    options.max_size(MAX_DIFF_FILE_BYTES as i64);
    let patch = Patch::from_buffers(
        old_bytes,
        Some(path),
        new_bytes,
        Some(path),
        Some(&mut options),
    )?;
    if patch.num_hunks() == 0 {
        append_bounded(output, b"Binary files ")?;
        append_bounded(
            output,
            if old.is_some() {
                &old_path
            } else {
                b"/dev/null"
            },
        )?;
        append_bounded(output, b" and ")?;
        append_bounded(
            output,
            if new.is_some() {
                &new_path
            } else {
                b"/dev/null"
            },
        )?;
        append_bounded(output, b" differ\n")?;
        return Ok(());
    }
    append_bounded(output, b"--- ")?;
    append_bounded(
        output,
        if old.is_some() {
            &old_path
        } else {
            b"/dev/null"
        },
    )?;
    append_bounded(output, b"\n+++ ")?;
    append_bounded(
        output,
        if new.is_some() {
            &new_path
        } else {
            b"/dev/null"
        },
    )?;
    append_bounded(output, b"\n")?;
    for hunk_index in 0..patch.num_hunks() {
        let (hunk, line_count) = patch.hunk(hunk_index)?;
        append_bounded(output, hunk.header())?;
        for line_index in 0..line_count {
            let line = patch.line_in_hunk(hunk_index, line_index)?;
            match line.origin() {
                ' ' | '+' | '-' => append_bounded(output, &[line.origin() as u8])?,
                '=' | '>' | '<' => {}
                _ => return Err(DiffError::UnsupportedMode),
            }
            append_bounded(output, line.content())?;
        }
    }
    Ok(())
}

fn index_entry_bytes(
    control: &ControlStore,
    repository_id: Uuid,
    entry: &GitIndexEntry,
) -> Result<DiffFile, DiffError> {
    Ok((
        read_anchor(control, repository_id, entry.oid, Some(entry.anchor_id))?,
        entry.mode,
        entry.oid,
    ))
}

pub fn repository_diff(
    control: &ControlStore,
    repository_id: Uuid,
    root: &Path,
    cached: bool,
) -> Result<GitDiff, DiffError> {
    repository_diff_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        root,
        cached,
    )
}

pub(crate) fn repository_diff_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root: &Path,
    cached: bool,
) -> Result<GitDiff, DiffError> {
    let working_root = (!cached)
        .then(|| PinnedReadDirectory::open(root))
        .transpose()?;
    repository_diff_with_directory(control, scope, working_root, cached)
}

fn repository_diff_with_directory(
    control: &ControlStore,
    scope: GitWorktreeScope,
    working_root: Option<PinnedReadDirectory>,
    cached: bool,
) -> Result<GitDiff, DiffError> {
    let repository_id = scope.repository_id();
    let staged = staged_entries_for_scope(control, scope)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let committed = if cached {
        committed_files_for_scope(control, scope)?
    } else {
        BTreeMap::new()
    };
    let paths = if cached {
        staged
            .keys()
            .chain(committed.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
    } else {
        staged.keys().cloned().collect::<BTreeSet<_>>()
    };
    let mut output = Vec::new();
    for path in paths {
        stage_path_key(&PathBuf::from(OsString::from_vec(path.clone())))?;
        let index = staged.get(&path);
        if cached {
            let head = committed.get(&path);
            if head.map(|(oid, mode)| (*oid, *mode)) == index.map(|entry| (entry.oid, entry.mode)) {
                continue;
            }
            if let (Some((oid, old_mode)), Some(new_entry)) = (head, index)
                && *oid == new_entry.oid
            {
                append_patch(
                    &mut output,
                    &path,
                    Some((Vec::new(), *old_mode, *oid)),
                    Some((Vec::new(), new_entry.mode, new_entry.oid)),
                )?;
                continue;
            }
            let old = head
                .map(|(oid, mode)| {
                    Ok::<_, DiffError>((
                        read_anchor(control, repository_id, *oid, None)?,
                        *mode,
                        *oid,
                    ))
                })
                .transpose()?;
            let new = index
                .map(|entry| index_entry_bytes(control, repository_id, entry))
                .transpose()?;
            append_patch(&mut output, &path, old, new)?;
        } else if let Some(index) = index {
            let anchor = indexed_anchor_manifest(control, repository_id, index)?;
            let new = read_worktree(
                working_root.as_ref().expect("uncached root"),
                &path,
                index,
                anchor.content_hash,
                anchor.logical_len,
            )?;
            if new
                .as_ref()
                .is_some_and(|(_, mode, oid)| *oid == index.oid && *mode == index.mode)
            {
                continue;
            }
            if let Some((_, mode, oid)) = new.as_ref()
                && *oid == index.oid
            {
                append_patch(
                    &mut output,
                    &path,
                    Some((Vec::new(), index.mode, index.oid)),
                    Some((Vec::new(), *mode, *oid)),
                )?;
                continue;
            }
            let old = Some(index_entry_bytes(control, repository_id, index)?);
            append_patch(&mut output, &path, old, new)?;
        }
    }
    Ok(GitDiff {
        format_version: 1,
        repository_id,
        cached,
        patch: output,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use git2::{ObjectType, Oid};

    use super::{DiffError, append_patch, read_worktree_file};
    use crate::stage::GitIndexEntry;

    #[test]
    fn diff_rejects_a_git_id_with_conflicting_native_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("file");
        fs::write(&path, b"bravo").unwrap();
        let entry = GitIndexEntry {
            format_version: 1,
            oid: Oid::hash_object(ObjectType::Blob, b"bravo")
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            mode: 0o100644,
            anchor_id: uuid::Uuid::new_v4(),
        };
        let mut file = fs::File::open(&path).unwrap();
        assert_eq!(
            read_worktree_file(&mut file, &entry, *blake3::hash(b"bravo").as_bytes(), 5).unwrap(),
            (Vec::new(), entry.mode, entry.oid)
        );
        let mut file = fs::File::open(&path).unwrap();
        assert!(matches!(
            read_worktree_file(&mut file, &entry, *blake3::hash(b"alpha").as_bytes(), 5),
            Err(DiffError::OidCollision)
        ));
    }

    fn blob(bytes: &[u8], mode: u32) -> (Vec<u8>, u32, [u8; 20]) {
        (
            bytes.to_vec(),
            mode,
            Oid::hash_object(ObjectType::Blob, bytes)
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn raw_diff_preserves_crlf_binary_and_git_file_modes() {
        let mut patch = Vec::new();
        append_patch(
            &mut patch,
            b"text",
            Some(blob(b"one\r\n", 0o100644)),
            Some(blob(b"two\n", 0o100755)),
        )
        .unwrap();
        assert!(
            patch
                .windows(b"old mode 100644\nnew mode 100755\n".len())
                .any(|part| { part == b"old mode 100644\nnew mode 100755\n" })
        );
        assert!(
            patch
                .windows(b"-one\r\n+two\n".len())
                .any(|part| part == b"-one\r\n+two\n")
        );

        let mut binary = Vec::new();
        append_patch(&mut binary, b"odd\xff", None, Some(blob(b"a\0b", 0o100644))).unwrap();
        assert!(binary.starts_with(b"diff --git \"a/odd\\377\" \"b/odd\\377\"\n"));
        assert!(
            binary
                .windows(b"new file mode 100644\n".len())
                .any(|part| { part == b"new file mode 100644\n" })
        );
        assert!(binary.ends_with(b"Binary files /dev/null and \"b/odd\\377\" differ\n"));

        let mut empty = Vec::new();
        append_patch(&mut empty, b"empty", None, Some(blob(b"", 0o100644))).unwrap();
        assert!(
            empty
                .windows(b"new file mode 100644\n".len())
                .any(|part| { part == b"new file mode 100644\n" })
        );
        assert!(!empty.windows(b"---".len()).any(|part| part == b"---"));

        let mut mode_only = Vec::new();
        append_patch(
            &mut mode_only,
            b"mode",
            Some(blob(b"unchanged", 0o100644)),
            Some(blob(b"unchanged", 0o100755)),
        )
        .unwrap();
        assert!(
            mode_only
                .windows(b"old mode 100644\nnew mode 100755\n".len())
                .any(|part| { part == b"old mode 100644\nnew mode 100755\n" })
        );
        assert!(!mode_only.windows(b"---".len()).any(|part| part == b"---"));

        let mut without_newline = Vec::new();
        append_patch(
            &mut without_newline,
            b"no-newline",
            Some(blob(b"one", 0o100644)),
            Some(blob(b"two", 0o100644)),
        )
        .unwrap();
        assert!(
            without_newline
                .windows(b"\\ No newline at end of file".len())
                .any(|part| { part == b"\\ No newline at end of file" })
        );
    }

    #[test]
    #[ignore = "requires a locally installed stock Git executable"]
    fn generated_text_patch_applies_byte_exactly_in_stock_git() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("text");
        fs::write(&source, b"one\r\n").unwrap();
        let mut patch = Vec::new();
        append_patch(
            &mut patch,
            b"text",
            Some(blob(b"one\r\n", 0o100644)),
            Some(blob(b"two\n", 0o100755)),
        )
        .unwrap();
        let patch_path = temp.path().join("change.patch");
        fs::write(&patch_path, patch).unwrap();
        let check = Command::new("git")
            .current_dir(temp.path())
            .args(["apply", "--check", "change.patch"])
            .status()
            .unwrap();
        assert!(check.success());
        let apply = Command::new("git")
            .current_dir(temp.path())
            .args(["apply", "change.patch"])
            .status()
            .unwrap();
        assert!(apply.success());
        assert_eq!(fs::read(&source).unwrap(), b"two\n");
        assert_ne!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o111,
            0
        );
    }
}

//! Byte-preserving Git attribute policy. We never invoke Git's conversion
//! machinery; explicit repository rules that request it fail before publishing
//! a Git index/ref or changing tracked worktree bytes.

use std::io::Read;
use std::path::{Component, Path};

use mb_store::{AnchorError, FileAnchorManifest, PinnedDirectory};
use thiserror::Error;

pub(crate) const MAX_ATTRIBUTES_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum GitAttributesError {
    #[error("repository attributes request a content conversion that mutualgit does not support")]
    ContentConversion,
    #[error("repository attributes exceed the local size limit")]
    TooLarge,
    #[error("repository attributes contain a NUL byte and cannot be interpreted safely")]
    Malformed,
    #[error("repository attributes cannot be read safely: {0}")]
    Anchor(#[from] AnchorError),
    #[error("repository attributes read failed: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn is_attributes_path(path: &[u8]) -> bool {
    path.rsplit(|byte| *byte == b'/').next() == Some(b".gitattributes".as_slice())
}

fn transforming_attribute(token: &[u8]) -> bool {
    let inactive = matches!(token.first(), Some(b'-' | b'!'));
    let token = if inactive { &token[1..] } else { token };
    let name = token.split(|byte| *byte == b'=').next().unwrap_or_default();
    let conversion = matches!(
        name,
        b"text" | b"crlf" | b"eol" | b"filter" | b"ident" | b"working-tree-encoding"
    );
    conversion && (!inactive || token.contains(&b'='))
}

pub(crate) fn validate_attributes(bytes: &[u8]) -> Result<(), GitAttributesError> {
    if bytes.contains(&0) {
        return Err(GitAttributesError::Malformed);
    }
    for line in bytes.split(|byte| *byte == b'\n') {
        let mut tokens = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|token| !token.is_empty());
        let Some(pattern) = tokens.next() else {
            continue;
        };
        if pattern.starts_with(b"#") {
            continue;
        }
        if tokens.any(transforming_attribute) {
            return Err(GitAttributesError::ContentConversion);
        }
    }
    Ok(())
}

pub(crate) fn validate_reader(mut reader: impl Read) -> Result<(), GitAttributesError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_ATTRIBUTES_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ATTRIBUTES_BYTES {
        return Err(GitAttributesError::TooLarge);
    }
    validate_attributes(&bytes)
}

pub(crate) fn validate_anchor(anchor: &FileAnchorManifest) -> Result<(), GitAttributesError> {
    if anchor.logical_len > MAX_ATTRIBUTES_BYTES {
        return Err(GitAttributesError::TooLarge);
    }
    validate_reader(anchor.open_verified()?)
}

/// Check every attributes file that would govern this worktree-relative path.
/// The pinned-directory API never follows an attributes symlink.
pub(crate) fn validate_worktree_path(
    source_root: &Path,
    relative_path: &Path,
) -> Result<(), GitAttributesError> {
    let mut directory = PinnedDirectory::open(source_root)?;
    validate_directory(&directory)?;
    for component in relative_path
        .parent()
        .into_iter()
        .flat_map(Path::components)
    {
        let Component::Normal(name) = component else {
            return Err(GitAttributesError::ContentConversion);
        };
        directory = directory
            .open_child_directory(name)?
            .ok_or_else(|| AnchorError::UnsupportedObject(relative_path.to_path_buf()))?;
        validate_directory(&directory)?;
    }
    Ok(())
}

fn validate_directory(directory: &PinnedDirectory) -> Result<(), GitAttributesError> {
    match directory.open_child_file(".gitattributes") {
        Ok(Some(file)) => validate_reader(file)?,
        Ok(None) | Err(AnchorError::UnsupportedObject(_)) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_conversion_rules_but_accepts_disabled_attributes() {
        for unsafe_rule in [
            b"* text=auto\n".as_slice(),
            b"*.txt filter=normalize\n",
            b"[attr]binary -text ident\n",
            b"* working-tree-encoding=UTF-16\n",
            b"* crlf\n",
            b"* -text=auto\n",
        ] {
            assert!(matches!(
                validate_attributes(unsafe_rule),
                Err(GitAttributesError::ContentConversion)
            ));
        }
        validate_attributes(b"# text=auto\n* -text -filter -ident !eol\n").unwrap();
        assert!(matches!(
            validate_attributes(b"* text\0=auto\n"),
            Err(GitAttributesError::Malformed)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlinked_attributes_are_not_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("rules"), b"* text=auto\n").unwrap();
        symlink("rules", directory.path().join(".gitattributes")).unwrap();
        validate_worktree_path(directory.path(), Path::new("payload")).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checks_each_ancestor_attributes_file() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join(".gitattributes"), b"* -text\n").unwrap();
        std::fs::write(
            directory.path().join("nested/.gitattributes"),
            b"* eol=crlf\n",
        )
        .unwrap();
        validate_worktree_path(directory.path(), Path::new("sibling")).unwrap();
        assert!(matches!(
            validate_worktree_path(directory.path(), Path::new("nested/payload")),
            Err(GitAttributesError::ContentConversion)
        ));
    }
}

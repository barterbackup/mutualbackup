//! Bounded Linux native-tree restore from retained paged ownership. Git history
//! and remote/seed-only paged recovery are separate consumer migration gates.

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mb_core::{
    CATALOG_FILE_PATH_BYTES, CATALOG_FILE_RECORD_BYTES, CatalogFileEvent, CatalogFileKind,
    CatalogFileReader, CatalogFileRecipeRecord, CatalogFileRecord, CatalogFileStat,
    CatalogNativeFileReader, CatalogScope, CatalogSection, KeyMaterial, SectorId,
    canonical_bytes_bounded, decode_canonical, merkle_commit,
};
use mb_store::{
    CatalogBundleState, ControlStore, NativeFileId, PinnedDirectory, RecordScratchStore,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::PagedPrivateMetadata;
use crate::snapshot::{decrypt_reference, native_id_for_file, set_metadata_durable};

const ENTRY_BYTES: usize = CATALOG_FILE_RECORD_BYTES + 128;

#[cfg(test)]
thread_local! {
    static IGNORE_NEXT_INDEX_INSERT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn ignore_next_restore_index_insert() {
    IGNORE_NEXT_INDEX_INSERT.with(|flag| flag.set(true));
}

#[derive(Serialize, Deserialize)]
struct RestoredEntry {
    record: CatalogFileRecord,
    identity: NativeFileId,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct RestoredLink {
    identity: NativeFileId,
    stat: CatalogFileStat,
    logical_len: u64,
}

struct RestoreIndex<'a> {
    control: &'a ControlStore,
    records: RecordScratchStore,
    kinds: [String; 4],
}

impl<'a> RestoreIndex<'a> {
    fn new(
        control: &'a ControlStore,
        target: [u8; 32],
        records: RecordScratchStore,
    ) -> Result<Self> {
        #[cfg(test)]
        if IGNORE_NEXT_INDEX_INSERT.with(|flag| flag.replace(false)) {
            records.database_shell_statement("CREATE TEMP TRIGGER ignore_restore_index BEFORE INSERT ON protocol_records WHEN NEW.kind LIKE 'paged-native-restore-entry-v1/%' BEGIN SELECT RAISE(IGNORE); END", false)?;
        }
        Ok(Self {
            control,
            records,
            kinds: ["entry", "directory", "link", "alias"]
                .map(|role| format!("paged-native-restore-{role}-v1/{}", hex::encode(target))),
        })
    }

    // Reclaim rows left by versions that kept disposable indexes in control.db.
    fn clear_legacy(&self) -> Result<()> {
        for kind in &self.kinds {
            while let Some((key, bytes)) = self.control.next_record_bounded(
                kind,
                None,
                CATALOG_FILE_PATH_BYTES + 1,
                ENTRY_BYTES,
            )? {
                self.control.delete_record_if_value(kind, &key, &bytes)?;
            }
        }
        Ok(())
    }

    fn put(&self, role: usize, key: &[u8], bytes: &[u8]) -> Result<()> {
        self.records
            .put_record_if_absent(&self.kinds[role], key, bytes)?;
        ensure!(
            self.records
                .get_record_bounded(&self.kinds[role], key, ENTRY_BYTES)?
                .as_deref()
                == Some(bytes),
            "restore index write was ignored or conflicts with another inode"
        );
        Ok(())
    }

    fn entry(&self, path: &[u8]) -> Result<RestoredEntry> {
        let bytes = self
            .records
            .get_record_bounded(&self.kinds[0], path, ENTRY_BYTES)?
            .context("restored path has no tracked inode")?;
        let entry = Self::decode_entry(&bytes)?;
        ensure!(
            entry.record.path == path,
            "restore entry key differs from its path"
        );
        Ok(entry)
    }

    fn decode_entry(bytes: &[u8]) -> Result<RestoredEntry> {
        let entry: RestoredEntry = decode_canonical(bytes)?;
        entry.record.validate()?;
        ensure!(
            canonical_bytes_bounded(&entry, ENTRY_BYTES)? == bytes,
            "noncanonical restore entry"
        );
        Ok(entry)
    }

    fn track(&self, entry: &RestoredEntry) -> Result<()> {
        let bytes = canonical_bytes_bounded(entry, ENTRY_BYTES)?;
        self.put(0, &entry.record.path, &bytes)?;
        if matches!(entry.record.kind, CatalogFileKind::Directory) {
            // Descendants precede their parents. The terminator sorts after
            // every complemented non-NUL path byte, reversing prefix order too.
            let key = directory_key(&entry.record.path);
            self.put(1, &key, &bytes)?;
        }
        Ok(())
    }

    fn link(&self, group: u64) -> Result<Option<RestoredLink>> {
        let Some(bytes) =
            self.records
                .get_record_bounded(&self.kinds[2], &group.to_be_bytes(), 128)?
        else {
            return Ok(None);
        };
        let link: RestoredLink = decode_canonical(&bytes)?;
        link.stat.validate()?;
        ensure!(
            canonical_bytes_bounded(&link, 128)? == bytes,
            "noncanonical restore link"
        );
        Ok(Some(link))
    }

    fn directory(&self, root: &PinnedDirectory, path: &[u8]) -> Result<PinnedDirectory> {
        let mut directory = root.try_clone()?;
        let mut prefix = Vec::new();
        for component in path
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
        {
            if !prefix.is_empty() {
                prefix.push(b'/');
            }
            prefix.extend(component);
            let expected = self.entry(&prefix)?;
            ensure!(
                matches!(expected.record.kind, CatalogFileKind::Directory),
                "restore parent is not a directory"
            );
            directory = directory
                .open_child_directory(raw_path(component))?
                .context("restored parent directory disappeared")?;
            ensure!(
                directory.identity()? == expected.identity,
                "restored parent directory was replaced"
            );
        }
        Ok(directory)
    }

    fn destination(
        &self,
        root: &PinnedDirectory,
        path: &[u8],
    ) -> Result<(PinnedDirectory, PathBuf)> {
        let split = path.iter().rposition(|byte| *byte == b'/');
        let (parent, name) = split.map_or((&[][..], path), |index| {
            (&path[..index], &path[index + 1..])
        });
        Ok((self.directory(root, parent)?, raw_path(name)))
    }

    fn verify_children(&self, directory: &PinnedDirectory, prefix: &[u8]) -> Result<()> {
        for child in fs::read_dir(directory.descriptor_path())? {
            let child = child?;
            let name = child.file_name();
            let mut path = prefix.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend(name.as_bytes());
            ensure!(
                path.len() <= CATALOG_FILE_PATH_BYTES,
                "unexpected overlong restored path"
            );
            let expected = self.entry(&path)?;
            let is_directory = matches!(expected.record.kind, CatalogFileKind::Directory);
            ensure!(
                directory.entry_identity(&name, is_directory)? == Some(expected.identity),
                "restored child was replaced"
            );
        }
        Ok(())
    }

    fn verify_tree(&self, root: &PinnedDirectory) -> Result<()> {
        self.verify_children(root, &[])?;
        let mut after = None;
        while let Some((key, bytes)) = self.records.next_record_bounded(
            &self.kinds[0],
            after.as_deref(),
            CATALOG_FILE_PATH_BYTES,
            ENTRY_BYTES,
        )? {
            let entry = Self::decode_entry(&bytes)?;
            ensure!(entry.record.path == key, "restore index path changed");
            let (parent, name) = self.destination(root, &key)?;
            let is_directory = matches!(entry.record.kind, CatalogFileKind::Directory);
            ensure!(
                parent.entry_identity(&name, is_directory)? == Some(entry.identity),
                "restored inode was replaced"
            );
            if is_directory {
                let directory = parent
                    .open_child_directory(&name)?
                    .context("restored directory disappeared")?;
                self.verify_children(&directory, &key)?;
            }
            after = Some(key);
        }
        Ok(())
    }

    fn finish_directories(&self, root: &PinnedDirectory) -> Result<()> {
        let mut after = None;
        while let Some((key, bytes)) = self.records.next_record_bounded(
            &self.kinds[1],
            after.as_deref(),
            CATALOG_FILE_PATH_BYTES + 1,
            ENTRY_BYTES,
        )? {
            let entry = Self::decode_entry(&bytes)?;
            ensure!(
                matches!(entry.record.kind, CatalogFileKind::Directory)
                    && directory_key(&entry.record.path) == key,
                "invalid restore directory index"
            );
            let directory = self.directory(root, &entry.record.path)?;
            apply_stat(directory.as_file(), entry.record.stat)?;
            after = Some(key);
        }
        Ok(())
    }
}

fn raw_path(bytes: &[u8]) -> PathBuf {
    std::ffi::OsString::from_vec(bytes.to_vec()).into()
}

fn directory_key(path: &[u8]) -> Vec<u8> {
    path.iter().map(|byte| !byte).chain([255]).collect()
}

fn apply_stat(file: &File, stat: CatalogFileStat) -> Result<()> {
    set_metadata_durable(file, stat.mode, stat.modified_secs, stat.modified_nanos)
}

struct PendingFile {
    record: CatalogFileRecord,
    file: Option<File>,
    identity: NativeFileId,
    group: Option<u64>,
    remaining_extent: u64,
}

impl PendingFile {
    fn finish(
        self,
        root: &PinnedDirectory,
        pool: &PinnedDirectory,
        index: &RestoreIndex<'_>,
    ) -> Result<()> {
        ensure!(self.remaining_extent == 0, "restored extent is incomplete");
        if let Some(file) = &self.file {
            apply_stat(file, self.record.stat)?;
            if let Some(group) = self.group {
                let (parent, name) = index.destination(root, &self.record.path)?;
                ensure!(
                    parent.entry_identity(&name, false)? == Some(self.identity),
                    "hard-link primary was replaced"
                );
                parent.hard_link_child_from(&name, pool, group.to_string())?;
                pool.sync_all()?;
                let CatalogFileKind::File { logical_len, .. } = self.record.kind else {
                    anyhow::bail!("missing file kind");
                };
                index.put(
                    2,
                    &group.to_be_bytes(),
                    &canonical_bytes_bounded(
                        &RestoredLink {
                            identity: self.identity,
                            stat: self.record.stat,
                            logical_len,
                        },
                        128,
                    )?,
                )?;
            }
        }
        index.track(&RestoredEntry {
            record: self.record,
            identity: self.identity,
        })
    }
}

impl PagedPrivateMetadata {
    /// Restore the native filesystem portion of a retained local paged
    /// revision. Git-history installation and remote paged restore remain
    /// separate migrations. Caller serializes retained-root cancellation.
    pub fn restore_retained_native_catalog(
        control: &ControlStore,
        keys: &KeyMaterial,
        revision_id: Uuid,
        scope: CatalogScope,
        target: &Path,
        load: impl FnMut(&SectorId) -> Result<Vec<u8>>,
    ) -> Result<()> {
        Self::restore_retained_native_catalog_checked(
            control,
            keys,
            (revision_id, None),
            scope,
            target,
            load,
            |publish| publish(),
        )
    }

    pub(crate) fn restore_retained_native_catalog_checked(
        control: &ControlStore,
        keys: &KeyMaterial,
        identity: (Uuid, Option<Uuid>),
        scope: CatalogScope,
        target: &Path,
        load: impl FnMut(&SectorId) -> Result<Vec<u8>>,
        publish: impl FnOnce(&mut dyn FnMut() -> Result<Vec<u8>>) -> Result<Vec<u8>>,
    ) -> Result<()> {
        Self::restore_retained_catalog_inner::<false>(
            control, keys, identity, scope, target, load, publish,
        )
    }

    pub(crate) fn restore_retained_catalog_checked(
        control: &ControlStore,
        keys: &KeyMaterial,
        identity: (Uuid, Option<Uuid>),
        scope: CatalogScope,
        target: &Path,
        load: impl FnMut(&SectorId) -> Result<Vec<u8>>,
        publish: impl FnOnce(&mut dyn FnMut() -> Result<Vec<u8>>) -> Result<Vec<u8>>,
    ) -> Result<()> {
        Self::restore_retained_catalog_inner::<true>(
            control, keys, identity, scope, target, load, publish,
        )
    }

    fn restore_retained_catalog_inner<const FULL: bool>(
        control: &ControlStore,
        keys: &KeyMaterial,
        identity: (Uuid, Option<Uuid>),
        scope: CatalogScope,
        target: &Path,
        mut load: impl FnMut(&SectorId) -> Result<Vec<u8>>,
        publish: impl FnOnce(&mut dyn FnMut() -> Result<Vec<u8>>) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let version = if FULL { 4 } else { 3 };
        let (revision_id, operation) = identity;
        let snapshot = Self::load_local_catalog(control, keys, revision_id, scope)?
            .context("retained paged revision is unavailable")?;
        let signed_hash = snapshot.revision.value.hash()?;
        let guild = snapshot.revision.value.guild_id;
        let mut identity = blake3::Hasher::new_derive_key(if FULL {
            "mutualbackup paged complete restore identity v1"
        } else {
            "mutualbackup paged native restore identity v1"
        });
        identity.update(&signed_hash);
        let operation = operation.unwrap_or_else(|| {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&identity.finalize().as_bytes()[..16]);
            Uuid::from_bytes(bytes)
        });
        if snapshot.state != CatalogBundleState::Published {
            ensure!(
                crate::snapshot::resume_restore_from_identity(
                    control, guild, operation, version, target
                )?,
                "retained paged revision is cancelled"
            );
            return Ok(());
        }
        let private = snapshot
            .private
            .context("retained private roots are unavailable")?;
        private.native.validate()?;
        let namespace = private.native.namespace;
        let mutations = namespace
            .records
            .records
            .checked_mul(3)
            .and_then(|n| n.checked_add(16))
            .context("restore mutation bound overflow")?;
        // At most two encoded entries per namespace row, plus fixed inode/link
        // fields. Recipes and file payload lengths do not expand this index.
        let values = namespace
            .records
            .page
            .byte_len
            .checked_mul(2)
            .and_then(|n| {
                namespace
                    .records
                    .records
                    .checked_mul(384)
                    .and_then(|m| n.checked_add(m))
            })
            .context("restore record bound overflow")?;
        let limits = mb_store::ScratchStorageLimits::for_record_writes(
            values,
            mutations,
            (CATALOG_FILE_PATH_BYTES + 128) as u32,
            mb_core::CATALOG_MAX_STREAM_BYTES * 4,
        )?;
        // Admission precedes namespace-page reads and restore output staging.
        let records = crate::volume::paged_scratch_store(control, limits.max_database_bytes)
            .context("fund native restore scratch")?;
        let git_restore = if FULL {
            private
                .git
                .as_ref()
                .map(|git| crate::paged_git_restore::prepare(control, scope, git))
                .transpose()?
        } else {
            None
        };
        if FULL && private.git.is_some() {
            let mut namespace = CatalogFileReader::new(scope, private.native.namespace)?;
            while let Some(entry) = namespace.next_file(&mut |page| {
                control.catalog_page(scope, CatalogSection::FileMetadata, page)
            })? {
                ensure!(
                    entry.path.split(|byte| *byte == b'/').next()
                        != Some(mb_store::GIT_CATALOG_DIRECTORY.as_bytes()),
                    "Git restore namespace collides with its private catalog"
                );
            }
        }
        crate::snapshot::restore_from_builder_checked(
            control,
            guild,
            operation,
            version,
            target,
            |root, target_id| {
                let index = RestoreIndex::new(control, target_id, records)?;
                index.clear_legacy()?;
                index.records.with_record_transaction(|| {
                    private.build_native_restore::<FULL>(
                        keys,
                        revision_id,
                        scope,
                        root,
                        &index,
                        &mut load,
                    )?;
                    if FULL {
                        if let Some(git) = &private.git {
                            let future = crate::snapshot::full_paged_restore_target(
                                control, target_id, root,
                            )?;
                            crate::paged_git_restore::restore(
                                control,
                                keys,
                                (revision_id, scope, git),
                                (root, &future),
                                git_restore.context("Git restore has no funded preflight")?,
                                &mut load,
                            )?;
                        }
                        apply_stat(root.as_file(), private.native.namespace.root_stat)?;
                    }
                    let current = Self::load_local_catalog(control, keys, revision_id, scope)?
                        .context("retained root disappeared during restore")?;
                    ensure!(
                        current.state == CatalogBundleState::Published
                            && current.revision.value.hash()? == signed_hash,
                        "retained authority changed during restore"
                    );
                    Ok(())
                })
            },
            publish,
        )
    }

    fn build_native_restore<const DEFER_ROOT: bool>(
        &self,
        keys: &KeyMaterial,
        revision_id: Uuid,
        scope: CatalogScope,
        root: &PinnedDirectory,
        index: &RestoreIndex<'_>,
        load: &mut impl FnMut(&SectorId) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let control = index.control;
        let CatalogScope::Dataset { guild_id, .. } = scope else {
            anyhow::bail!("restore requires dataset scope");
        };
        let mut fetch = |page| control.catalog_page(scope, CatalogSection::FileMetadata, page);
        let pool_name = loop {
            let name = format!(".mutualbackup-restore-links-{}", Uuid::new_v4());
            let mut namespace = CatalogFileReader::new(scope, self.native.namespace)?;
            let mut conflict = false;
            while let Some(entry) = namespace.next_file(&mut fetch)? {
                conflict |= entry.path.split(|byte| *byte == b'/').next() == Some(name.as_bytes());
            }
            if !conflict {
                break name;
            }
        };
        let pool = root.create_child_directory(&pool_name)?;
        let pool_identity = pool.identity()?;
        let mut reader = CatalogNativeFileReader::new(scope, self.native)?;
        let encryption = keys.guild_data_key(&guild_id);
        let mut pending: Option<PendingFile> = None;
        while let Some(event) = reader.next_event(&mut fetch)? {
            match event {
                CatalogFileEvent::Entry(entry) => {
                    if let Some(file) = pending.take() {
                        file.finish(root, &pool, index)?;
                    }
                    let (parent, name) = index.destination(root, &entry.path)?;
                    match entry.kind {
                        CatalogFileKind::Directory => {
                            let directory = parent.create_child_directory(&name)?;
                            index.track(&RestoredEntry {
                                identity: directory.identity()?,
                                record: entry,
                            })?;
                        }
                        CatalogFileKind::HardLink {
                            logical_len,
                            link_group,
                        } => {
                            let group = control
                                .native_file_catalog_link(revision_id, link_group)?
                                .context("hard-link group is not validated")?;
                            ensure!(
                                group.stat == entry.stat && group.logical_len == logical_len,
                                "hard-link attributes differ from validated group"
                            );
                            index.put(
                                3,
                                &entry.path,
                                &canonical_bytes_bounded(&entry, CATALOG_FILE_RECORD_BYTES)?,
                            )?;
                        }
                        CatalogFileKind::File {
                            logical_len,
                            link_group,
                            ..
                        } => {
                            let existing = if let Some(group) = link_group {
                                let validated = control
                                    .native_file_catalog_link(revision_id, group)?
                                    .context("file link group is not validated")?;
                                ensure!(
                                    validated.stat == entry.stat
                                        && validated.logical_len == logical_len,
                                    "file attributes differ from validated group"
                                );
                                index.link(group)?
                            } else {
                                None
                            };
                            let (file, identity) = if let Some(link) = existing {
                                ensure!(
                                    link.stat == entry.stat && link.logical_len == logical_len,
                                    "restored hard-link attributes differ"
                                );
                                let group = link_group.context("missing file link group")?;
                                ensure!(
                                    pool.entry_identity(group.to_string(), false)?
                                        == Some(link.identity),
                                    "restored link pool inode was replaced"
                                );
                                pool.hard_link_child_from(group.to_string(), &parent, &name)?;
                                (None, link.identity)
                            } else {
                                let file = parent.create_child_file(&name)?;
                                file.set_len(logical_len)?;
                                let identity = native_id_for_file(root, &file)?;
                                (Some(file), identity)
                            };
                            pending = Some(PendingFile {
                                record: entry,
                                file,
                                identity,
                                group: link_group,
                                remaining_extent: 0,
                            });
                        }
                    }
                }
                CatalogFileEvent::Recipe(recipe) => {
                    let file = pending.as_mut().context("recipe has no restored file")?;
                    match recipe {
                        CatalogFileRecipeRecord::File { .. } => {}
                        CatalogFileRecipeRecord::Extent {
                            offset,
                            logical_len,
                            ..
                        } => {
                            ensure!(
                                file.remaining_extent == 0,
                                "previous restored extent is incomplete"
                            );
                            if let Some(output) = &mut file.file {
                                output.seek(SeekFrom::Start(offset))?;
                            }
                            file.remaining_extent = logical_len;
                        }
                        CatalogFileRecipeRecord::Sectors { references, .. } => {
                            for reference in references {
                                let source = control
                                    .native_file_catalog_source(revision_id, reference.id)?
                                    .context("file source is not validated")?;
                                ensure!(
                                    source.sector == reference,
                                    "file source differs from signed catalog"
                                );
                                file.remaining_extent = file
                                    .remaining_extent
                                    .checked_sub(u64::from(reference.logical_len))
                                    .context("restored extent overflow")?;
                                if let Some(output) = &mut file.file {
                                    let plaintext =
                                        decrypt_reference(&encryption, &reference, &mut |id| {
                                            let bytes = load(id)?;
                                            ensure!(
                                                merkle_commit(&bytes)? == source.commitment,
                                                "restored source Merkle commitment differs"
                                            );
                                            Ok(bytes)
                                        })?;
                                    output.write_all(&plaintext)?;
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(file) = pending {
            file.finish(root, &pool, index)?;
        }
        let mut after = None;
        while let Some((key, bytes)) = index.records.next_record_bounded(
            &index.kinds[3],
            after.as_deref(),
            CATALOG_FILE_PATH_BYTES,
            CATALOG_FILE_RECORD_BYTES,
        )? {
            let entry = CatalogFileRecord::decode(&bytes)?;
            ensure!(key == entry.path, "deferred alias path changed");
            let CatalogFileKind::HardLink {
                logical_len,
                link_group,
            } = entry.kind
            else {
                anyhow::bail!("invalid deferred hard link");
            };
            let link = index
                .link(link_group)?
                .context("deferred alias has no restored primary")?;
            ensure!(
                entry.stat == link.stat && logical_len == link.logical_len,
                "deferred alias differs from primary"
            );
            let (parent, name) = index.destination(root, &entry.path)?;
            ensure!(
                pool.entry_identity(link_group.to_string(), false)? == Some(link.identity),
                "deferred hard-link primary was replaced"
            );
            pool.hard_link_child_from(link_group.to_string(), &parent, &name)?;
            index.track(&RestoredEntry {
                record: entry,
                identity: link.identity,
            })?;
            after = Some(key);
        }
        let mut after = None;
        while let Some((key, bytes)) =
            index
                .records
                .next_record_bounded(&index.kinds[2], after.as_deref(), 8, 128)?
        {
            let group = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .context("invalid restored link key")?,
            );
            let link: RestoredLink = decode_canonical(&bytes)?;
            pool.remove_child_file_if_identity(group.to_string(), link.identity)?;
            after = Some(key);
        }
        pool.sync_all()?;
        root.remove_child_directory(&pool_name, pool_identity)?;
        index.verify_tree(root)?;
        index.finish_directories(root)?;
        if DEFER_ROOT {
            root.sync_all()?;
            Ok(())
        } else {
            apply_stat(root.as_file(), self.native.namespace.root_stat)
        }
    }
}

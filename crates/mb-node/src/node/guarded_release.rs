use super::*;
use mb_store::{restore_visible_release_metadata, verify_visible_release_namespace};

pub(super) const GUARDED_SEPARATE_RELEASE_KIND: &str = "guarded-separate-root-release-v1";
const RELEASE_METADATA_KIND: &str = "guarded-separate-root-release-metadata-v1";
const RELEASE_NAMES_KIND: &str = "guarded-separate-root-release-names-v1";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct GuardedSeparateReleaseIntentV1 {
    format_version: u16,
    root: ProtectedRoot,
    pub(super) anchor_id: Uuid,
    #[serde(with = "mb_store::raw_path_bytes")]
    lower_path: PathBuf,
    lower_id: NativeFileId,
    placeholder_id: NativeFileId,
    lower_parent_id: NativeFileId,
    view_parent_id: NativeFileId,
    view_uid: u32,
    view_gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuardedSeparateReleaseMetadataV1 {
    format_version: u16,
    root_id: Uuid,
    anchor_id: Uuid,
    intent_hash: [u8; 32],
    visible: GuardedViewMetadataV1,
}

impl GuardedSeparateReleaseIntentV1 {
    fn validate(&self, id: &[u8]) -> Result<()> {
        let normalized = |path: &Path| path.components().collect::<PathBuf>();
        let in_place_lower = self.root.path.parent().map(|parent| {
            parent.join(format!(".mutualbackup-guarded-lower-{}", self.root.root_id))
        });
        if self.format_version != 1
            || self.root.format_version != 4
            || self.root.root_id.is_nil()
            || id != self.root.root_id.as_bytes()
            || self.anchor_id.is_nil()
            || self.root.path == self.lower_path
            || in_place_lower.as_ref() == Some(&self.lower_path)
            || !self.root.path.is_absolute()
            || !self.lower_path.is_absolute()
            || normalized(&self.root.path) != self.root.path
            || normalized(&self.lower_path) != self.lower_path
            || [self.root.path.as_path(), self.lower_path.as_path()]
                .iter()
                .any(|path| {
                    path.components()
                        .any(|part| part == std::path::Component::ParentDir)
                })
            || self.root.path.starts_with(&self.lower_path)
            || self.lower_path.starts_with(&self.root.path)
            || self.view_uid == 0
            || self.root.filesystem_id != self.lower_id.filesystem_id
            || self.root.root_inode != self.lower_id.inode
            || self.placeholder_id.filesystem_id != self.root.filesystem_id
            || self.lower_parent_id.filesystem_id != self.root.filesystem_id
            || self.view_parent_id.filesystem_id != self.root.filesystem_id
        {
            anyhow::bail!("invalid separate guarded release intent");
        }
        Ok(())
    }

    fn parents(&self) -> Result<(PinnedDirectory, PinnedDirectory)> {
        let lower = PinnedDirectory::open(
            self.lower_path
                .parent()
                .context("guarded lower has no parent")?,
        )?;
        let view = PinnedDirectory::open(
            self.root
                .path
                .parent()
                .context("guarded view has no parent")?,
        )?;
        if lower.identity()? != self.lower_parent_id || view.identity()? != self.view_parent_id {
            anyhow::bail!("guarded release parent directory changed");
        }
        Ok((lower, view))
    }

    fn visible(&self, control: &ControlStore) -> Result<Option<GuardedViewMetadataV1>> {
        let Some(bytes) =
            control.get_record(RELEASE_METADATA_KIND, self.root.root_id.as_bytes())?
        else {
            return Ok(None);
        };
        if bytes.len() > mb_core::V1_MAX_CATALOG_BYTES * 2 + 4096 {
            anyhow::bail!("separate guarded release metadata exceeds its local bound");
        }
        let saved: GuardedSeparateReleaseMetadataV1 = decode_canonical(&bytes)?;
        saved.visible.validate_shape()?;
        if saved.format_version != 1
            || saved.root_id != self.root.root_id
            || saved.anchor_id != self.anchor_id
            || saved.intent_hash != *blake3::hash(&canonical_bytes(self)?).as_bytes()
            || saved.visible.anchor_id != self.anchor_id
            || saved.visible.lower_root_id != self.lower_id
            || saved.visible.root_uid != self.view_uid
            || saved.visible.root_gid != self.view_gid
        {
            anyhow::bail!("separate guarded release metadata changed");
        }
        Ok(Some(saved.visible))
    }

    fn save_visible(&self, control: &ControlStore, visible: GuardedViewMetadataV1) -> Result<()> {
        let record = GuardedSeparateReleaseMetadataV1 {
            format_version: 1,
            root_id: self.root.root_id,
            anchor_id: self.anchor_id,
            intent_hash: *blake3::hash(&canonical_bytes(self)?).as_bytes(),
            visible,
        };
        let bytes = canonical_bytes(&record)?;
        if bytes.len() > mb_core::V1_MAX_CATALOG_BYTES * 2 + 4096 {
            anyhow::bail!("separate guarded release metadata exceeds its local bound");
        }
        if !control.put_record_if_absent(
            RELEASE_METADATA_KIND,
            self.root.root_id.as_bytes(),
            &bytes,
        )? && control.get_record(RELEASE_METADATA_KIND, self.root.root_id.as_bytes())?
            != Some(bytes)
        {
            anyhow::bail!("separate guarded release metadata changed after preparation");
        }
        self.visible(control)?
            .context("guarded release lost its snapshot")?;
        Ok(())
    }

    fn release_names(&self, control: &ControlStore, visible: &GuardedViewMetadataV1) -> Result<()> {
        GuardedViewMount::require_retired_release_binding(
            self.anchor_id,
            control,
            &self.lower_path,
            self.lower_id,
            &self.root.path,
            self.placeholder_id,
        )?;
        let (lower_parent, view_parent) = self.parents()?;
        let lower_name = self
            .lower_path
            .file_name()
            .context("guarded lower has no name")?;
        let view_name = self
            .root
            .path
            .file_name()
            .context("guarded view has no name")?;
        let marker = canonical_bytes(self)?;
        if let Some(existing) =
            control.get_record(RELEASE_NAMES_KIND, self.root.root_id.as_bytes())?
        {
            if existing != marker {
                anyhow::bail!("separate guarded release name marker changed");
            }
        } else {
            if lower_parent.entry_identity(lower_name, true)? != Some(self.lower_id)
                || view_parent.entry_identity(view_name, true)? != Some(self.placeholder_id)
                || !view_parent.child_directory_is_empty(view_name, self.placeholder_id)?
            {
                anyhow::bail!("separate guarded release names changed before preparation");
            }
            let lower = lower_parent
                .open_child_directory(lower_name)?
                .context("separate guarded lower disappeared")?;
            verify_visible_release_namespace(&lower, visible)?;
            if !control.put_record_if_absent(
                RELEASE_NAMES_KIND,
                self.root.root_id.as_bytes(),
                &marker,
            )? {
                anyhow::bail!("separate guarded release name marker changed concurrently");
            }
        }
        if lower_parent.entry_identity(lower_name, true)? == Some(self.lower_id) {
            let lower = lower_parent
                .open_child_directory(lower_name)?
                .context("separate guarded lower disappeared")?;
            verify_visible_release_namespace(&lower, visible)?;
        }
        match (
            lower_parent.entry_identity(lower_name, true)?,
            view_parent.entry_identity(view_name, true)?,
        ) {
            (None, Some(id)) if id == self.lower_id => return Ok(()),
            (Some(lower), Some(view)) if lower == self.lower_id && view == self.placeholder_id => {
                if !view_parent.remove_empty_child_directory(view_name, self.placeholder_id)? {
                    anyhow::bail!("separate guarded placeholder changed before removal");
                }
            }
            (Some(lower), None) if lower == self.lower_id => {}
            _ => anyhow::bail!("separate guarded lower or view name changed"),
        }
        lower_parent.move_child_directory_no_replace(
            lower_name,
            self.lower_id,
            &view_parent,
            view_name,
        )?;
        if lower_parent.entry_identity(lower_name, true)?.is_some()
            || view_parent.entry_identity(view_name, true)? != Some(self.lower_id)
        {
            anyhow::bail!("separate guarded release did not return its view path");
        }
        Ok(())
    }
}

impl Node {
    pub(super) fn pending_separate_guarded_releases(
        control: &ControlStore,
    ) -> Result<Vec<(GuardedSeparateReleaseIntentV1, Vec<u8>)>> {
        let pending = control.records(GUARDED_SEPARATE_RELEASE_KIND)?;
        if pending.len() > 1
            || !pending.is_empty() && !control.records(GUARDED_RELEASE_KIND)?.is_empty()
        {
            anyhow::bail!("multiple guarded releases are pending");
        }
        pending
            .into_iter()
            .map(|(id, bytes)| {
                let intent: GuardedSeparateReleaseIntentV1 = decode_canonical(&bytes)?;
                intent.validate(&id)?;
                if control.get_record("protected-root", &id)?
                    != Some(canonical_bytes(&intent.root)?)
                {
                    anyhow::bail!("separate guarded release lost its protected root");
                }
                let guarded: GuardedProtectedRootV1 = decode_canonical(
                    &control
                        .get_record("guarded-protected-root-v1", &id)?
                        .context("separate guarded release lost its anchor binding")?,
                )?;
                if guarded.format_version != 1
                    || guarded.root_id != intent.root.root_id
                    || guarded.anchor_id != intent.anchor_id
                {
                    anyhow::bail!("separate guarded release anchor binding changed");
                }
                let backend: SourceBackendBinding = decode_canonical(
                    &control
                        .get_record("source-backend", &id)?
                        .context("separate guarded release lost its source backend")?,
                )?;
                if !backend.is_supported_guarded_for(
                    intent.root.root_id,
                    intent.root.filesystem_id,
                    intent.root.root_inode,
                ) {
                    anyhow::bail!("separate guarded release source backend changed");
                }
                intent.parents()?;
                match GuardedRootCapturePlan::load_for_retirement(control, intent.anchor_id)? {
                    Some(plan)
                        if plan.source_root() != intent.lower_path
                            || plan.source_root_identity() != intent.lower_id =>
                    {
                        anyhow::bail!("separate guarded release source plan changed");
                    }
                    None => GuardedRootCapturePlan::require_completed_retirement(
                        control,
                        intent.anchor_id,
                    )?,
                    Some(_) => {}
                }
                intent.visible(control)?;
                if let Some(marker) = control.get_record(RELEASE_NAMES_KIND, &id)?
                    && marker != bytes
                {
                    anyhow::bail!("separate guarded release name marker changed");
                }
                Ok((intent, bytes))
            })
            .collect()
    }

    pub(super) fn reconcile_separate_guarded_releases(
        &mut self,
        pending: &[(GuardedSeparateReleaseIntentV1, Vec<u8>)],
    ) -> Result<()> {
        for (intent, bytes) in pending {
            self.finish_separate_guarded_release(intent, bytes)?;
        }
        Ok(())
    }

    pub(super) fn remove_separate_guarded_root(&mut self, root_id: Uuid) -> Result<()> {
        self.check_guarded_mounts()?;
        let intent = self.new_separate_guarded_release_intent(root_id)?;
        let bytes = canonical_bytes(&intent)?;
        if !self.control.put_record_if_absent(
            GUARDED_SEPARATE_RELEASE_KIND,
            root_id.as_bytes(),
            &bytes,
        )? {
            anyhow::bail!("separate guarded release intent changed concurrently");
        }
        self.finish_separate_guarded_release(&intent, &bytes)
    }

    fn new_separate_guarded_release_intent(
        &self,
        root_id: Uuid,
    ) -> Result<GuardedSeparateReleaseIntentV1> {
        let (root, binding) = self.guarded_root_release_preflight_common(root_id)?;
        if GuardedRecoveryHandoff::load(&self.control, root_id)?.is_some() {
            anyhow::bail!("in-place guarded root has a different release handoff");
        }
        let lower_parent = PinnedDirectory::open(
            binding
                .lower_root
                .parent()
                .context("guarded lower has no parent")?,
        )?;
        let view_parent = PinnedDirectory::open(
            binding
                .mountpoint
                .parent()
                .context("guarded view has no parent")?,
        )?;
        let intent = GuardedSeparateReleaseIntentV1 {
            format_version: 1,
            root,
            anchor_id: binding.anchor_id,
            lower_path: binding.lower_root,
            lower_id: binding.lower_id,
            placeholder_id: binding.mountpoint_id,
            lower_parent_id: lower_parent.identity()?,
            view_parent_id: view_parent.identity()?,
            view_uid: binding.view_uid,
            view_gid: binding.view_gid,
        };
        intent.validate(root_id.as_bytes())?;
        Ok(intent)
    }

    fn finish_separate_guarded_release(
        &mut self,
        intent: &GuardedSeparateReleaseIntentV1,
        bytes: &[u8],
    ) -> Result<()> {
        intent.validate(intent.root.root_id.as_bytes())?;
        if self.control.get_record(
            GUARDED_SEPARATE_RELEASE_KIND,
            intent.root.root_id.as_bytes(),
        )? != Some(bytes.to_vec())
            || Self::pending_separate_guarded_releases(&self.control)?
                .first()
                .map(|(saved, _)| saved)
                != Some(intent)
        {
            anyhow::bail!("separate guarded release intent changed before replay");
        }
        self.require_guarded_release_unpinned(
            intent.root.root_id,
            intent.anchor_id,
            &intent.root.path,
        )?;
        let active =
            GuardedViewMount::claimed_anchor_ids(&self.control)?.contains(&intent.anchor_id);
        if active {
            if let Some(index) = self
                .guarded_mounts
                .iter()
                .position(|mount| mount.anchor_id() == intent.anchor_id)
            {
                self.guarded_mounts.swap_remove(index).stop()?;
            }
            let control = Arc::new(Mutex::new(ControlStore::open_with_key(
                self.data_dir.join("control.db"),
                &self.control_database_key,
            )?));
            GuardedViewMount::detach_stopped_files_for_release(
                intent.anchor_id,
                Arc::clone(&control),
            )?;
            let visible = GuardedViewMount::snapshot_stopped(intent.anchor_id, control)?;
            intent.save_visible(&self.control, visible)?;
            GuardedViewMount::retire_claim(intent.anchor_id, &self.control)?;
        }
        let visible = intent
            .visible(&self.control)?
            .context("retired separate guarded view lost its snapshot")?;
        self.reconcile_guarded_git_file_gc(intent.anchor_id)?;
        if let Some(plan) =
            GuardedRootCapturePlan::load_for_retirement(&self.control, intent.anchor_id)?
        {
            plan.discard_unreferenced(&self.control)?;
        }
        GuardedRootCapturePlan::require_completed_retirement(&self.control, intent.anchor_id)?;
        intent.release_names(&self.control, &visible)?;
        let (_, view_parent) = intent.parents()?;
        let name = intent
            .root
            .path
            .file_name()
            .context("guarded view has no name")?;
        let root = view_parent
            .open_child_directory(name)?
            .context("released guarded view disappeared")?;
        restore_visible_release_metadata(&root, &visible)?;
        self.finalize_guarded_root_removal(
            intent.root.root_id,
            [
                GUARDED_SEPARATE_RELEASE_KIND,
                RELEASE_METADATA_KIND,
                RELEASE_NAMES_KIND,
            ]
            .into_iter()
            .map(|kind| (kind.to_owned(), intent.root.root_id.as_bytes().to_vec()))
            .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CString, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    #[test]
    #[ignore = "requires root, FUSE passthrough, and fanotify permission events"]
    fn separate_release_replays_deferred_guarded_git_file_cleanup() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        for stage in 0..4_u8 {
            let area = tempfile::Builder::new()
                .prefix("mb-guarded-git-release-")
                .tempdir_in(&test_root)
                .unwrap();
            fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let lower = area.path().join("lower");
            let view = area.path().join("view");
            let data_dir = area.path().join("node");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(&view).unwrap();
            fs::set_permissions(&lower, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&view, fs::Permissions::from_mode(0o755)).unwrap();
            let original = b"deferred\r\nrelease\0";
            let edited = b"Deferred\r\nrelease\0";
            fs::write(lower.join("tracked"), original).unwrap();
            fs::set_permissions(lower.join("tracked"), fs::Permissions::from_mode(0o644)).unwrap();

            let seed = Seed::from_bytes([stage + 110; 32]);
            let mut node = Node::open(&data_dir, seed.clone()).unwrap();
            let root = node
                .add_guarded_protected_root(&lower, &view, 65534, 65534)
                .unwrap();
            let binding = node.guarded_root_mount_binding(&root).unwrap();
            let repository_id = root.root_id;
            let key = node.git_catalog_key(repository_id);
            GitRepository::init_with_catalog_root(
                &view,
                &binding.lower_root,
                repository_id,
                &key,
                SourceBackendKind::GuardedLinkFreezeV1,
            )
            .unwrap();
            node.control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: view.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let edit = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.pwrite(fd,b'D',0); os.fsync(fd); os.close(fd)")
                .arg(view.join("tracked"))
                .output()
                .unwrap();
            assert!(edit.status.success(), "{edit:?}");
            node.guarded_mounts.pop().unwrap().stop().unwrap();
            let control = Arc::new(Mutex::new(
                ControlStore::open_with_key(
                    data_dir.join("control.db"),
                    &node.control_database_key,
                )
                .unwrap(),
            ));
            let attempt_id = Uuid::new_v4();
            GuardedViewMount::prepare_stopped_file_capture(
                binding.anchor_id,
                attempt_id,
                Arc::clone(&control),
                "tracked",
            )
            .unwrap();
            let manifest = GuardedViewMount::finish_stopped_file_capture(
                binding.anchor_id,
                attempt_id,
                Arc::clone(&control),
            )
            .unwrap();
            assert_eq!(manifest.format_version, 1);
            GuardedViewMount::transfer_stopped_file_capture_to_git(
                attempt_id,
                repository_id,
                repository_id,
                &control.lock().unwrap(),
            )
            .unwrap();
            drop(control);
            drop(node);

            let mut node = Node::open(&data_dir, seed.clone()).unwrap();
            let catalog = ControlStore::open_existing_with_key(
                binding.lower_root.join(".mutualbackup/catalog.db"),
                &key,
            )
            .unwrap();
            assert!(mb_git::remove_cached(&catalog, repository_id, "tracked").unwrap());
            drop(catalog);
            assert_eq!(
                node.git_prune(repository_id)
                    .unwrap()
                    .native_anchors_removed,
                0
            );
            assert!(manifest.open_verified().is_ok());
            node.git_retire_empty_guarded_repository(repository_id)
                .unwrap();
            assert!(!binding.lower_root.join(".mutualbackup").exists());
            if stage == 0 {
                node.remove_guarded_protected_root(repository_id).unwrap();
            } else {
                let intent = node
                    .new_separate_guarded_release_intent(repository_id)
                    .unwrap();
                node.control
                    .put_record(
                        GUARDED_SEPARATE_RELEASE_KIND,
                        repository_id.as_bytes(),
                        &canonical_bytes(&intent).unwrap(),
                    )
                    .unwrap();
                if stage >= 2 {
                    node.guarded_mounts.pop().unwrap().stop().unwrap();
                    let control = Arc::new(Mutex::new(
                        ControlStore::open_with_key(
                            data_dir.join("control.db"),
                            &node.control_database_key,
                        )
                        .unwrap(),
                    ));
                    GuardedViewMount::detach_stopped_files_for_release(
                        binding.anchor_id,
                        Arc::clone(&control),
                    )
                    .unwrap();
                    let visible =
                        GuardedViewMount::snapshot_stopped(binding.anchor_id, control).unwrap();
                    intent.save_visible(&node.control, visible).unwrap();
                    GuardedViewMount::retire_claim(binding.anchor_id, &node.control).unwrap();
                    if stage == 3 {
                        node.reconcile_guarded_git_file_gc(binding.anchor_id)
                            .unwrap();
                        assert!(manifest.open_verified().is_err());
                    }
                }
                drop(node);
                node = Node::open(&data_dir, seed.clone()).unwrap();
            }
            assert!(manifest.open_verified().is_err());
            assert!(
                node.control
                    .get_record(GUARDED_GIT_FILE_GC_KIND, manifest.anchor_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(node.protected_root_by_id(repository_id).is_err());
            assert_eq!(fs::read(view.join("tracked")).unwrap(), edited);
            drop(node);
            let reopened = Node::open(&data_dir, seed).unwrap();
            assert!(reopened.protected_root_by_id(repository_id).is_err());
            assert_eq!(fs::read(view.join("tracked")).unwrap(), edited);
        }
    }

    #[test]
    #[ignore = "requires root, FUSE passthrough, and fanotify permission events"]
    fn in_place_release_replays_deferred_guarded_git_file_cleanup() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let area = tempfile::Builder::new()
            .prefix("mb-guarded-git-in-place-release-")
            .tempdir_in(&test_root)
            .unwrap();
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let target = area.path().join("work");
        let data_dir = area.path().join("node");
        fs::create_dir(&target).unwrap();
        let original = b"deferred\r\nrelease\0";
        let edited = b"Deferred\r\nrelease\0";
        fs::write(target.join("tracked"), original).unwrap();
        for path in [&target, &target.join("tracked")] {
            let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        }
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(target.join("tracked"), fs::Permissions::from_mode(0o644)).unwrap();

        let seed = Seed::from_bytes([114; 32]);
        let mut node = Node::open(&data_dir, seed.clone()).unwrap();
        let root = node.add_guarded_protected_root_in_place(&target).unwrap();
        let binding = node.guarded_root_mount_binding(&root).unwrap();
        let repository_id = root.root_id;
        let key = node.git_catalog_key(repository_id);
        GitRepository::init_with_catalog_root(
            &target,
            &binding.lower_root,
            repository_id,
            &key,
            SourceBackendKind::GuardedLinkFreezeV1,
        )
        .unwrap();
        node.control
            .put_record(
                "git-repository",
                repository_id.as_bytes(),
                &canonical_bytes(&GitRepositoryInfo {
                    format_version: 1,
                    repository_id,
                    path: target.clone(),
                })
                .unwrap(),
            )
            .unwrap();
        let edit = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.pwrite(fd,b'D',0); os.fsync(fd); os.close(fd)")
            .arg(target.join("tracked"))
            .output()
            .unwrap();
        assert!(edit.status.success(), "{edit:?}");
        node.guarded_mounts.pop().unwrap().stop().unwrap();
        let control = Arc::new(Mutex::new(
            ControlStore::open_with_key(data_dir.join("control.db"), &node.control_database_key)
                .unwrap(),
        ));
        let attempt_id = Uuid::new_v4();
        GuardedViewMount::prepare_stopped_file_capture(
            binding.anchor_id,
            attempt_id,
            Arc::clone(&control),
            "tracked",
        )
        .unwrap();
        let manifest = GuardedViewMount::finish_stopped_file_capture(
            binding.anchor_id,
            attempt_id,
            Arc::clone(&control),
        )
        .unwrap();
        assert_eq!(manifest.format_version, 1);
        GuardedViewMount::transfer_stopped_file_capture_to_git(
            attempt_id,
            repository_id,
            repository_id,
            &control.lock().unwrap(),
        )
        .unwrap();
        drop(control);
        drop(node);

        let mut node = Node::open(&data_dir, seed.clone()).unwrap();
        let catalog = ControlStore::open_existing_with_key(
            binding.lower_root.join(".mutualbackup/catalog.db"),
            &key,
        )
        .unwrap();
        assert!(mb_git::remove_cached(&catalog, repository_id, "tracked").unwrap());
        drop(catalog);
        assert_eq!(
            node.git_prune(repository_id)
                .unwrap()
                .native_anchors_removed,
            0
        );
        assert!(manifest.open_verified().is_ok());
        node.git_retire_empty_guarded_repository(repository_id)
            .unwrap();
        let handoff = GuardedRecoveryHandoff::load(&node.control, repository_id)
            .unwrap()
            .unwrap();
        let intent = GuardedReleaseIntentV1 {
            format_version: 1,
            root: root.clone(),
            anchor_id: binding.anchor_id,
            handoff_hash: *blake3::hash(&canonical_bytes(&handoff).unwrap()).as_bytes(),
        };
        node.control
            .put_record(
                GUARDED_RELEASE_KIND,
                repository_id.as_bytes(),
                &canonical_bytes(&intent).unwrap(),
            )
            .unwrap();
        node.guarded_mounts.pop().unwrap().stop().unwrap();
        let control = Arc::new(Mutex::new(
            ControlStore::open_with_key(data_dir.join("control.db"), &node.control_database_key)
                .unwrap(),
        ));
        let parent = PinnedDirectory::open(area.path()).unwrap();
        handoff
            .prepare_release_metadata(control, &parent, binding.anchor_id)
            .unwrap();
        GuardedViewMount::retire_claim(binding.anchor_id, &node.control).unwrap();
        drop(node);

        let reopened = Node::open(&data_dir, seed.clone()).unwrap();
        assert!(manifest.open_verified().is_err());
        assert!(
            reopened
                .control
                .get_record(GUARDED_GIT_FILE_GC_KIND, manifest.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(reopened.protected_root_by_id(repository_id).is_err());
        assert_eq!(fs::read(target.join("tracked")).unwrap(), edited);
        drop(reopened);
        let reopened = Node::open(&data_dir, seed).unwrap();
        assert_eq!(fs::read(target.join("tracked")).unwrap(), edited);
        assert!(reopened.protected_root_by_id(repository_id).is_err());
    }

    #[test]
    #[ignore = "requires root, FUSE passthrough, and fanotify permission events"]
    fn separate_guarded_release_replays_each_boundary_and_keeps_view_path() {
        if let Some(area) = std::env::var_os("MUTUALBACKUP_SEPARATE_RELEASE_CHILD") {
            let area = PathBuf::from(area);
            let node = Node::open(area.join("node"), Seed::from_bytes([189; 32])).unwrap();
            let root = node.protected_roots().unwrap().pop().unwrap();
            let intent = node
                .new_separate_guarded_release_intent(root.root_id)
                .unwrap();
            node.control
                .put_record(
                    GUARDED_SEPARATE_RELEASE_KIND,
                    root.root_id.as_bytes(),
                    &canonical_bytes(&intent).unwrap(),
                )
                .unwrap();
            assert_eq!(
                fs::read(root.path.join("sample")).unwrap(),
                b"edited\r\nbytes\0"
            );
            fs::write(area.join("separate-release-child-ready"), b"ready").unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        for stage in 0..12_u8 {
            let area = tempfile::Builder::new()
                .prefix("mb-separate-release-")
                .tempdir_in(&test_root)
                .unwrap();
            fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let lower_name = if stage == 1 {
                OsString::from_vec(b"lower-\xfe".to_vec())
            } else {
                OsString::from("lower")
            };
            let view_name = if stage == 1 {
                OsString::from_vec(b"view-\xff".to_vec())
            } else {
                OsString::from("view")
            };
            let (lower_parent, view_parent) = if stage == 2 {
                let lower_parent = area.path().join("private");
                let view_parent = area.path().join("worktrees");
                fs::create_dir(&lower_parent).unwrap();
                fs::create_dir(&view_parent).unwrap();
                (lower_parent, view_parent)
            } else {
                (area.path().to_path_buf(), area.path().to_path_buf())
            };
            let lower = lower_parent.join(lower_name);
            let view = view_parent.join(view_name);
            let data_dir = area.path().join("node");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(&view).unwrap();
            fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&view, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(lower.join("sample"), b"original\r\nbytes\0").unwrap();
            let seed = Seed::from_bytes([stage + 180; 32]);
            let mut node = Node::open(&data_dir, seed.clone()).unwrap();
            let root = node
                .add_guarded_protected_root(&lower, &view, 65534, 65534)
                .unwrap();
            let edited = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'edited\\r\\nbytes\\0'); pathlib.Path(sys.argv[2]).write_bytes(b'new\\nbytes')")
                .arg(view.join("sample"))
                .arg(view.join("new-file"))
                .output()
                .unwrap();
            assert!(edited.status.success(), "{edited:?}");
            let anchor_id = node.guarded_root_mount_binding(&root).unwrap().anchor_id;
            if stage == 9 {
                drop(node);
                struct ReleaseChild(std::process::Child);
                impl Drop for ReleaseChild {
                    fn drop(&mut self) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
                let mut child = ReleaseChild(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--ignored",
                            "--exact",
                            "node::guarded_release::tests::separate_guarded_release_replays_each_boundary_and_keeps_view_path",
                            "--nocapture",
                        ])
                        .env("MUTUALBACKUP_SEPARATE_RELEASE_CHILD", area.path())
                        .spawn()
                        .unwrap(),
                );
                for _ in 0..200 {
                    if area.path().join("separate-release-child-ready").exists() {
                        break;
                    }
                    assert!(child.0.try_wait().unwrap().is_none());
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                assert!(area.path().join("separate-release-child-ready").exists());
                child.0.kill().unwrap();
                assert!(!child.0.wait().unwrap().success());
                assert!(fs::read(view.join("sample")).is_err());
                node = Node::open(&data_dir, seed.clone()).unwrap();
            } else if stage == 0 {
                node.remove_guarded_protected_root(root.root_id).unwrap();
            } else {
                let intent = node
                    .new_separate_guarded_release_intent(root.root_id)
                    .unwrap();
                node.control
                    .put_record(
                        GUARDED_SEPARATE_RELEASE_KIND,
                        root.root_id.as_bytes(),
                        &canonical_bytes(&intent).unwrap(),
                    )
                    .unwrap();
                assert!(node.check_guarded_mounts().is_err());
                if stage >= 2 {
                    node.guarded_mounts.pop().unwrap().stop().unwrap();
                    let control = Arc::new(Mutex::new(
                        ControlStore::open_with_key(
                            data_dir.join("control.db"),
                            &node.control_database_key,
                        )
                        .unwrap(),
                    ));
                    GuardedViewMount::detach_stopped_files_for_release(
                        anchor_id,
                        Arc::clone(&control),
                    )
                    .unwrap();
                    let visible = GuardedViewMount::snapshot_stopped(anchor_id, control).unwrap();
                    intent.save_visible(&node.control, visible.clone()).unwrap();
                    if stage >= 3 {
                        GuardedViewMount::retire_claim(anchor_id, &node.control).unwrap();
                    }
                    if stage >= 4 && stage != 11 {
                        GuardedRootCapturePlan::load_for_retirement(&node.control, anchor_id)
                            .unwrap()
                            .unwrap()
                            .discard_unreferenced(&node.control)
                            .unwrap();
                    }
                    if stage == 5 || stage == 10 {
                        node.control
                            .put_record(
                                RELEASE_NAMES_KIND,
                                root.root_id.as_bytes(),
                                &canonical_bytes(&intent).unwrap(),
                            )
                            .unwrap();
                        let (_, view_parent) = intent.parents().unwrap();
                        assert!(
                            view_parent
                                .remove_empty_child_directory("view", intent.placeholder_id)
                                .unwrap()
                        );
                    } else if stage >= 6 && stage != 8 && stage != 10 && stage != 11 {
                        intent.release_names(&node.control, &visible).unwrap();
                    }
                    if stage == 7 {
                        let view_root = PinnedDirectory::open(&view).unwrap();
                        restore_visible_release_metadata(&view_root, &visible).unwrap();
                    }
                }
                if stage == 11 {
                    let plan_bytes = node
                        .control
                        .get_record("guarded-root-plan-v1", anchor_id.as_bytes())
                        .unwrap()
                        .unwrap();
                    node.control
                        .delete_record("guarded-root-plan-v1", anchor_id.as_bytes())
                        .unwrap();
                    let database_key = node.control_database_key;
                    drop(node);
                    assert!(Node::open(&data_dir, seed.clone()).is_err());
                    assert_eq!(
                        fs::read(lower.join("sample")).unwrap(),
                        b"edited\r\nbytes\0"
                    );
                    assert!(!view.join("sample").exists());
                    ControlStore::open_with_key(data_dir.join("control.db"), &database_key)
                        .unwrap()
                        .put_record("guarded-root-plan-v1", anchor_id.as_bytes(), &plan_bytes)
                        .unwrap();
                    node = Node::open(&data_dir, seed.clone()).unwrap();
                } else if stage == 8 || stage == 10 {
                    let original_placeholder = area.path().join("original-placeholder");
                    if stage == 8 {
                        fs::rename(&view, &original_placeholder).unwrap();
                    }
                    fs::create_dir(&view).unwrap();
                    fs::write(view.join("foreign"), b"foreign bytes").unwrap();
                    drop(node);
                    assert!(Node::open(&data_dir, seed.clone()).is_err());
                    assert_eq!(
                        fs::read(lower.join("sample")).unwrap(),
                        b"edited\r\nbytes\0"
                    );
                    fs::remove_dir_all(&view).unwrap();
                    if stage == 8 {
                        fs::rename(original_placeholder, &view).unwrap();
                    }
                    node = Node::open(&data_dir, seed.clone()).unwrap();
                } else {
                    drop(node);
                    node = Node::open(&data_dir, seed.clone()).unwrap();
                }
            }
            node.check_guarded_mounts().unwrap();
            assert!(node.protected_root_by_id(root.root_id).is_err());
            assert!(
                node.control
                    .records(GUARDED_SEPARATE_RELEASE_KIND)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                GuardedRootCapturePlan::load_for_retirement(&node.control, anchor_id)
                    .unwrap()
                    .is_none()
            );
            assert!(!lower.exists());
            assert_eq!(fs::read(view.join("sample")).unwrap(), b"edited\r\nbytes\0");
            assert_eq!(fs::read(view.join("new-file")).unwrap(), b"new\nbytes");
            assert_eq!(fs::metadata(&view).unwrap().uid(), 65534);
            fs::write(view.join("sample"), b"independent after release").unwrap();
            drop(node);
            let reopened = Node::open(&data_dir, seed).unwrap();
            reopened.check_guarded_mounts().unwrap();
            assert_eq!(
                fs::read(view.join("sample")).unwrap(),
                b"independent after release"
            );
        }
    }
}

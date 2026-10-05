use super::*;

pub(super) const GUARDED_GIT_RETIRE_KIND: &str = "guarded-git-repository-retirement-v1";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuardedGitRepositoryRetirementV1 {
    format_version: u16,
    repository_id: Uuid,
    #[serde(with = "mb_store::raw_path_bytes")]
    lower_root: PathBuf,
    lower_id: NativeFileId,
    catalog: mb_git::GitGuardedCatalogRetirementV1,
    registration: Vec<u8>,
}

impl GuardedGitRepositoryRetirementV1 {
    fn validate(&self, id: &[u8], bytes: &[u8]) -> Result<()> {
        let info: GitRepositoryInfo = decode_canonical(&self.registration)?;
        anyhow::ensure!(
            self.format_version == 1
                && !self.repository_id.is_nil()
                && id == self.repository_id.as_bytes()
                && self.catalog.format_version == 1
                && self.catalog.repository_id == self.repository_id
                && self.lower_root.is_absolute()
                && self.lower_id.filesystem_id == self.catalog.directory_id.filesystem_id
                && info.format_version == 1
                && info.repository_id == self.repository_id
                && canonical_bytes(&info)? == self.registration
                && canonical_bytes(self)? == bytes,
            "guarded Git repository retirement intent is invalid"
        );
        Ok(())
    }
}

impl Node {
    /// Remove only a truly empty guarded Git catalog. The protected source
    /// root stays enrolled; its release has its own signed-revision gates.
    pub fn git_retire_empty_guarded_repository(&mut self, repository_id: Uuid) -> Result<()> {
        SourceBackendKind::GuardedLinkFreezeV1.require_supported()?;
        self.reconcile_guarded_git_prunes()?;
        self.reconcile_guarded_git_stages()?;
        let root = self.protected_root_by_id(repository_id)?;
        let binding = self.guarded_root_mount_binding(&root)?;
        anyhow::ensure!(
            !git_prune_capture_pending(&self.control, repository_id, &root.path)?,
            "guarded Git repository still has an unfinished source capture"
        );
        for (_, bytes) in self.control.records("backup-job")? {
            let job: BackupJob = decode_canonical(&bytes)?;
            validate_backup_descriptor(&job.descriptor)?;
            anyhow::ensure!(
                job.format_version == 1
                    && (job.descriptor.protected_root_id != repository_id
                        || job.state == BackupJobState::Committed),
                "guarded Git repository still has an unfinished backup job"
            );
        }
        let repository = self.open_guarded_git_repository(repository_id)?;
        let catalog = repository.prepare_empty_guarded_catalog_retirement()?;
        drop(repository);
        let registration = self
            .control
            .get_record("git-repository", repository_id.as_bytes())?
            .context("guarded Git repository registration disappeared")?;
        let intent = GuardedGitRepositoryRetirementV1 {
            format_version: 1,
            repository_id,
            lower_root: binding.lower_root,
            lower_id: binding.lower_id,
            catalog,
            registration,
        };
        let bytes = canonical_bytes(&intent)?;
        intent.validate(repository_id.as_bytes(), &bytes)?;
        anyhow::ensure!(
            self.control.put_record_if_absent(
                GUARDED_GIT_RETIRE_KIND,
                repository_id.as_bytes(),
                &bytes,
            )?,
            "another guarded Git retirement is pending"
        );
        Self::finish_guarded_git_repository_retirement(&self.control, &self.keys, &intent, &bytes)
    }

    /// This runs before a claimed guarded view is remounted. The catalog's
    /// marker is the last file removed, so a crash at any deletion step can
    /// finish here before namespace recovery inspects the lower directory.
    pub(super) fn reconcile_guarded_git_repository_retirements(
        control: &ControlStore,
        keys: &KeyMaterial,
    ) -> Result<()> {
        for (id, bytes) in control.records(GUARDED_GIT_RETIRE_KIND)? {
            let intent: GuardedGitRepositoryRetirementV1 = decode_canonical(&bytes)?;
            intent.validate(&id, &bytes)?;
            Self::finish_guarded_git_repository_retirement(control, keys, &intent, &bytes)?;
        }
        Ok(())
    }

    fn finish_guarded_git_repository_retirement(
        control: &ControlStore,
        keys: &KeyMaterial,
        intent: &GuardedGitRepositoryRetirementV1,
        bytes: &[u8],
    ) -> Result<()> {
        intent.validate(intent.repository_id.as_bytes(), bytes)?;
        anyhow::ensure!(
            control.get_record(GUARDED_GIT_RETIRE_KIND, intent.repository_id.as_bytes())?
                == Some(bytes.to_vec())
                && control.get_record("git-repository", intent.repository_id.as_bytes())?
                    == Some(intent.registration.clone()),
            "guarded Git retirement lost its exact node fence or registration"
        );
        GitRepository::resume_empty_guarded_catalog_retirement(
            &intent.lower_root,
            intent.lower_id,
            &intent.catalog,
            &mb_git::catalog_key(keys, intent.repository_id),
        )?;
        control.put_records_and_retire_and_delete_if_value(
            &[],
            &[(
                "git-repository".to_owned(),
                intent.repository_id.as_bytes().to_vec(),
            )],
            GUARDED_GIT_RETIRE_KIND,
            intent.repository_id.as_bytes(),
            bytes,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn empty_guarded_git_retirement_replays_before_mount_and_allows_root_release() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        for interruption_stage in 0..3 {
            let area = tempfile::Builder::new()
                .prefix("mb-node-guarded-git-deinit-")
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
            fs::write(lower.join("sample"), b"retirement\r\nbytes\0").unwrap();
            fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o644)).unwrap();

            let seed = Seed::from_bytes([116; 32]);
            let mut node = Node::open(&data_dir, seed.clone()).unwrap();
            let root = node
                .enroll_test_guarded_root(&lower, &view, 65534, 65534)
                .unwrap();
            let binding = node.guarded_root_mount_binding(&root).unwrap();
            let repository_id = root.root_id;
            let key = node.git_catalog_key(repository_id);
            let repository = GitRepository::init_with_catalog_root(
                &view,
                &binding.lower_root,
                repository_id,
                &key,
                SourceBackendKind::GuardedLinkFreezeV1,
            )
            .unwrap();
            let registration = canonical_bytes(&GitRepositoryInfo {
                format_version: 1,
                repository_id,
                path: view.clone(),
            })
            .unwrap();
            node.control
                .put_record("git-repository", repository_id.as_bytes(), &registration)
                .unwrap();
            assert!(node.remove_guarded_protected_root(repository_id).is_err());
            if interruption_stage != 0 {
                let catalog = repository
                    .prepare_empty_guarded_catalog_retirement()
                    .unwrap();
                drop(repository);
                let intent = GuardedGitRepositoryRetirementV1 {
                    format_version: 1,
                    repository_id,
                    lower_root: binding.lower_root.clone(),
                    lower_id: binding.lower_id,
                    catalog,
                    registration,
                };
                let bytes = canonical_bytes(&intent).unwrap();
                node.control
                    .put_record(GUARDED_GIT_RETIRE_KIND, repository_id.as_bytes(), &bytes)
                    .unwrap();
                let catalog_path = binding.lower_root.join(".mutualbackup");
                for name in ["catalog.db-wal", "catalog.db-shm", "catalog.db"] {
                    let path = catalog_path.join(name);
                    if path.exists() {
                        fs::remove_file(path).unwrap();
                    }
                }
                if interruption_stage == 2 {
                    fs::remove_file(catalog_path.join("repository")).unwrap();
                }
            } else {
                drop(repository);
                node.git_retire_empty_guarded_repository(repository_id)
                    .unwrap();
            }
            node.guarded_mounts.pop().unwrap().stop().unwrap();
            drop(node);

            let mut reopened = Node::open(&data_dir, seed).unwrap();
            assert!(
                reopened
                    .control
                    .get_record("git-repository", repository_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(
                reopened
                    .control
                    .get_record(GUARDED_GIT_RETIRE_KIND, repository_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(!binding.lower_root.join(".mutualbackup").exists());
            reopened
                .remove_guarded_protected_root(repository_id)
                .unwrap();
            assert!(reopened.protected_root_by_id(repository_id).is_err());
            assert_eq!(
                fs::read(view.join("sample")).unwrap(),
                b"retirement\r\nbytes\0"
            );
        }
    }
}

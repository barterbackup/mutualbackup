//! Admission policy for source backends withdrawn from the product.
//!
//! Inspect existing records read-only before key/schema migration or replay.
//! Even unfinished or malformed guarded journals must remain untouched.

use anyhow::{Result, bail};
use mb_core::decode_canonical;
use mb_store::{ControlStore, SourceBackendBinding, WITHDRAWN_GUARDED_BACKEND};

use crate::control::ProtectedRoot;

pub(crate) fn require_native_source_state(control: &ControlStore) -> Result<()> {
    for prefix in ["guarded-", "link-freeze-"] {
        if control.has_records_with_kind_prefix(prefix)? {
            bail!("{WITHDRAWN_GUARDED_BACKEND}");
        }
    }
    control.for_each_record_value("protected-root", |bytes| {
        let root: ProtectedRoot = decode_canonical(bytes)?;
        if root.format_version == 4 {
            bail!("{WITHDRAWN_GUARDED_BACKEND}");
        }
        Ok(())
    })?;
    control.for_each_record_value("source-backend", |bytes| {
        let binding: SourceBackendBinding = decode_canonical(bytes)?;
        binding.backend.require_supported()?;
        Ok(())
    })?;
    crate::snapshot::require_native_capture_state(control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Node;
    use mb_core::{KeyMaterial, Seed, canonical_bytes};
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn guarded_journals_are_rejected_before_replay_or_catalog_mutation() {
        for kind in [
            "guarded-view-mount-v1",
            "guarded-root-enrollment-v1",
            "guarded-git-anchor-pin-v1",
            "link-freeze-capture-v1",
        ] {
            let area = tempfile::tempdir().unwrap();
            let data = area.path().join("node");
            let source = area.path().join("source");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("file"), b"working\r\n\0bytes").unwrap();
            let seed = Seed::from_bytes([91; 32]);
            let node = Node::open(&data, seed.clone()).unwrap();
            drop(node);
            let keys = KeyMaterial::from_seed(&seed);
            let (mut control, _) = crate::volume::open_control_store(&data, &keys).unwrap();
            control
                .put_record(kind, b"id", b"unfinished legacy state")
                .unwrap();
            // Normal startup would clear this before replay. Rejection must
            // happen before even that recomputable operation is discarded.
            control
                .begin_operation(&[7; 16], "ensure-filler", &[8; 32], &[9; 32])
                .unwrap();
            drop(control);
            let database = fs::read(data.join("control.db")).unwrap();
            let envelope = fs::read(data.join("control.key")).unwrap();
            let parity = fs::read(data.join("parity.db")).unwrap();
            let error = match Node::open(&data, seed) {
                Err(error) => error,
                Ok(_) => panic!("withdrawn state was reopened: {kind}"),
            };
            assert!(error.to_string().contains("withdrawn"), "{error:#}");
            assert_eq!(fs::read(data.join("control.db")).unwrap(), database);
            assert_eq!(fs::read(data.join("control.key")).unwrap(), envelope);
            assert_eq!(fs::read(data.join("parity.db")).unwrap(), parity);
            assert_eq!(
                fs::read(source.join("file")).unwrap(),
                b"working\r\n\0bytes"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarded_enrollment_rejects_before_creating_or_moving_paths() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("node");
        let source = area.path().join("source");
        let view = area.path().join("view");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"working bytes").unwrap();
        let mut node = Node::open(&data, Seed::from_bytes([90; 32])).unwrap();
        for error in [
            node.add_guarded_protected_root(&source, &view, 1000, 1000)
                .unwrap_err(),
            node.add_guarded_protected_root_in_place(&source)
                .unwrap_err(),
            node.remove_guarded_protected_root(Uuid::new_v4())
                .unwrap_err(),
            node.git_retire_empty_guarded_repository(Uuid::new_v4())
                .unwrap_err(),
        ] {
            assert!(error.to_string().contains("withdrawn"), "{error:#}");
        }
        assert_eq!(fs::read(source.join("file")).unwrap(), b"working bytes");
        assert!(!view.exists());
        assert_eq!(fs::read_dir(source).unwrap().count(), 1);
    }

    #[test]
    fn legacy_unwrapped_keys_are_not_rekeyed_on_withdrawal() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path();
        let seed = Seed::from_bytes([92; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        let database = data.join("control.db");
        {
            let control = ControlStore::open(&database, &keys).unwrap();
            control
                .put_record("guarded-file-plan-v1", b"id", b"legacy")
                .unwrap();
        }
        let original = fs::read(&database).unwrap();
        assert!(Node::open(data, seed).is_err());
        assert_eq!(fs::read(database).unwrap(), original);
        assert!(!data.join("control.key").exists());
        assert!(!data.join("parity.db").exists());
    }

    #[test]
    fn root_records_alone_cannot_reenable_guarded_mounts() {
        let area = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[93; 32]).unwrap();
        let root = ProtectedRoot {
            format_version: 4,
            root_id: Uuid::new_v4(),
            path: area.path().join("old-view"),
            filesystem_id: 11,
            root_inode: 12,
        };
        control
            .put_record(
                "protected-root",
                root.root_id.as_bytes(),
                &canonical_bytes(&root).unwrap(),
            )
            .unwrap();
        control.make_query_only().unwrap();
        assert!(
            require_native_source_state(&control)
                .unwrap_err()
                .to_string()
                .contains("withdrawn")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backend_bindings_alone_cannot_reenable_guarded_capture() {
        let area = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[94; 32]).unwrap();
        let binding = SourceBackendBinding::guarded_link_freeze_v1(Uuid::new_v4(), 11, 12, 13);
        control
            .put_record(
                "source-backend",
                binding.root_id.as_bytes(),
                &canonical_bytes(&binding).unwrap(),
            )
            .unwrap();
        control.make_query_only().unwrap();
        assert!(
            require_native_source_state(&control)
                .unwrap_err()
                .to_string()
                .contains("withdrawn")
        );
    }
}

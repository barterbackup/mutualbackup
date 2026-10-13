use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

macro_rules! cases {
    ($test:ident,$constructor:ident,$layout:ident,$metadata:ident,$revision:ident,$lookup:ident,$cancel:ident,$release:ident,$journal:literal) => {
        #[test]
        fn $test() {
            let (temp, seed, mut node, mut keys) = fixture();
            let local = keys.iter().position(|key| key.node_id() == node.keys.node_id()).unwrap();
            keys.swap(0, local);
            let (proof, captures) = $constructor(&mut node, &keys, true);
            let first = proof.index().next_revision(None).unwrap().unwrap();
            let record = proof.index().next_revision(first.revision_key()).unwrap().unwrap();
            let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = record else {
                panic!("original private revision expected")
            };
            let key = mb_core::CatalogCheckpointRevisionKey::from(&signed.value);
            let owner = Uuid::from_u128(930);
            node.$metadata(owner, &proof).unwrap();
            node.$revision(owner, &proof, key).unwrap();
            node.$lookup(owner, &proof).unwrap();
            let guild = proof.trust().guild_id;
            let budget = proof.transition().budget();
            let snapshot = crate::SnapshotInfo {
                protected_root_id: key.protected_root_id,
                revision_id: key.revision_id,
                sequence: key.sequence,
                checkpoint_generation: proof.certificate().checkpoint.generation,
                checkpoint_hash: proof.certificate().hash().unwrap(),
            };
            let layout = mb_core::PagedCheckpointLayout::$layout;
            let target = temp.path().join("invalid-selection");
            for field in 0..5 {
                let mut wrong = snapshot.clone();
                match field {
                    0 => wrong.checkpoint_hash[0] ^= 1,
                    1 => wrong.checkpoint_generation += 1,
                    2 => wrong.protected_root_id = Uuid::from_u128(999),
                    3 => wrong.revision_id = Uuid::from_u128(998),
                    _ => wrong.sequence += 1,
                }
                assert!(node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &wrong, &target, budget).is_err());
            }
            let other_layout = match layout {
                mb_core::PagedCheckpointLayout::Individual => mb_core::PagedCheckpointLayout::Directory,
                mb_core::PagedCheckpointLayout::Directory => mb_core::PagedCheckpointLayout::Individual,
            };
            for (layout, id, guild) in [(other_layout, owner, guild), (layout, Uuid::from_u128(997), guild), (layout, owner, [249; 32])] {
                assert!(node.restore_retained_checkpoint_native_snapshot(layout, id, guild, &snapshot, &target, budget).is_err());
            }
            assert!(node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, Work { bytes: 0, ..budget }).is_err());
            assert!(!target.exists());
            assert!(node.control.records("restore-job").unwrap().is_empty());

            for (number, action) in ["ABORT", "IGNORE"].into_iter().enumerate() {
                let target = temp.path().join(format!("publication-fault-{number}"));
                node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER refuse_restore BEFORE UPDATE ON protocol_records WHEN NEW.kind='restore-job' AND substr(NEW.bytes,-1)=X'01' BEGIN SELECT RAISE({action}{}); END", if action == "ABORT" { ",'test'" } else { "" }), false).unwrap();
                assert!(node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, budget).is_err());
                assert!(!target.exists());
                assert_eq!(node.control.records("restore-job").unwrap().len(), 1);
                node.control.database_shell_statement("DROP TRIGGER refuse_restore", false).unwrap();
                node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, budget).unwrap();
                assert!(target.is_dir());
                assert!(node.control.records("restore-job").unwrap().is_empty());
            }

            // Cancellation injected by the publication write must roll back
            // together with that write, leaving the source owner Published.
            let published = node.control.get_record($journal, owner.as_bytes()).unwrap().unwrap();
            node.control.$cancel(owner).unwrap();
            let cancelled = node.control.get_record($journal, owner.as_bytes()).unwrap().unwrap();
            node.control.put_record($journal, owner.as_bytes(), &published).unwrap();
            let target = temp.path().join("late-cancellation");
            node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER cancel_restore AFTER UPDATE ON protocol_records WHEN NEW.kind='restore-job' AND substr(NEW.bytes,-1)=X'01' BEGIN UPDATE protocol_records SET bytes=X'{}' WHERE kind='{}' AND record_id=X'{}'; END", hex::encode(&cancelled), $journal, hex::encode(owner.as_bytes())), false).unwrap();
            assert!(node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, budget).is_err());
            assert!(!target.exists());
            assert_eq!(node.control.get_record($journal, owner.as_bytes()).unwrap().unwrap(), published);
            node.control.database_shell_statement("DROP TRIGGER cancel_restore", false).unwrap();
            node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, budget).unwrap();
            assert!(node.control.records("restore-job").unwrap().is_empty());

            for intent in captures {
                node.control.cancel_catalog(intent).unwrap();
                while node.control.release_catalog_pin(intent).unwrap() {}
            }
            while node.control.collect_catalog_page().unwrap() {}
            drop(node);
            let node = Node::open(temp.path(), seed.clone()).unwrap();
            let target = temp.path().join("retained-after-reopen");
            node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, budget).unwrap();
            let stat = std::fs::metadata(&target).unwrap();
            assert_eq!(stat.permissions().mode() & 0o777, 0o700);
            assert_eq!((stat.mtime(), stat.mtime_nsec()), (123, 456));
            assert!(node.control.checkpoint_head_identity(&guild).unwrap().is_none());

            let target = temp.path().join("interrupted-published-tree");
            crate::snapshot::interrupt_next_restore_after_rename();
            assert!(node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, budget).is_err());
            assert!(target.is_dir());
            let inode = std::fs::metadata(&target).unwrap().ino();
            assert_eq!(node.control.records("restore-job").unwrap().len(), 1);
            assert!(node.restore_retained_checkpoint_native_snapshot(layout, Uuid::from_u128(996), guild, &snapshot, &target, budget).is_err());
            assert_eq!(std::fs::metadata(&target).unwrap().ino(), inode);
            node.control.$cancel(owner).unwrap();
            while node.control.$release(owner).unwrap() {}
            node.control.cancel_paged_revision_catalog(signed.value.revision_id).unwrap();
            drop(node);
            let node = Node::open(temp.path(), seed).unwrap();
            node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &target, Work::default()).unwrap();
            assert_eq!(std::fs::metadata(&target).unwrap().ino(), inode);
            assert!(node.control.records("restore-job").unwrap().is_empty());
            assert!(node.control.checkpoint_head_identity(&guild).unwrap().is_none());
            assert!(node.restore_retained_checkpoint_native_snapshot(layout, owner, guild, &snapshot, &temp.path().join("cancelled-new-request"), budget).is_err());
        }
    };
}

cases!(
    retained_individual_checkpoint_native_restore_fences_publication_and_reopens_owned_output,
    checkpoint_owner_proof_with_private,
    Individual,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_revision,
    build_retained_paged_checkpoint_lookup,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root,
    "catalog-paged-checkpoint-retention-v1"
);
cases!(
    retained_directory_checkpoint_native_restore_fences_publication_and_reopens_owned_output,
    directory_owner_proof,
    Directory,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_revision,
    build_retained_paged_checkpoint_directory_lookup,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root,
    "catalog-directory-checkpoint-retention-v1"
);

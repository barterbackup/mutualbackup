use super::*;

#[derive(Clone, Copy, Debug)]
enum Layout {
    Legacy,
    #[cfg(target_os = "linux")]
    Managed,
}

fn layouts() -> &'static [Layout] {
    #[cfg(target_os = "linux")]
    {
        &[Layout::Legacy, Layout::Managed]
    }
    #[cfg(not(target_os = "linux"))]
    {
        &[Layout::Legacy]
    }
}

fn create(path: &Path, seed: Seed, layout: Layout) -> Node {
    match layout {
        Layout::Legacy => Node::open(path, seed).unwrap(),
        #[cfg(target_os = "linux")]
        Layout::Managed => {
            Node::create_native(path, seed, crate::volume::native_node::tests::policy()).unwrap()
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    Ignore,
    Abort,
    Replace,
}

impl Fault {
    fn install(self, node: &Node) {
        let (timing, action) = match self {
            Self::Ignore => ("BEFORE", "SELECT RAISE(IGNORE)"),
            Self::Abort => ("BEFORE", "SELECT RAISE(ABORT, 'registry fault')"),
            Self::Replace => (
                "AFTER",
                "UPDATE protocol_records SET bytes=X'00' WHERE kind='node-config' AND record_id=X'73746f726167652d766f6c756d6573'",
            ),
        };
        node.database_shell_statement(None, &format!("CREATE TEMP TRIGGER registry_fault {timing} UPDATE ON protocol_records WHEN NEW.kind='node-config' AND NEW.record_id=X'73746f726167652d766f6c756d6573' BEGIN {action}; END"), true).unwrap();
    }

    fn clear(node: &Node) {
        node.database_shell_statement(None, "DROP TRIGGER registry_fault", true)
            .unwrap();
    }
}

fn registry(node: &Node) -> Vec<u8> {
    node.control
        .get_record("node-config", b"storage-volumes")
        .unwrap()
        .unwrap()
}

fn authority(node: &Node) -> Vec<(Uuid, PathBuf, crate::StorageVolumeState, u64, u64)> {
    node.storage_status()
        .unwrap()
        .into_iter()
        .map(|s| {
            (
                s.volume_id,
                s.path,
                s.state,
                s.budget_bytes,
                s.headroom_bytes,
            )
        })
        .collect()
}

fn object() -> ParityObject {
    let bytes = vec![73; mb_core::V1_SECTOR_SIZE];
    ParityObject {
        format_version: 1,
        guild_id: [74; 32],
        group_id: [75; 32],
        shard_index: 2,
        root: mb_core::sector_root(&bytes),
        bytes,
    }
}

const ACK: &[u8] = b"configuration keeps the original acknowledgement";

fn install_object(node: &mut Node, object: &ParityObject) {
    node.volumes.store(&node.control, object, ACK).unwrap();
    node.refresh_volume_readers().unwrap();
}

fn check_object(node: &Node, object: &ParityObject) {
    let config = node.reader_config();
    let reader = config.open().unwrap();
    assert_eq!(
        reader
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
    let parity = node
        .volumes
        .reader_configs()
        .into_iter()
        .find_map(|config| {
            let store = config.open().unwrap();
            store
                .publication_is_complete(object, ACK)
                .unwrap()
                .then_some(store)
        });
    assert!(
        parity.is_some(),
        "original publication acknowledgement must remain durable"
    );
}

#[test]
fn budget_faults_preserve_live_capacity_and_original_registry_through_reopen() {
    for &layout in layouts() {
        for fault in [Fault::Ignore, Fault::Abort, Fault::Replace] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("node");
            let seed = Seed::from_bytes([90; 32]);
            let mut node = create(&data, seed.clone(), layout);
            node.configure_parity_budget(4 << 20).unwrap();
            let object = object();
            install_object(&mut node, &object);
            let before = authority(&node);
            let bytes = registry(&node);
            let capacity = node
                .coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
                .unwrap();
            fault.install(&node);
            assert!(
                node.configure_parity_budget(8 << 20).is_err(),
                "{layout:?} {fault:?}"
            );
            assert_eq!(authority(&node), before, "{layout:?} {fault:?}");
            assert!(registry(&node) == bytes);
            assert_eq!(
                node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
                    .unwrap(),
                capacity
            );
            check_object(&node, &object);
            Fault::clear(&node);
            drop(node);
            let mut node = Node::open(&data, seed.clone()).unwrap();
            assert_eq!(authority(&node), before);
            check_object(&node, &object);
            node.configure_parity_budget(8 << 20).unwrap();
            drop(node);
            let node = Node::open(&data, seed).unwrap();
            assert_eq!(node.storage_status().unwrap()[0].budget_bytes, 8 << 20);
            check_object(&node, &object);
        }
    }
}

#[test]
fn path_configuration_faults_preserve_live_readers_and_durable_budgets() {
    for &layout in layouts() {
        for fault in [Fault::Ignore, Fault::Abort, Fault::Replace] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("node");
            let seed = Seed::from_bytes([90; 32]);
            let mut node = create(&data, seed.clone(), layout);
            node.configure_parity_budget(4 << 20).unwrap();
            let object = object();
            install_object(&mut node, &object);
            let before = authority(&node);
            let bytes = registry(&node);
            fault.install(&node);
            assert!(
                node.configure_storage_volumes(std::slice::from_ref(&data), 8 << 20, 1 << 20)
                    .is_err(),
                "{layout:?} {fault:?}"
            );
            assert_eq!(authority(&node), before);
            assert!(registry(&node) == bytes);
            check_object(&node, &object);
            Fault::clear(&node);
            drop(node);
            let mut node = Node::open(&data, seed.clone()).unwrap();
            assert_eq!(authority(&node), before);
            check_object(&node, &object);
            node.configure_storage_volumes(std::slice::from_ref(&data), 8 << 20, 1 << 20)
                .unwrap();
            drop(node);
            let node = Node::open(&data, seed).unwrap();
            let status = node.storage_status().unwrap();
            assert_eq!(
                (status[0].budget_bytes, status[0].headroom_bytes),
                (8 << 20, 1 << 20)
            );
            check_object(&node, &object);
        }
    }
}

#[test]
fn late_configuration_validation_leaves_original_capacity_and_readers_unchanged() {
    for &layout in layouts() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("node");
        let seed = Seed::from_bytes([90; 32]);
        let mut node = create(&data, seed.clone(), layout);
        node.configure_parity_budget(4 << 20).unwrap();
        let object = object();
        install_object(&mut node, &object);
        let before = authority(&node);
        let bytes = registry(&node);
        let capacity = node
            .coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
            .unwrap();
        for second in [data.clone(), temp.path().join("absent")] {
            assert!(
                node.configure_storage_volumes(&[data.clone(), second], 8 << 20, 1 << 20)
                    .is_err()
            );
            assert_eq!(authority(&node), before);
            assert!(registry(&node) == bytes);
            assert_eq!(
                node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
                    .unwrap(),
                capacity
            );
            check_object(&node, &object);
        }
        drop(node);
        let node = Node::open(&data, seed).unwrap();
        assert_eq!(authority(&node), before);
        check_object(&node, &object);
    }
}

#[test]
fn failed_volume_addition_resumes_the_original_manifest_without_live_enrollment() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("node");
    let extra = temp.path().join("extra");
    fs::create_dir(&extra).unwrap();
    let seed = Seed::from_bytes([90; 32]);
    let mut node = create(&data, seed.clone(), Layout::Legacy);
    node.configure_parity_budget(4 << 20).unwrap();
    let object = object();
    install_object(&mut node, &object);
    let before = authority(&node);
    let bytes = registry(&node);
    Fault::Ignore.install(&node);
    assert!(
        node.configure_storage_volumes(&[data.clone(), extra.clone()], 8 << 20, 0)
            .is_err()
    );
    assert_eq!(authority(&node), before);
    assert!(registry(&node) == bytes);
    check_object(&node, &object);
    let manifest = fs::read(extra.join(".mutualbackup-volume")).unwrap();
    Fault::clear(&node);
    drop(node);
    let mut node = Node::open(&data, seed.clone()).unwrap();
    assert_eq!(authority(&node), before);
    node.configure_storage_volumes(&[data.clone(), extra.clone()], 8 << 20, 0)
        .unwrap();
    assert!(fs::read(extra.join(".mutualbackup-volume")).unwrap() == manifest);
    let configured = authority(&node);
    assert_eq!(configured.len(), 2);
    check_object(&node, &object);
    drop(node);
    let node = Node::open(&data, seed).unwrap();
    assert_eq!(authority(&node), configured);
    check_object(&node, &object);
}

#[test]
fn drain_faults_never_publish_a_live_transition_before_its_registry_commit() {
    for &layout in layouts() {
        for fault in [Fault::Ignore, Fault::Abort, Fault::Replace] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("node");
            let seed = Seed::from_bytes([90; 32]);
            let mut node = create(&data, seed.clone(), layout);
            let object = object();
            install_object(&mut node, &object);
            let before = authority(&node);
            let bytes = registry(&node);
            let id = before[0].0;
            fault.install(&node);
            assert!(
                node.drain_storage_volume(id).is_err(),
                "{layout:?} {fault:?}"
            );
            assert_eq!(authority(&node), before);
            assert!(registry(&node) == bytes);
            check_object(&node, &object);
            Fault::clear(&node);
            drop(node);
            let mut node = Node::open(&data, seed.clone()).unwrap();
            assert_eq!(authority(&node), before);
            node.drain_storage_volume(id).unwrap();
            drop(node);
            let node = Node::open(&data, seed).unwrap();
            assert_eq!(
                node.storage_status().unwrap()[0].state,
                crate::StorageVolumeState::Draining
            );
            check_object(&node, &object);
        }
    }
}

#[test]
fn reactivation_faults_keep_retired_volumes_out_of_live_placement() {
    for &layout in layouts() {
        for fault in [Fault::Ignore, Fault::Abort, Fault::Replace] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("node");
            let seed = Seed::from_bytes([90; 32]);
            let mut node = create(&data, seed.clone(), layout);
            let id = node.storage_status().unwrap()[0].volume_id;
            node.drain_storage_volume(id).unwrap();
            node.migrate_draining_volumes().unwrap();
            let before = authority(&node);
            let bytes = registry(&node);
            assert_eq!(before[0].2, crate::StorageVolumeState::Retired);
            fault.install(&node);
            assert!(
                node.reactivate_storage_volume(id).is_err(),
                "{layout:?} {fault:?}"
            );
            assert_eq!(authority(&node), before);
            assert!(registry(&node) == bytes);
            assert_eq!(
                node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
                    .unwrap(),
                0
            );
            Fault::clear(&node);
            drop(node);
            let mut node = Node::open(&data, seed.clone()).unwrap();
            assert_eq!(authority(&node), before);
            node.reactivate_storage_volume(id).unwrap();
            assert!(
                node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
                    .unwrap()
                    > 0
            );
            let object = object();
            install_object(&mut node, &object);
            check_object(&node, &object);
            drop(node);
            let node = Node::open(&data, seed).unwrap();
            check_object(&node, &object);
        }
    }
}

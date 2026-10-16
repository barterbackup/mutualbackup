use super::*;

fn selected(cert: &Certificate) -> CatalogCheckpointRecoveryTip {
    CatalogCheckpointRecoveryTip {
        owner: Uuid::from_u128(2200),
        guild_id: cert.guild_id(),
        layout: cert.layout(),
        generation: cert.generation(),
        hash: cert.hash().unwrap(),
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly provisioned sudo OverlayFS mount support"]
fn live_recovery_overlay_alias_cannot_be_mistaken_for_an_independent_copy() {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;
    struct Mount {
        path: std::path::PathBuf,
        mounted: bool,
    }
    impl Mount {
        fn unmount(&mut self) {
            assert!(
                Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.path)
                    .status()
                    .unwrap()
                    .success()
            );
            self.mounted = false;
        }
    }
    impl Drop for Mount {
        fn drop(&mut self) {
            if self.mounted {
                let result = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.path)
                    .status();
                if !result.is_ok_and(|s| s.success()) {
                    eprintln!("failed fixture unmount: {}", self.path.display());
                }
            }
        }
    }
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    // Keep this small provisioned negative fixture for domain/alias inspection;
    // OverlayFS creates root-owned work entries. Never remove a live mount.
    let directory = tempfile::Builder::new()
        .prefix("mb-live-overlay-")
        .tempdir()
        .unwrap()
        .keep();
    println!("overlay work-domain fixture: {}", directory.display());
    for name in ["lower", "upper", "work", "merged"] {
        std::fs::create_dir(directory.join(name)).unwrap();
    }
    let path = directory.join("upper/control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let mut work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    assert!(
        Command::new("sudo")
            .args(["-n", "mount", "-t", "overlay", "-o"])
            .arg(format!(
                "lowerdir={0}/lower,upperdir={0}/upper,workdir={0}/work,xino=on",
                directory.display()
            ))
            .arg("overlay")
            .arg(directory.join("merged"))
            .status()
            .unwrap()
            .success()
    );
    let mut mount = Mount {
        path: directory.join("merged"),
        mounted: true,
    };
    let alias = directory.join("merged/control.db");
    let original = std::fs::metadata(&path).unwrap();
    let aliased = std::fs::metadata(&alias).unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (aliased.dev(), aliased.ino())
    );
    let observer = ControlStore::open(&alias, &history.keys[0]).unwrap();
    assert!(matches!(
        observer.reclaim_abandoned_checkpoint_recovery_work(),
        Err(CatalogStoreError::UnsupportedTraversalFilesystem)
    ));
    assert!(matches!(
        observer.begin_checkpoint_recovery_work(selected(&cert), base(&cert)),
        Err(CatalogStoreError::UnsupportedTraversalFilesystem)
    ));
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    work.check().unwrap();
    drop(observer);
    mount.unmount();
    assert!(
        !std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.split_whitespace().nth(4) == mount.path.to_str())
    );
    work.finish().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly provisioned sudo PID/mount namespace support"]
fn live_recovery_scopes_do_not_steal_across_pid_namespaces() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    if let Some(directory) = std::env::var_os("MB_LIVE_SCOPE_NAMESPACE_CHILD") {
        let directory = std::path::PathBuf::from(directory);
        let (key, tip, amount): ([u8; 32], CatalogCheckpointRecoveryTip, Work) =
            mb_core::decode_canonical(&std::fs::read(directory.join("input")).unwrap()).unwrap();
        let store = ControlStore::open_with_key(directory.join("control.db"), &key).unwrap();
        assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
        let _work = store.begin_checkpoint_recovery_work(tip, amount).unwrap();
        let mut stream = UnixStream::connect(directory.join("scope.sock")).unwrap();
        stream.write_all(b"r").unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        panic!("namespace child must be killed while its scope is live");
    }

    struct ChildGuard {
        process: Child,
        peer: Option<UnixStream>,
        pidfd: Option<OwnedFd>,
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.peer.take();
            if let Some(pidfd) = &self.pidfd {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
            } else {
                let _ = self.process.kill();
            }
            let _ = self.process.wait();
        }
    }
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let amount = base(&cert);
    let mut own = store
        .begin_checkpoint_recovery_work(selected(&cert), amount)
        .unwrap();
    let key = history.keys[0].database_key(crate::database::CONTROL_DATABASE_ID);
    std::fs::write(
        temp.path().join("input"),
        mb_core::canonical_bytes(&(key, selected(&cert), amount)).unwrap(),
    )
    .unwrap();
    let listener = UnixListener::bind(temp.path().join("scope.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let log = std::fs::File::create(temp.path().join("namespace-child.log")).unwrap();
    let mut child = ChildGuard {
        process: Command::new("sudo").args(["-n", "env"])
            .arg(format!("MB_LIVE_SCOPE_NAMESPACE_CHILD={}", temp.path().display()))
            .args(["unshare", "--pid", "--fork", "--mount-proc", "setpriv", "--reuid"])
            .arg(unsafe { libc::getuid() }.to_string()).arg("--regid")
            .arg(unsafe { libc::getgid() }.to_string()).arg("--clear-groups")
            .arg(std::env::current_exe().unwrap())
            .args(["database::catalog::guild_history::tests::checkpoint_acquisition::work::live::live_recovery_scopes_do_not_steal_across_pid_namespaces", "--exact", "--ignored", "--nocapture"])
            .stdout(Stdio::null()).stderr(log).spawn().unwrap(),
        peer: None, pidfd: None,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("namespace handshake failed: {error}"),
        }
        assert!(
            child.process.try_wait().unwrap().is_none(),
            "namespace child exited: {}",
            std::fs::read_to_string(temp.path().join("namespace-child.log")).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "namespace child did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut ready = [0];
    stream.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [b'r']);
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // Kernel peer credentials translate the child's PID into this parent's
    // namespace; no process-name search or guessed PID is needed for cleanup.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(length as usize, std::mem::size_of::<libc::ucred>());
    let credentials = unsafe { credentials.assume_init() };
    assert_eq!(credentials.uid, unsafe { libc::getuid() });
    assert!(credentials.pid > 0);
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, credentials.pid, 0) };
    assert!(
        pidfd >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    child.pidfd = Some(unsafe { OwnedFd::from_raw_fd(pidfd as i32) });
    child.peer = Some(stream);
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        2
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    own.check().unwrap();
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                child.pidfd.as_ref().unwrap().as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
    assert!(!child.process.wait().unwrap().success());
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        amount
    );
    own.check().unwrap();
    own.finish().unwrap();
}

#[test]
fn live_recovery_competes_with_acquisitions_in_every_work_dimension() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    for dimension in 0..3 {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
        let other = ControlStore::open(&path, &history.keys[0]).unwrap();
        configure(&mut store, &cert, 16);
        activate(&store);
        let limit = store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .limit;
        store
            .configure_catalog_traversal_pool_policy(CatalogTraversalPoolPolicy {
                format_version: 1,
                capacity: capacity(&cert),
                limit: limit.checked_add(limit).unwrap(),
            })
            .unwrap();
        let mut amount = base(&cert);
        let mut whole_chain = amount;
        match dimension {
            0 => {
                amount.bytes = limit.bytes / 2 + limit.bytes / 4 + 1;
                whole_chain.bytes = limit.bytes + 1;
            }
            1 => {
                amount.records = limit.records / 2 + limit.records / 4 + 1;
                whole_chain.records = limit.records + 1;
            }
            _ => {
                amount.page_occurrences =
                    limit.page_occurrences / 2 + limit.page_occurrences / 4 + 1;
                whole_chain.page_occurrences = limit.page_occurrences + 1;
            }
        }
        let job = store
            .begin_checkpoint_acquisition(
                Uuid::from_u128(2201),
                cert.clone(),
                proof.trust().clone(),
                amount,
            )
            .unwrap();
        let mut work = other
            .begin_checkpoint_recovery_work(selected(&cert), amount)
            .unwrap();
        assert_eq!(
            store
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            amount.checked_add(amount).unwrap()
        );
        assert!(
            store
                .begin_checkpoint_recovery_work(selected(&cert), amount)
                .is_err()
        );
        assert!(
            store
                .begin_checkpoint_acquisition(
                    Uuid::from_u128(2202),
                    cert.clone(),
                    proof.trust().clone(),
                    amount
                )
                .is_err()
        );
        assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
        work.check().unwrap();
        store.cancel_checkpoint_acquisition(&job).unwrap();
        let mut larger = store
            .begin_checkpoint_recovery_work(selected(&cert), whole_chain)
            .unwrap();
        larger.check().unwrap();
        assert_eq!(
            store
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            amount.checked_add(whole_chain).unwrap()
        );
        larger.finish().unwrap();
        assert!(larger.check().is_err());
        work.finish().unwrap();
        work.finish().unwrap();
        assert_eq!(
            store
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            Work::default()
        );
        assert_eq!(
            store.checkpoint_acquisition_state(&job).unwrap(),
            State::Cancelled
        );
        drop(larger);
        drop(work);
        drop(store);
        assert_eq!(
            ControlStore::open(&path, &history.keys[0])
                .unwrap()
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .open_jobs,
            0
        );
    }
}

#[test]
fn live_recovery_slots_and_policy_enrollment_fence_unfunded_traversals() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    let other = ControlStore::open(&path, &history.keys[0]).unwrap();
    let mut old = other
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    old.check().unwrap();
    configure(&mut store, &cert, 2);
    assert!(old.check().is_err());
    assert!(old.finish().is_err());
    assert!(
        store
            .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
            .is_err()
    );
    activate(&store);
    drop(old);
    let mut work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let job = other
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2210),
            cert.clone(),
            proof.trust().clone(),
            base(&cert),
        )
        .unwrap();
    let usage = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    usage
        .limit
        .remaining_after(usage.reserved.checked_add(base(&cert)).unwrap())
        .unwrap();
    assert_eq!(usage.open_jobs, 2);
    assert!(
        other
            .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
            .is_err()
    );
    assert!(!other.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    work.finish().unwrap();
    let replacement = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    drop(replacement);
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        1
    );
    other.cancel_checkpoint_acquisition(&job).unwrap();
}

#[test]
fn live_recovery_reservation_and_failed_drop_cleanup_are_atomic_under_write_faults() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let job = store
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2220),
            cert.clone(),
            proof.trust().clone(),
            base(&cert),
        )
        .unwrap();
    let before = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    for action in ["ABORT", "IGNORE"] {
        for kind in [
            "catalog-live-recovery-work-v2",
            "catalog-live-recovery-work-guard-v2",
            "catalog-acquisition-work-lease-v1",
            "catalog-acquisition-work-lease-guard-v1",
            "catalog-acquisition-work-held-v1",
            "catalog-acquisition-work-held-guard-v1",
            "catalog-acquisition-work-v1",
            "catalog-acquisition-work-guard-v1",
        ] {
            let suffix = if action == "ABORT" { ",'test'" } else { "" };
            let counter = matches!(
                kind,
                "catalog-acquisition-work-v1" | "catalog-acquisition-work-guard-v1"
            );
            let operation = if counter { "UPDATE" } else { "INSERT" };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER live_fault BEFORE {operation} ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(
                store
                    .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                    .is_err()
            );
            store
                .connection
                .execute_batch("DROP TRIGGER live_fault")
                .unwrap();
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                before
            );
            assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            let mut work = store
                .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                .unwrap();
            let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
            let operation = if counter { "UPDATE" } else { "DELETE" };
            let column = if counter { "NEW" } else { "OLD" };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER live_fault BEFORE {operation} ON protocol_records WHEN {column}.kind='{kind}' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(work.finish().is_err());
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                held
            );
            work.check().unwrap();
            assert!(
                !ControlStore::open(&path, &history.keys[0])
                    .unwrap()
                    .reclaim_abandoned_checkpoint_recovery_work()
                    .unwrap()
            );
            drop(work);
            store
                .connection
                .execute_batch("DROP TRIGGER live_fault")
                .unwrap();
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                held
            );
            assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                before
            );
        }
    }
    assert_eq!(
        store.checkpoint_acquisition_state(&job).unwrap(),
        State::Building
    );
    store.cancel_checkpoint_acquisition(&job).unwrap();
}

#[test]
fn live_recovery_domain_installation_is_atomic_under_write_faults() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    for action in ["ABORT", "IGNORE"] {
        for kind in [
            "catalog-live-work-domain-v1",
            "catalog-live-work-domain-guard-v1",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
            configure(&mut store, &cert, 16);
            activate(&store);
            let before = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
            let suffix = if action == "ABORT" { ",'test'" } else { "" };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER domain_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(
                store
                    .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                    .is_err()
            );
            store
                .connection
                .execute_batch("DROP TRIGGER domain_fault")
                .unwrap();
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                before
            );
            assert!(
                store
                    .next_record_bounded("catalog-live-work-domain-v1", None, 16, 4096)
                    .unwrap()
                    .is_none()
            );
            drop(store);
            // Failed SQL can leave only an empty, synced lock file. Reopen may
            // adopt it, and its abandoned file description holds no slot.
            let store = ControlStore::open(&path, &history.keys[0]).unwrap();
            let mut work = store
                .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                .unwrap();
            assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            work.finish().unwrap();
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                before
            );
        }
    }
}

#[test]
fn live_recovery_torn_domain_cannot_release_or_rebind_live_slots() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let mut work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    let (id, bytes) = store
        .next_record_bounded("catalog-live-work-domain-guard-v1", None, 16, 4096)
        .unwrap()
        .unwrap();
    for corrupt in [false, true] {
        if corrupt {
            store.connection.execute("UPDATE protocol_records SET bytes=x'00' WHERE kind='catalog-live-work-domain-guard-v1' AND record_id=?1", [&id]).unwrap();
        } else {
            store.connection.execute("DELETE FROM protocol_records WHERE kind='catalog-live-work-domain-guard-v1' AND record_id=?1", [&id]).unwrap();
        }
        assert!(work.check().is_err());
        assert!(work.finish().is_err());
        assert!(store.reclaim_abandoned_checkpoint_recovery_work().is_err());
        assert!(
            store
                .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                .is_err()
        );
        assert!(ControlStore::open(&path, &history.keys[0]).is_err());
        store.connection.execute("INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('catalog-live-work-domain-guard-v1',?1,?2) ON CONFLICT(kind,record_id) DO UPDATE SET bytes=excluded.bytes", params![id, bytes]).unwrap();
        assert_eq!(
            store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
            held
        );
        assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
        work.check().unwrap();
    }
    work.finish().unwrap();
}

#[test]
fn live_recovery_torn_scope_and_copied_catalog_preserve_original_live_credits() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let mut work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    let (id, bytes) = store
        .next_record_bounded("catalog-live-recovery-work-guard-v2", None, 16, 4096)
        .unwrap()
        .unwrap();
    store.connection.execute("DELETE FROM protocol_records WHERE kind='catalog-live-recovery-work-guard-v2' AND record_id=?1", [&id]).unwrap();
    assert!(work.check().is_err());
    assert!(work.finish().is_err());
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().is_err());
    assert!(ControlStore::open(&path, &history.keys[0]).is_err());
    store.connection.execute("INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('catalog-live-recovery-work-guard-v2',?1,?2)", params![id, bytes]).unwrap();
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    work.check().unwrap();
    // This fixture has one quiescent SQL connection; the permit keeps only its
    // work token live. Checkpoint WAL before copying the encrypted main file.
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    let copied_path = temp.path().join("copied.db");
    std::fs::copy(&path, &copied_path).unwrap();
    let copied = ControlStore::open(&copied_path, &history.keys[0]).unwrap();
    assert_eq!(
        copied.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert!(copied.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        copied
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
    let mut copied_work = copied
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    assert!(!copied.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    copied_work.check().unwrap();
    copied_work.finish().unwrap();
    assert_eq!(
        copied
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    work.check().unwrap();
    work.finish().unwrap();
    assert_eq!(
        ControlStore::open(&path, &history.keys[0])
            .unwrap()
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
}

#[test]
fn legacy_kernel_domains_preserve_copied_debt_and_upgrade_only_without_scopes() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    let kinds = [
        "catalog-live-work-domain-v1",
        "catalog-live-work-domain-guard-v1",
    ];
    type Domain = (u16, Uuid, (u64, u64), (u64, u64));
    let (_, bytes) = store
        .next_record_bounded(kinds[0], None, 16, 4096)
        .unwrap()
        .unwrap();
    let mut domain: Domain = mb_core::decode_canonical(&bytes).unwrap();
    assert_eq!(domain.0, 2);
    domain.0 = 1;
    let bytes = mb_core::canonical_bytes(&domain).unwrap();
    for kind in kinds {
        assert_eq!(
            store
                .connection
                .execute(
                    "UPDATE protocol_records SET bytes=?1 WHERE kind=?2 AND record_id=?3",
                    params![bytes, kind, b"store"]
                )
                .unwrap(),
            1
        );
    }
    // Simulate the exact old envelope, whose filesystem provenance was not
    // established. Its original kernel slot still proves live ownership.
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    let copied_path = temp.path().join("copied.db");
    std::fs::copy(&path, &copied_path).unwrap();
    let copied = ControlStore::open(&copied_path, &history.keys[0]).unwrap();
    assert!(!copied.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert!(
        copied
            .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
            .is_err()
    );
    assert_eq!(
        copied.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    // The simulated old domain cannot be finished by the new permit's token;
    // Drop releases its kernel lock and leaves the declaration for reclamation.
    drop(work);
    drop(store);
    let store = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    let mut current = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let (_, bytes) = store
        .next_record_bounded(kinds[0], None, 16, 4096)
        .unwrap()
        .unwrap();
    let upgraded: Domain = mb_core::decode_canonical(&bytes).unwrap();
    assert_eq!(upgraded.0, 2);
    assert_ne!(upgraded.1, domain.1);
    assert_eq!((upgraded.2, upgraded.3), (domain.2, domain.3));
    current.check().unwrap();
    current.finish().unwrap();
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
    // Cleanup in the original never authorizes a copy to discard old debt.
    drop(copied);
    let copied = ControlStore::open(&copied_path, &history.keys[0]).unwrap();
    assert!(!copied.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        copied.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_process_scopes_remain_debt_without_namespace_liveness_guesses() {
    use std::os::unix::fs::MetadataExt;
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let amount = base(&cert);
    let work = store
        .begin_checkpoint_recovery_work(selected(&cert), amount)
        .unwrap();
    let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    let (id, _) = store
        .next_record_bounded("catalog-live-recovery-work-v2", None, 16, 4096)
        .unwrap()
        .unwrap();
    let scope_id = Uuid::from_slice(&id).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    // Exact original v1 field order. An unobservable numeric PID in another
    // namespace does not prove that its process stopped; old credits stay held.
    let owner = (
        Uuid::new_v4(),
        u32::MAX,
        1_u64,
        Uuid::new_v4(),
        metadata.dev(),
        metadata.ino(),
    );
    let legacy = (1_u16, scope_id, selected(&cert), amount, owner);
    let bytes = mb_core::canonical_bytes(&legacy).unwrap();
    let hash = mb_core::canonical_hash_bounded(&legacy, 4096).unwrap();
    let lease = mb_core::canonical_bytes(&(1_u16, hash, amount, true)).unwrap();
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )
    .unwrap();
    for (current, old) in [
        (
            "catalog-live-recovery-work-v2",
            "catalog-live-recovery-work-v1",
        ),
        (
            "catalog-live-recovery-work-guard-v2",
            "catalog-live-recovery-work-guard-v1",
        ),
    ] {
        assert_eq!(
            tx.execute(
                "UPDATE protocol_records SET kind=?1,bytes=?2 WHERE kind=?3 AND record_id=?4",
                params![old, bytes, current, id]
            )
            .unwrap(),
            1
        );
    }
    for kind in [
        "catalog-acquisition-work-lease-v1",
        "catalog-acquisition-work-lease-guard-v1",
        "catalog-acquisition-work-held-v1",
        "catalog-acquisition-work-held-guard-v1",
    ] {
        assert_eq!(
            tx.execute(
                "UPDATE protocol_records SET bytes=?1 WHERE kind=?2 AND record_id=?3",
                params![lease, kind, id]
            )
            .unwrap(),
            1
        );
    }
    tx.commit().unwrap();
    drop(work);
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    drop(store);
    let store = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert_eq!(
        store
            .next_record_bounded("catalog-live-recovery-work-v1", None, 16, 4096)
            .unwrap()
            .unwrap(),
        (id, bytes)
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    let mut current = store
        .begin_checkpoint_recovery_work(selected(&cert), amount)
        .unwrap();
    current.check().unwrap();
    current.finish().unwrap();
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    let copied_path = temp.path().join("copied.db");
    std::fs::copy(&path, &copied_path).unwrap();
    let copied = ControlStore::open(&copied_path, &history.keys[0]).unwrap();
    // Old process envelopes cannot distinguish a real copy from a layered
    // alias. Preserve their exact debt in both catalogs without PID guesses.
    assert!(!copied.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    let mut copied_work = copied
        .begin_checkpoint_recovery_work(selected(&cert), amount)
        .unwrap();
    copied_work.finish().unwrap();
    assert_eq!(
        copied.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn live_recovery_sigkill_reclaims_one_scope_without_releasing_durable_jobs() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    if let Some(directory) = std::env::var_os("MB_LIVE_RECOVERY_CHILD") {
        let directory = std::path::PathBuf::from(directory);
        let (key, tip, amount): ([u8; 32], CatalogCheckpointRecoveryTip, Work) =
            mb_core::decode_canonical(&std::fs::read(directory.join("input")).unwrap()).unwrap();
        let store = ControlStore::open_with_key(directory.join("control.db"), &key).unwrap();
        let _first = store.begin_checkpoint_recovery_work(tip, amount).unwrap();
        let _second = store.begin_checkpoint_recovery_work(tip, amount).unwrap();
        std::fs::write(directory.join("ready"), b"two live scopes").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let limit = store
        .checkpoint_acquisition_work_usage()
        .unwrap()
        .unwrap()
        .limit;
    store
        .configure_catalog_traversal_pool_policy(CatalogTraversalPoolPolicy {
            format_version: 1,
            capacity: capacity(&cert),
            limit: limit.checked_add(limit).unwrap(),
        })
        .unwrap();
    let amount = base(&cert);
    let job = store
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2230),
            cert.clone(),
            proof.trust().clone(),
            amount,
        )
        .unwrap();
    let key = history.keys[0].database_key(crate::database::CONTROL_DATABASE_ID);
    std::fs::write(
        temp.path().join("input"),
        mb_core::canonical_bytes(&(key, selected(&cert), amount)).unwrap(),
    )
    .unwrap();
    let mut child = ChildGuard(Command::new(std::env::current_exe().unwrap()).args([
        "database::catalog::guild_history::tests::checkpoint_acquisition::work::live::live_recovery_sigkill_reclaims_one_scope_without_releasing_durable_jobs", "--exact", "--nocapture"
    ]).env("MB_LIVE_RECOVERY_CHILD", temp.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !temp.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before reserving its scopes"
        );
        assert!(Instant::now() < deadline, "child did not reserve scopes");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        3
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        3
    );
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        2
    );
    drop(store);
    let store = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        amount
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store.checkpoint_acquisition_state(&job).unwrap(),
        State::Building
    );
    store.cancel_checkpoint_acquisition(&job).unwrap();
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        0
    );
}

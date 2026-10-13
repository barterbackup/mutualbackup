use super::*;
use mb_core::{Seed, merkle_commit, merkle_verify_range};
use mb_store::{
    CatalogPackingAuthorityBase, CatalogPackingPayload, CatalogPackingPayloadRetention,
    CatalogStoreError,
};
use tempfile::TempDir;

struct Fixture {
    data: TempDir,
    keys: Arc<KeyMaterial>,
    control: ControlStore,
    volumes: StorageVolumes,
    payload: CatalogPackingPayload,
    bytes: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        Self::sized(mb_core::V1_SECTOR_SIZE)
    }
    fn sized(size: usize) -> Self {
        let data = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([231; 32])));
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        let bytes = (0..size)
            .map(|i| (232_usize ^ (i * 13 + i / 4096 + i / mb_core::V1_SECTOR_SIZE)) as u8)
            .collect::<Vec<_>>();
        let attempt = [233; 16];
        let guild = [234; 32];
        let storage = [235; 32];
        let shard = 63;
        volumes
            .reserve_attempt(&control, &attempt, guild, shard, bytes.len() as u32)
            .unwrap();
        let reservation: AttemptReservationRecord = decode_canonical(
            &control
                .get_record(
                    "volume-attempt-reservation",
                    &attempt_reservation_id(&attempt, shard as u8),
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let payload = CatalogPackingPayload {
            guild_id: guild,
            storage_id: storage,
            shard_index: shard,
            commitment: merkle_commit(&bytes).unwrap(),
            attempt_id: attempt,
            volume_id: reservation.volume_id,
        };
        Self {
            data,
            keys,
            control,
            volumes,
            payload,
            bytes,
        }
    }
    fn loan(&self) -> CatalogPackingPayloadRetention {
        CatalogPackingPayloadRetention {
            id: Uuid::new_v4(),
            base: CatalogPackingAuthorityBase {
                guild_id: self.payload.guild_id,
                checkpoint_hash: [236; 32],
                generation: 1,
                membership_epoch: Some(1),
            },
            budget: mb_core::CatalogCodingTraversalBudget {
                bytes: 16 * 1024 * 1024,
                page_occurrences: 0,
                records: 100,
            },
        }
    }
    fn retain(&self, r: CatalogPackingPayloadRetention) {
        self.control
            .begin_catalog_packing_payload_retention(r, |_| Ok::<_, CatalogStoreError>(()))
            .unwrap();
        self.control
            .retain_catalog_packing_payload_checked(
                r,
                &self.payload,
                (
                    |_| Ok::<_, CatalogStoreError>(()),
                    |p| {
                        assert_eq!(p, &self.payload);
                        self.volumes
                            .verify_packing_payload(&self.control, p)
                            .unwrap();
                        Ok(())
                    },
                ),
            )
            .unwrap();
    }
    fn upload(&mut self) {
        for (i, bytes) in self.bytes.chunks(mb_core::V1_SECTOR_SIZE).enumerate() {
            self.volumes
                .write_attempt_range(
                    &self.control,
                    &self.payload.attempt_id,
                    self.payload.shard_index,
                    (i * mb_core::V1_SECTOR_SIZE) as u32,
                    bytes,
                )
                .unwrap();
        }
        self.volumes
            .finish_attempt_upload(
                &self.control,
                &self.payload.attempt_id,
                self.payload.storage_id,
                self.payload.shard_index,
                &self.payload.commitment,
            )
            .unwrap();
    }
    fn verify(&self) {
        self.volumes
            .verify_packing_payload(&self.control, &self.payload)
            .unwrap();
        let chunks = self.bytes.chunks(mb_core::V1_SECTOR_SIZE);
        let last = chunks.len() - 1;
        for (i, bytes) in chunks.enumerate().filter(|(i, _)| *i == 0 || *i == last) {
            let proof = self
                .volumes
                .open_attempt_range(
                    &self.control,
                    &self.payload.attempt_id,
                    &self.payload.storage_id,
                    self.payload.shard_index,
                    (i * mb_core::V1_SECTOR_SIZE / mb_core::MERKLE_LEAF_SIZE) as u32,
                    (bytes.len() / mb_core::MERKLE_LEAF_SIZE) as u32,
                )
                .unwrap();
            assert_eq!(
                merkle_verify_range(&self.payload.commitment, &proof).unwrap(),
                bytes
            );
        }
    }
    fn reopen(self) -> Self {
        let Self {
            data,
            keys,
            control,
            volumes,
            payload,
            bytes,
        } = self;
        drop(volumes);
        drop(control);
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        Self {
            data,
            keys,
            control,
            volumes,
            payload,
            bytes,
        }
    }
    fn release(&self, r: CatalogPackingPayloadRetention) {
        self.control
            .cancel_catalog_packing_payload_retention(r)
            .unwrap();
        assert!(self.control.release_catalog_packing_payload(r).unwrap());
        assert!(!self.control.release_catalog_packing_payload(r).unwrap());
    }
    fn discard(&mut self) -> bool {
        self.volumes
            .discard_attempt(&self.control, &self.payload.attempt_id, &BTreeSet::new())
            .unwrap()
    }
}

#[test]
fn pending_packing_output_preserves_partial_reservation_through_abort_reopen_and_retry() {
    let mut f = Fixture::new();
    let r = f.loan();
    f.volumes
        .write_attempt_range(
            &f.control,
            &f.payload.attempt_id,
            f.payload.shard_index,
            0,
            &f.bytes[..32],
        )
        .unwrap();
    f.retain(r);
    assert!(!f.discard());
    f = f.reopen();
    assert!(!f.discard());
    assert_eq!(
        f.volumes
            .reserve_attempt(
                &f.control,
                &f.payload.attempt_id,
                f.payload.guild_id,
                f.payload.shard_index,
                f.bytes.len() as u32
            )
            .unwrap(),
        32
    );
    f.volumes
        .write_attempt_range(
            &f.control,
            &f.payload.attempt_id,
            f.payload.shard_index,
            32,
            &f.bytes[32..],
        )
        .unwrap();
    f.volumes
        .finish_attempt_upload(
            &f.control,
            &f.payload.attempt_id,
            f.payload.storage_id,
            f.payload.shard_index,
            &f.payload.commitment,
        )
        .unwrap();
    f.verify();
    f.release(r);
    assert!(f.discard());
    assert!(
        f.volumes
            .open_attempt_range(
                &f.control,
                &f.payload.attempt_id,
                &f.payload.storage_id,
                f.payload.shard_index,
                0,
                1
            )
            .is_err()
    );
}

#[test]
fn pending_packing_output_keeps_real_staged_bytes_and_receipts_shared_until_last_loan_releases() {
    for size in [
        mb_core::V1_SECTOR_SIZE,
        mb_core::MAX_PROFILE_SHARD_SIZE as usize,
    ] {
        let mut f = Fixture::sized(size);
        f.upload();
        let loans = [f.loan(), f.loan()];
        for r in loans {
            f.retain(r);
        }
        f.verify();
        assert!(!f.discard());
        assert!(
            f.volumes
                .finalize_attempt(&f.control, &f.payload.attempt_id)
                .is_err()
        );
        f = f.reopen();
        f.verify();
        f.release(loans[0]);
        assert!(!f.discard());
        f.verify();
        f.release(loans[1]);
        assert!(f.discard());
        assert!(
            f.control
                .get_record(
                    "volume-attempt-receipt",
                    &attempt_volume_object_id(
                        &f.payload.attempt_id,
                        &f.payload.storage_id,
                        f.payload.shard_index as u8
                    )
                )
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn pending_packing_output_offline_and_ready_copies_remain_owned_and_cleanup_resumes_after_reopen() {
    let mut f = Fixture::new();
    f.upload();
    let r = f.loan();
    f.retain(r);
    f.volumes
        .attach_attempt_receipt(
            &f.control,
            &f.payload.attempt_id,
            &f.payload.storage_id,
            f.payload.shard_index,
            b"original local receipt",
        )
        .unwrap();
    f.volumes
        .activate_attempt_object(
            &f.control,
            &f.payload.attempt_id,
            &f.payload.storage_id,
            f.payload.shard_index,
            &f.payload.commitment,
            &[237; 32],
        )
        .unwrap();
    assert!(!f.discard());
    f.volumes
        .volumes
        .get_mut(&f.payload.volume_id)
        .unwrap()
        .store = None;
    f.release(r);
    assert!(!f.discard());
    assert!(
        f.control
            .get_record(
                "volume-attempt-receipt",
                &attempt_volume_object_id(
                    &f.payload.attempt_id,
                    &f.payload.storage_id,
                    f.payload.shard_index as u8
                )
            )
            .unwrap()
            .is_some()
    );
    f = f.reopen();
    f.verify();
    assert!(f.discard());
    assert!(
        f.volumes
            .load_ready_variable(&f.control, &f.payload.storage_id, f.payload.shard_index)
            .is_err()
    );
}

#[test]
fn pending_packing_output_rejects_changed_locators_and_corrupt_physical_bytes_before_loan_publication()
 {
    let mut other = Fixture::new();
    other.upload();
    other.volumes.volumes[&other.payload.volume_id]
        .store
        .as_ref()
        .unwrap()
        .database_shell_statement("UPDATE parity_objects SET guild_id = zeroblob(32)", false)
        .unwrap();
    assert!(
        other
            .volumes
            .verify_packing_payload(&other.control, &other.payload)
            .is_err()
    );
    let mut f = Fixture::sized(mb_core::MAX_PROFILE_SHARD_SIZE as usize);
    f.upload();
    for field in 0..4 {
        let r = f.loan();
        f.control
            .begin_catalog_packing_payload_retention(r, |_| Ok::<_, CatalogStoreError>(()))
            .unwrap();
        let mut changed = f.payload.clone();
        match field {
            0 => changed.volume_id = Uuid::new_v4(),
            1 => changed.attempt_id = [238; 16],
            2 => changed.commitment = merkle_commit(&vec![239; f.bytes.len()]).unwrap(),
            _ => changed.guild_id = [240; 32],
        }
        let result: Result<()> = f.control.retain_catalog_packing_payload_checked(
            r,
            &changed,
            (
                |_| Ok(()),
                |p| f.volumes.verify_packing_payload(&f.control, p),
            ),
        );
        assert!(result.is_err());
        assert!(
            f.control
                .catalog_packing_payload(r, f.payload.storage_id, f.payload.shard_index)
                .unwrap()
                .is_none()
        );
    }
    f.volumes.volumes[&f.payload.volume_id]
        .store
        .as_ref()
        .unwrap()
        .database_shell_statement(
            "UPDATE parity_objects SET bytes = CAST(substr(bytes, 1, 2097152) || X'00' || substr(bytes, 2097154) AS BLOB)",
            false,
        )
        .unwrap();
    let r = f.loan();
    f.control
        .begin_catalog_packing_payload_retention(r, |_| Ok::<_, CatalogStoreError>(()))
        .unwrap();
    let result: Result<()> = f.control.retain_catalog_packing_payload_checked(
        r,
        &f.payload,
        (
            |_| Ok(()),
            |p| f.volumes.verify_packing_payload(&f.control, p),
        ),
    );
    assert!(result.is_err());
    assert!(
        !f.control
            .catalog_checkpoint_payload_is_pinned(
                f.payload.storage_id,
                f.payload.shard_index,
                f.payload.commitment.root
            )
            .unwrap()
    );
}

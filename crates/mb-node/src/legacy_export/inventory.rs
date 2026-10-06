//! Authenticated metadata inventory; never opens the withdrawn runtime or data sources.

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result, ensure};
use mb_core::{
    KeyMaterial, QuorumCheckpoint, SignedRecord, USER_REVISION_DOMAIN, UserRevision,
    V1_MAX_CATALOG_BYTES, canonical_bytes_bounded, canonical_size_bounded, decode_canonical,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One authenticated revision available in the selected local metadata sources.
/// This does not prove that its private metadata or ciphertext can be recovered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyRevisionInventoryEntry {
    pub guild_id: String,
    pub protected_root_id: Uuid,
    pub revision_id: Uuid,
    pub sequence: u64,
    pub signed_format: u16,
    pub revision_body_hash: String,
    pub signed_record_hash: String,
    pub metadata_sectors: u64,
    pub data_sectors: u64,
    pub saved_revision: bool,
    pub recovery_head: bool,
    pub certified_checkpoint: bool,
}

/// Local available metadata only. Missing records, remote history, root/Git
/// catalogs, pins and pending intents require separate preservation/recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyRevisionInventory {
    pub format_version: u16,
    pub owner: String,
    pub scope: String,
    pub retained_history_complete: bool,
    pub revisions: Vec<LegacyRevisionInventoryEntry>,
}

const SCOPE: &str = "available-local-signed-revision-metadata";

/// Inspect existing encrypted control data without startup, migration, key
/// wrapping, journal replay, source reads or mutation. Invalid evidence and
/// conflicting records fail the whole inventory; no partial success is returned.
pub fn inventory_withdrawn_revisions_from_catalog(
    keys: &KeyMaterial,
    data_dir: &Path,
) -> Result<LegacyRevisionInventory> {
    inventory_catalog(keys, data_dir, V1_MAX_CATALOG_BYTES)
}

fn inventory_catalog(
    keys: &KeyMaterial,
    data_dir: &Path,
    summary_budget: usize,
) -> Result<LegacyRevisionInventory> {
    let control = crate::volume::inspect_control_store(data_dir, keys)?
        .context("original control catalog is unavailable")?;
    let mut entries = BTreeMap::<Uuid, LegacyRevisionInventoryEntry>::new();
    let mut summary_size = 0usize;
    let mut add = |revision: &SignedRecord<UserRevision>, source: usize| -> Result<()> {
        let signed = canonical_bytes_bounded(revision, V1_MAX_CATALOG_BYTES)?;
        revision.verify(USER_REVISION_DOMAIN)?;
        revision.value.verify_writer()?;
        if revision.value.owner != keys.node_id() {
            return Ok(());
        }
        crate::snapshot::checked_metadata_length(revision)?;
        crate::snapshot::validate_restore_revision(keys, revision.value.guild_id, revision)?;
        let hash = hex::encode(blake3::hash(&signed).as_bytes());
        if let Some(entry) = entries.get_mut(&revision.value.revision_id) {
            ensure!(
                entry.signed_record_hash == hash,
                "conflicting signed records for one revision ID"
            );
            match source {
                0 => entry.saved_revision = true,
                1 => entry.recovery_head = true,
                _ => entry.certified_checkpoint = true,
            }
            return Ok(());
        }
        let entry = LegacyRevisionInventoryEntry {
            guild_id: hex::encode(revision.value.guild_id),
            protected_root_id: revision.value.protected_root_id,
            revision_id: revision.value.revision_id,
            sequence: revision.value.sequence,
            signed_format: revision.value.format_version,
            revision_body_hash: hex::encode(revision.value.hash()?),
            signed_record_hash: hash,
            metadata_sectors: revision.value.metadata_sectors.len() as u64,
            data_sectors: revision.value.data_sectors.len() as u64,
            saved_revision: source == 0,
            recovery_head: source == 1,
            certified_checkpoint: source == 2,
        };
        summary_size = summary_size
            .checked_add(canonical_size_bounded(&entry, summary_budget)?)
            .context("revision inventory size overflow")?;
        ensure!(
            summary_size <= summary_budget,
            "revision inventory exceeds its bounded metadata budget"
        );
        entries.insert(entry.revision_id, entry);
        Ok(())
    };
    for (namespace, max_key, source) in [("user-revision", 16, 0), ("user-revision-head", 48, 1)] {
        control.for_each_record_bounded(
            namespace,
            max_key,
            V1_MAX_CATALOG_BYTES,
            |key, bytes| {
                let revision: SignedRecord<UserRevision> = decode_canonical(bytes)?;
                ensure!(
                    canonical_bytes_bounded(&revision, V1_MAX_CATALOG_BYTES)? == bytes,
                    "revision inventory record is not canonical"
                );
                if source == 0 {
                    ensure!(
                        key == revision.value.revision_id.as_bytes(),
                        "revision inventory record has a conflicting ID"
                    );
                } else {
                    let mut scope = revision.value.guild_id.to_vec();
                    scope.extend(revision.value.protected_root_id.as_bytes());
                    ensure!(
                        key == scope || key == revision.value.guild_id,
                        "revision inventory head has a conflicting scope"
                    );
                }
                add(&revision, source)?;
                Ok(true)
            },
        )?;
    }
    control.for_each_record_bounded(
        "guild-checkpoint",
        32,
        V1_MAX_CATALOG_BYTES,
        |key, bytes| {
            let checkpoint: QuorumCheckpoint = decode_canonical(bytes)?;
            ensure!(
                canonical_bytes_bounded(&checkpoint, V1_MAX_CATALOG_BYTES)? == bytes,
                "revision inventory checkpoint is not canonical"
            );
            checkpoint.verify()?;
            ensure!(
                key == checkpoint.hash()?,
                "revision inventory checkpoint has a conflicting hash"
            );
            for revision in &checkpoint.checkpoint.revisions {
                add(revision, 2)?;
            }
            Ok(true)
        },
    )?;
    let mut revisions: Vec<_> = entries.into_values().collect();
    revisions.sort_by(|a, b| {
        (&a.guild_id, a.protected_root_id, a.sequence, a.revision_id).cmp(&(
            &b.guild_id,
            b.protected_root_id,
            b.sequence,
            b.revision_id,
        ))
    });
    let report = LegacyRevisionInventory {
        format_version: 1,
        owner: keys.node_id().to_string(),
        scope: SCOPE.to_owned(),
        retained_history_complete: false,
        revisions,
    };
    canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{Seed, canonical_bytes};
    use mb_store::ControlStore;
    use std::fs;

    #[test]
    fn legacy_inventory_authenticates_deduplicates_and_preserves_unavailable_history() {
        for (format, wrapped) in [(6, false), (7, true)] {
            let ((keys, revision, _), _, _, checkpoint) =
                super::super::tests::fixed_checkpoint_fixture(format);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = if wrapped {
                crate::volume::open_control_store(&data, &keys).unwrap().0
            } else {
                ControlStore::open(data.join("control.db"), &keys).unwrap()
            };
            let mut next = revision.value.clone();
            next.revision_id = Uuid::from_bytes([87; 16]);
            next.sequence = 2;
            next.parent = Some(revision.value.hash().unwrap());
            next.sign_writer(&ed25519_dalek::SigningKey::from_bytes(&[53; 32]))
                .unwrap();
            let next = SignedRecord::sign(USER_REVISION_DOMAIN, next, &keys).unwrap();
            store
                .put_record(
                    "user-revision",
                    next.value.revision_id.as_bytes(),
                    &canonical_bytes(&next).unwrap(),
                )
                .unwrap();
            let foreign_keys = KeyMaterial::from_seed(&Seed::from_bytes([88; 32]));
            let mut foreign = revision.value.clone();
            foreign.owner = foreign_keys.node_id();
            foreign.revision_id = Uuid::from_bytes([89; 16]);
            foreign
                .sign_writer(&ed25519_dalek::SigningKey::from_bytes(&[53; 32]))
                .unwrap();
            let foreign = SignedRecord::sign(USER_REVISION_DOMAIN, foreign, &foreign_keys).unwrap();
            store
                .put_record(
                    "user-revision",
                    foreign.value.revision_id.as_bytes(),
                    &canonical_bytes(&foreign).unwrap(),
                )
                .unwrap();
            let signed = canonical_bytes(&revision).unwrap();
            store
                .put_record(
                    "user-revision",
                    revision.value.revision_id.as_bytes(),
                    &signed,
                )
                .unwrap();
            let mut scope = revision.value.guild_id.to_vec();
            scope.extend(revision.value.protected_root_id.as_bytes());
            store
                .put_record("user-revision-head", &scope, &signed)
                .unwrap();
            store
                .put_record("user-revision-head", &revision.value.guild_id, &signed)
                .unwrap();
            store
                .put_record(
                    "guild-checkpoint",
                    &checkpoint.hash().unwrap(),
                    &canonical_bytes(&checkpoint).unwrap(),
                )
                .unwrap();
            store
                .put_record("guarded-view-mount-v1", b"legacy", b"preserve")
                .unwrap();
            store
                .put_record("guarded-capture-intent", b"pending", b"preserve")
                .unwrap();
            drop(store);
            let before = fs::read(data.join("control.db")).unwrap();
            let key_before = fs::read(data.join("control.key")).ok();
            assert!(crate::Node::open(&data, Seed::from_bytes([49; 32])).is_err());
            let report = inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.scope, SCOPE);
            assert!(!report.retained_history_complete);
            assert_eq!(report.revisions.len(), 2);
            let entry = &report.revisions[0];
            assert_eq!(entry.revision_id, revision.value.revision_id);
            assert_eq!(entry.signed_format, revision.value.format_version);
            assert!(entry.saved_revision && entry.recovery_head && entry.certified_checkpoint);
            assert_eq!(
                entry.revision_body_hash,
                hex::encode(revision.value.hash().unwrap())
            );
            assert_eq!(report.revisions[1].revision_id, next.value.revision_id);
            assert_eq!(report.revisions[1].sequence, 2);
            assert!(report.revisions[1].saved_revision);
            assert!(
                !report.revisions[1].recovery_head && !report.revisions[1].certified_checkpoint
            );
            let cost = report
                .revisions
                .iter()
                .map(|entry| canonical_size_bounded(entry, V1_MAX_CATALOG_BYTES).unwrap())
                .sum();
            assert!(inventory_catalog(&keys, &data, cost).is_ok());
            assert!(inventory_catalog(&keys, &data, cost - 1).is_err());
            assert_eq!(fs::read(data.join("control.db")).unwrap(), before);
            assert_eq!(fs::read(data.join("control.key")).ok(), key_before);
            assert!(!data.join("parity.db").exists());
            assert!(
                inventory_withdrawn_revisions_from_catalog(
                    &KeyMaterial::from_seed(&Seed::from_bytes([99; 32])),
                    &data
                )
                .is_err()
            );
        }
    }

    #[test]
    fn legacy_inventory_rejects_invalid_scopes_signatures_certificates_and_conflicts() {
        for case in 0..8 {
            let ((keys, revision, _), _, _, checkpoint) =
                super::super::tests::fixed_checkpoint_fixture(6);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
            let mut candidate = revision.clone();
            match case {
                0 => store
                    .put_record(
                        "user-revision",
                        &[0; 16],
                        &canonical_bytes(&revision).unwrap(),
                    )
                    .unwrap(),
                1 => store
                    .put_record(
                        "user-revision-head",
                        &[0; 32],
                        &canonical_bytes(&revision).unwrap(),
                    )
                    .unwrap(),
                2 => {
                    candidate.signature[0] ^= 1;
                    store
                        .put_record(
                            "user-revision",
                            candidate.value.revision_id.as_bytes(),
                            &canonical_bytes(&candidate).unwrap(),
                        )
                        .unwrap();
                }
                3 => {
                    candidate.value.writer_signature[0] ^= 1;
                    candidate =
                        SignedRecord::sign(USER_REVISION_DOMAIN, candidate.value, &keys).unwrap();
                    store
                        .put_record(
                            "user-revision",
                            candidate.value.revision_id.as_bytes(),
                            &canonical_bytes(&candidate).unwrap(),
                        )
                        .unwrap();
                }
                4 => store
                    .put_record(
                        "guild-checkpoint",
                        &[0; 32],
                        &canonical_bytes(&checkpoint).unwrap(),
                    )
                    .unwrap(),
                5 => {
                    let mut checkpoint = checkpoint;
                    checkpoint.signatures[0].signature[0] ^= 1;
                    store
                        .put_record(
                            "guild-checkpoint",
                            &checkpoint.hash().unwrap(),
                            &canonical_bytes(&checkpoint).unwrap(),
                        )
                        .unwrap();
                }
                6 => {
                    store
                        .put_record(
                            "user-revision",
                            revision.value.revision_id.as_bytes(),
                            &canonical_bytes(&revision).unwrap(),
                        )
                        .unwrap();
                    candidate.value.protected_root_id = Uuid::from_bytes([88; 16]);
                    candidate
                        .value
                        .sign_writer(&ed25519_dalek::SigningKey::from_bytes(&[53; 32]))
                        .unwrap();
                    candidate =
                        SignedRecord::sign(USER_REVISION_DOMAIN, candidate.value, &keys).unwrap();
                    store
                        .put_record(
                            "user-revision-head",
                            &candidate.value.guild_id,
                            &canonical_bytes(&candidate).unwrap(),
                        )
                        .unwrap();
                }
                _ => store
                    .put_record(
                        "user-revision",
                        revision.value.revision_id.as_bytes(),
                        b"damaged",
                    )
                    .unwrap(),
            }
            drop(store);
            let before = fs::read(data.join("control.db")).unwrap();
            assert!(
                inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err(),
                "case {case}"
            );
            assert_eq!(fs::read(data.join("control.db")).unwrap(), before);
            assert!(!data.join("control.key").exists());
        }
        let temp = tempfile::tempdir().unwrap();
        let absent = temp.path().join("absent");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([49; 32]));
        assert!(inventory_withdrawn_revisions_from_catalog(&keys, &absent).is_err());
        assert!(!absent.exists());
    }
}

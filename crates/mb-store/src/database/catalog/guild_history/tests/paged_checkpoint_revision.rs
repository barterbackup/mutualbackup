use super::*;
use mb_core::{
    CatalogCheckpointAuthorityRecord as R, CatalogCheckpointRevisionKey, CatalogSectorReader,
    SignedRecord,
};

fn private_checkpoint(
    control: &ControlStore,
) -> (
    super::super::super::checkpoint_validation::tests::Fixture,
    History,
    CatalogBundle,
    Vec<u8>,
) {
    let mut fixture = super::super::super::checkpoint_validation::tests::Fixture::new(true, false);
    let scope = fixture.paged().value.scope();
    let keys = &fixture.sources.keys[0];
    let (bundle, bootstrap) = super::super::super::paged_revision::tests::fixture_with_context(
        control,
        1,
        None,
        keys,
        &fixture.sources.writer,
        scope,
    );
    let signed = mb_core::PagedUserRevision::decode_signed(&bundle.descriptor).unwrap();
    let mut ciphertext = BTreeMap::from([(signed.value.metadata.sector.id, bootstrap.clone())]);
    for member in &bundle.roots {
        let mut reader =
            mb_core::CatalogReader::new(scope, member.intent.section, member.root).unwrap();
        while reader
            .next_leaf(&mut |page| {
                let bytes = control.catalog_page(scope, member.intent.section, page)?;
                fixture.pages.insert(page.hash, bytes.clone());
                if member.intent.section.is_private() {
                    let (sector, encrypted) = page.seal_private_page(
                        &keys.guild_content_id_key(&signed.value.guild_id),
                        &keys.guild_data_key(&signed.value.guild_id),
                        scope,
                        member.intent.section,
                        &bytes,
                    )?;
                    ciphertext.insert(sector.id, encrypted);
                }
                Ok::<_, CatalogStoreError>(bytes)
            })
            .unwrap()
            .is_some()
        {}
    }
    let mut reader = CatalogSectorReader::new(scope, signed.value.sources).unwrap();
    let mut records = Vec::new();
    while let Some(record) = reader
        .next_sector(&mut |page| {
            control.catalog_page(scope, CatalogSection::SectorReferences, page)
        })
        .unwrap()
    {
        records.push(record);
    }
    fixture.sources.bytes = records
        .iter()
        .map(|record| ciphertext[&record.sector.id].clone())
        .collect();
    fixture.sources.records = records;
    fixture
        .records
        .retain(|record| !matches!(record, R::LegacyRevision(_) | R::PagedRevision(_)));
    fixture.records.push(R::PagedRevision(signed));
    let (fixture, history) = real_checkpoint_with_fixture(fixture);
    (fixture, history, bundle, bootstrap)
}

fn private_proof(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
) -> CatalogQuorumPagedCheckpointIndex {
    private_proof_with_budget(fixture, history, budget())
}

fn private_proof_with_budget(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
    limit: Work,
) -> CatalogQuorumPagedCheckpointIndex {
    let trust = history.trust();
    let reader = real_reader(history, &trust);
    fixture.context.generation = 1;
    fixture.context.event_sequence = trust.event_sequence;
    fixture.context.event_head = trust.event_head;
    fixture.context.authority = trust.authority;
    fixture
        .records
        .retain(|record| !matches!(record, R::Member(_)));
    fixture
        .records
        .extend(trust.members.iter().cloned().map(R::Member));
    let entries = history
        .source
        .objects
        .iter()
        .filter_map(|(key, bytes)| {
            if !matches!(key, CatalogGuildHistoryObject::Transcript(_)) {
                return None;
            }
            let transcript: SignedRecord<mb_core::CodingVerificationTranscript> =
                decode_canonical(bytes).unwrap();
            let retained = history
                .state
                .coding_groups
                .iter()
                .find(|group| group.group.id == transcript.value.manifest.value.group.id)
                .unwrap()
                .clone();
            Some(CatalogCodingEntry {
                retained,
                transcript,
            })
        })
        .collect::<Vec<_>>();
    let (body, _) = fixture.joined_with_groups_and_members(
        limit,
        CatalogCodingCoveragePolicy::Current,
        &trust.members,
        true,
        |_, _| entries,
    );
    let body = body
        .validate_certified_history_coding_state(&reader, limit, || Ok(trust.clone()))
        .unwrap();
    let transition = body
        .validate_certified_history_authority_transition(None, &reader, limit, || Ok(trust.clone()))
        .unwrap();
    real_certificate(transition, history)
}

fn publish_private(
    control: &ControlStore,
    fixture: &super::super::super::checkpoint_validation::tests::Fixture,
    bundle: &CatalogBundle,
    bootstrap: &[u8],
    anchor: Uuid,
) -> mb_core::CatalogSectorRecord {
    let signed = fixture.paged();
    let keys = &fixture.sources.keys[0];
    let mut anchored = None;
    control
        .publish_paged_revision_catalog_checked(bundle, bootstrap, |view| {
            for member in &bundle.roots[..2] {
                let mut reader =
                    mb_core::CatalogReader::new(bundle.scope, member.intent.section, member.root)?;
                while reader
                    .next_leaf(&mut |page| {
                        let bytes = view.catalog_page(member.intent.section, page)?;
                        let (sector, encrypted) = page.seal_private_page(
                            &keys.guild_content_id_key(&signed.value.guild_id),
                            &keys.guild_data_key(&signed.value.guild_id),
                            bundle.scope,
                            member.intent.section,
                            &bytes,
                        )?;
                        let record = mb_core::CatalogSectorRecord {
                            format_version: 1,
                            sector,
                            commitment: mb_core::merkle_commit(&encrypted).unwrap(),
                        };
                        view.bind_private_page_source(member.intent, page, &record)?;
                        if anchored.is_none() {
                            // Exercise the real durable anchor transfer/cleanup path;
                            // this store-only opaque recipe is not physical-byte proof.
                            view.bind_data_source(&record, anchor, b"test anchor recipe")?;
                            anchored = Some(record);
                        }
                        Ok::<_, CatalogStoreError>(bytes)
                    })
                    .map_err(|error| match error {
                        mb_core::CatalogStreamError::Catalog(error) => {
                            CatalogStoreError::from(error)
                        }
                        mb_core::CatalogStreamError::Storage(error) => error,
                    })?
                    .is_some()
                {}
            }
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
    anchored.unwrap()
}

fn retain(
    control: &ControlStore,
    id: Uuid,
    proof: &CatalogQuorumPagedCheckpointIndex,
    key: CatalogCheckpointRevisionKey,
) -> Result<PagedCatalogSnapshot, CatalogStoreError> {
    control.retain_catalog_paged_checkpoint_revision_checked(
        id,
        proof,
        key,
        || Ok(proof.trust().clone()),
        |_| Ok(()),
    )
}

#[test]
fn checkpoint_private_dependency_preserves_bootstrap_pages_and_anchor_across_sharing_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (mut fixture, history, bundle, bootstrap) = private_checkpoint(&control);
    let anchor = Uuid::from_u128(500);
    let data = publish_private(&control, &fixture, &bundle, &bootstrap, anchor);
    let proof = private_proof(&mut fixture, &history);
    let (captures, _) =
        super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &proof, 1000);
    let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
    let key = CatalogCheckpointRevisionKey::from(&fixture.paged().value);
    let snapshot = control.paged_revision_catalog(bundle.id).unwrap().unwrap();
    for id in ids {
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .unwrap();
        assert_eq!(retain(&control, id, &proof, key).unwrap(), snapshot);
        assert_eq!(retain(&control, id, &proof, key).unwrap(), snapshot);
    }
    for capture in captures {
        control.cancel_catalog(capture).unwrap();
        while control.release_catalog_pin(capture).unwrap() {}
    }
    while control.collect_catalog_page().unwrap() {}
    assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
    assert!(control.cancel_catalog_bundle(bundle.id).is_err());
    assert!(
        control
            .release_paged_revision_data_source(bundle.id)
            .is_err()
    );
    assert!(
        control
            .release_paged_revision_page_source(bundle.id)
            .is_err()
    );
    // Replacement remains allowed: it atomically transfers existing physical
    // custody without changing the checkpoint's authenticated private bundle.
    let source = control
        .paged_revision_data_source(bundle.id, data.sector.id)
        .unwrap()
        .unwrap();
    let replacement = Uuid::from_u128(501);
    control
        .replace_paged_revision_data_source_checked(
            &source,
            replacement,
            b"replacement recipe",
            |_| Ok::<_, CatalogStoreError>(()),
        )
        .unwrap();
    assert!(!control.paged_data_anchor_is_pinned(anchor).unwrap());
    drop(control);
    let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    assert!(control.paged_data_anchor_is_pinned(replacement).unwrap());
    assert_eq!(
        control
            .catalog_paged_checkpoint_revision(ids[0], bundle.id)
            .unwrap(),
        Some(snapshot.clone())
    );
    assert_eq!(
        control
            .paged_revision_bootstrap_catalog(fixture.paged().value.metadata.sector.id)
            .unwrap(),
        Some(snapshot.clone())
    );
    for member in &bundle.roots {
        assert!(
            control
                .catalog_page(bundle.scope, member.intent.section, member.root)
                .is_ok()
        );
    }
    control
        .cancel_catalog_paged_checkpoint_retention(ids[0])
        .unwrap();
    assert!(
        control
            .release_catalog_paged_checkpoint_root(ids[0])
            .unwrap()
    );
    assert!(
        control
            .catalog_paged_checkpoint_revision(ids[0], bundle.id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .catalog_paged_checkpoint_certificate(ids[0])
            .unwrap()
            .is_some()
    );
    while control
        .release_catalog_paged_checkpoint_root(ids[0])
        .unwrap()
    {}
    assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
    assert_eq!(
        control
            .catalog_paged_checkpoint_revision(ids[1], bundle.id)
            .unwrap(),
        Some(snapshot)
    );
    control
        .cancel_catalog_paged_checkpoint_retention(ids[1])
        .unwrap();
    while control
        .release_catalog_paged_checkpoint_root(ids[1])
        .unwrap()
    {}
    assert!(retain(&control, ids[1], &proof, key).is_err());
    control.cancel_paged_revision_catalog(bundle.id).unwrap();
    assert!(
        control
            .paged_revision_bootstrap_catalog(fixture.paged().value.metadata.sector.id)
            .unwrap()
            .is_none()
    );
    assert!(control.paged_data_anchor_is_pinned(replacement).unwrap());
    while control
        .release_paged_revision_data_source(bundle.id)
        .unwrap()
    {}
    while control
        .release_paged_revision_page_source(bundle.id)
        .unwrap()
    {}
    assert!(!control.paged_data_anchor_is_pinned(replacement).unwrap());
}

#[test]
fn checkpoint_private_dependency_acquisition_rejects_stale_trust_forged_membership_and_pin_faults()
{
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (mut fixture, history, bundle, bootstrap) = private_checkpoint(&control);
    publish_private(
        &control,
        &fixture,
        &bundle,
        &bootstrap,
        Uuid::from_u128(500),
    );
    let proof = private_proof(&mut fixture, &history);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &proof, 1000);
    let id = Uuid::from_u128(1);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    let key = CatalogCheckpointRevisionKey::from(&fixture.paged().value);
    let forward = format!("catalog-checkpoint-private-revision-v1/{}", id.simple());
    let reverse = format!(
        "catalog-private-revision-checkpoint-v1/{}",
        bundle.id.simple()
    );
    let totals = "catalog-checkpoint-private-work-v1";
    let absent = || {
        assert!(
            control
                .catalog_paged_checkpoint_revision(id, bundle.id)
                .unwrap()
                .is_none()
        );
        assert!(control.get_record(totals, id.as_bytes()).unwrap().is_none());
    };
    let mut missing = key;
    missing.sequence += 1;
    assert!(retain(&control, id, &proof, missing).is_err());
    assert!(
        control
            .retain_catalog_paged_checkpoint_revision_checked(
                id,
                &proof,
                key,
                || Ok(proof.trust().clone()),
                |_| Err::<(), _>(CatalogStoreError::from(DatabaseError::Conflict))
            )
            .is_err()
    );
    // Even a valid owner signature cannot replace the reference from the
    // completed original join under the same revision identity.
    let scratch = &proof.index().index().packing().store;
    let kind = super::super::super::checkpoint_validation::REVISIONS;
    let bytes = scratch
        .get_record_bounded(
            kind,
            &key.index_key(),
            mb_core::CATALOG_CHECKPOINT_RECORD_BYTES,
        )
        .unwrap()
        .unwrap();
    let mut changed = fixture.paged().value;
    changed.metadata.sector.root[0] ^= 1;
    let forged = changed
        .sign(&fixture.sources.writer, &fixture.sources.keys[0])
        .unwrap();
    let replacement = canonical_bytes(&R::PagedRevision(forged)).unwrap();
    scratch
        .replace_record_if_value(kind, &key.index_key(), &bytes, &replacement)
        .unwrap();
    assert!(retain(&control, id, &proof, key).is_err());
    scratch
        .replace_record_if_value(
            kind,
            &key.index_key(),
            &replacement,
            &vec![0; mb_core::CATALOG_CHECKPOINT_RECORD_BYTES + 1],
        )
        .unwrap();
    assert!(retain(&control, id, &proof, key).is_err());
    scratch
        .replace_record_if_value(
            kind,
            &key.index_key(),
            &vec![0; mb_core::CATALOG_CHECKPOINT_RECORD_BYTES + 1],
            &bytes,
        )
        .unwrap();
    absent();
    for kind in [&forward, &reverse, totals] {
        control.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_private_insert BEFORE INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END;"
        )).unwrap();
        assert!(retain(&control, id, &proof, key).is_err(), "{kind}");
        absent();
        control
            .connection
            .execute_batch("DROP TRIGGER fail_private_insert")
            .unwrap();
    }
    let changed = std::cell::Cell::new(false);
    let mut stale = proof.trust().clone();
    stale.event_head[0] ^= 1;
    assert!(
        control
            .retain_catalog_paged_checkpoint_revision_checked(
                id,
                &proof,
                key,
                || Ok(if changed.get() {
                    stale.clone()
                } else {
                    proof.trust().clone()
                }),
                |_| {
                    changed.set(true);
                    Ok::<_, CatalogStoreError>(())
                }
            )
            .is_err()
    );
    absent();
    let checkpoint = proof.certificate().checkpoint;
    control.connection.execute_batch(&format!(
        "CREATE TEMP TRIGGER change_private_head AFTER INSERT ON protocol_records WHEN NEW.kind = '{forward}' BEGIN INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'00'); END;",
        hex::encode(checkpoint.guild_id), hex::encode(checkpoint.hash().unwrap()),
    )).unwrap();
    assert!(retain(&control, id, &proof, key).is_err());
    assert!(
        control
            .checkpoint_head_identity(&checkpoint.guild_id)
            .unwrap()
            .is_none()
    );
    absent();
    control
        .connection
        .execute_batch("DROP TRIGGER change_private_head")
        .unwrap();
    let snapshot = retain(&control, id, &proof, key).unwrap();
    assert_eq!(
        control
            .catalog_paged_checkpoint_revision(id, bundle.id)
            .unwrap(),
        Some(snapshot)
    );
}

#[test]
fn checkpoint_private_dependency_retirement_fences_current_heads_and_rolls_back_each_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (mut fixture, history, bundle, bootstrap) = private_checkpoint(&control);
    publish_private(
        &control,
        &fixture,
        &bundle,
        &bootstrap,
        Uuid::from_u128(500),
    );
    let proof = private_proof(&mut fixture, &history);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &proof, 1000);
    let id = Uuid::from_u128(1);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    let key = CatalogCheckpointRevisionKey::from(&fixture.paged().value);
    let snapshot = retain(&control, id, &proof, key).unwrap();
    let forward = format!("catalog-checkpoint-private-revision-v1/{}", id.simple());
    let reverse = format!(
        "catalog-private-revision-checkpoint-v1/{}",
        bundle.id.simple()
    );
    let totals = "catalog-checkpoint-private-work-v1";
    let original_work = control.get_record(totals, id.as_bytes()).unwrap().unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    for (operation, kind) in [
        ("DELETE", forward.as_str()),
        ("DELETE", reverse.as_str()),
        ("UPDATE", totals),
    ] {
        control.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_private_release BEFORE {operation} ON protocol_records WHEN OLD.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END;"
        )).unwrap();
        assert!(
            control.release_catalog_paged_checkpoint_root(id).is_err(),
            "{kind}"
        );
        assert_eq!(
            control
                .catalog_paged_checkpoint_revision(id, bundle.id)
                .unwrap(),
            Some(snapshot.clone())
        );
        assert_eq!(
            control.get_record(totals, id.as_bytes()).unwrap(),
            Some(original_work.clone())
        );
        assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
        control
            .connection
            .execute_batch("DROP TRIGGER fail_private_release")
            .unwrap();
    }
    let certificate = proof.certificate().checkpoint;
    let activate = format!(
        "INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'00');",
        hex::encode(certificate.guild_id),
        hex::encode(certificate.hash().unwrap())
    );
    control.connection.execute_batch(&format!(
        "CREATE TEMP TRIGGER change_private_head AFTER DELETE ON protocol_records WHEN OLD.kind = '{forward}' BEGIN {activate} END;"
    )).unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    assert!(
        control
            .checkpoint_head_identity(&certificate.guild_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_revision(id, bundle.id)
            .unwrap(),
        Some(snapshot.clone())
    );
    control
        .connection
        .execute_batch("DROP TRIGGER change_private_head")
        .unwrap();
    control.connection.execute_batch(&activate).unwrap();
    drop(control);
    let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
    assert_eq!(
        control
            .catalog_paged_checkpoint_revision(id, bundle.id)
            .unwrap(),
        Some(snapshot)
    );
    control
        .connection
        .execute(
            "DELETE FROM checkpoint_heads WHERE guild_id = ?1",
            params![certificate.guild_id],
        )
        .unwrap();
    // Oversized or one-sided dependency rows and counter damage never release
    // custody or get silently repaired by an idempotent retry.
    let bytes = control
        .get_record(&reverse, id.as_bytes())
        .unwrap()
        .unwrap();
    control.delete_record(&reverse, id.as_bytes()).unwrap();
    assert!(
        control
            .catalog_paged_checkpoint_revision(id, bundle.id)
            .is_err()
    );
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    control
        .put_record(&reverse, id.as_bytes(), &[0; 129])
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    control.put_record(&reverse, id.as_bytes(), &bytes).unwrap();
    control
        .put_record(totals, id.as_bytes(), &[0; 129])
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    control
        .put_record(totals, id.as_bytes(), &original_work)
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).unwrap());
    assert!(
        control
            .catalog_paged_checkpoint_revision(id, bundle.id)
            .unwrap()
            .is_none()
    );
    control.cancel_paged_revision_catalog(bundle.id).unwrap();
    while control.release_catalog_paged_checkpoint_root(id).unwrap() {}
}

#[test]
fn checkpoint_private_dependency_debits_the_enclosing_proof_budget() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (mut fixture, history, bundle, bootstrap) = private_checkpoint(&control);
    publish_private(
        &control,
        &fixture,
        &bundle,
        &bootstrap,
        Uuid::from_u128(500),
    );
    let proof = private_proof(&mut fixture, &history);
    let minimum = proof
        .transition()
        .represented_work()
        .checked_add(proof.certificate().checkpoint.represented_work().unwrap())
        .unwrap();
    let limited = private_proof_with_budget(&mut fixture, &history, minimum);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &limited, 1000);
    let id = Uuid::from_u128(1);
    control
        .retain_catalog_paged_checkpoint(id, &limited, || Ok(limited.trust().clone()))
        .unwrap();
    let key = CatalogCheckpointRevisionKey::from(&fixture.paged().value);
    assert!(retain(&control, id, &limited, key).is_err());
    assert!(
        control
            .catalog_paged_checkpoint_revision(id, bundle.id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .get_record("catalog-checkpoint-private-work-v1", id.as_bytes())
            .unwrap()
            .is_none()
    );
}

#[test]
fn checkpoint_private_dependency_budget_accumulates_across_retained_revisions() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (mut fixture, history, first, bootstrap) = private_checkpoint(&control);
    let original = fixture.paged();
    let (second, second_bootstrap) =
        super::super::super::paged_revision::tests::fixture_with_context(
            &control,
            2,
            Some(original.value.hash().unwrap()),
            &fixture.sources.keys[0],
            &fixture.sources.writer,
            original.value.scope(),
        );
    let successor = mb_core::PagedUserRevision::decode_signed(&second.descriptor).unwrap();
    // Identical private content still represents two separately retained
    // revisions, each with its own immutable bundle and dependency work.
    assert_eq!(original.value.sources, successor.value.sources);
    assert_eq!(bootstrap, second_bootstrap);
    publish_private(&control, &fixture, &first, &bootstrap, Uuid::from_u128(500));
    publish_private(
        &control,
        &fixture,
        &second,
        &second_bootstrap,
        Uuid::from_u128(500),
    );
    fixture.records.push(R::PagedRevision(successor.clone()));
    let proof = private_proof(&mut fixture, &history);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &proof, 1000);
    let id = Uuid::from_u128(1);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    let first_key = CatalogCheckpointRevisionKey::from(&original.value);
    let second_key = CatalogCheckpointRevisionKey::from(&successor.value);
    let totals = "catalog-checkpoint-private-work-v1";
    retain(&control, id, &proof, first_key).unwrap();
    let first_work: Work =
        decode_canonical(&control.get_record(totals, id.as_bytes()).unwrap().unwrap()).unwrap();
    retain(&control, id, &proof, second_key).unwrap();
    let combined: Work =
        decode_canonical(&control.get_record(totals, id.as_bytes()).unwrap().unwrap()).unwrap();
    assert_eq!(combined, first_work.checked_add(first_work).unwrap());
    let public = proof
        .transition()
        .represented_work()
        .checked_add(proof.certificate().checkpoint.represented_work().unwrap())
        .unwrap();
    let limited = private_proof_with_budget(
        &mut fixture,
        &history,
        public.checked_add(first_work).unwrap(),
    );
    let limited_id = Uuid::from_u128(2);
    control
        .retain_catalog_paged_checkpoint(limited_id, &limited, || Ok(limited.trust().clone()))
        .unwrap();
    retain(&control, limited_id, &limited, first_key).unwrap();
    assert!(retain(&control, limited_id, &limited, second_key).is_err());
    assert!(
        control
            .catalog_paged_checkpoint_revision(limited_id, second.id)
            .unwrap()
            .is_none()
    );
    let kept: Work = decode_canonical(
        &control
            .get_record(totals, limited_id.as_bytes())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(kept, first_work);
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).unwrap());
    let left = [first.id, second.id]
        .into_iter()
        .filter(|revision| {
            control
                .catalog_paged_checkpoint_revision(id, *revision)
                .unwrap()
                .is_some()
        })
        .count();
    assert_eq!(left, 1);
    assert!(control.release_catalog_paged_checkpoint_root(id).unwrap());
    assert!([first.id, second.id].into_iter().all(|revision| {
        control
            .catalog_paged_checkpoint_revision(id, revision)
            .unwrap()
            .is_none()
    }));
    while control.release_catalog_paged_checkpoint_root(id).unwrap() {}
    assert!(control.cancel_paged_revision_catalog(first.id).is_err());
    control.cancel_paged_revision_catalog(second.id).unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(limited_id)
        .unwrap();
    while control
        .release_catalog_paged_checkpoint_root(limited_id)
        .unwrap()
    {}
    control.cancel_paged_revision_catalog(first.id).unwrap();
}

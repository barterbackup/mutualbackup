use super::*;
use mb_core::{
    CatalogFileEvent, CatalogNativeFileReader, CatalogSection, CatalogSectorBuilder, CodingProfile,
    PackingProfile, PagedUserRevision, Seed, WriterFence,
};
use mb_store::{
    CatalogIntent, CatalogIntentState, CatalogPageReservation, CatalogPublishedRevisionQuota,
    CatalogPublishedRevisionQuotas, CatalogRetainedSourceQuota, CatalogStorageQuota,
    StableAnchorAreaLocator,
};
use uuid::Uuid;

fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([203; 32]))
}
fn scope() -> CatalogScope {
    CatalogScope::Dataset {
        guild_id: [204; 32],
        owner: keys().node_id(),
        protected_root_id: Uuid::from_u128(205),
    }
}
fn policy() -> CatalogCapacityPolicy {
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 2,
        legacy_revisions: 0,
        legacy_source_occurrences: 0,
        data_bytes_per_dataset: 512 * V1_SECTOR_SIZE as u64,
        data_sources_per_dataset: 512,
        private_work_per_revision: Work {
            bytes: 2 * 1024 * 1024,
            page_occurrences: 64,
            records: 500_000,
        },
        source_pages_per_revision: 64,
        authority_control_records: 257,
        packing_profile: PackingProfile {
            format_version: 1,
            sector_size: V1_SECTOR_SIZE as u32,
            slot_size: (V1_SECTOR_SIZE / 4) as u32,
        },
        coding_profile: CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32),
        packed_sectors: 856,
        coding_groups: 286,
        replay_work: Work::default(),
    }
}
fn manifest(entries: Vec<CapturedEntry>) -> StableAnchorManifest {
    StableAnchorManifest {
        format_version: 2,
        anchor_id: Uuid::from_u128(206),
        source_root_hint: "/missing/source".into(),
        area: StableAnchorAreaLocator {
            area_id: Uuid::from_u128(207),
            path_hint: "/missing/area".into(),
            filesystem_id: 208,
            volume_root_hint: "/missing".into(),
        },
        root_mode: 0o750,
        root_modified_secs: -7,
        root_modified_nanos: 9,
        entries,
    }
}
fn file(path: &str, logical_len: u64, data_extents: Vec<FileExtent>) -> CapturedEntry {
    CapturedEntry::FileV2 {
        path: path.into(),
        mode: 0o640,
        logical_len,
        modified_secs: -11,
        modified_nanos: 13,
        native_id: NativeFileId {
            filesystem_id: 1,
            inode: 2,
        },
        data_extents,
    }
}

#[test]
fn native_anchor_admission_derives_dense_one_tib_recipes_without_payloads_or_sector_vectors() {
    let mut p = policy();
    p.revisions_per_dataset = 1;
    p.data_bytes_per_dataset = 1 << 40;
    p.data_sources_per_dataset = (1 << 40) / V1_SECTOR_SIZE as u64;
    p.private_work_per_revision = Work {
        bytes: 2 << 30,
        page_occurrences: 40_000,
        records: 5 * CATALOG_MAX_RECORDS,
    };
    p.source_pages_per_revision = CATALOG_MAX_PAGE_OCCURRENCES - 40_000;
    p.packed_sectors = 22_422_956;
    p.coding_groups = 7_474_319;
    let m = manifest(vec![file(
        "dense",
        1 << 40,
        vec![FileExtent {
            offset: 0,
            logical_len: 1 << 40,
        }],
    )]);
    let a = NativeCatalogAdmission::for_anchor(&m, scope(), p).unwrap();
    assert_eq!(a.data_occurrences, 16_777_216);
    assert_eq!(a.data_occurrence_bytes, 1 << 40);
    assert!(a.native_work.bytes > 1 << 30);
    assert!(a.native_work.bytes < p.private_work_per_revision.bytes);
    assert!(a.native_work.page_occurrences > 20_000);
    assert!(a.native_work.page_occurrences < 40_000);
    let mut missing_recipe = p;
    missing_recipe.private_work_per_revision.bytes = 1 << 30;
    assert!(NativeCatalogAdmission::for_anchor(&m, scope(), missing_recipe).is_err());
}

#[test]
fn native_anchor_admission_counts_sparse_occurrences_and_hard_links_separately_from_unique_data() {
    let mut m = manifest(vec![file(
        "z-primary",
        1 << 40,
        vec![FileExtent {
            offset: (1 << 40) - 3,
            logical_len: 3,
        }],
    )]);
    let mut alias = m.entries[0].clone();
    if let CapturedEntry::FileV2 { path, .. } = &mut alias {
        *path = "a-alias".into();
    }
    m.entries.push(alias);
    let a = NativeCatalogAdmission::for_anchor(&m, scope(), policy()).unwrap();
    assert_eq!(a.data_occurrences, 1);
    assert_eq!(a.data_occurrence_bytes, 3);
    assert_eq!(a.native_work.page_occurrences, 2);
    // Distinct native files may repeat the same content. Preflight keeps
    // occurrence bounds; actual signed IDs are charged by the source ledger.
    let mut other = m.entries[0].clone();
    if let CapturedEntry::FileV2 {
        path, native_id, ..
    } = &mut other
    {
        *path = "other".into();
        native_id.inode += 1;
    }
    m.entries.push(other);
    assert_eq!(
        NativeCatalogAdmission::for_anchor(&m, scope(), policy())
            .unwrap()
            .data_occurrences,
        2
    );
}

#[test]
fn native_anchor_preflight_refuses_bad_geometry_before_source_io_or_sink_callbacks() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[209; 32]).unwrap();
    let valid = manifest(vec![file(
        "file",
        8,
        vec![FileExtent {
            offset: 1,
            logical_len: 3,
        }],
    )]);
    let mut cases = Vec::new();
    let mut bad = valid.clone();
    bad.root_modified_nanos = 1_000_000_000;
    cases.push(bad);
    let mut bad = valid.clone();
    if let CapturedEntry::FileV2 { path, .. } = &mut bad.entries[0] {
        *path = "../escape".into();
    }
    cases.push(bad);
    let mut bad = valid.clone();
    if let CapturedEntry::FileV2 { data_extents, .. } = &mut bad.entries[0] {
        data_extents.push(FileExtent {
            offset: 2,
            logical_len: 2,
        });
    }
    cases.push(bad);
    let mut bad = valid.clone();
    if let CapturedEntry::FileV2 { data_extents, .. } = &mut bad.entries[0] {
        data_extents[0].logical_len = u64::MAX;
    }
    cases.push(bad);
    let mut bad = valid.clone();
    let mut alias = bad.entries[0].clone();
    if let CapturedEntry::FileV2 {
        path, logical_len, ..
    } = &mut alias
    {
        *path = "alias".into();
        *logical_len += 1;
    }
    bad.entries.push(alias);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entries.push(bad.entries[0].clone());
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entries = vec![bad.entries[0].clone(); 8193];
    cases.push(bad);
    let mut bad = valid.clone();
    bad.format_version = 4;
    cases.push(bad);
    for bad in cases {
        let mut pages = 0;
        let mut sources = 0;
        let error = PagedPrivateMetadata::write_native_anchor_catalog(
            &control,
            &keys(),
            scope(),
            policy(),
            &bad,
            &mut |_, _, _| {
                pages += 1;
                Ok(())
            },
            &mut |_, _| {
                sources += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!error.to_string().contains("No such file"), "{error:#}");
        assert_eq!((pages, sources), (0, 0));
    }
    let mut small = policy();
    small.private_work_per_revision = Work {
        bytes: 16,
        page_occurrences: 2,
        records: 0,
    };
    let mut callbacks = 0;
    assert!(
        PagedPrivateMetadata::write_native_anchor_catalog(
            &control,
            &keys(),
            scope(),
            small,
            &valid,
            &mut |_, _, _| {
                callbacks += 1;
                Ok(())
            },
            &mut |_, _| panic!("no payload callback before admission")
        )
        .is_err()
    );
    assert_eq!(callbacks, 0);
}

#[test]
fn native_anchor_encoder_preserves_order_empty_files_and_eof_and_propagates_sink_failure() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[210; 32]).unwrap();
    let m = manifest(vec![
        CapturedEntry::File {
            path: "dir/empty".into(),
            mode: 0o640,
            logical_len: 0,
            modified_secs: -5,
            modified_nanos: 7,
        },
        CapturedEntry::Directory {
            path: "dir".into(),
            mode: 0o750,
            modified_secs: -2,
            modified_nanos: 3,
        },
    ]);
    let mut pages = BTreeMap::new();
    let root = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        policy(),
        &m,
        &mut |_, page, bytes| {
            pages.insert(page.hash, bytes);
            Ok(())
        },
        &mut |_, _| panic!("empty file has no data source"),
    )
    .unwrap();
    let a = NativeCatalogAdmission::for_anchor(&m, scope(), policy()).unwrap();
    assert!(root.page_roots().iter().map(|p| p.byte_len).sum::<u64>() <= a.native_work.bytes);
    assert_eq!(root.namespace.root_stat.modified_secs, -7);
    let mut reader = CatalogNativeFileReader::new(scope(), root).unwrap();
    let mut fetch = |page: CatalogPageRef| Ok::<_, anyhow::Error>(pages[&page.hash].clone());
    assert!(
        matches!(reader.next_event(&mut fetch).unwrap(), Some(CatalogFileEvent::Entry(e)) if e.path == b"dir")
    );
    assert!(
        matches!(reader.next_event(&mut fetch).unwrap(), Some(CatalogFileEvent::Entry(e)) if e.path == b"dir/empty")
    );
    assert!(matches!(
        reader.next_event(&mut fetch).unwrap(),
        Some(CatalogFileEvent::Recipe(CatalogFileRecipeRecord::File {
            sectors: 0,
            ..
        }))
    ));
    assert!(reader.next_event(&mut fetch).unwrap().is_none());
    let mut calls = 0;
    let error = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        policy(),
        &m,
        &mut |_, _, _| {
            calls += 1;
            anyhow::bail!("injected private sink refusal")
        },
        &mut |_, _| panic!("empty data"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected private sink refusal"));
    assert_eq!(calls, 1);
}

#[test]
fn native_anchor_encoder_rechecks_the_original_enrolled_contract_after_its_last_callback() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[214; 32]).unwrap();
    let p = policy();
    let q = CatalogPublishedRevisionQuota {
        revisions: 100,
        work: p.plan().unwrap().retained_revision_work,
    };
    let mut usage = control
        .begin_catalog_published_revision_quota_adoption(CatalogPublishedRevisionQuotas {
            global: q,
            dataset: q,
            guild: q,
        })
        .unwrap();
    while usage.state == mb_store::CatalogPublishedRevisionQuotaState::Adopting {
        usage = control
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
    let data = CatalogRetainedSourceQuota {
        logical_bytes: p.data_bytes_per_dataset,
        sources: p.data_sources_per_dataset,
        open_reservations: 8,
    };
    control
        .configure_catalog_retained_source_quota(data)
        .unwrap();
    control
        .configure_catalog_retained_source_guild_quota(data)
        .unwrap();
    control.configure_catalog_capacity_policy(p).unwrap();
    let m = manifest(vec![]);
    let mut other = p;
    other.revisions_per_dataset = 1;
    let mut calls = 0;
    let error = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        other,
        &m,
        &mut |_, _, _| {
            calls += 1;
            Ok(())
        },
        &mut |_, _| panic!("no data"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("enrolled capacity contract"));
    assert_eq!(calls, 0);
    let error = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        p,
        &m,
        &mut |_, _, _| {
            calls += 1;
            if calls == 2 {
                control.put_record("catalog-capacity-policy-v1", b"store", b"broken")?;
            }
            Ok(())
        },
        &mut |_, _| panic!("no data"),
    )
    .unwrap_err();
    assert_eq!(calls, 2);
    assert!(
        matches!(
            error.downcast_ref::<mb_store::CatalogStoreError>(),
            Some(mb_store::CatalogStoreError::Database(
                mb_store::DatabaseError::Integrity
            ))
        ),
        "{error:#}"
    );
    assert!(
        control
            .records("catalog-paged-publication-v1")
            .unwrap()
            .is_empty()
    );
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn native_anchor_produces_and_restores_paged_catalog_without_a_flat_revision() {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").expect("provisioned Btrfs root");
    let temp = tempfile::tempdir_in(root).unwrap();
    let source = temp.path().join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    let dense: Vec<u8> = (0..145)
        .flat_map(|n| {
            let mut b = vec![n as u8; V1_SECTOR_SIZE];
            b[..8].copy_from_slice(&(n as u64).to_le_bytes());
            b
        })
        .collect();
    std::fs::write(source.join("nested/dense"), &dense).unwrap();
    std::fs::hard_link(source.join("nested/dense"), source.join("linked")).unwrap();
    let mut sparse = std::fs::File::create(source.join("nested/sparse")).unwrap();
    sparse.set_len(1 << 40).unwrap();
    sparse.seek(SeekFrom::Start((1 << 40) - 4096)).unwrap();
    sparse.write_all(b"tail\r\n\0").unwrap();
    sparse.sync_all().unwrap();
    drop(sparse);
    std::fs::write(source.join("empty"), []).unwrap();
    let manifest = mb_store::ReflinkAnchor::capture(&source).unwrap();
    let path = temp.path().join("control.db");
    let mut control = ControlStore::open_with_key(&path, &[211; 32]).unwrap();
    let mut record_usage = control
        .begin_record_quota_adoption(mb_store::DatabaseRecordQuota {
            max_rows: 100_000,
            max_accounted_bytes: 1 << 30,
        })
        .unwrap();
    while record_usage.state == mb_store::DatabaseRecordQuotaState::Adopting {
        record_usage = control.resume_record_quota_adoption().unwrap();
    }
    control
        .configure_page_quota(mb_store::DatabasePageQuota { max_pages: 262_144 })
        .unwrap();
    control
        .configure_journal_quota(mb_store::DatabaseJournalQuota { max_bytes: 1 << 30 })
        .unwrap();
    let p = policy();
    let plan = p.plan().unwrap();
    let q = CatalogPublishedRevisionQuota {
        revisions: 100,
        work: Work {
            bytes: plan.retained_revision_work.bytes,
            page_occurrences: plan.retained_revision_work.page_occurrences,
            records: plan.retained_revision_work.records,
        },
    };
    let mut revision_usage = control
        .begin_catalog_published_revision_quota_adoption(CatalogPublishedRevisionQuotas {
            global: q,
            dataset: q,
            guild: q,
        })
        .unwrap();
    while revision_usage.state == mb_store::CatalogPublishedRevisionQuotaState::Adopting {
        revision_usage = control
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
    let data = CatalogRetainedSourceQuota {
        logical_bytes: p.data_bytes_per_dataset,
        sources: p.data_sources_per_dataset,
        open_reservations: 8,
    };
    control
        .configure_catalog_retained_source_quota(data)
        .unwrap();
    control
        .configure_catalog_retained_source_guild_quota(data)
        .unwrap();
    control.configure_catalog_capacity_policy(p).unwrap();
    let storage = CatalogStorageQuota {
        page_bytes: 64 * 1024 * 512,
        pages: 512,
        open_reservations: 8,
    };
    control.configure_catalog_storage_quota(storage).unwrap();
    control
        .configure_catalog_scoped_storage_quotas(storage, storage)
        .unwrap();
    let intents: [CatalogIntent; 3] = std::array::from_fn(|n| CatalogIntent {
        id: Uuid::from_u128(220 + n as u128),
        scope: scope(),
        section: if n == 2 {
            CatalogSection::SectorReferences
        } else {
            CatalogSection::FileMetadata
        },
    });
    let requests: Vec<_> = intents
        .iter()
        .map(|i| {
            (
                *i,
                CatalogPageReservation {
                    page_bytes: 64 * 65536,
                    pages: 64,
                },
            )
        })
        .collect();
    control
        .with_catalog_page_reservations(&requests, |states| -> Result<()> {
            assert!(states.iter().all(|s| *s == CatalogIntentState::Building));
            Ok(())
        })
        .unwrap();
    let mut data_calls = 0;
    let mut page_calls = 0;
    let error = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        p,
        &manifest,
        &mut |_, _, _| {
            page_calls += 1;
            Ok(())
        },
        &mut |_, _| {
            data_calls += 1;
            if data_calls == 7 {
                anyhow::bail!("injected data sink refusal");
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected data sink refusal"));
    assert_eq!(data_calls, 7);
    assert_eq!(page_calls, 0);
    data_calls = 0;
    let error = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        p,
        &manifest,
        &mut |_, _, _| {
            page_calls += 1;
            anyhow::bail!("injected private page refusal")
        },
        &mut |_, _| {
            data_calls += 1;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected private page refusal"));
    assert_eq!(page_calls, 1);
    assert!(data_calls > CATALOG_FILE_SECTOR_REFS);
    assert!(
        control
            .paged_revision_catalog(Uuid::from_u128(213))
            .unwrap()
            .is_none()
    );
    let mut sources = BTreeMap::<[u8; 32], CatalogSectorRecord>::new();
    let mut recipes = BTreeMap::<[u8; 32], PagedAnchorSectorSource>::new();
    let native = PagedPrivateMetadata::write_native_anchor_catalog(
        &control,
        &keys(),
        scope(),
        p,
        &manifest,
        &mut |stream, page, bytes| {
            control.stage_catalog_page(intents[stream.index()], page, &bytes)?;
            Ok(())
        },
        &mut |record, anchor| {
            sources.insert(record.sector.id, record.clone());
            recipes.entry(record.sector.id).or_insert(anchor);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(native.namespace.hard_links, 1);
    assert!(native.recipes.sectors > CATALOG_FILE_SECTOR_REFS as u64);
    let private = PagedPrivateMetadata {
        format_version: mb_core::PAGED_USER_REVISION_VERSION,
        native,
        git: None,
    };
    // Seal/index each owned private page, including internal index nodes.
    for role in &intents[..2] {
        let page_root = native.page_roots()[if *role == intents[0] { 0 } else { 1 }];
        let mut reader =
            mb_core::CatalogReader::new(scope(), CatalogSection::FileMetadata, page_root).unwrap();
        while reader
            .next_leaf(&mut |page: CatalogPageRef| -> Result<Vec<u8>> {
                let bytes = control.catalog_page(scope(), CatalogSection::FileMetadata, page)?;
                let (sector, ciphertext) = page.seal_private_page(
                    &keys().guild_content_id_key(&[204; 32]),
                    &keys().guild_data_key(&[204; 32]),
                    scope(),
                    CatalogSection::FileMetadata,
                    &bytes,
                )?;
                sources.insert(
                    sector.id,
                    CatalogSectorRecord {
                        format_version: 1,
                        sector,
                        commitment: merkle_commit(&ciphertext)?,
                    },
                );
                Ok(bytes)
            })
            .unwrap()
            .is_some()
        {}
    }
    let (metadata, _) = private.seal(&keys(), scope()).unwrap();
    sources.insert(metadata.sector.id, metadata.clone());
    let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
    for record in sources.values() {
        builder
            .push(record, &mut |page, bytes| {
                control.stage_catalog_page(intents[2], page, &bytes)
            })
            .unwrap();
    }
    let sources_root = builder
        .finish(&mut |page, bytes| control.stage_catalog_page(intents[2], page, &bytes))
        .unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[212; 32]);
    let fence = WriterFence {
        owner: keys().node_id(),
        epoch: 1,
        public_key: signing.verifying_key().to_bytes(),
    };
    let signed = PagedUserRevision {
        format_version: mb_core::PAGED_USER_REVISION_VERSION,
        guild_id: [204; 32],
        protected_root_id: Uuid::from_u128(205),
        cipher_profile: mb_core::V1_CIPHER_PROFILE,
        revision_id: Uuid::from_u128(213),
        owner: keys().node_id(),
        writer_epoch: 1,
        writer_public_key: fence.public_key,
        writer_signature: vec![],
        sequence: 1,
        parent: None,
        metadata,
        sources: sources_root,
    }
    .sign(&signing, &keys())
    .unwrap();
    control
        .with_record_transaction(|| -> Result<()> {
            control.reserve_catalog_retained_sources_with_dependencies_in_transaction(
                signed.value.revision_id,
                scope(),
                || {
                    sources
                        .values()
                        .filter(|r| recipes.contains_key(&r.sector.id))
                        .cloned()
                        .map(Ok)
                },
            )?;
            Ok(())
        })
        .unwrap();
    private
        .publish_local_catalog_with_data_sources(
            &control,
            &keys(),
            &signed,
            &fence,
            crate::PagedCatalogIntents {
                native: [intents[0], intents[1]],
                sources: intents[2],
                git: None,
            },
            |r| Ok(recipes.get(&r.sector.id).cloned()),
        )
        .unwrap();
    assert!(control.records("user-revision").unwrap().is_empty());
    assert!(control.records("user-revision-head").unwrap().is_empty());
    std::fs::write(source.join("nested/dense"), b"changed working bytes").unwrap();
    let before = mb_core::canonical_bytes(&signed).unwrap();
    drop(control);
    let control = ControlStore::open_with_key(&path, &[211; 32]).unwrap();
    let snapshot = PagedPrivateMetadata::load_local_catalog(
        &control,
        &keys(),
        signed.value.revision_id,
        scope(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        mb_core::canonical_bytes(&snapshot.revision).unwrap(),
        before
    );
    let target = temp.path().join("restored");
    PagedPrivateMetadata::restore_retained_native_catalog(
        &control,
        &keys(),
        signed.value.revision_id,
        scope(),
        &target,
        |id| crate::snapshot::render_sector(&control, &keys(), id, Some(&[204; 32])),
    )
    .unwrap();
    assert_eq!(std::fs::read(target.join("nested/dense")).unwrap(), dense);
    assert_eq!(
        std::fs::metadata(target.join("linked")).unwrap().ino(),
        std::fs::metadata(target.join("nested/dense"))
            .unwrap()
            .ino()
    );
    assert_eq!(
        std::fs::metadata(target.join("nested/sparse"))
            .unwrap()
            .len(),
        1 << 40
    );
    let mut sparse = std::fs::File::open(target.join("nested/sparse")).unwrap();
    sparse.seek(SeekFrom::Start((1 << 40) - 4096)).unwrap();
    let mut tail = [0; 7];
    sparse.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"tail\r\n\0");
    assert!(control.records("user-revision").unwrap().is_empty());
    assert!(control.records("user-revision-head").unwrap().is_empty());
}

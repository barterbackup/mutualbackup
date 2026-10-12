use super::*;

fn retired_fixture() -> (Fixture, SignedRecord<PagedUserRevision>, Pages) {
    let mut fixture = Fixture::new(true, false);
    let original = fixture.certificate.checkpoint.revisions[0].clone();
    let parent = fixture.certificate.hash().unwrap();
    let mut retained = original.value.clone();
    retained.sequence += 1;
    retained.parent = Some(original.value.hash().unwrap());
    retained.revision_id = Uuid::from_u128(200);
    retained.sign_writer(&fixture.writer).unwrap();
    let retained = SignedRecord::sign(USER_REVISION_DOMAIN, retained, &fixture.keys[0]).unwrap();
    fixture.certificate.checkpoint.generation = 2;
    fixture.certificate.checkpoint.parent = Some(parent);
    fixture.certificate.checkpoint.revisions = vec![retained];
    fixture
        .certificate
        .checkpoint
        .revision_tombstones
        .push(mb_core::RevisionTombstone {
            owner: original.value.owner,
            protected_root_id: original.value.protected_root_id,
            through_sequence: original.value.sequence,
            last_revision_id: original.value.revision_id,
            last_revision_hash: original.value.hash().unwrap(),
            retired_at_generation: 2,
        });
    fixture.resign();
    let (next, pages) = fixture.candidate(&fixture.records);
    (fixture, next, pages)
}

#[test]
fn source_authority_retired_root_rejects_restart_and_reserved_uuid_before_fetch() {
    let (fixture, next, _) = retired_fixture();
    for fault in 0..3 {
        let mut value = next.value.clone();
        match fault {
            0 => {
                value.sequence = 1;
                value.parent = None;
            }
            1 => value.parent = Some([234; 32]),
            _ => {
                value.revision_id =
                    fixture.certificate.checkpoint.revision_tombstones[0].last_revision_id
            }
        }
        let signed = value.sign(&fixture.writer, &fixture.keys[0]).unwrap();
        assert!(
            fixture
                .authority()
                .with_paged_revision(&signed, |_| {
                    panic!("invalid retired-root continuation fetched source pages")
                })
                .is_err()
        );
    }
}

#[test]
fn source_authority_retired_root_preserves_exact_continuation_and_all_reserved_ids() {
    let (fixture, next, pages) = retired_fixture();
    let job = fixture
        .authority()
        .with_paged_revision(&next, |page| {
            pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    assert_eq!(job.candidates, 1);
    assert_eq!(job.sources, 2);
    let mut third = next.value.clone();
    third.sequence += 1;
    third.parent = Some(next.value.hash().unwrap());
    third.revision_id = Uuid::from_u128(9000);
    let third = third.sign(&fixture.writer, &fixture.keys[0]).unwrap();
    let job = job
        .with_paged_revision(&third, |page| {
            pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    assert_eq!(job.candidates, 2);
    assert_eq!(job.sources, 2);
    for id in [
        fixture.certificate.checkpoint.revision_tombstones[0].last_revision_id,
        next.value.revision_id,
        third.value.revision_id,
    ] {
        assert_eq!(
            read::<bool>(&job.store, IDS, id.as_bytes())
                .unwrap()
                .map(|r| r.0),
            Some(true)
        );
    }
}

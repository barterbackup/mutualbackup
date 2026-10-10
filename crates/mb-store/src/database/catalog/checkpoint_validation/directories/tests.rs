use super::super::tests::Fixture as Authority;
use super::*;
use crate::database::catalog::packing_directories_coverage::tests::{PackingParts, shard};
use mb_core::{
    CatalogCodingDirectoryBuilder, CatalogCodingEntry, MemberSignature,
    QuorumPagedCheckpointDirectory, canonical_bytes,
};
use std::collections::HashMap;

fn budget() -> CatalogCodingTraversalBudget {
    CatalogCodingTraversalBudget {
        bytes: 96 << 30,
        page_occurrences: 2_000_000,
        records: 128_000_000,
    }
}

struct Fixture {
    authority: Authority,
    packing: PackingParts,
    coding: CatalogCodingDirectoryRoot,
    entry: CatalogCodingEntry,
    pages: HashMap<[u8; 32], Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let mut authority = Authority::new(true, false);
        authority.authority_budget = Some(budget());
        let (original, pages, inputs) = authority.packing_inputs_with_byte_roots();
        let packing = shard(original, pages.into_iter().collect());
        let entry = crate::database::catalog::coding_coverage::tests::entry(
            &inputs,
            [0, 1, 2],
            701,
            3,
            None,
        );
        let mut pages = packing.pages.clone();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder = CatalogCodingDirectoryBuilder::new(
            authority.scope(),
            authority.context.event_sequence,
            budget(),
        )
        .unwrap();
        builder.push_group(&entry, &mut sink).unwrap();
        let coding = builder.finish(&mut sink).unwrap();
        Self {
            authority,
            packing,
            coding,
            entry,
            pages,
        }
    }
    fn packing(
        &mut self,
        limit: CatalogCodingTraversalBudget,
    ) -> Result<CatalogCheckpointPackingDirectoryIndex, CatalogStoreError> {
        self.authority
            .build(limit)?
            .validate_packing_directory(self.packing.manifest, |page| fetch(&self.pages, page))
    }
    fn joined(
        &mut self,
        policy: CatalogCodingCoveragePolicy,
    ) -> CatalogCheckpointCodingDirectoriesIndex {
        self.packing(budget())
            .unwrap()
            .validate_coding_directory(
                self.coding,
                policy,
                |page| fetch(&self.pages, page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap()
    }
}
fn fetch(
    pages: &HashMap<[u8; 32], Vec<u8>>,
    page: CatalogPageRef,
) -> Result<Vec<u8>, CatalogStoreError> {
    pages
        .get(&page.hash)
        .cloned()
        .ok_or_else(|| DatabaseError::NotReady.into())
}

fn coding_trust(fixture: &Fixture) -> CatalogCheckpointCodingTrust {
    CatalogCheckpointCodingTrust {
        checkpoint: fixture.authority.trust(),
        retained_groups: 1,
        retired_groups: 0,
    }
}
fn fact(
    fixture: &Fixture,
    authorization: CatalogCodingAuthorization,
) -> CatalogCertifiedCodingGroup {
    CatalogCertifiedCodingGroup::from_retained(
        &fixture.entry.retained,
        mb_core::canonical_hash_bounded(
            &fixture.entry.transcript,
            mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
        )
        .unwrap(),
        authorization,
    )
    .unwrap()
}
fn certified(fixture: &mut Fixture) -> CatalogCheckpointDirectoriesCodingStateIndex {
    let trust = coding_trust(fixture);
    let original = fact(fixture, CatalogCodingAuthorization::CurrentPlacement);
    // Unit point-provider contract. Real original-history membership/domain
    // and witness replay is qualified by the guild_history directory cases.
    fixture
        .joined(CatalogCodingCoveragePolicy::Current)
        .validate_certified_coding_state(
            budget(),
            || Ok(trust.clone()),
            |id, snapshot| {
                assert_eq!(snapshot, &trust);
                Ok((id == original.lifecycle.group_id).then_some(original))
            },
        )
        .unwrap()
}
fn transition(fixture: &mut Fixture) -> CatalogCheckpointDirectoriesTransitionIndex {
    let old_trust = fixture.authority.previous_trust();
    let trust = fixture.authority.trust();
    let writer = fixture
        .authority
        .sources
        .certificate
        .checkpoint
        .writer_fences[0]
        .clone();
    certified(fixture)
        .validate_authority_transition(
            Some(CatalogCheckpointPrevious::Legacy {
                certificate: &fixture.authority.sources.certificate,
                trust: &old_trust,
            }),
            budget(),
            || Ok(trust.clone()),
            |owner, _| Ok((owner == writer.owner).then(|| writer.clone())),
        )
        .unwrap()
}
fn certificate(
    proof: &CatalogCheckpointDirectoriesTransitionIndex,
    fixture: &Fixture,
) -> QuorumPagedCheckpointDirectory {
    let mut checkpoint = None;
    let mut signatures = Vec::new();
    for keys in &fixture.authority.sources.keys {
        let (header, signature) = proof
            .sign_paged_checkpoint_header(keys, || Ok(proof.trust().clone()))
            .unwrap();
        checkpoint = Some(header);
        signatures.push(signature);
    }
    signatures.sort_by_key(|signature| signature.signer);
    QuorumPagedCheckpointDirectory {
        checkpoint: checkpoint.unwrap(),
        signatures,
    }
}

#[test]
fn directory_certified_state_transitions_and_binds_its_exact_original_quorum() {
    let mut fixture = Fixture::new();
    let trust = fixture.authority.trust();
    let proof = transition(&mut fixture);
    assert!(!proof.has_certified_history_transition());
    assert!(proof.represented_work().bytes > proof.coding_state().represented_work().bytes);
    let certificate = certificate(&proof, &fixture);
    assert_eq!(
        certificate.checkpoint.packing,
        fixture.packing.manifest.directory
    );
    let bound = proof
        .bind_paged_checkpoint_header(certificate.clone(), || Ok(trust.clone()))
        .unwrap();
    assert_eq!(bound.certificate(), &certificate);
    assert_eq!(
        bound.index().authority(),
        fixture.authority.build(budget()).unwrap().manifest()
    );
    bound.recheck_header(|| Ok(trust.clone())).unwrap();
    assert!(bound.index().next_revision(None).unwrap().is_some());
}

#[test]
fn directory_certified_state_rejects_missing_changed_and_historical_placement_facts() {
    for case in 0..7 {
        let mut fixture = Fixture::new();
        let trust = coding_trust(&fixture);
        let mut original = fact(&fixture, CatalogCodingAuthorization::CurrentPlacement);
        match case {
            1 => original.transcript_hash[0] ^= 1,
            2 => original.lifecycle.added_at_event += 1,
            3 => original.guild_id[0] ^= 1,
            4 => original.authorization = CatalogCodingAuthorization::Retained,
            5 => original.lifecycle.retired_at_event = Some(100),
            6 => original.profile.parity_shards += 1,
            _ => {}
        }
        assert!(
            fixture
                .joined(CatalogCodingCoveragePolicy::Current)
                .validate_certified_coding_state(
                    budget(),
                    || Ok(trust.clone()),
                    |_, _| Ok((case != 0).then_some(original))
                )
                .is_err()
        );
    }
}

#[test]
fn directory_certified_state_admits_the_whole_job_before_original_group_lookups() {
    let mut fixture = Fixture::new();
    let exact = certified(&mut fixture).represented_work();
    let trust = coding_trust(&fixture);
    let original = fact(&fixture, CatalogCodingAuthorization::CurrentPlacement);
    for dimension in 0..3 {
        let mut short = exact;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(
            fixture
                .joined(CatalogCodingCoveragePolicy::Current)
                .validate_certified_coding_state(
                    short,
                    || Ok(trust.clone()),
                    |_, _| panic!("short job looked up a certified group")
                )
                .is_err()
        );
    }
    let proof = fixture
        .joined(CatalogCodingCoveragePolicy::Current)
        .validate_certified_coding_state(exact, || Ok(trust.clone()), |_, _| Ok(Some(original)))
        .unwrap();
    assert_eq!(proof.represented_work(), exact);
    let mut reads = 0;
    assert!(
        fixture
            .joined(CatalogCodingCoveragePolicy::Current)
            .validate_certified_coding_state(
                budget(),
                || {
                    reads += 1;
                    let mut current = trust.clone();
                    if reads > 1 {
                        current.checkpoint.event_head[0] ^= 1;
                    }
                    Ok(current)
                },
                |_, _| Ok(Some(original))
            )
            .is_err()
    );
}

#[test]
fn directory_certified_state_completion_faults_roll_back_and_fence_transition() {
    let mut fixture = Fixture::new();
    let trust = coding_trust(&fixture);
    let original = fact(&fixture, CatalogCodingAuthorization::CurrentPlacement);
    let body = fixture.joined(CatalogCodingCoveragePolicy::Current);
    body.index().packing().store.database_shell_statement("CREATE TEMP TRIGGER ignore_certified BEFORE INSERT ON scratch.protocol_records WHEN NEW.kind='checkpoint-certified-coding-complete' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
    assert!(
        body.validate_certified_coding_state(
            budget(),
            || Ok(trust.clone()),
            |_, _| Ok(Some(original))
        )
        .is_err()
    );
    let body = certified(&mut fixture);
    let store = &body.index().index().packing().store;
    let marker = store
        .get_record_bounded("checkpoint-certified-coding-complete", b"root", 4096)
        .unwrap()
        .unwrap();
    store
        .delete_record_if_value("checkpoint-certified-coding-complete", b"root", &marker)
        .unwrap();
    assert!(
        body.validate_authority_transition(
            None,
            budget(),
            || Ok(trust.checkpoint.clone()),
            |_, _| panic!("withdrawn coding proof looked up a writer")
        )
        .is_err()
    );
}

#[test]
fn directory_transition_requires_the_exact_previous_state_and_current_writer() {
    let mut fixture = Fixture::new();
    let trust = fixture.authority.trust();
    assert!(
        certified(&mut fixture)
            .validate_authority_transition(
                None,
                budget(),
                || Ok(trust.clone()),
                |_, _| panic!("missing predecessor read writer")
            )
            .is_err()
    );
    let old_trust = fixture.authority.previous_trust();
    assert!(
        certified(&mut fixture)
            .validate_authority_transition(
                Some(CatalogCheckpointPrevious::Legacy {
                    certificate: &fixture.authority.sources.certificate,
                    trust: &old_trust
                }),
                budget(),
                || Ok(trust.clone()),
                |_, _| Ok(None)
            )
            .is_err()
    );
    let exact = transition(&mut fixture).represented_work();
    for dimension in 0..3 {
        let mut short = exact;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(
            certified(&mut fixture)
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Legacy {
                        certificate: &fixture.authority.sources.certificate,
                        trust: &old_trust
                    }),
                    short,
                    || Ok(trust.clone()),
                    |_, _| panic!("short transition read current writer")
                )
                .is_err()
        );
    }
}

#[test]
fn directory_quorum_rejects_substituted_headers_stale_trust_and_withdrawn_proofs() {
    let mut fixture = Fixture::new();
    let proof = transition(&mut fixture);
    let trust = fixture.authority.trust();
    let mut substituted = certificate(&proof, &fixture);
    substituted.checkpoint.packing.records.page.hash[0] ^= 1;
    let bytes = canonical_bytes(&substituted.checkpoint).unwrap();
    for signature in &mut substituted.signatures {
        signature.signature = fixture
            .authority
            .sources
            .keys
            .iter()
            .find(|key| key.node_id() == signature.signer)
            .unwrap()
            .sign(mb_core::PAGED_GUILD_CHECKPOINT_DOMAIN, &bytes)
            .to_vec();
    }
    substituted.verify_header(&trust, budget()).unwrap();
    assert!(
        proof
            .bind_paged_checkpoint_header(substituted, || Ok(trust.clone()))
            .is_err()
    );
    let proof = transition(&mut fixture);
    let mut reads = 0;
    assert!(
        proof
            .sign_paged_checkpoint_header(&fixture.authority.sources.keys[0], || {
                reads += 1;
                let mut current = trust.clone();
                if reads > 1 {
                    current.event_head[0] ^= 1;
                }
                Ok(current)
            })
            .is_err()
    );
    let store = &proof.index().index().packing().store;
    let marker = store
        .get_record_bounded("checkpoint-authority-transition-complete", b"root", 4096)
        .unwrap()
        .unwrap();
    store
        .delete_record_if_value("checkpoint-authority-transition-complete", b"root", &marker)
        .unwrap();
    assert!(
        proof
            .sign_paged_checkpoint_header(&fixture.authority.sources.keys[0], || Ok(trust.clone()))
            .is_err()
    );
}

#[test]
fn directory_previous_quorum_preserves_retained_authority_and_requires_its_live_proof() {
    let mut fixture = Fixture::new();
    let proof = transition(&mut fixture);
    let trust = fixture.authority.trust();
    let certificate = certificate(&proof, &fixture);
    let previous = proof
        .bind_paged_checkpoint_header(certificate, || Ok(trust.clone()))
        .unwrap();
    fixture.authority.context.generation += 1;
    let mut current = fixture.authority.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: previous.certificate().checkpoint.generation,
        hash: previous.certificate().hash().unwrap(),
    });
    let coding_trust = CatalogCheckpointCodingTrust {
        checkpoint: current.clone(),
        retained_groups: 1,
        retired_groups: 0,
    };
    let original = fact(&fixture, CatalogCodingAuthorization::CurrentPlacement);
    let body = fixture
        .joined(CatalogCodingCoveragePolicy::Current)
        .validate_certified_coding_state(
            budget(),
            || Ok(coding_trust.clone()),
            |_, _| Ok(Some(original)),
        )
        .unwrap();
    let successor = body
        .validate_authority_transition(
            Some(CatalogCheckpointPrevious::Directory(&previous)),
            budget(),
            || Ok(current.clone()),
            |_, _| panic!("retained revision looked up a new writer"),
        )
        .unwrap();
    assert_eq!(
        successor.index().header_candidate(&current).unwrap().parent,
        Some(previous.certificate().hash().unwrap())
    );
    let store = &previous.index().index().packing().store;
    let marker = store
        .get_record_bounded("checkpoint-authority-transition-complete", b"root", 4096)
        .unwrap()
        .unwrap();
    store
        .delete_record_if_value("checkpoint-authority-transition-complete", b"root", &marker)
        .unwrap();
    let body = fixture
        .joined(CatalogCodingCoveragePolicy::Current)
        .validate_certified_coding_state(
            budget(),
            || Ok(coding_trust.clone()),
            |_, _| Ok(Some(original)),
        )
        .unwrap();
    assert!(
        body.validate_authority_transition(
            Some(CatalogCheckpointPrevious::Directory(&previous)),
            budget(),
            || Ok(current.clone()),
            |_, _| panic!("withdrawn predecessor read writer")
        )
        .is_err()
    );
}

#[test]
fn public_directories_join_original_sources_coding_and_exact_header_ledger() {
    let mut fixture = Fixture::new();
    let trust = fixture.authority.trust();
    let proof = fixture.joined(CatalogCodingCoveragePolicy::Current);
    let header = proof.header_candidate(&trust).unwrap();
    assert_eq!(header.authority_root.format_version, 2);
    assert_eq!(header.authority_root, proof.authority().root);
    assert_eq!(
        header.authority_records,
        proof.index().manifest().prior_work.records
    );
    assert_eq!(header.packing, fixture.packing.manifest.directory);
    assert_eq!(header.packing.summary.sources, 2);
    assert_eq!(header.packing.summary.source_parts, 2);
    assert_eq!(header.packing.summary.sector_parts, 3);
    assert_eq!(header.coding, fixture.coding);
    let mut cursor = None;
    let mut revisions = Vec::new();
    while let Some(record) = proof.next_revision(cursor).unwrap() {
        let key = record.revision_key().unwrap();
        assert_eq!(proof.revision(key).unwrap(), Some(record.clone()));
        cursor = Some(key);
        revisions.push(record);
    }
    assert_eq!(revisions.len(), 2);
    assert!(
        revisions
            .iter()
            .any(|record| matches!(record, CatalogCheckpointAuthorityRecord::LegacyRevision(_)))
    );
    assert!(
        revisions
            .iter()
            .any(|record| matches!(record, CatalogCheckpointAuthorityRecord::PagedRevision(_)))
    );
    assert_eq!(
        proof
            .index()
            .read_group(fixture.entry.retained.group.id, |page| fetch(
                &fixture.pages,
                page
            ))
            .unwrap(),
        Some(fixture.entry.clone())
    );
    for role in &fixture.entry.retained.group.roles {
        if let mb_core::ShardRoleV2::Information(role) = role {
            let coverage = proof.index().coverage(role.sector.id).unwrap().unwrap();
            assert_eq!(coverage.group_id, fixture.entry.retained.group.id);
            assert_eq!(coverage.holder, role.owner);
        }
    }
    // A wire/quorum smoke check only; this candidate still does not authorize
    // production signing, history transition, custody or activation.
    let encoded = canonical_bytes(&header).unwrap();
    let mut signatures = fixture
        .authority
        .sources
        .keys
        .iter()
        .map(|keys| MemberSignature {
            signer: keys.node_id(),
            signature: keys
                .sign(mb_core::PAGED_GUILD_CHECKPOINT_DOMAIN, &encoded)
                .to_vec(),
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|signature| signature.signer);
    let quorum = QuorumPagedCheckpointDirectory {
        checkpoint: header,
        signatures,
    };
    assert_eq!(
        QuorumPagedCheckpointDirectory::decode_header(
            &canonical_bytes(&quorum).unwrap(),
            &trust,
            budget()
        )
        .unwrap(),
        quorum
    );
}

#[test]
fn public_directories_reject_legacy_authority_scope_and_cardinality_before_io() {
    let mut fixture = Fixture::new();
    fixture.authority.authority_budget = None;
    assert!(
        fixture
            .authority
            .build(budget())
            .unwrap()
            .validate_packing_directory(fixture.packing.manifest, |_| panic!(
                "legacy authority read sharded packing"
            ))
            .is_err()
    );
    fixture.authority.authority_budget = Some(budget());
    let mut wrong_scope = fixture.packing.manifest;
    wrong_scope.scope = CatalogScope::Guild { guild_id: [99; 32] };
    assert!(
        fixture
            .authority
            .build(budget())
            .unwrap()
            .validate_packing_directory(wrong_scope, |_| panic!("wrong scope read packing"))
            .is_err()
    );
    let mut other = crate::database::catalog::packing_directories_coverage::tests::Fixture::new(3)
        .packing
        .manifest;
    other.scope = fixture.authority.scope();
    assert_ne!(other.directory.summary.sources, 2);
    assert!(
        fixture
            .authority
            .build(budget())
            .unwrap()
            .validate_packing_directory(other, |_| panic!("wrong source count read packing"))
            .is_err()
    );
}

#[test]
fn public_directories_preserve_authority_debt_and_reserve_coding_before_io() {
    let mut fixture = Fixture::new();
    let authority_work = fixture
        .authority
        .build(budget())
        .unwrap()
        .represented_work();
    let packing_work = fixture.packing.manifest.represented_work().unwrap();
    let reserved = authority_work
        .checked_add(packing_work)
        .unwrap()
        .checked_add(CatalogCodingTraversalBudget {
            bytes: 4096,
            ..Default::default()
        })
        .unwrap();
    for dimension in 0..3 {
        let mut short = reserved;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(
            fixture
                .authority
                .build(short)
                .unwrap()
                .validate_packing_directory(fixture.packing.manifest, |_| panic!(
                    "short packing budget performed I/O"
                ))
                .is_err()
        );
    }
    let manifest = CatalogPackingCodingDirectoriesValidation {
        format_version: 1,
        packing: fixture.packing.manifest,
        coding: fixture.coding,
        policy: CatalogCodingCoveragePolicy::Current,
        prior_work: authority_work,
    };
    let total = manifest.represented_work().unwrap();
    for dimension in 0..3 {
        let mut short = total;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(
            fixture
                .packing(short)
                .unwrap()
                .validate_coding_directory(
                    fixture.coding,
                    manifest.policy,
                    |_| panic!("short coding budget performed I/O"),
                    |_| panic!("short coding budget authorized group")
                )
                .is_err()
        );
    }
    let proof = fixture
        .packing(total)
        .unwrap()
        .validate_coding_directory(
            fixture.coding,
            manifest.policy,
            |page| fetch(&fixture.pages, page),
            |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
        )
        .unwrap();
    assert_eq!(proof.index().manifest().represented_work().unwrap(), total);
    // The public certificate has its own fixed 32 KiB envelope reservation.
    assert!(proof.header_candidate(&fixture.authority.trust()).is_err());
}

#[test]
fn public_directory_candidate_requires_exact_members_current_policy_and_event() {
    let mut fixture = Fixture::new();
    let trust = fixture.authority.trust();
    let historical = fixture.joined(CatalogCodingCoveragePolicy::Historical);
    assert!(historical.header_candidate(&trust).is_err());
    let proof = fixture.joined(CatalogCodingCoveragePolicy::Current);
    for field in 0..3 {
        let mut stale = trust.clone();
        match field {
            0 => stale.members[0].failure_domain.push_str("-changed"),
            1 => stale.members[0].recovery_public_key = stale.members[1].recovery_public_key,
            _ => stale.event_head[0] ^= 1,
        }
        assert!(proof.header_candidate(&stale).is_err());
    }
    let mut wrong = fixture.coding;
    wrong.guild_event_sequence += 1;
    assert!(
        fixture
            .packing(budget())
            .unwrap()
            .validate_coding_directory(
                wrong,
                CatalogCodingCoveragePolicy::Current,
                |_| panic!("wrong event fetched coding"),
                |_| panic!("wrong event authorized coding")
            )
            .is_err()
    );
}

#[test]
fn public_directory_candidate_and_revision_replay_require_both_completion_markers() {
    for kind in [COMPLETE, "packing-coding-directories-complete"] {
        let mut fixture = Fixture::new();
        let proof = fixture.joined(CatalogCodingCoveragePolicy::Current);
        let store = &proof.index().packing().store;
        let marker = store
            .get_record_bounded(kind, b"root", 4096)
            .unwrap()
            .unwrap();
        store
            .delete_record_if_value(kind, b"root", &marker)
            .unwrap();
        assert!(proof.header_candidate(&fixture.authority.trust()).is_err());
        assert!(proof.next_revision(None).is_err());
    }
}

#[test]
fn public_directory_join_rejects_tail_damage_and_suppressed_completion_writes() {
    let mut fixture = Fixture::new();
    let tail = fixture
        .packing
        .sectors
        .last()
        .unwrap()
        .root
        .records
        .page
        .hash;
    let original = fixture.pages[&tail].clone();
    fixture.pages.get_mut(&tail).unwrap()[0] ^= 1;
    assert!(fixture.packing(budget()).is_err());
    fixture.pages.insert(tail, original);
    let packing = fixture.packing(budget()).unwrap();
    packing.index.store.database_shell_statement("CREATE TEMP TRIGGER ignore_directory BEFORE INSERT ON scratch.protocol_records WHEN NEW.kind='packing-coding-directories-complete' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
    assert!(
        packing
            .validate_coding_directory(
                fixture.coding,
                CatalogCodingCoveragePolicy::Current,
                |page| fetch(&fixture.pages, page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement)
            )
            .is_err()
    );
    // A fresh scratch store can rebuild the same original roots after failure.
    fixture
        .joined(CatalogCodingCoveragePolicy::Current)
        .header_candidate(&fixture.authority.trust())
        .unwrap();
}

use super::*;
use crate::{CatalogPackingDirectoryBuilder, KeyMaterial, canonical_bytes};

fn unlimited() -> CatalogCodingTraversalBudget {
    CatalogCodingTraversalBudget {
        bytes: u64::MAX,
        page_occurrences: u64::MAX,
        records: u64::MAX,
    }
}

fn fixture() -> (
    PagedGuildCheckpointDirectory,
    PagedCheckpointTrust,
    Vec<KeyMaterial>,
) {
    let (old, trust, keys) = super::super::tests::fixture();
    let mut authority_root = old.authority_root;
    authority_root.format_version = 2;
    // Shape-only header tests. Complete source/body proof is exercised by the
    // public Store join; empty packing here grants no signing capability.
    let packing = CatalogPackingDirectoryBuilder::new(
        CatalogScope::Guild {
            guild_id: trust.guild_id,
        },
        5,
        old.packed_sources.profile,
        unlimited(),
    )
    .unwrap()
    .finish(&mut |_, _| Ok::<_, ()>(()))
    .unwrap();
    (
        PagedGuildCheckpointDirectory {
            format_version: PAGED_GUILD_CHECKPOINT_DIRECTORY_VERSION,
            guild_id: old.guild_id,
            genesis_hash: old.genesis_hash,
            generation: old.generation,
            parent: old.parent,
            event_sequence: old.event_sequence,
            event_head: old.event_head,
            authority: old.authority,
            authority_root,
            authority_records: old.authority_records,
            packing,
            coding: old.coding,
        },
        trust,
        keys,
    )
}

fn certificate(
    checkpoint: PagedGuildCheckpointDirectory,
    keys: &[KeyMaterial],
) -> QuorumPagedCheckpointDirectory {
    let encoded = canonical_bytes(&checkpoint).unwrap();
    let mut signatures = keys
        .iter()
        .map(|keys| MemberSignature {
            signer: keys.node_id(),
            signature: keys.sign(PAGED_GUILD_CHECKPOINT_DOMAIN, &encoded).to_vec(),
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|signature| signature.signer);
    QuorumPagedCheckpointDirectory {
        checkpoint,
        signatures,
    }
}

#[test]
fn directory_header_is_canonical_and_separate_from_original_formats() {
    let (header, trust, _) = fixture();
    let bytes = canonical_bytes(&header).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        include_str!("../../../../../protocol/vectors/paged-checkpoint-directory-v10.postcard.hex")
            .trim()
    );
    assert!(bytes.len() <= PAGED_GUILD_CHECKPOINT_BYTES);
    assert_eq!(
        PagedGuildCheckpointDirectory::decode(&bytes, unlimited()).unwrap(),
        header
    );
    header.validate_trust(&trust, unlimited()).unwrap();
    assert!(PagedGuildCheckpoint::decode(&bytes, unlimited()).is_err());
    let (old, _, _) = super::super::tests::fixture();
    assert!(
        PagedGuildCheckpointDirectory::decode(&canonical_bytes(&old).unwrap(), unlimited())
            .is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(PagedGuildCheckpointDirectory::decode(&trailing, unlimited()).is_err());
    for format in [8, 9, 11] {
        let mut wrong = header;
        wrong.format_version = format;
        assert!(wrong.validate_header(unlimited()).is_err());
    }
    let mut wrong = header;
    wrong.authority_root.format_version = 1;
    assert!(wrong.validate_header(unlimited()).is_err());
}

#[test]
fn directory_header_charges_all_three_cumulative_dimensions() {
    let (header, _, _) = fixture();
    let work = header.represented_work().unwrap();
    header.validate_header(work).unwrap();
    assert_eq!(
        work.bytes,
        PAGED_QUORUM_CHECKPOINT_BYTES as u64
            + header.authority_root.records.page.byte_len
            + header.authority_root.summary.legacy_bytes
            + header.authority_root.summary.source_bytes
            + header.packing.work().unwrap().bytes
            - crate::CATALOG_PACKING_DIRECTORY_ROOT_BYTES as u64
            + header.coding.work().unwrap().bytes
            - CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64
    );
    assert_eq!(
        work.page_occurrences,
        header.authority_root.page_occurrences().unwrap()
            + header.packing.work().unwrap().page_occurrences
            + header.coding.work().unwrap().page_occurrences
    );
    assert_eq!(
        work.records,
        header.authority_records
            + header.packing.work().unwrap().records
            + header.coding.work().unwrap().records
    );
    for dimension in 0..3 {
        let mut short = work;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(header.validate_header(short).is_err());
    }
}

#[test]
fn directory_header_requires_exact_trust_and_valid_authority_ledger() {
    let (header, trust, _) = fixture();
    for field in 0..6 {
        let mut stale = trust.clone();
        match field {
            0 => stale.event_head[0] ^= 1,
            1 => stale.event_sequence += 1,
            2 => stale.genesis_hash[0] ^= 1,
            3 => stale.previous.as_mut().unwrap().hash[0] ^= 1,
            4 => stale.previous.as_mut().unwrap().generation += 1,
            _ => stale.guild_id[0] ^= 1,
        }
        assert!(header.validate_trust(&stale, unlimited()).is_err());
    }
    for records in [0, u64::MAX] {
        let mut wrong = header;
        wrong.authority_records = records;
        assert!(wrong.validate_header(unlimited()).is_err());
    }
    let mut wrong = header;
    wrong.coding.guild_event_sequence += 1;
    assert!(wrong.validate_header(unlimited()).is_err());
    let mut invalid = trust;
    invalid.members[0].recovery_public_key = crate::RecoveryPublicKey([0; 32]);
    assert!(header.validate_trust(&invalid, unlimited()).is_err());
}

#[test]
fn directory_quorum_binds_original_members_and_canonical_body() {
    let (header, trust, keys) = fixture();
    let quorum = certificate(header, &keys);
    let bytes = canonical_bytes(&quorum).unwrap();
    assert_eq!(
        QuorumPagedCheckpointDirectory::decode_header(&bytes, &trust, unlimited()).unwrap(),
        quorum
    );
    assert_eq!(quorum.hash().unwrap(), header.hash().unwrap());
    let mut insufficient = quorum.clone();
    insufficient.signatures.pop();
    assert!(insufficient.verify_header(&trust, unlimited()).is_err());
    let mut duplicate = quorum.clone();
    duplicate.signatures[1] = duplicate.signatures[0].clone();
    assert!(duplicate.verify_header(&trust, unlimited()).is_err());
    let mut reversed = quorum.clone();
    reversed.signatures.reverse();
    assert!(reversed.verify_header(&trust, unlimited()).is_err());
    let mut tampered = quorum.clone();
    tampered.checkpoint.packing.packing_version = 3;
    assert!(tampered.verify_header(&trust, unlimited()).is_err());
    let (old, _, _) = super::super::tests::fixture();
    let mut old_signature = quorum;
    old_signature.signatures[0].signature = keys
        .iter()
        .find(|key| key.node_id() == old_signature.signatures[0].signer)
        .unwrap()
        .sign(
            PAGED_GUILD_CHECKPOINT_DOMAIN,
            &canonical_bytes(&old).unwrap(),
        )
        .to_vec();
    assert!(old_signature.verify_header(&trust, unlimited()).is_err());
}

#[test]
fn directory_quorum_rejects_oversized_nested_signature_lengths_before_allocation() {
    let (header, trust, keys) = fixture();
    let mut bytes = canonical_bytes(&header).unwrap();
    // Postcard vector length is a varint; this claims a huge signer vector
    // while providing no signer rows. The bounded decoder rejects it.
    bytes.extend([0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert!(QuorumPagedCheckpointDirectory::decode_header(&bytes, &trust, unlimited()).is_err());
    let mut bytes = canonical_bytes(&header).unwrap();
    bytes.push(1);
    bytes.extend(keys[0].node_id().0);
    bytes.extend([0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert!(QuorumPagedCheckpointDirectory::decode_header(&bytes, &trust, unlimited()).is_err());
    assert!(
        QuorumPagedCheckpointDirectory::decode_header(
            &vec![0; PAGED_QUORUM_CHECKPOINT_BYTES + 1],
            &trust,
            unlimited()
        )
        .is_err()
    );
}

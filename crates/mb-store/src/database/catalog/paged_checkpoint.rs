//! Paged quorum headers bound to a completed public checkpoint proof. These
//! APIs deliberately provide no production publication/retirement capability.

use mb_core::{
    KeyMaterial, Member, MemberSignature, PAGED_GUILD_CHECKPOINT_BYTES,
    PAGED_GUILD_CHECKPOINT_DOMAIN, PAGED_GUILD_CHECKPOINT_VERSION, PagedCheckpointTrust,
    PagedGuildCheckpoint, QuorumPagedCheckpoint, canonical_bytes_bounded,
};

use super::checkpoint_validation::{MEMBER_BYTES, MEMBER_RECORDS};
use super::*;

impl CatalogCheckpointCodingDirectoryIndex {
    pub(super) fn header(
        &self,
        trust: &PagedCheckpointTrust,
    ) -> Result<PagedGuildCheckpoint, CatalogStoreError> {
        self.require_complete()?;
        trust.validate()?;
        let authority = self.authority();
        let context = authority.context;
        let manifest = self.index().manifest();
        if manifest.policy != CatalogCodingCoveragePolicy::Current
            || context.guild_id != trust.guild_id
            || context.generation != trust.next_generation()?
            || context.event_sequence != trust.event_sequence
            || context.event_head != trust.event_head
            || context.authority != trust.authority
            || authority.root.summary.members as usize != trust.members.len()
        {
            return Err(DatabaseError::Conflict.into());
        }
        // Compare the exact original member records, including recovery keys
        // and domains. Node IDs/counts alone do not bind the event snapshot.
        for member in &trust.members {
            let bytes = self
                .index()
                .packing()
                .store
                .get_record_bounded(MEMBER_RECORDS, &member.node_id.0, MEMBER_BYTES)?
                .ok_or(DatabaseError::NotReady)?;
            let original: Member = decode_canonical(&bytes)?;
            if original != *member || canonical_bytes_bounded(&original, MEMBER_BYTES)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
        }
        let checkpoint = PagedGuildCheckpoint {
            format_version: PAGED_GUILD_CHECKPOINT_VERSION,
            guild_id: trust.guild_id,
            genesis_hash: trust.genesis_hash,
            generation: context.generation,
            parent: trust.previous.map(|parent| parent.hash),
            event_sequence: context.event_sequence,
            event_head: context.event_head,
            authority: context.authority,
            authority_root: authority.root,
            authority_records: manifest.prior_work.records,
            packed_sectors: manifest.packing.descriptors,
            packed_sources: manifest.packing.sources,
            coding: manifest.coding,
        };
        // The proof budget was independently supplied at authority admission.
        // Reserve the complete certificate envelope before any key operation.
        checkpoint.validate_trust(trust, self.index().budget())?;
        Ok(checkpoint)
    }
}

impl CatalogCheckpointTransitionIndex {
    /// Sign only the public header backed by this completed current-coverage
    /// proof. `read_trust` must reread independently certified event state and
    /// the trusted previous checkpoint, with no production writer held across
    /// validation. The returned signature alone does not authorize activation:
    /// coding lifecycle, private/payload joins and the atomic current-state
    /// publication guard remain
    /// mandatory. No normal checkpoint producer calls this draft bridge yet.
    pub fn sign_paged_checkpoint_header(
        &self,
        keys: &KeyMaterial,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(PagedGuildCheckpoint, MemberSignature), CatalogStoreError> {
        let trust = read_trust()?;
        let checkpoint = self.header(&trust)?;
        if trust
            .members
            .binary_search_by_key(&keys.node_id(), |member| member.node_id)
            .is_err()
        {
            return Err(ModelError::NonMemberSigner(keys.node_id()).into());
        }
        let encoded = canonical_bytes_bounded(&checkpoint, PAGED_GUILD_CHECKPOINT_BYTES)?;
        let signature = MemberSignature {
            signer: keys.node_id(),
            signature: keys.sign(PAGED_GUILD_CHECKPOINT_DOMAIN, &encoded).to_vec(),
        };
        if read_trust()? != trust {
            return Err(DatabaseError::Conflict.into());
        }
        self.header(&trust)?;
        Ok((checkpoint, signature))
    }

    /// Bind exact roots/ledger and original quorum to a completed public proof.
    /// A cryptographically valid substituted header or historical-only coverage
    /// cannot acquire this wrapper. This is not a full transition/publication
    /// token; all remaining private, payload and durable ownership joins apply.
    pub fn bind_paged_checkpoint_header(
        self,
        certificate: QuorumPagedCheckpoint,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<CatalogQuorumPagedCheckpointIndex, CatalogStoreError> {
        let trust = read_trust()?;
        if certificate.checkpoint != self.header(&trust)? {
            return Err(DatabaseError::Conflict.into());
        }
        certificate.verify_header(&trust, self.index().index().budget())?;
        if read_trust()? != trust {
            return Err(DatabaseError::Conflict.into());
        }
        self.header(&trust)?;
        Ok(CatalogQuorumPagedCheckpointIndex {
            certificate,
            trust,
            index: self,
        })
    }
}

/// Completed public body plus independently checked quorum/event/base binding.
/// The original certificate, authority and indexed cursors remain available.
/// There is deliberately no constructor from a manifest or header alone.
pub struct CatalogQuorumPagedCheckpointIndex {
    certificate: QuorumPagedCheckpoint,
    trust: PagedCheckpointTrust,
    index: CatalogCheckpointTransitionIndex,
}

impl CatalogQuorumPagedCheckpointIndex {
    pub fn certificate(&self) -> &QuorumPagedCheckpoint {
        &self.certificate
    }
    pub fn trust(&self) -> &PagedCheckpointTrust {
        &self.trust
    }
    pub fn index(&self) -> &CatalogCheckpointCodingDirectoryIndex {
        self.index.index()
    }
    pub fn transition(&self) -> &CatalogCheckpointTransitionIndex {
        &self.index
    }
    /// Recheck the exact trusted event/base snapshot before a later enclosing
    /// operation. A caller still needs its atomic publication/retirement guard.
    pub fn recheck_header(
        &self,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        if read_trust()? != self.trust
            || self.index.header(&self.trust)? != self.certificate.checkpoint
        {
            return Err(DatabaseError::Conflict.into());
        }
        self.certificate
            .verify_header(&self.trust, self.index.index().index().budget())?;
        if read_trust()? != self.trust {
            return Err(DatabaseError::Conflict.into());
        }
        self.index.header(&self.trust).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::super::checkpoint_validation::tests::Fixture;
    use super::*;
    use mb_core::{CatalogCodingTraversalBudget, QuorumRule, Seed, canonical_bytes};
    use std::cell::Cell;

    fn budget() -> CatalogCodingTraversalBudget {
        CatalogCodingTraversalBudget {
            bytes: 96 << 30,
            page_occurrences: 2_000_000,
            records: 128_000_000,
        }
    }
    fn sign_all(
        fixture: &Fixture,
        index: &CatalogCheckpointTransitionIndex,
    ) -> QuorumPagedCheckpoint {
        let trust = fixture.trust();
        let mut checkpoint = None;
        let mut signatures = Vec::new();
        for keys in &fixture.sources.keys {
            if trust
                .members
                .iter()
                .any(|member| member.node_id == keys.node_id())
            {
                let (header, signature) = index
                    .sign_paged_checkpoint_header(keys, || Ok(trust.clone()))
                    .unwrap();
                assert!(checkpoint.is_none_or(|previous| previous == header));
                checkpoint = Some(header);
                signatures.push(signature);
            }
        }
        signatures.sort_by_key(|signature| signature.signer);
        QuorumPagedCheckpoint {
            checkpoint: checkpoint.unwrap(),
            signatures,
        }
    }
    fn resign(fixture: &Fixture, certificate: &mut QuorumPagedCheckpoint) {
        let encoded = canonical_bytes(&certificate.checkpoint).unwrap();
        for signature in &mut certificate.signatures {
            let keys = fixture
                .sources
                .keys
                .iter()
                .find(|keys| keys.node_id() == signature.signer)
                .unwrap();
            signature.signature = keys.sign(PAGED_GUILD_CHECKPOINT_DOMAIN, &encoded).to_vec();
        }
    }

    #[test]
    fn paged_certificate_binds_original_complete_proof_and_trusted_legacy_parent() {
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        let joined = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let mut certificate = sign_all(&fixture, &joined);
        certificate.signatures.pop(); // Two of three independently trusted active members.
        certificate.verify_header(&trust, budget()).unwrap();
        assert_eq!(
            certificate.checkpoint.parent,
            Some(fixture.sources.certificate.hash().unwrap())
        );
        assert_eq!(
            certificate.checkpoint.authority_records,
            joined.index().index().manifest().prior_work.records
        );
        assert_eq!(
            certificate.checkpoint.authority_root,
            joined.index().authority().root
        );
        assert_eq!(
            certificate.checkpoint.packed_sectors,
            joined.index().index().packing().manifest().descriptors
        );
        let bytes = canonical_bytes(&certificate).unwrap();
        assert_eq!(
            QuorumPagedCheckpoint::decode_header(&bytes, &trust, budget()).unwrap(),
            certificate
        );
        let calls = Cell::new(0);
        let bound = joined
            .bind_paged_checkpoint_header(certificate.clone(), || {
                calls.set(calls.get() + 1);
                Ok(trust.clone())
            })
            .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(bound.certificate(), &certificate);
        assert_eq!(bound.trust(), &trust);
        assert!(bound.index().next_revision(None).unwrap().is_some());
        assert_eq!(
            bound.index().index().manifest().coding,
            certificate.checkpoint.coding
        );
        bound.recheck_header(|| Ok(trust.clone())).unwrap();
        let mut advanced = trust.clone();
        advanced.event_sequence += 1;
        assert!(bound.recheck_header(|| Ok(advanced.clone())).is_err());
    }

    #[test]
    fn paged_certificate_signing_requires_exact_members_current_coverage_and_live_snapshot() {
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        let joined = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let changes: Vec<fn(&mut PagedCheckpointTrust)> = vec![
            |trust| trust.guild_id[0] ^= 1,
            |trust| trust.event_sequence -= 1,
            |trust| trust.event_head[0] ^= 1,
            |trust| trust.authority.membership_epoch += 1,
            |trust| trust.authority.quorum.rule = QuorumRule::Unanimous,
            |trust| trust.members[0].failure_domain.push('x'),
            |trust| {
                trust.members[0].recovery_public_key =
                    KeyMaterial::from_seed(&Seed::from_bytes([72; 32])).recovery_public_key()
            },
            |trust| trust.previous.as_mut().unwrap().generation += 1,
            |trust| trust.previous = None,
        ];
        for change in changes {
            let mut stale = trust.clone();
            change(&mut stale);
            assert!(
                joined
                    .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(stale.clone()))
                    .is_err()
            );
        }
        let outsider = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        assert!(
            joined
                .sign_paged_checkpoint_header(&outsider, || Ok(trust.clone()))
                .is_err()
        );
        assert!(
            fixture
                .transitioned(budget(), CatalogCodingCoveragePolicy::Historical)
                .is_err()
        );
        // New candidates from a removed owner require rejection before signing.
        let mut removed = Fixture::new(true, true);
        assert!(
            removed
                .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
                .is_err()
        );
    }

    #[test]
    fn paged_certificate_fences_event_base_changes_during_signing_and_binding() {
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        let joined = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let changes: Vec<fn(&mut PagedCheckpointTrust)> = vec![
            |trust| trust.event_head[0] ^= 1,
            |trust| trust.event_sequence += 1,
            |trust| trust.authority.membership_epoch += 1,
            |trust| trust.previous.as_mut().unwrap().hash[0] ^= 1,
            |trust| trust.previous.as_mut().unwrap().generation += 1,
            |trust| trust.genesis_hash[0] ^= 1,
            |trust| trust.members[0].failure_domain.push('x'),
        ];
        for change in changes {
            let calls = Cell::new(0);
            assert!(
                joined
                    .sign_paged_checkpoint_header(&fixture.sources.keys[0], || {
                        calls.set(calls.get() + 1);
                        let mut current = trust.clone();
                        if calls.get() == 2 {
                            change(&mut current);
                        }
                        Ok(current)
                    })
                    .is_err()
            );
            assert_eq!(calls.get(), 2);
        }
        assert!(
            joined
                .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Err(
                    DatabaseError::NotReady.into()
                ))
                .is_err()
        );
        let certificate = sign_all(&fixture, &joined);
        let calls = Cell::new(0);
        assert!(
            joined
                .bind_paged_checkpoint_header(certificate, || {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        Err(DatabaseError::NotReady.into())
                    } else {
                        Ok(trust.clone())
                    }
                })
                .is_err()
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn paged_certificate_rejects_quorum_valid_substituted_roots_and_record_ledger() {
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        let index = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let certificate = sign_all(&fixture, &index);
        drop(index);
        let changes: Vec<fn(&mut PagedGuildCheckpoint)> = vec![
            |header| header.authority_root.records.page.hash[0] ^= 1,
            |header| header.packed_sectors.records.page.hash[0] ^= 1,
            |header| header.packed_sources.records.page.hash[0] ^= 1,
            |header| header.coding.records.page.hash[0] ^= 1,
            |header| header.authority_records += 1,
        ];
        for change in changes {
            let index = fixture
                .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
                .unwrap();
            let mut substituted = certificate.clone();
            change(&mut substituted.checkpoint);
            resign(&fixture, &mut substituted);
            // Cryptographic header validity cannot stand in for the body proof.
            substituted.verify_header(&trust, budget()).unwrap();
            assert!(
                index
                    .bind_paged_checkpoint_header(substituted, || Ok(trust.clone()))
                    .is_err()
            );
        }
        for dimension in 0..4 {
            let index = fixture
                .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
                .unwrap();
            let mut other = trust.clone();
            match dimension {
                0 => other.previous.as_mut().unwrap().hash[0] ^= 1,
                1 => other.genesis_hash[0] ^= 1,
                2 => other.members[0].failure_domain.push('x'),
                _ => other.event_head[0] ^= 1,
            }
            assert!(
                index
                    .bind_paged_checkpoint_header(certificate.clone(), || Ok(other.clone()))
                    .is_err()
            );
        }
    }

    #[test]
    fn paged_certificate_reserves_one_complete_envelope_under_original_admission() {
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        let index = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let (header, _) = index
            .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(trust.clone()))
            .unwrap();
        let work = header.represented_work().unwrap();
        let local = index.index().index().manifest().represented_work().unwrap();
        assert_eq!(
            work.bytes,
            local.bytes + (mb_core::PAGED_QUORUM_CHECKPOINT_BYTES - 2048 - 4096) as u64
        );
        assert_eq!(work.page_occurrences, local.page_occurrences);
        assert_eq!(work.records, local.records);
        drop(index);
        let index = fixture
            .transitioned(work, CatalogCodingCoveragePolicy::Current)
            .unwrap();
        index
            .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(trust.clone()))
            .unwrap();
        drop(index);
        let mut short = work;
        short.bytes -= 1;
        let index = fixture.joined(short, CatalogCodingCoveragePolicy::Current);
        let previous_trust = fixture.previous_trust();
        let calls = Cell::new(0);
        assert!(
            index
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Legacy {
                        certificate: &fixture.sources.certificate,
                        trust: &previous_trust,
                    }),
                    budget(),
                    || {
                        calls.set(calls.get() + 1);
                        Ok(trust.clone())
                    },
                    |_, _| panic!("exhausted header budget read a writer")
                )
                .is_err()
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn paged_certificate_requires_all_completion_markers_and_original_member_rows() {
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        for kind in [
            "checkpoint-authority-complete",
            "packing-complete",
            "packing-coding-directory-complete",
            "checkpoint-authority-transition-complete",
        ] {
            let index = fixture
                .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
                .unwrap();
            let certificate = sign_all(&fixture, &index);
            let store = &index.index().index().packing().store;
            let bytes = store
                .get_record_bounded(kind, b"root", 4096)
                .unwrap()
                .unwrap();
            store.delete_record_if_value(kind, b"root", &bytes).unwrap();
            assert!(
                index
                    .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(trust.clone()))
                    .is_err()
            );
            assert!(
                index
                    .bind_paged_checkpoint_header(certificate, || Ok(trust.clone()))
                    .is_err()
            );
        }
        let index = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let store = &index.index().index().packing().store;
        let member = &trust.members[0];
        let bytes = store
            .get_record_bounded(MEMBER_RECORDS, &member.node_id.0, MEMBER_BYTES)
            .unwrap()
            .unwrap();
        store
            .delete_record_if_value(MEMBER_RECORDS, &member.node_id.0, &bytes)
            .unwrap();
        assert!(
            index
                .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(trust.clone()))
                .is_err()
        );
        // Markers are rechecked after the live callback as well, so removal
        // while collecting a signature cannot return a reusable signed result.
        let index = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let calls = Cell::new(0);
        assert!(
            index
                .sign_paged_checkpoint_header(&fixture.sources.keys[0], || {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        let store = &index.index().index().packing().store;
                        let bytes = store
                            .get_record_bounded("packing-complete", b"root", 4096)?
                            .unwrap();
                        store.delete_record_if_value("packing-complete", b"root", &bytes)?;
                    }
                    Ok(trust.clone())
                })
                .is_err()
        );
    }
}

//! Public acquisition uses an independent leased connection. Original history
//! and complete public joins govern promotion; no peer I/O holds a SQL writer.
use super::*;
use mb_core::{
    CatalogCodingTraversalBudget as Work, CatalogPageContents, CatalogPagePath, CatalogPageRef,
    CatalogScope, CatalogSection, WriterFence,
};
use mb_store::{
    CatalogCheckpointAcquisition as Job, CatalogCheckpointAcquisitionState as State,
    CatalogPublicCheckpoint as Certificate,
};

/// A completed original quorum/transition proof. Keep the previous proof live
/// while verifying its successor; no proposed header constructs this value.
pub enum RecoveredCheckpointProof {
    Individual(Box<mb_store::CatalogQuorumPagedCheckpointIndex>),
    Directory(Box<mb_store::CatalogQuorumPagedCheckpointDirectoryIndex>),
}
impl RecoveredCheckpointProof {
    fn trust(&self) -> &mb_core::PagedCheckpointTrust {
        match self {
            Self::Individual(p) => p.trust(),
            Self::Directory(p) => p.trust(),
        }
    }
    pub(super) fn previous(&self) -> mb_store::CatalogCheckpointPrevious<'_> {
        match self {
            Self::Individual(p) => mb_store::CatalogCheckpointPrevious::Paged(p),
            Self::Directory(p) => mb_store::CatalogCheckpointPrevious::Directory(p),
        }
    }
    pub fn certificate(&self) -> Certificate {
        match self {
            Self::Individual(p) => Certificate::Individual(p.certificate().clone()),
            Self::Directory(p) => Certificate::Directory(p.certificate().clone()),
        }
    }
    pub(super) fn verify(&self) -> Result<()> {
        macro_rules! check {
            ($p:expr) => {{
                anyhow::ensure!(
                    $p.transition().has_certified_history_transition(),
                    "predecessor requires certified original history"
                );
                $p.recheck_header(|| Ok($p.trust().clone()))?;
            }};
        }
        match self {
            Self::Individual(p) => check!(p),
            Self::Directory(p) => check!(p),
        };
        Ok(())
    }
}

struct HistoryPrefix<'a> {
    control: &'a ControlStore,
    sequence: u64,
}
impl mb_store::CatalogGuildHistorySource for HistoryPrefix<'_> {
    fn next_event(
        &mut self,
        after: Option<u64>,
    ) -> std::result::Result<Option<(u64, usize)>, mb_store::CatalogStoreError> {
        if after.is_some_and(|after| after >= self.sequence) || self.sequence == 0 {
            return Ok(None);
        }
        let mut source = self.control;
        Ok(
            mb_store::CatalogGuildHistorySource::next_event(&mut source, after)?
                .filter(|(sequence, _)| *sequence <= self.sequence),
        )
    }
    fn length(
        &mut self,
        object: mb_store::CatalogGuildHistoryObject,
    ) -> std::result::Result<Option<usize>, mb_store::CatalogStoreError> {
        if matches!(object,mb_store::CatalogGuildHistoryObject::Event(sequence) if sequence>self.sequence)
        {
            return Err(mb_store::DatabaseError::Conflict.into());
        }
        let mut source = self.control;
        mb_store::CatalogGuildHistorySource::length(&mut source, object)
    }
    fn read(
        &mut self,
        object: mb_store::CatalogGuildHistoryObject,
        limit: usize,
    ) -> std::result::Result<Option<Vec<u8>>, mb_store::CatalogStoreError> {
        if matches!(object,mb_store::CatalogGuildHistoryObject::Event(sequence) if sequence>self.sequence)
        {
            return Err(mb_store::DatabaseError::Conflict.into());
        }
        let mut source = self.control;
        mb_store::CatalogGuildHistorySource::read(&mut source, object, limit)
    }
}

mod rebuild;

type Fetch<'a> = dyn FnMut(CatalogPagePath) -> Result<Vec<u8>> + 'a;

#[derive(Clone, Copy)]
enum ProofInput<'a> {
    Acquisition {
        job: &'a Job,
        recovery: Option<Option<&'a RecoveredCheckpointProof>>,
    },
    Retained {
        source: &'a mb_store::CatalogCheckpointRecoverySource,
        selected: mb_store::CatalogCheckpointRecoveryTip,
        previous: Option<&'a RecoveredCheckpointProof>,
        meter: &'a rebuild::RecoveryWorkMeter,
    },
}
impl<'a> ProofInput<'a> {
    fn material(self) -> (Uuid, &'a Certificate, Work) {
        match self {
            Self::Acquisition { job, .. } => (job.id, &job.certificate, job.budget),
            Self::Retained { source, .. } => (source.owner, &source.certificate, source.budget),
        }
    }
    fn recovery(self) -> Option<Option<&'a RecoveredCheckpointProof>> {
        match self {
            Self::Acquisition { recovery, .. } => recovery,
            Self::Retained { previous, .. } => Some(previous),
        }
    }
}

impl RetainedCheckpointRestore {
    pub(crate) fn public_checkpoint_trust(&self) -> Result<mb_core::PagedCheckpointTrust> {
        guild_authority::frozen_original_history(&self.reader.control)?.paged_checkpoint_trust()
    }
    pub(crate) fn public_checkpoint_trust_after(
        &self,
        sequence: u64,
        previous: Option<&RecoveredCheckpointProof>,
    ) -> Result<mb_core::PagedCheckpointTrust> {
        let authority = guild_authority::frozen_original_history(&self.reader.control)?;
        let parent = if let Some(previous) = previous {
            previous.verify()?;
            let original = authority.paged_checkpoint_trust_at(
                previous.trust().event_sequence,
                previous.trust().previous,
            )?;
            anyhow::ensure!(
                original == *previous.trust() && original.event_sequence <= sequence,
                "predecessor differs from original historical authority"
            );
            let certificate = previous.certificate();
            Some(mb_core::PagedCheckpointParent {
                generation: certificate.generation(),
                hash: certificate.hash()?,
            })
        } else {
            None
        };
        authority.paged_checkpoint_trust_at(sequence, parent)
    }
    fn check_recovery_base(
        &self,
        id: Uuid,
        certificate: &Certificate,
        previous: Option<&RecoveredCheckpointProof>,
    ) -> Result<()> {
        let tip = self.reader.control.checkpoint_recovery_tip()?;
        if tip.is_some_and(|tip| {
            tip.owner == id
                && tip.guild_id == certificate.guild_id()
                && tip.layout == certificate.layout()
                && tip.generation == certificate.generation()
                && certificate.hash().ok() == Some(tip.hash)
        }) {
            return Ok(());
        }
        let expected = previous
            .map(|proof| -> Result<_> {
                let certificate = proof.certificate();
                Ok((certificate.generation(), certificate.hash()?))
            })
            .transpose()?;
        anyhow::ensure!(
            tip.map(|tip| (tip.generation, tip.hash)) == expected
                && tip.is_none_or(|tip| tip.guild_id == certificate.guild_id()),
            "verified recovery predecessor changed"
        );
        Ok(())
    }
    pub fn acquire_public_checkpoint_after(
        &self,
        id: Uuid,
        certificate: Certificate,
        budget: Work,
        previous: Option<&RecoveredCheckpointProof>,
        fetch: impl FnMut(CatalogPagePath) -> Result<Vec<u8>>,
    ) -> Result<Job> {
        self.acquire_public_checkpoint_inner(id, certificate, budget, Some(previous), fetch)
    }
    /// Acquire every public tree referenced by the original certificate. The
    /// separately installed original history supplies trust. Returns staging
    /// ownership only; promotion still needs the complete predecessor proof.
    pub fn acquire_public_checkpoint(
        &self,
        id: Uuid,
        certificate: Certificate,
        budget: Work,
        fetch: impl FnMut(CatalogPagePath) -> Result<Vec<u8>>,
    ) -> Result<Job> {
        self.acquire_public_checkpoint_inner(id, certificate, budget, None, fetch)
    }
    fn acquire_public_checkpoint_inner(
        &self,
        id: Uuid,
        certificate: Certificate,
        budget: Work,
        recovery: Option<Option<&RecoveredCheckpointProof>>,
        mut fetch: impl FnMut(CatalogPagePath) -> Result<Vec<u8>>,
    ) -> Result<Job> {
        let control = &self.reader.control;
        let authority = guild_authority::frozen_original_history(control)?;
        let trust = match recovery {
            Some(previous) => {
                self.public_checkpoint_trust_after(certificate.event_sequence(), previous)?
            }
            None => authority.paged_checkpoint_trust()?,
        };
        let job = control.begin_checkpoint_acquisition(id, certificate, trust.clone(), budget)?;
        let check = || -> Result<()> {
            authority.check()?;
            if let Some(previous) = recovery {
                self.check_recovery_base(id, &job.certificate, previous)?;
            }
            Ok(())
        };
        check()?;
        if control.checkpoint_acquisition_state(&job)? == State::Complete {
            return Ok(job);
        }
        let mut acquire = |scope, section, page| -> Result<()> {
            check()?;
            let intent = control.reserve_checkpoint_acquisition_root(&job, scope, section, page)?;
            match control.catalog_intent_state(intent)? {
                mb_store::CatalogIntentState::Building => {
                    let mut path = CatalogPagePath {
                        scope,
                        section,
                        pages: vec![page],
                    };
                    acquire_tree(control, &job, intent, page, &mut path, &mut fetch, &|| {
                        check()
                    })?;
                    control.complete_checkpoint_acquisition_root(&job, intent, page)?;
                }
                mb_store::CatalogIntentState::Published(root) if root == page => {}
                _ => anyhow::bail!("public acquisition root has changed state"),
            }
            let mut reader = mb_core::CatalogReader::new(scope, section, page)?;
            while reader
                .next_leaf(&mut |page| control.catalog_page(scope, section, page))?
                .is_some()
            {}
            check()
        };
        for (scope, section, page) in job.certificate.initial_roots() {
            acquire(scope, section, page)?;
        }
        let scope = CatalogScope::Guild {
            guild_id: job.certificate.guild_id(),
        };
        let mut records = mb_core::CatalogCheckpointAuthorityReader::new_with_budget(
            scope,
            job.certificate.authority(),
            budget,
        )?;
        while let Some(record) = records.next_record(&mut |page| {
            control.catalog_page(scope, CatalogSection::Checkpoint, page)
        })? {
            match record {
                mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(reference) => {
                    acquire(scope, CatalogSection::Checkpoint, reference.body)?
                }
                mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) => {
                    let body = &signed.value;
                    anyhow::ensure!(
                        authority
                            .writer_key_for_retained_revision(body.owner, body.writer_epoch)?
                            == Some(body.writer_public_key),
                        "public revision writer differs from original history"
                    );
                    acquire(
                        body.scope(),
                        CatalogSection::SectorReferences,
                        body.sources.records.page,
                    )?;
                    let fence = WriterFence {
                        owner: body.owner,
                        epoch: body.writer_epoch,
                        public_key: body.writer_public_key,
                    };
                    let mut sources = mb_core::PagedRevisionSourceReader::new(
                        &signed,
                        body.guild_id,
                        body.owner,
                        &fence,
                    )?;
                    while sources
                        .next_sector(&mut |page| {
                            control.catalog_page(
                                body.scope(),
                                CatalogSection::SectorReferences,
                                page,
                            )
                        })?
                        .is_some()
                    {}
                }
                _ => {}
            }
        }
        if let Certificate::Directory(c) = &job.certificate {
            let mut records = mb_core::CatalogRecordReader::new(
                scope,
                CatalogSection::Packing,
                c.checkpoint.packing.records,
            )?;
            while let Some(bytes) = records.next_record(&mut |page| {
                control.catalog_page(scope, CatalogSection::Packing, page)
            })? {
                let page = match mb_core::CatalogPackingDirectoryRecord::decode(&bytes)? {
                    mb_core::CatalogPackingDirectoryRecord::Sources(part) => part.root.records.page,
                    mb_core::CatalogPackingDirectoryRecord::Sectors(part) => part.root.records.page,
                };
                acquire(scope, CatalogSection::Packing, page)?;
            }
        }
        let mut coding =
            mb_core::CatalogCodingDirectoryReader::new(scope, job.certificate.coding(), budget)?;
        while coding
            .next_group_with_forest(
                &mut |page| {
                    Ok::<_, anyhow::Error>(control.catalog_page(
                        scope,
                        CatalogSection::Coding,
                        page,
                    )?)
                },
                &mut |forest: &mb_core::CatalogCodingRoot| -> Result<()> {
                    for part in &forest.parts {
                        acquire(scope, CatalogSection::Coding, part.page)?;
                    }
                    Ok(())
                },
            )?
            .is_some()
        {}
        check()?;
        Ok(job)
    }

    /// Rebuild complete original-history/packing/coding/transition authority
    /// from acquired pages and retain the original certificate. Previous
    /// checkpoint proof is supplied by the same normal validation machinery.
    pub fn promote_acquired_checkpoint(
        &self,
        job: &Job,
        previous: Option<mb_store::CatalogCheckpointPrevious<'_>>,
    ) -> Result<()> {
        self.promote_public_checkpoint_inner(
            ProofInput::Acquisition {
                job,
                recovery: None,
            },
            previous,
        )
        .map(|_| ())
    }
    pub fn promote_acquired_checkpoint_after(
        &self,
        job: &Job,
        previous: Option<&RecoveredCheckpointProof>,
    ) -> Result<RecoveredCheckpointProof> {
        self.promote_public_checkpoint_inner(
            ProofInput::Acquisition {
                job,
                recovery: Some(previous),
            },
            previous.map(RecoveredCheckpointProof::previous),
        )
    }
    fn promote_public_checkpoint_inner(
        &self,
        input: ProofInput<'_>,
        previous: Option<mb_store::CatalogCheckpointPrevious<'_>>,
    ) -> Result<RecoveredCheckpointProof> {
        let (id, certificate, budget) = input.material();
        if let ProofInput::Retained { meter, .. } = input {
            meter.guard()?;
        }
        let recovery = input.recovery();
        let control = &self.reader.control;
        let authority = guild_authority::frozen_original_history(control)?;
        let trust = match recovery {
            Some(previous) => {
                self.public_checkpoint_trust_after(certificate.event_sequence(), previous)?
            }
            None => authority.paged_checkpoint_trust()?,
        };
        let current = || -> std::result::Result<_, mb_store::CatalogStoreError> {
            authority
                .check()
                .map_err(|_| mb_store::DatabaseError::Conflict)?;
            match input {
                ProofInput::Acquisition { .. } => {
                    if let Some(previous) = recovery {
                        self.check_recovery_base(id, certificate, previous)
                            .map_err(|_| mb_store::DatabaseError::Conflict)?;
                    }
                }
                ProofInput::Retained {
                    source,
                    selected,
                    meter,
                    ..
                } => {
                    meter.guard()?;
                    if control.checkpoint_recovery_tip()? != Some(selected) {
                        return Err(mb_store::DatabaseError::Conflict.into());
                    }
                    control.check_checkpoint_recovery_source(source, &trust)?;
                }
            }
            Ok(trust.clone())
        };
        match input {
            ProofInput::Acquisition { job, .. } => {
                control.check_checkpoint_acquisition_trust(job, &trust)?
            }
            ProofInput::Retained { source, .. } => {
                control.check_checkpoint_recovery_source(source, &trust)?
            }
        }
        current()?;
        let installed: InstalledGuild = decode_canonical(
            &control
                .get_record_bounded(
                    "guild-installed",
                    b"primary",
                    mb_core::GUILD_AUTHORITY_SNAPSHOT_BYTES,
                )?
                .context("acquisition has no original genesis")?,
        )?;
        let scratch =
            || crate::volume::paged_scratch_store(control, mb_core::CATALOG_MAX_STREAM_BYTES * 4);
        let mut source = HistoryPrefix {
            control,
            sequence: trust.event_sequence,
        };
        let history = mb_store::CatalogGuildHistoryIndex::build(
            scratch()?,
            &installed.certificate,
            budget,
            if recovery.is_some() {
                mb_store::CatalogDurableGuildHistoryView::historical_authority_work()
            } else {
                Work::default()
            },
            current,
            &mut source,
        )?;
        let context = mb_store::CatalogCheckpointAuthorityContext {
            guild_id: trust.guild_id,
            generation: trust.next_generation()?,
            event_sequence: trust.event_sequence,
            event_head: trust.event_head,
            authority: trust.authority,
        };
        let view = history.view(current)?;
        let body = mb_store::CatalogCheckpointAuthorityIndex::build(
            context,
            certificate.authority(),
            &trust.members,
            budget,
            scratch()?,
            |scope, section, page| control.catalog_page(scope, section, page),
            |fence, kind| {
                let original = view
                    .writer_key(fence.owner, fence.epoch, &trust)?
                    .ok_or(mb_store::DatabaseError::NotReady)?;
                if original.public_key != fence.public_key
                    || (kind == mb_store::CatalogCheckpointWriterAuthorization::LatestRetained
                        && view.current_writer(fence.owner, &trust)? != Some(fence.clone()))
                {
                    return Err(mb_store::DatabaseError::Conflict.into());
                }
                Ok(())
            },
        )?;
        let scope = CatalogScope::Guild {
            guild_id: trust.guild_id,
        };
        let read = |page| control.catalog_page(scope, CatalogSection::Packing, page);
        let authorize = |_: &mb_core::CatalogCodingEntry| {
            Ok(mb_store::CatalogCodingAuthorization::CurrentPlacement)
        };
        macro_rules! promote {
            ($proof:expr,$certificate:expr,$retain:ident,$lookup:ident,$chunks:ident,$sources:ident,$variant:ident) => {{
                let proof = $proof
                    .validate_certified_history_coding_state(&history, budget, current)?
                    .validate_certified_history_authority_transition(
                        previous, &history, budget, current,
                    )?
                    .bind_paged_checkpoint_header($certificate.clone(), current)?;
                if matches!(input, ProofInput::Acquisition { .. }) {
                    control.$retain(id, &proof, current)?;
                    control.$lookup(id, &proof, current)?;
                    control.$chunks(id, &proof, current)?;
                    let mut after = None;
                    while let Some(record) = proof.index().next_revision(after)? {
                        after = record.revision_key();
                        if let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) =
                            record
                        {
                            control.$sources(id, &proof, signed.value.revision_id, current)?;
                        }
                    }
                }
                RecoveredCheckpointProof::$variant(Box::new(proof))
            }};
        }
        let proof = match certificate {
            Certificate::Individual(c) => {
                let proof = body
                    .validate_packing(
                        mb_store::CatalogPackingValidation {
                            format_version: 1,
                            scope,
                            descriptors: c.checkpoint.packed_sectors,
                            sources: c.checkpoint.packed_sources,
                        },
                        read,
                    )?
                    .validate_coding_directory(
                        c.checkpoint.coding,
                        mb_store::CatalogCodingCoveragePolicy::Current,
                        |page| control.catalog_page(scope, CatalogSection::Coding, page),
                        authorize,
                    )?;
                promote!(
                    proof,
                    c,
                    retain_catalog_paged_checkpoint,
                    build_catalog_paged_checkpoint_lookup,
                    build_catalog_paged_checkpoint_chunk_index,
                    build_catalog_paged_checkpoint_source_lookup,
                    Individual
                )
            }
            Certificate::Directory(c) => {
                let proof = body
                    .validate_packing_directory(
                        mb_store::CatalogPackingDirectoryValidation {
                            format_version: 1,
                            scope,
                            directory: c.checkpoint.packing,
                        },
                        read,
                    )?
                    .validate_coding_directory(
                        c.checkpoint.coding,
                        mb_store::CatalogCodingCoveragePolicy::Current,
                        |page| control.catalog_page(scope, CatalogSection::Coding, page),
                        authorize,
                    )?;
                promote!(
                    proof,
                    c,
                    retain_catalog_paged_checkpoint_directory,
                    build_catalog_paged_checkpoint_directory_lookup,
                    build_catalog_paged_checkpoint_directory_chunk_index,
                    build_catalog_paged_checkpoint_directory_source_lookup,
                    Directory
                )
            }
        };
        current()?;
        if let ProofInput::Acquisition { job, .. } = input {
            if recovery.is_some() {
                if let Some(tip) = control.checkpoint_recovery_tip()?
                    && tip.owner != id
                {
                    current()?;
                    control.begin_checkpoint_ancestry_archive(tip.owner)?;
                    while control.advance_checkpoint_ancestry_archive(tip.owner)? {
                        current()?;
                    }
                }
                control.finish_checkpoint_recovery_acquisition(job)?;
            } else {
                control.finish_checkpoint_acquisition(job)?;
            }
        }
        Ok(proof)
    }
}

fn acquire_tree(
    control: &ControlStore,
    job: &Job,
    intent: mb_store::CatalogIntent,
    root: CatalogPageRef,
    path: &mut CatalogPagePath,
    fetch: &mut Fetch<'_>,
    guard: &dyn Fn() -> Result<()>,
) -> Result<()> {
    path.validate()?;
    guard()?;
    let page = *path
        .pages
        .last()
        .context("public acquisition path is empty")?;
    let bytes = match control.catalog_page(path.scope, path.section, page) {
        Ok(bytes) => bytes,
        Err(mb_store::CatalogStoreError::Database(mb_store::DatabaseError::NotReady)) => {
            fetch(path.clone())?
        }
        Err(error) => return Err(error.into()),
    };
    if let CatalogPageContents::Index(children) =
        page.verify_page(path.scope, path.section, &bytes)?
    {
        for child in children {
            path.pages.push(child);
            acquire_tree(control, job, intent, root, path, fetch, guard)?;
            path.pages.pop();
        }
    }
    guard()?;
    control.stage_checkpoint_acquisition_page(job, intent, root, page, &bytes)?;
    Ok(())
}

impl Node {
    /// Retain an original READY role under a fully verified recovered public
    /// checkpoint. Later writer/membership projections do not replace its
    /// independently indexed historical authority or physical byte checks.
    pub fn retain_recovered_checkpoint_payload(
        &self,
        id: Uuid,
        proof: &RecoveredCheckpointProof,
        group: [u8; 32],
        shard: u16,
    ) -> Result<mb_store::CatalogCheckpointPayload> {
        proof.verify()?;
        let authority = guild_authority::frozen_original_history(&self.control)?;
        let trust = authority
            .paged_checkpoint_trust_at(proof.trust().event_sequence, proof.trust().previous)?;
        anyhow::ensure!(
            trust == *proof.trust(),
            "recovered payload proof differs from original history"
        );
        let current = || {
            authority
                .check()
                .map_err(|_| mb_store::DatabaseError::Conflict)?;
            Ok(trust.clone())
        };
        let ready = |payload: &mb_store::CatalogCheckpointPayload| -> Result<()> {
            anyhow::ensure!(
                payload.holder == self.keys.node_id(),
                "recovered payload belongs to another holder"
            );
            let ready = self.volumes.load_ready_variable(
                &self.control,
                &payload.storage_id,
                payload.shard_index,
            )?;
            anyhow::ensure!(
                ready.guild_id == payload.guild_id
                    && ready.commitment == payload.commitment
                    && merkle_commit(&ready.bytes)? == payload.commitment,
                "recovered READY bytes differ from their original witness"
            );
            Ok(())
        };
        Ok(match proof {
            RecoveredCheckpointProof::Individual(p) => self
                .control
                .retain_catalog_paged_checkpoint_payload_checked(
                    id, p, group, shard, current, ready,
                )?,
            RecoveredCheckpointProof::Directory(p) => self
                .control
                .retain_catalog_paged_checkpoint_directory_payload_checked(
                    id, p, group, shard, current, ready,
                )?,
        })
    }
}

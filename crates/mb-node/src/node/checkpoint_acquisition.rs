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

type Fetch<'a> = dyn FnMut(CatalogPagePath) -> Result<Vec<u8>> + 'a;

impl RetainedCheckpointRestore {
    pub(crate) fn public_checkpoint_trust(&self) -> Result<mb_core::PagedCheckpointTrust> {
        guild_authority::frozen_original_history(&self.reader.control)?.paged_checkpoint_trust()
    }
    /// Acquire every public tree referenced by the original certificate. The
    /// separately installed original history supplies trust. Returns staging
    /// ownership only; promotion still needs the complete predecessor proof.
    pub fn acquire_public_checkpoint(
        &self,
        id: Uuid,
        certificate: Certificate,
        budget: Work,
        mut fetch: impl FnMut(CatalogPagePath) -> Result<Vec<u8>>,
    ) -> Result<Job> {
        let control = &self.reader.control;
        let authority = guild_authority::frozen_original_history(control)?;
        let trust = authority.paged_checkpoint_trust()?;
        let job = control.begin_checkpoint_acquisition(id, certificate, trust.clone(), budget)?;
        if control.checkpoint_acquisition_state(&job)? == State::Complete {
            return Ok(job);
        }
        let mut acquire = |scope, section, page| -> Result<()> {
            authority.check()?;
            let intent = control.reserve_checkpoint_acquisition_root(&job, scope, section, page)?;
            match control.catalog_intent_state(intent)? {
                mb_store::CatalogIntentState::Building => {
                    let mut path = CatalogPagePath {
                        scope,
                        section,
                        pages: vec![page],
                    };
                    acquire_tree(control, &job, intent, page, &mut path, &mut fetch, &|| {
                        authority.check()
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
            authority.check()
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
        authority.check()?;
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
        let control = &self.reader.control;
        let authority = guild_authority::frozen_original_history(control)?;
        let trust = authority.paged_checkpoint_trust()?;
        control.check_checkpoint_acquisition_trust(job, &trust)?;
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
        let mut source = control;
        let history = mb_store::CatalogGuildHistoryIndex::build(
            scratch()?,
            &installed.certificate,
            job.budget,
            Work::default(),
            || {
                authority
                    .paged_checkpoint_trust()
                    .map_err(|_| mb_store::DatabaseError::Conflict.into())
            },
            &mut source,
        )?;
        let context = mb_store::CatalogCheckpointAuthorityContext {
            guild_id: trust.guild_id,
            generation: trust.next_generation()?,
            event_sequence: trust.event_sequence,
            event_head: trust.event_head,
            authority: trust.authority,
        };
        let body = mb_store::CatalogCheckpointAuthorityIndex::build(
            context,
            job.certificate.authority(),
            &trust.members,
            job.budget,
            scratch()?,
            |scope, section, page| control.catalog_page(scope, section, page),
            |fence, kind| {
                if authority
                    .writer_key_for_retained_revision(fence.owner, fence.epoch)
                    .map_err(|_| mb_store::DatabaseError::Conflict)?
                    != Some(fence.public_key)
                    || (kind == mb_store::CatalogCheckpointWriterAuthorization::LatestRetained
                        && !authority
                            .writer_epoch_is_current(fence.owner, fence.epoch)
                            .map_err(|_| mb_store::DatabaseError::Conflict)?)
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
        let current = || {
            authority
                .paged_checkpoint_trust()
                .map_err(|_| mb_store::DatabaseError::Conflict.into())
        };
        macro_rules! promote {
            ($proof:expr,$certificate:expr,$retain:ident,$lookup:ident,$chunks:ident,$sources:ident) => {{
                let proof = $proof
                    .validate_certified_history_coding_state(&history, job.budget, current)?
                    .validate_certified_history_authority_transition(
                        previous, &history, job.budget, current,
                    )?
                    .bind_paged_checkpoint_header($certificate.clone(), current)?;
                control.$retain(job.id, &proof, current)?;
                control.$lookup(job.id, &proof, current)?;
                control.$chunks(job.id, &proof, current)?;
                let mut after = None;
                while let Some(record) = proof.index().next_revision(after)? {
                    after = record.revision_key();
                    if let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = record
                    {
                        control.$sources(job.id, &proof, signed.value.revision_id, current)?;
                    }
                }
            }};
        }
        match &job.certificate {
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
                    build_catalog_paged_checkpoint_source_lookup
                );
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
                    build_catalog_paged_checkpoint_directory_source_lookup
                );
            }
        }
        authority.check()?;
        control.finish_checkpoint_acquisition(job)?;
        Ok(())
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

//! Original history bootstrap keeps one peer tail and one coding witness live.
//! A locator's tip is a selection hint; every installed event is independently
//! certified and replay-verified by the ordinary durable history validator.
use super::*;
use mb_core::CatalogCodingTraversalBudget as Work;

const JOB: &str = "checkpoint-history-recovery-v1";
const GUARD: &str = "checkpoint-history-recovery-guard-v1";
const BYTES: usize = 32768;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointHistoryTarget {
    pub guild_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub event_sequence: u64,
    pub event_head: [u8; 32],
}
impl CheckpointHistoryTarget {
    pub(crate) fn validate(self) -> Result<()> {
        anyhow::ensure!(
            self.guild_id != [0; 32]
                && self.genesis_hash != [0; 32]
                && self.event_head != [0; 32]
                && self.event_sequence <= i64::MAX as u64
                && (self.event_sequence != 0 || self.event_head == self.genesis_hash),
            "invalid history recovery target"
        );
        Ok(())
    }
    /// Declare the entire selected history's conservative work before peer
    /// fetches. Retries cannot reset this immutable total or its final tip.
    pub fn required_work(self) -> Result<Work> {
        self.validate()?;
        let step = guild_authority::original_history::budget();
        let bytes = step
            .bytes
            .checked_add(crate::network::MAX_PEER_FRAME_BYTES as u64)
            .and_then(|n| n.checked_add((BYTES * 8) as u64))
            .and_then(|n| n.checked_mul(self.event_sequence))
            .and_then(|n| {
                n.checked_add((mb_core::GUILD_AUTHORITY_SNAPSHOT_BYTES * 8 + BYTES * 8) as u64)
            })
            .context("history recovery byte declaration overflow")?;
        let records = step
            .records
            .checked_add(16)
            .and_then(|n| n.checked_mul(self.event_sequence))
            .and_then(|n| n.checked_add(64))
            .context("history recovery record declaration overflow")?;
        Ok(Work {
            bytes,
            records,
            page_occurrences: 0,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CheckpointHistoryRecoveryState {
    Building,
    Complete,
    Cancelled,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointHistoryRecovery {
    pub id: Uuid,
    pub target: CheckpointHistoryTarget,
    pub budget: Work,
    pub capacity: Option<mb_core::CatalogCapacityPolicy>,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct Job {
    version: u16,
    spec: CheckpointHistoryRecovery,
    sequence: u64,
    head: [u8; 32],
    state: CheckpointHistoryRecoveryState,
}
fn read(control: &ControlStore, id: Uuid) -> Result<Option<Job>> {
    let bytes = control.get_record_bounded(JOB, id.as_bytes(), BYTES)?;
    let guard = control.get_record_bounded(GUARD, id.as_bytes(), BYTES)?;
    anyhow::ensure!(bytes == guard, "history recovery job/guard differ");
    bytes
        .map(|bytes| -> Result<Job> {
            let job: Job = decode_canonical(&bytes)?;
            job.spec
                .budget
                .remaining_after(job.spec.target.required_work()?)?;
            anyhow::ensure!(
                job.version == 1
                    && job.spec.id == id
                    && !id.is_nil()
                    && job.sequence <= job.spec.target.event_sequence
                    && job.head != [0; 32]
                    && canonical_bytes(&job)? == bytes,
                "invalid history recovery job"
            );
            if job.state == CheckpointHistoryRecoveryState::Complete {
                anyhow::ensure!(
                    (job.sequence, job.head)
                        == (job.spec.target.event_sequence, job.spec.target.event_head),
                    "incomplete history marked complete"
                );
            }
            Ok(job)
        })
        .transpose()
}
fn check_capacity(control: &ControlStore, job: &Job) -> Result<()> {
    anyhow::ensure!(
        control.catalog_capacity_policy()? == job.spec.capacity,
        "history recovery capacity backing changed"
    );
    Ok(())
}
fn check_tip(control: &ControlStore, job: &Job) -> Result<()> {
    let history = guild_authority::frozen_original_history(control)?;
    let trust = history.paged_checkpoint_trust()?;
    anyhow::ensure!(
        (
            trust.guild_id,
            trust.genesis_hash,
            trust.event_sequence,
            trust.event_head
        ) == (
            job.spec.target.guild_id,
            job.spec.target.genesis_hash,
            job.sequence,
            job.head
        ),
        "history recovery progress differs from original authority"
    );
    history.check()
}
fn require(control: &ControlStore, spec: &CheckpointHistoryRecovery) -> Result<Job> {
    let job = read(control, spec.id)?.context("history recovery job is missing")?;
    anyhow::ensure!(
        job.spec == *spec && job.state != CheckpointHistoryRecoveryState::Cancelled,
        "history recovery was cancelled or substituted"
    );
    check_capacity(control, &job)?;
    check_tip(control, &job)?;
    Ok(job)
}
fn exact(control: &ControlStore, job: &Job) -> Result<()> {
    anyhow::ensure!(
        read(control, job.spec.id)?.as_ref() == Some(job),
        "history recovery state changed"
    );
    check_capacity(control, job)
}
fn replace(control: &ControlStore, old: &Job, next: &Job) -> Result<()> {
    let bytes = canonical_bytes(next)?;
    for kind in [JOB, GUARD] {
        control.replace_record_if_value(
            kind,
            old.spec.id.as_bytes(),
            &canonical_bytes(old)?,
            &bytes,
        )?;
    }
    exact(control, next)
}
impl Node {
    pub(crate) fn begin_checkpoint_history_from_genesis(
        &mut self,
        id: Uuid,
        certificate: QuorumGuildGenesis,
        target: CheckpointHistoryTarget,
        budget: Work,
    ) -> Result<CheckpointHistoryRecovery> {
        budget.remaining_after(target.required_work()?)?;
        mb_core::canonical_size_bounded(&certificate, mb_core::GUILD_AUTHORITY_SNAPSHOT_BYTES)?;
        certificate.verify()?;
        anyhow::ensure!(
            certificate.genesis.guild_id == target.guild_id
                && certificate.hash()? == target.genesis_hash,
            "history recovery genesis differs from its selected target"
        );
        if let Some(bytes) = self.control.get_record_bounded(
            "guild-installed",
            b"primary",
            mb_core::GUILD_AUTHORITY_SNAPSHOT_BYTES,
        )? {
            let installed = decode_installed_guild(&bytes)?;
            anyhow::ensure!(
                installed.certificate == certificate,
                "history recovery has another original genesis"
            );
        } else {
            let peers = certificate
                .genesis
                .members
                .iter()
                .cloned()
                .map(|member| GuildPeer {
                    member,
                    endpoints: Vec::new(),
                })
                .collect();
            self.adopt_recovered_guild(certificate, peers)?;
        }
        self.begin_checkpoint_history_recovery(id, target, budget)
    }
    /// Original genesis must already be adopted with the recovered seed's
    /// original signature/key. A target never substitutes for event authority.
    pub fn begin_checkpoint_history_recovery(
        &self,
        id: Uuid,
        target: CheckpointHistoryTarget,
        budget: Work,
    ) -> Result<CheckpointHistoryRecovery> {
        budget.remaining_after(target.required_work()?)?;
        anyhow::ensure!(!id.is_nil(), "nil history recovery identity");
        let control = &self.control;
        control.with_record_transaction(|| -> Result<CheckpointHistoryRecovery> {
            let spec = CheckpointHistoryRecovery {
                id,
                target,
                budget,
                capacity: control.catalog_capacity_policy()?,
            };
            if let Some(old) = read(control, id)? {
                anyhow::ensure!(
                    old.spec == spec && old.state != CheckpointHistoryRecoveryState::Cancelled,
                    "history recovery identity cannot be reused"
                );
                require(control, &spec)?;
                return Ok(spec);
            }
            let authority = guild_authority::frozen_original_history(control)?;
            let trust = authority.paged_checkpoint_trust()?;
            anyhow::ensure!(
                (trust.guild_id, trust.genesis_hash) == (target.guild_id, target.genesis_hash)
                    && trust.event_sequence <= target.event_sequence,
                "original history differs from recovery target"
            );
            let complete = trust.event_sequence == target.event_sequence;
            anyhow::ensure!(
                !complete || trust.event_head == target.event_head,
                "target names another original history"
            );
            let job = Job {
                version: 1,
                spec: spec.clone(),
                sequence: trust.event_sequence,
                head: trust.event_head,
                state: if complete {
                    CheckpointHistoryRecoveryState::Complete
                } else {
                    CheckpointHistoryRecoveryState::Building
                },
            };
            let bytes = canonical_bytes(&job)?;
            for kind in [JOB, GUARD] {
                anyhow::ensure!(
                    control.put_record_if_absent(kind, id.as_bytes(), &bytes)?,
                    "history recovery insert raced"
                );
            }
            exact(control, &job)?;
            check_tip(control, &job)?;
            Ok(spec)
        })
    }
    pub fn checkpoint_history_recovery_progress(
        &self,
        spec: &CheckpointHistoryRecovery,
    ) -> Result<(CheckpointHistoryRecoveryState, u64, [u8; 32])> {
        self.control.with_record_transaction(|| -> Result<_> {
            let job = read(&self.control, spec.id)?.context("history recovery job is missing")?;
            anyhow::ensure!(job.spec == *spec, "history recovery was substituted");
            if job.state != CheckpointHistoryRecoveryState::Cancelled {
                check_capacity(&self.control, &job)?;
                check_tip(&self.control, &job)?;
            }
            Ok((job.state, job.sequence, job.head))
        })
    }
    /// Full original-history effects and coding witness replay precede the
    /// writer. Event/evidence, compact/indexed authority and job advance share
    /// the existing guarded publication writer, including final readbacks.
    pub(crate) fn install_checkpoint_history_event(
        &self,
        spec: &CheckpointHistoryRecovery,
        event: QuorumGuildEvent,
        transcript: Option<SignedRecord<CodingVerificationTranscript>>,
        binding: Option<QuorumLegacyCodingAddBinding>,
    ) -> Result<()> {
        let control = &self.control;
        let old = require(control, spec)?;
        anyhow::ensure!(
            old.state == CheckpointHistoryRecoveryState::Building
                && event.event.sequence
                    == old
                        .sequence
                        .checked_add(1)
                        .context("history sequence exhausted")?
                && event.event.parent == old.head
                && event.event.sequence <= spec.target.event_sequence,
            "history recovery event is out of order"
        );
        let encoded = mb_core::canonical_bytes_bounded(&event, mb_core::GUILD_EVENT_BYTES)?;
        let hash = event.event.hash()?;
        let mut records = vec![(
            "guild-event".to_owned(),
            event.event.sequence.to_be_bytes().to_vec(),
            encoded,
        )];
        match (event.event.kind.coding_group_add(), transcript) {
            (Some(_), Some(transcript)) => {
                anyhow::ensure!(
                    binding.is_some()
                        == matches!(
                            event.event.kind,
                            mb_core::GuildEventKind::AddCodingGroup { .. }
                        ),
                    "history recovery coding binding differs from the original event kind"
                );
                records.push((
                    "coding-event-transcript".to_owned(),
                    hash.to_vec(),
                    mb_core::canonical_bytes_bounded(
                        &transcript,
                        mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
                    )?,
                ));
                if let Some(binding) = binding {
                    records.push((
                        "coding-legacy-add-binding".to_owned(),
                        hash.to_vec(),
                        mb_core::canonical_bytes_bounded(
                            &binding,
                            mb_core::LEGACY_CODING_ADD_BINDING_BYTES,
                        )?,
                    ));
                }
            }
            (None, None) if binding.is_none() => {}
            _ => anyhow::bail!("history recovery event/evidence mismatch"),
        }
        let complete = event.event.sequence == spec.target.event_sequence;
        anyhow::ensure!(
            !complete || hash == spec.target.event_head,
            "history recovery did not reach its selected tip"
        );
        let next = Job {
            sequence: event.event.sequence,
            head: hash,
            state: if complete {
                CheckpointHistoryRecoveryState::Complete
            } else {
                CheckpointHistoryRecoveryState::Building
            },
            ..old.clone()
        };
        for kind in [JOB, GUARD] {
            records.push((
                kind.to_owned(),
                spec.id.as_bytes().to_vec(),
                canonical_bytes(&next)?,
            ));
        }
        let history = guild_authority::original_history::complete_index(control)?
            .context("history recovery needs original indexing")?;
        let installed = decode_installed_guild(
            &control
                .get_record_bounded(
                    "guild-installed",
                    b"primary",
                    mb_core::GUILD_AUTHORITY_SNAPSHOT_BYTES,
                )?
                .context("history recovery has no original genesis")?,
        )?;
        guild_authority::publish_indexed_recovery_event(
            control,
            &installed,
            &history,
            &event,
            &records,
            |published| {
                exact(control, if published { &next } else { &old })?;
                check_tip(control, if published { &next } else { &old })
            },
        )
    }
    /// Already certified original prefixes remain installed. Cancellation
    /// fences this operation's late peer responses and exact identity reuse.
    pub fn cancel_checkpoint_history_recovery(
        &self,
        spec: &CheckpointHistoryRecovery,
    ) -> Result<()> {
        self.control.with_record_transaction(|| -> Result<()> {
            let old = read(&self.control, spec.id)?.context("history recovery job is missing")?;
            anyhow::ensure!(old.spec == *spec, "history recovery was substituted");
            let next = Job {
                state: CheckpointHistoryRecoveryState::Cancelled,
                ..old.clone()
            };
            replace(&self.control, &old, &next)
        })
    }
}

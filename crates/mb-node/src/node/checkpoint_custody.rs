//! Shared original-authority and local private/READY custody for both public layouts.
use super::*;

impl NodeReader {
    /// Serve one exact retained physical role through original coding roots,
    /// independently of current heads, placement projections or Forget state.
    pub(crate) fn retained_checkpoint_shard(
        &self,
        guild: [u8; 32],
        layout: mb_core::PagedCheckpointLayout,
        owner: Uuid,
        checkpoint_hash: [u8; 32],
        group: [u8; 32],
        index: u16,
    ) -> Result<Vec<u8>> {
        let work = mb_core::CatalogCodingTraversalBudget {
            bytes: 16 * 1024 * 1024,
            page_occurrences: 256,
            records: 512,
        };
        macro_rules! serve {
            ($retention:ident,$group:ident) => {{
                let (retention, state) = self
                    .control
                    .$retention(owner)?
                    .context("retained checkpoint shard owner is unavailable")?;
                anyhow::ensure!(
                    state == mb_store::CatalogPagedCheckpointRetentionState::Published
                        && retention.checkpoint.guild_id == guild
                        && retention.checkpoint.hash()? == checkpoint_hash,
                    "shard request differs from its retained checkpoint"
                );
                let entry = self
                    .control
                    .$group(retention, group, work)?
                    .context("shard lacks its original retained coding witness")?;
                let payload = self
                    .control
                    .catalog_paged_checkpoint_payload(owner, group, index)?
                    .context("shard lacks retained READY custody")?;
                let role = entry
                    .retained
                    .group
                    .roles
                    .get(usize::from(index))
                    .context("retained shard index is outside its original group")?;
                let (holder, storage, commitment) = match role {
                    ShardRoleV2::Information(role) if !role.sector.virtual_zero => {
                        (role.owner, role.sector.id, &role.sector.commitment)
                    }
                    ShardRoleV2::Parity(role) => (role.holder, group, &role.commitment),
                    _ => anyhow::bail!("virtual information has no physical retained shard"),
                };
                anyhow::ensure!(
                    holder == self.keys.node_id()
                        && payload.holder == holder
                        && payload.guild_id == guild
                        && payload.storage_id == storage
                        && payload.commitment == *commitment
                        && payload.transcript_hash
                            == *blake3::hash(&canonical_bytes(&entry.transcript)?).as_bytes(),
                    "retained physical role differs from its original witness"
                );
                let object = self.ready_variable_object(&storage, index)?;
                anyhow::ensure!(
                    object.guild_id == guild
                        && object.commitment == *commitment
                        && merkle_commit(&object.bytes)? == *commitment,
                    "retained shard bytes fail their original commitment"
                );
                let current = self
                    .control
                    .$retention(owner)?
                    .context("retained shard owner disappeared during reading")?;
                anyhow::ensure!(
                    current == (retention, state)
                        && self
                            .control
                            .catalog_paged_checkpoint_payload(owner, group, index)?
                            .as_ref()
                            == Some(&payload),
                    "retained shard custody changed during reading"
                );
                Ok(object.bytes)
            }};
        }
        match layout {
            mb_core::PagedCheckpointLayout::Individual => serve!(
                catalog_paged_checkpoint_retention,
                catalog_paged_checkpoint_indexed_group
            ),
            mb_core::PagedCheckpointLayout::Directory => serve!(
                catalog_paged_checkpoint_directory_retention,
                catalog_paged_checkpoint_directory_indexed_group
            ),
        }
    }
}

impl Node {
    /// Restore the native tree selected by an exact retained checkpoint page.
    /// Original legacy IDs select their independently retained conversion.
    /// The complete staged inode owns publication after the final custody writer;
    /// normal current protection, remote data recovery and Git installation
    /// retain their separate activation/consumer gates.
    #[cfg(target_os = "linux")]
    pub fn restore_retained_checkpoint_native_snapshot(
        &self,
        layout: mb_core::PagedCheckpointLayout,
        owner: Uuid,
        guild_id: [u8; 32],
        snapshot: &SnapshotInfo,
        target: &Path,
        budget: mb_core::CatalogCodingTraversalBudget,
    ) -> Result<()> {
        self.restore_retained_checkpoint_snapshot_inner::<false>(
            layout, owner, guild_id, snapshot, target, budget,
        )
    }

    /// Restore the complete native tree and optional paged Git catalog from
    /// this exact retained checkpoint, including original legacy conversions.
    #[cfg(target_os = "linux")]
    pub fn restore_retained_checkpoint_snapshot(
        &self,
        layout: mb_core::PagedCheckpointLayout,
        owner: Uuid,
        guild_id: [u8; 32],
        snapshot: &SnapshotInfo,
        target: &Path,
        budget: mb_core::CatalogCodingTraversalBudget,
    ) -> Result<()> {
        self.restore_retained_checkpoint_snapshot_inner::<true>(
            layout, owner, guild_id, snapshot, target, budget,
        )
    }

    #[cfg(target_os = "linux")]
    fn restore_retained_checkpoint_snapshot_inner<const FULL: bool>(
        &self,
        layout: mb_core::PagedCheckpointLayout,
        owner: Uuid,
        guild_id: [u8; 32],
        snapshot: &SnapshotInfo,
        target: &Path,
        budget: mb_core::CatalogCodingTraversalBudget,
    ) -> Result<()> {
        let local = |sector: &SectorId| self.sector_for_guild(&guild_id, sector);
        let ready = |payload: &mb_store::CatalogCheckpointPayload| {
            let object = self.volumes.load_ready_variable(
                &self.control,
                &payload.storage_id,
                payload.shard_index,
            )?;
            anyhow::ensure!(
                object.guild_id == payload.guild_id && object.commitment == payload.commitment,
                "retained READY bytes differ from their owner"
            );
            Ok(object.bytes)
        };
        super::checkpoint_restore::restore::<FULL>(
            super::checkpoint_restore::Sources {
                control: &self.control,
                keys: &self.keys,
                local: &local,
                ready: &ready,
            },
            &RetainedSnapshotRestore {
                layout,
                owner,
                guild_id,
                snapshot: snapshot.clone(),
                budget,
            },
            target,
            &mut |_, _| Ok(None),
        )
    }

    /// Build restart-stable lookups from the original completed public proof.
    /// No checkpoint head or distributed protection is published here.
    pub fn build_retained_paged_checkpoint_lookup(
        &self,
        id: Uuid,
        proof: &mb_store::CatalogQuorumPagedCheckpointIndex,
    ) -> Result<()> {
        guild_authority::with_history(&self.control, |authority| {
            self.control
                .build_catalog_paged_checkpoint_lookup(id, proof, || {
                    authority.paged_checkpoint_trust().map_err(|_| {
                        mb_store::CatalogStoreError::Database(mb_store::DatabaseError::Conflict)
                    })
                })?;
            Ok(())
        })?
        .context("checkpoint lookup requires original guild authority")
    }

    /// Retain bounded recovery hints from the complete original public proof.
    /// Original witnesses and full source commitments remain recovery authority.
    pub fn build_retained_paged_checkpoint_chunk_index(
        &self,
        owner: Uuid,
        proof: &mb_store::CatalogQuorumPagedCheckpointIndex,
    ) -> Result<()> {
        guild_authority::with_history(&self.control, |authority| {
            self.control
                .build_catalog_paged_checkpoint_chunk_index(owner, proof, || {
                    authority.paged_checkpoint_trust().map_err(|_| {
                        mb_store::CatalogStoreError::Database(mb_store::DatabaseError::Conflict)
                    })
                })?;
            Ok(())
        })?
        .context("checkpoint recovery index requires original guild authority")
    }

    pub fn build_retained_paged_checkpoint_directory_chunk_index(
        &self,
        owner: Uuid,
        proof: &mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    ) -> Result<()> {
        guild_authority::with_history(&self.control, |authority| {
            self.control
                .build_catalog_paged_checkpoint_directory_chunk_index(owner, proof, || {
                    authority.paged_checkpoint_trust().map_err(|_| {
                        mb_store::CatalogStoreError::Database(mb_store::DatabaseError::Conflict)
                    })
                })?;
            Ok(())
        })?
        .context("checkpoint recovery index requires original guild authority")
    }

    pub fn build_retained_paged_checkpoint_directory_lookup(
        &self,
        id: Uuid,
        proof: &mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    ) -> Result<()> {
        guild_authority::with_history(&self.control, |authority| {
            self.control
                .build_catalog_paged_checkpoint_directory_lookup(id, proof, || {
                    authority.paged_checkpoint_trust().map_err(|_| {
                        mb_store::CatalogStoreError::Database(mb_store::DatabaseError::Conflict)
                    })
                })?;
            Ok(())
        })?
        .context("checkpoint lookup requires original guild authority")
    }

    /// Visit a bounded number of authenticated revision records from an exact
    /// retained checkpoint. This lists local history metadata; current-state
    /// activation and remote availability must be established by the caller.
    pub fn retained_checkpoint_snapshot_page(
        &self,
        layout: mb_core::PagedCheckpointLayout,
        owner: Uuid,
        checkpoint_hash: [u8; 32],
        after: Option<mb_core::CatalogCheckpointRevisionKey>,
        limit: u16,
        page_budget: mb_core::CatalogCodingTraversalBudget,
    ) -> Result<(
        Vec<SnapshotInfo>,
        Option<mb_core::CatalogCheckpointRevisionKey>,
    )> {
        anyhow::ensure!(
            limit > 0 && limit <= 1024,
            "snapshot page limit is outside the admitted range"
        );
        let read_budget = mb_core::CatalogCodingTraversalBudget {
            bytes: page_budget.bytes / u64::from(limit),
            page_occurrences: page_budget.page_occurrences / u64::from(limit),
            records: page_budget.records / u64::from(limit),
        };
        let mut cursor = after;
        let mut snapshots = Vec::new();
        macro_rules! page {
            ($retention:ident,$next:ident) => {{
                let (retention, state) = self
                    .control
                    .$retention(owner)?
                    .context("retained checkpoint owner is unavailable")?;
                anyhow::ensure!(
                    state == mb_store::CatalogPagedCheckpointRetentionState::Published
                        && retention.checkpoint.hash()? == checkpoint_hash,
                    "snapshot page belongs to another checkpoint owner"
                );
                for _ in 0..limit {
                    let Some(record) = self.control.$next(retention, cursor, read_budget)? else {
                        return Ok((snapshots, None));
                    };
                    let key = record
                        .revision_key()
                        .context("checkpoint index returned a nonrevision record")?;
                    cursor = Some(key);
                    if key.owner == self.keys.node_id() {
                        snapshots.push(SnapshotInfo {
                            protected_root_id: key.protected_root_id,
                            revision_id: key.revision_id,
                            sequence: key.sequence,
                            checkpoint_generation: retention.checkpoint.generation,
                            checkpoint_hash,
                        });
                    }
                }
            }};
        }
        match layout {
            mb_core::PagedCheckpointLayout::Individual => page!(
                catalog_paged_checkpoint_retention,
                next_catalog_paged_checkpoint_indexed_revision
            ),
            mb_core::PagedCheckpointLayout::Directory => page!(
                catalog_paged_checkpoint_directory_retention,
                next_catalog_paged_checkpoint_directory_indexed_revision
            ),
        }
        Ok((snapshots, cursor))
    }

    /// Retain independently admitted pending packing output under the actual
    /// original-history base. Reservations remain unfinished; existing bytes
    /// authenticate without creating availability evidence or advancing heads.
    /// The enclosing producer still owns complete source/output proof and pages.
    pub fn retain_paged_packing_payload(
        &self,
        retention: mb_store::CatalogPackingPayloadRetention,
        payload: &mb_store::CatalogPackingPayload,
    ) -> Result<()> {
        let policy = self
            .control
            .catalog_capacity_policy()?
            .context("packing output requires explicit capacity admission")?;
        anyhow::ensure!(
            retention.budget == policy.plan()?.job_work
                && payload.guild_id == retention.base.guild_id
                && self
                    .control
                    .record_quota_usage()?
                    .is_some_and(|usage| usage.state == mb_store::DatabaseRecordQuotaState::Active)
                && self.control.page_quota_usage()?.is_some()
                && self.control.journal_quota_usage()?.is_some()
                && self.control.catalog_storage_usage()?.is_some()
                && self
                    .control
                    .catalog_guild_storage_usage(payload.guild_id)?
                    .is_some(),
            "packing output requires active database and guild admission"
        );
        let authority = guild_authority::frozen_original_history(&self.control)?;
        anyhow::ensure!(
            authority.snapshot().guild_id == payload.guild_id
                && authority
                    .snapshot()
                    .active_members()
                    .any(|member| member.node_id == self.keys.node_id()),
            "packing output owner is not a current guild member"
        );
        let guard = |_: &mb_store::CatalogPackingPayloadView<'_>| -> Result<()> {
            authority.check()?;
            self.control.check_catalog_capacity_policy(policy)?;
            anyhow::ensure!(
                self.control.checkpoint_head_identity(&payload.guild_id)?
                    == Some((retention.base.generation, retention.base.checkpoint_hash)),
                "packing output checkpoint base changed"
            );
            Ok(())
        };
        self.control
            .begin_catalog_packing_payload_retention(retention, guard)?;
        self.control.retain_catalog_packing_payload_checked(
            retention,
            payload,
            (guard, |payload| {
                self.volumes.verify_packing_payload(&self.control, payload)
            }),
        )?;
        authority.check()?;
        Ok(())
    }

    pub fn close_paged_packing_payloads(
        &self,
        retention: mb_store::CatalogPackingPayloadRetention,
    ) -> Result<()> {
        self.control
            .cancel_catalog_packing_payload_retention(retention)?;
        Ok(())
    }

    pub fn release_paged_packing_payload_step(
        &self,
        retention: mb_store::CatalogPackingPayloadRetention,
    ) -> Result<bool> {
        Ok(self.control.release_catalog_packing_payload(retention)?)
    }

    /// Borrow this node's exact published paged source before packing reads.
    /// The enclosing producer still supplies complete original source/candidate
    /// authority. Current indexed membership/base and private seed ownership
    /// are checked independently; no backup head or protection is published.
    pub fn retain_paged_packing_source(
        &self,
        source: mb_store::CatalogPackingSourceRetention,
        signed: &SignedRecord<mb_core::PagedUserRevision>,
    ) -> Result<()> {
        anyhow::ensure!(
            signed.value.owner == self.keys.node_id()
                && signed.value.guild_id == source.base.guild_id,
            "packing private source belongs to another owner or guild"
        );
        let policy = self
            .control
            .catalog_capacity_policy()?
            .context("packing sources require explicit capacity admission")?;
        anyhow::ensure!(
            source.budget == policy.plan()?.job_work
                && self
                    .control
                    .record_quota_usage()?
                    .is_some_and(|usage| usage.state == mb_store::DatabaseRecordQuotaState::Active)
                && self.control.page_quota_usage()?.is_some()
                && self.control.journal_quota_usage()?.is_some()
                && self.control.catalog_storage_usage()?.is_some()
                && self
                    .control
                    .catalog_dataset_storage_usage(signed.value.scope())?
                    .is_some()
                && self
                    .control
                    .catalog_guild_storage_usage(source.base.guild_id)?
                    .is_some(),
            "packing sources require active database and scoped admission"
        );
        let authority = guild_authority::frozen_original_history(&self.control)?;
        anyhow::ensure!(
            authority.snapshot().guild_id == source.base.guild_id
                && authority
                    .snapshot()
                    .active_members()
                    .any(|member| member.node_id == self.keys.node_id()),
            "packing source owner is not a current guild member"
        );
        let guard = |_: &mb_store::CatalogPackingSourceView<'_>| -> Result<()> {
            authority.check()?;
            self.control.check_catalog_capacity_policy(policy)?;
            anyhow::ensure!(
                self.control
                    .checkpoint_head_identity(&source.base.guild_id)?
                    == Some((source.base.generation, source.base.checkpoint_hash)),
                "packing source checkpoint base changed"
            );
            Ok(())
        };
        self.control
            .begin_catalog_packing_source_retention(source, guard)?;
        self.control.retain_catalog_packing_source_checked(
            source,
            signed,
            (guard, |_, snapshot| -> Result<()> {
                let opened = crate::PagedPrivateMetadata::open_local_snapshot(
                    &self.keys,
                    snapshot,
                    signed.value.scope(),
                )?;
                anyhow::ensure!(
                    opened.private.is_some() && opened.revision == *signed,
                    "packing private source is retired or changed"
                );
                Ok(())
            }),
        )?;
        authority.check()?;
        Ok(())
    }

    /// Fence further source borrowing while retaining all existing loans.
    /// Successful handoff and failed-operation cleanup both close this source
    /// owner; the enclosing packing operation has its own completion state.
    pub fn close_paged_packing_sources(
        &self,
        source: mb_store::CatalogPackingSourceRetention,
    ) -> Result<()> {
        self.control
            .cancel_catalog_packing_source_retention(source)?;
        Ok(())
    }

    pub fn release_paged_packing_source_step(
        &self,
        source: mb_store::CatalogPackingSourceRetention,
    ) -> Result<bool> {
        Ok(self.control.release_catalog_packing_source(source)?)
    }
}

macro_rules! custody_reads {
    ($node:ty) => {
        impl $node {
            /// Original retained certificate; the caller must independently
            /// verify its historical quorum, identity and complete body.
            pub fn retained_paged_checkpoint_certificate(
                &self,
                guild_id: [u8; 32],
                layout: mb_core::PagedCheckpointLayout,
                id: Uuid,
                checkpoint_hash: [u8; 32],
            ) -> Result<Vec<u8>> {
                self.control
                    .catalog_retained_paged_checkpoint_certificate(
                        layout,
                        guild_id,
                        id,
                        checkpoint_hash,
                    )?
                    .context("paged checkpoint metadata owner is not published")
            }

            /// Fetch only public metadata reachable from this owner's exact
            /// root. No private file or Git plaintext is served by this path.
            pub fn retained_paged_checkpoint_public_page(
                &self,
                guild_id: [u8; 32],
                layout: mb_core::PagedCheckpointLayout,
                id: Uuid,
                checkpoint_hash: [u8; 32],
                path: &mb_core::CatalogPagePath,
            ) -> Result<Vec<u8>> {
                let path_guild = match path.scope {
                    mb_core::CatalogScope::Guild { guild_id }
                    | mb_core::CatalogScope::Dataset { guild_id, .. } => guild_id,
                };
                anyhow::ensure!(
                    path_guild == guild_id,
                    "paged checkpoint path belongs to another guild"
                );
                self.control
                    .catalog_retained_paged_checkpoint_public_page(
                        layout,
                        id,
                        checkpoint_hash,
                        path,
                    )?
                    .context("paged checkpoint metadata owner is not published")
            }
        }
    };
}
custody_reads!(Node);
custody_reads!(NodeReader);

macro_rules! custody {
    ($proof:ty, $retention:ty, $metadata:ident, $revision:ident, $payload:ident,
     $retain:ident, $retain_revision:ident, $retain_payload:ident,
     $step:ident, $retain_step:ident, $legacy:ident, $retain_legacy:ident,
     $handoff:ident, $transfer:ident) => {
        impl Node {
            /// Hand one closed packing-source loan to the exact original-history
            /// successor checkpoint in one writer, with seed/private, current
            /// base/event and complete public proof guards. Payload availability
            /// and checkpoint activation remain required separate operations.
            pub fn $handoff(
                &self,
                source: mb_store::CatalogPackingSourceRetention,
                id: Uuid,
                proof: &$proof,
                key: mb_core::CatalogCheckpointRevisionKey,
            ) -> Result<()> {
                anyhow::ensure!(
                    key.owner == self.keys.node_id(),
                    "packing source belongs to another owner"
                );
                guild_authority::with_history(&self.control, |authority| {
                    self.control.$transfer(
                        source,
                        id,
                        proof,
                        key,
                        || {
                            authority.paged_checkpoint_trust().map_err(|_| {
                                mb_store::CatalogStoreError::Database(
                                    mb_store::DatabaseError::Conflict,
                                )
                            })
                        },
                        |snapshot| -> Result<()> {
                            let opened = crate::PagedPrivateMetadata::open_local_snapshot(
                                &self.keys,
                                snapshot,
                                snapshot.bundle.scope,
                            )?;
                            anyhow::ensure!(
                                opened.private.is_some(),
                                "packing private source is retired"
                            );
                            Ok(())
                        },
                    )?;
                    Ok(())
                })?
                .context("packing handoff requires original guild authority")
            }
            /// Retain this node's existing authenticated conversion for an
            /// original legacy revision. The checkpoint keeps the old signed
            /// identity; the conversion stays a separate local private owner.
            pub fn $legacy(
                &self,
                id: Uuid,
                proof: &$proof,
                key: mb_core::CatalogCheckpointRevisionKey,
                migration: Uuid,
            ) -> Result<()> {
                anyhow::ensure!(
                    key.owner == self.keys.node_id(),
                    "private checkpoint revision belongs to another owner"
                );
                guild_authority::with_history(&self.control, |authority| {
                    self.control.$retain_legacy(
                        id,
                        proof,
                        key,
                        migration,
                        || {
                            authority.paged_checkpoint_trust().map_err(|_| {
                                mb_store::CatalogStoreError::Database(
                                    mb_store::DatabaseError::Conflict,
                                )
                            })
                        },
                        |snapshot, legacy| -> Result<()> {
                            crate::RetainedLegacyMigration::load(
                                &self.control,
                                &self.keys,
                                migration,
                            )?
                            .context("checkpoint requires the original retained migration")?
                            .check_checkpoint_custody(
                                &self.control,
                                &self.keys,
                                legacy,
                                snapshot,
                            )?;
                            let opened = crate::PagedPrivateMetadata::open_local_snapshot(
                                &self.keys,
                                snapshot,
                                snapshot.bundle.scope,
                            )?;
                            anyhow::ensure!(
                                opened.private.is_some(),
                                "checkpoint private revision is retired"
                            );
                            Ok(())
                        },
                    )?;
                    Ok(())
                })?
                .context("paged checkpoint requires original guild authority")
            }
            /// Acquire one local private revision or one bounded group's local
            /// READY assignments under this exact metadata owner. Durable progress
            /// resumes after reopen. Complete is local custody, not distributed
            /// protection or permission to activate a checkpoint.
            pub fn $step(
                &self,
                id: Uuid,
                proof: &$proof,
            ) -> Result<mb_store::CatalogCheckpointLocalCustody> {
                guild_authority::with_history(&self.control, |authority| {
                    self.control.$retain_step(
                        id,
                        proof,
                        self.keys.node_id(),
                        || {
                            authority.paged_checkpoint_trust().map_err(|_| {
                                mb_store::CatalogStoreError::Database(
                                    mb_store::DatabaseError::Conflict,
                                )
                            })
                        },
                        |snapshot| -> Result<()> {
                            let opened = crate::PagedPrivateMetadata::open_local_snapshot(
                                &self.keys,
                                snapshot,
                                snapshot.bundle.scope,
                            )?;
                            anyhow::ensure!(
                                opened.private.is_some(),
                                "checkpoint private revision is retired"
                            );
                            Ok(())
                        },
                        |payload| -> Result<()> {
                            anyhow::ensure!(
                                payload.holder == self.keys.node_id(),
                                "checkpoint payload belongs to another holder"
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
                                "checkpoint READY payload differs from its original coding witness"
                            );
                            Ok(())
                        },
                    )
                })?
                .context("paged checkpoint requires original guild authority")
            }

            /// Stage the complete public metadata owner against independently checked
            /// original events and the actual current predecessor. This does not
            /// publish/activate a protected checkpoint or replace private/payload owners.
            pub fn $metadata(&self, id: Uuid, proof: &$proof) -> Result<$retention> {
                guild_authority::with_history(&self.control, |authority| {
                    Ok(self.control.$retain(id, proof, || {
                        authority.paged_checkpoint_trust().map_err(|_| {
                            mb_store::CatalogStoreError::Database(mb_store::DatabaseError::Conflict)
                        })
                    })?)
                })?
                .context("paged checkpoint requires original guild authority")
            }

            /// Keep this node's authenticated private bundle and its existing payload
            /// pins live for a revision in the exact public checkpoint proof. Complete
            /// information/parity custody is still required before activation.
            pub fn $revision(
                &self,
                id: Uuid,
                proof: &$proof,
                key: mb_core::CatalogCheckpointRevisionKey,
            ) -> Result<()> {
                anyhow::ensure!(
                    key.owner == self.keys.node_id(),
                    "private checkpoint revision belongs to another owner"
                );
                guild_authority::with_history(&self.control, |authority| {
                    self.control.$retain_revision(
                        id,
                        proof,
                        key,
                        || {
                            authority.paged_checkpoint_trust().map_err(|_| {
                                mb_store::CatalogStoreError::Database(
                                    mb_store::DatabaseError::Conflict,
                                )
                            })
                        },
                        |snapshot| -> Result<()> {
                            let opened = crate::PagedPrivateMetadata::open_local_snapshot(
                                &self.keys,
                                snapshot,
                                snapshot.bundle.scope,
                            )?;
                            anyhow::ensure!(
                                opened.private.is_some(),
                                "checkpoint private revision is retired"
                            );
                            Ok(())
                        },
                    )?;
                    Ok(())
                })?
                .context("paged checkpoint requires original guild authority")
            }

            /// Retain one actual local READY role from the original quorum-bound
            /// checkpoint. Full bytes are checked while the control writer excludes GC.
            pub fn $payload(
                &self,
                id: Uuid,
                proof: &$proof,
                group: [u8; 32],
                shard: u16,
            ) -> Result<mb_store::CatalogCheckpointPayload> {
                guild_authority::with_history(&self.control, |authority| {
                    self.control.$retain_payload(
                        id,
                        proof,
                        group,
                        shard,
                        || {
                            authority.paged_checkpoint_trust().map_err(|_| {
                                mb_store::CatalogStoreError::Database(
                                    mb_store::DatabaseError::Conflict,
                                )
                            })
                        },
                        |payload| -> Result<()> {
                            anyhow::ensure!(
                                payload.holder == self.keys.node_id(),
                                "checkpoint payload belongs to another holder"
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
                                "checkpoint READY payload differs from its original coding witness"
                            );
                            Ok(())
                        },
                    )
                })?
                .context("paged checkpoint requires original guild authority")
            }
        }
    };
}
custody!(
    mb_store::CatalogQuorumPagedCheckpointIndex,
    mb_store::CatalogPagedCheckpointRetention,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_revision,
    retain_paged_checkpoint_local_payload,
    retain_catalog_paged_checkpoint,
    retain_catalog_paged_checkpoint_revision_checked,
    retain_catalog_paged_checkpoint_payload_checked,
    retain_paged_checkpoint_local_custody_step,
    retain_catalog_paged_checkpoint_local_custody_step_checked,
    retain_paged_checkpoint_local_legacy_revision,
    retain_catalog_paged_checkpoint_legacy_revision_checked,
    handoff_paged_packing_source_to_checkpoint,
    handoff_catalog_packing_source_to_paged_checkpoint_checked
);
custody!(
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    mb_store::CatalogPagedCheckpointDirectoryRetention,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_revision,
    retain_paged_checkpoint_directory_local_payload,
    retain_catalog_paged_checkpoint_directory,
    retain_catalog_paged_checkpoint_directory_revision_checked,
    retain_catalog_paged_checkpoint_directory_payload_checked,
    retain_paged_checkpoint_directory_local_custody_step,
    retain_catalog_paged_checkpoint_directory_local_custody_step_checked,
    retain_paged_checkpoint_directory_local_legacy_revision,
    retain_catalog_paged_checkpoint_directory_legacy_revision_checked,
    handoff_paged_packing_source_to_checkpoint_directory,
    handoff_catalog_packing_source_to_paged_checkpoint_directory_checked
);

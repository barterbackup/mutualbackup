//! Normal coverage and replacement planning share one frozen original-history
//! stream. Accumulated coding history is never collected by indexed callers.
use super::*;
use guild_authority::original_history::AuthorityReader;

enum Target<'a> {
    Sector {
        owner: NodeId,
        reference: &'a SectorRef,
        commitment: Option<&'a mb_core::MerkleCommitment>,
        allow_legacy_root: bool,
        require_full_root_binding: bool,
    },
    Packed(&'a PackedSectorDescriptor),
}

impl Target<'_> {
    fn allows_legacy_placement(&self) -> bool {
        matches!(
            self,
            Self::Sector {
                allow_legacy_root: true,
                ..
            }
        )
    }
    fn information_index(&self, group: &mb_core::CodingGroupV2) -> Option<usize> {
        let index = group.roles.iter().position(|role| {
            let ShardRoleV2::Information(information) = role else {
                return false;
            };
            if information.sector.virtual_zero {
                return false;
            }
            match self {
                Self::Packed(descriptor) => {
                    information.sector.id == descriptor.id
                        && information.sector.logical_len == descriptor.commitment.byte_len
                        && information.sector.commitment == descriptor.commitment
                }
                Self::Sector {
                    owner, reference, ..
                } => {
                    information.owner == *owner
                        && information.sector.id == reference.id
                        && information.sector.logical_len == reference.logical_len
                        && information.sector.commitment.byte_len == V1_SECTOR_SIZE as u32
                }
            }
        })?;
        if let Self::Sector {
            commitment: Some(expected),
            require_full_root_binding: true,
            ..
        } = self
        {
            let ShardRoleV2::Information(information) = &group.roles[index] else {
                unreachable!()
            };
            if information.sector.commitment != **expected {
                return None;
            }
        }
        Some(index)
    }

    fn covered(&self, transcript: &SignedRecord<CodingVerificationTranscript>) -> bool {
        let group = &transcript.value.manifest.value.group;
        let Some(index) = self.information_index(group) else {
            return false;
        };
        let plan = &transcript.value.plan.value;
        match self {
            Self::Packed(descriptor) => {
                (descriptor.flat_root == descriptor.commitment.root || plan.format_version == 3)
                    && plan.information_root(index) == Some(descriptor.flat_root)
            }
            Self::Sector {
                reference,
                commitment,
                allow_legacy_root,
                require_full_root_binding,
                ..
            } => {
                let root_matches = plan.information_root(index) == Some(reference.root);
                if *require_full_root_binding {
                    plan.format_version == 3 && root_matches
                } else {
                    let ShardRoleV2::Information(information) = &group.roles[index] else {
                        unreachable!()
                    };
                    root_matches
                        || plan.format_version == 1
                            && (*allow_legacy_root
                                || commitment.is_some_and(|expected| {
                                    information.sector.commitment == *expected
                                }))
                }
            }
        }
    }
}

impl Node {
    fn current_variable_coverage(
        &self,
        authority: &AuthorityReader<'_>,
        targets: &[Target<'_>],
        include: impl Fn(&mb_core::CodingGroupV2) -> bool,
    ) -> Result<Vec<bool>> {
        let mut covered = vec![false; targets.len()];
        authority.for_each_retained_group(|retained| {
            let group = &retained.group;
            let current_placement = authority
                .snapshot()
                .validate_current_group_placement(group)
                .is_ok();
            if retained.retired_at_event.is_some()
                || !include(group)
                || !targets.iter().zip(&covered).any(|(target, covered)| {
                    !covered
                        && (current_placement || target.allows_legacy_placement())
                        && target.information_index(group).is_some()
                })
            {
                return Ok(());
            }
            // Missing evidence cannot establish coverage. Present evidence is
            // bounded before allocation and must be the original Add witness.
            if self
                .control
                .record_length("coding-group-transcript", &group.id)?
                .is_none()
            {
                return Ok(());
            }
            let transcript = coding_transcript_for_group_from_store(
                &self.control,
                authority.snapshot().guild_id,
                group.id,
            )?;
            authority.validate_retained_coding_transcript(&transcript)?;
            for (target, covered) in targets.iter().zip(&mut covered) {
                *covered |= (current_placement || target.allows_legacy_placement())
                    && target.covered(&transcript);
            }
            Ok(())
        })?;
        Ok(covered)
    }

    pub(super) fn validate_current_variable_checkpoint_coverage(
        &self,
        checkpoint: &GuildCheckpoint,
        authority: &AuthorityReader<'_>,
    ) -> Result<()> {
        if authority.snapshot().guild_id != checkpoint.guild_id {
            anyhow::bail!("checkpoint and dynamic guild state differ");
        }
        let hash = checkpoint.hash()?;
        let previous_head = self
            .control
            .checkpoint_head_identity(&checkpoint.guild_id)?;
        let previous =
            self.control
                .checkpoint_head(&checkpoint.guild_id)?
                .filter(|(generation, head, _)| {
                    *generation == checkpoint.generation && *head == hash
                        || generation.checked_add(1) == Some(checkpoint.generation)
                            && checkpoint.parent == Some(*head)
                });
        let exact_head = previous.as_ref().is_some_and(|(generation, head, _)| {
            *generation == checkpoint.generation && *head == hash
        });
        let previous_revisions = previous
            .map(|(_, _, bytes)| decode_canonical::<QuorumCheckpoint>(&bytes))
            .transpose()?
            .map(|previous| previous.checkpoint.revisions);
        let legacy = checkpoint
            .coding_groups
            .iter()
            .flat_map(|group| &group.roles)
            .filter_map(|role| match role {
                ShardRole::Information(information) => Some(information.sector.id),
                ShardRole::Parity(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let mut targets = Vec::new();
        for revision in &checkpoint.revisions {
            if authority.writer_key_for_retained_revision(
                revision.value.owner,
                revision.value.writer_epoch,
            )? != Some(revision.value.writer_public_key)
            {
                anyhow::bail!(
                    "checkpoint revision writer is absent from the authenticated guild history"
                );
            }
            if !previous_revisions
                .as_ref()
                .is_some_and(|previous| previous.contains(revision))
                && !authority
                    .writer_epoch_is_current(revision.value.owner, revision.value.writer_epoch)?
            {
                anyhow::bail!("checkpoint revision was signed by a superseded writer epoch");
            }
            for (index, reference) in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
                .enumerate()
            {
                if checkpoint.format_version != 7 && !legacy.contains(&reference.id) {
                    targets.push(Target::Sector {
                        owner: revision.value.owner,
                        reference,
                        commitment: revision
                            .value
                            .sector_commitments
                            .as_ref()
                            .and_then(|commitments| commitments.get(index)),
                        allow_legacy_root: exact_head,
                        require_full_root_binding: !exact_head,
                    });
                }
            }
        }
        if let Some(catalog) = &checkpoint.packing_catalog {
            targets.extend(catalog.sectors.iter().map(Target::Packed));
        }
        // Exact-head legacy sector compatibility preserves historical placement;
        // packed coverage still requires the current placement.
        if self
            .current_variable_coverage(authority, &targets, |_| true)?
            .iter()
            .any(|covered| !covered)
        {
            anyhow::bail!(
                "checkpoint sector has no verified variable coding group bound to its revision"
            );
        }
        if self
            .control
            .checkpoint_head_identity(&checkpoint.guild_id)?
            != previous_head
        {
            anyhow::bail!("checkpoint head changed during variable coverage validation");
        }
        Ok(())
    }

    pub(crate) fn uncovered_variable_sectors(
        &self,
        owner: NodeId,
        sectors: &[SectorRef],
        commitments: Option<&[mb_core::MerkleCommitment]>,
    ) -> Result<Vec<SectorRef>> {
        if commitments.is_some_and(|commitments| commitments.len() != sectors.len()) {
            anyhow::bail!("revision sector commitments do not align with its sectors");
        }
        guild_authority::with_history(&self.control, |authority| {
            let targets = sectors
                .iter()
                .enumerate()
                .map(|(index, reference)| Target::Sector {
                    owner,
                    reference,
                    commitment: commitments.and_then(|commitments| commitments.get(index)),
                    allow_legacy_root: false,
                    require_full_root_binding: true,
                })
                .collect::<Vec<_>>();
            let covered = self.current_variable_coverage(authority, &targets, |_| true)?;
            Ok(sectors
                .iter()
                .zip(covered)
                .filter(|(_, covered)| !covered)
                .map(|(sector, _)| sector.clone())
                .collect())
        })?
        .context("variable coverage requires dynamic guild state")
    }

    pub(crate) fn uncovered_packed_sectors(
        &self,
        descriptors: &[PackedSectorDescriptor],
    ) -> Result<Vec<PackedSectorDescriptor>> {
        self.uncovered_current_packed_sectors(descriptors, false)
    }

    pub(crate) fn packed_sectors_for_group_replacement(
        &self,
        descriptors: &[PackedSectorDescriptor],
    ) -> Result<Vec<PackedSectorDescriptor>> {
        self.uncovered_current_packed_sectors(descriptors, true)
    }

    fn uncovered_current_packed_sectors(
        &self,
        descriptors: &[PackedSectorDescriptor],
        replacement: bool,
    ) -> Result<Vec<PackedSectorDescriptor>> {
        guild_authority::with_history(&self.control, |authority| {
            let targets = descriptors.iter().map(Target::Packed).collect::<Vec<_>>();
            let live = descriptors.iter().map(|descriptor| descriptor.id).collect::<BTreeSet<_>>();
            let covered = self.current_variable_coverage(authority, &targets, |group| {
                !replacement || group.roles.iter().all(|role| {
                    !matches!(role, ShardRoleV2::Information(information)
                        if !information.sector.virtual_zero && !live.contains(&information.sector.id))
                })
            })?;
            Ok(descriptors.iter().zip(covered).filter(|(_, covered)| !covered).map(|(descriptor, _)| descriptor.clone()).collect())
        })?.context("packed coverage requires dynamic guild state")
    }
}

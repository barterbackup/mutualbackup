//! Independent checkpoint restore sessions retain the original directory lease.
//! Source and peer I/O precede the short final retained custody writer.
use super::*;

/// One exact retained selection; availability is proved by fetched bytes.
#[derive(Clone, Debug)]
pub struct RetainedSnapshotRestore {
    pub layout: mb_core::PagedCheckpointLayout,
    pub owner: Uuid,
    pub guild_id: [u8; 32],
    pub snapshot: SnapshotInfo,
    pub budget: mb_core::CatalogCodingTraversalBudget,
}

/// The holder's independently retained owner for this same checkpoint.
#[derive(Clone, Copy, Debug)]
pub struct RetainedCheckpointPeer {
    pub node_id: NodeId,
    pub owner_id: Uuid,
}

/// A dedicated writable journal connection and directory lease. This session
/// needs no Node mutation lock while reading local or remote original roles.
pub struct RetainedCheckpointRestore {
    reader: NodeReader,
}

pub(super) struct Sources<'a> {
    pub control: &'a ControlStore,
    pub keys: &'a KeyMaterial,
    pub local: &'a dyn Fn(&SectorId) -> Result<Vec<u8>>,
    pub ready: &'a dyn Fn(&mb_store::CatalogCheckpointPayload) -> Result<Vec<u8>>,
}

type FetchRole<'a> = dyn FnMut(&mb_core::CatalogCodingEntry, u16) -> Result<Option<Vec<u8>>> + 'a;

impl Node {
    pub fn retained_checkpoint_restore(&self) -> Result<RetainedCheckpointRestore> {
        Ok(RetainedCheckpointRestore {
            reader: self.reader_config().open_for_retained_restore()?,
        })
    }
}

impl RetainedCheckpointRestore {
    /// Fetch receives one bounded original root-authenticated coding witness
    /// and its exact role index. Every returned shard is fully authenticated.
    /// Returning None permits another original role to satisfy reconstruction.
    pub fn restore(
        &self,
        request: &RetainedSnapshotRestore,
        target: &Path,
        mut fetch: impl FnMut(&mb_core::CatalogCodingEntry, u16) -> Result<Option<Vec<u8>>>,
    ) -> Result<()> {
        let local = |sector: &SectorId| self.reader.sector_for_guild(&request.guild_id, sector);
        let ready = |payload: &mb_store::CatalogCheckpointPayload| {
            let object = self
                .reader
                .ready_variable_object(&payload.storage_id, payload.shard_index)?;
            anyhow::ensure!(
                object.guild_id == payload.guild_id && object.commitment == payload.commitment,
                "retained READY bytes differ from their owner"
            );
            Ok(object.bytes)
        };
        restore::<true>(
            Sources {
                control: &self.reader.control,
                keys: &self.reader.keys,
                local: &local,
                ready: &ready,
            },
            request,
            target,
            &mut fetch,
        )
    }
}

pub(super) fn restore<const FULL: bool>(
    sources: Sources<'_>,
    request: &RetainedSnapshotRestore,
    target: &Path,
    fetch: &mut FetchRole<'_>,
) -> Result<()> {
    let RetainedSnapshotRestore {
        layout,
        owner,
        guild_id,
        snapshot,
        budget,
    } = request;
    let (layout, owner, guild_id, budget) = (*layout, *owner, *guild_id, *budget);
    let version = if FULL { 4 } else { 3 };
    anyhow::ensure!(
        !owner.is_nil()
            && !snapshot.revision_id.is_nil()
            && !snapshot.protected_root_id.is_nil()
            && snapshot.checkpoint_hash != [0; 32],
        "retained snapshot identity is invalid"
    );
    let key = mb_core::CatalogCheckpointRevisionKey {
        owner: sources.keys.node_id(),
        protected_root_id: snapshot.protected_root_id,
        sequence: snapshot.sequence,
        revision_id: snapshot.revision_id,
    };
    let mut identity = blake3::Hasher::new_derive_key(if FULL {
        "mutualbackup retained checkpoint complete restore v1"
    } else {
        "mutualbackup retained checkpoint native restore v1"
    });
    identity.update(&canonical_bytes(&(
        layout,
        owner,
        guild_id,
        key,
        snapshot.checkpoint_generation,
        snapshot.checkpoint_hash,
    ))?);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&identity.finalize().as_bytes()[..16]);
    let operation = Uuid::from_bytes(bytes);
    if crate::snapshot::resume_matching_restore_publication(
        sources.control,
        guild_id,
        operation,
        version,
        target,
    )? {
        return Ok(());
    }
    macro_rules! restore {
        ($retention:ident,$point:ident,$publish:ident,$chunk:ident,$group:ident) => {{
            let (retention, state) = sources
                .control
                .$retention(owner)?
                .context("retained checkpoint is unavailable")?;
            anyhow::ensure!(
                state == mb_store::CatalogPagedCheckpointRetentionState::Published
                    && retention.checkpoint.guild_id == guild_id
                    && retention.checkpoint.generation == snapshot.checkpoint_generation
                    && retention.checkpoint.hash()? == snapshot.checkpoint_hash,
                "native snapshot belongs to another retained checkpoint"
            );
            let record = sources
                .control
                .$point(retention, key.revision_id, budget)?
                .context("retained snapshot revision is unavailable")?;
            anyhow::ensure!(
                record.revision_key() == Some(key),
                "native snapshot revision identity differs"
            );
            let catalog = match &record {
                mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) => {
                    let catalog = sources
                        .control
                        .catalog_paged_checkpoint_revision(owner, key.revision_id)?
                        .context("checkpoint has no retained private revision")?;
                    anyhow::ensure!(
                        catalog.bundle.descriptor == canonical_bytes(signed)?,
                        "private snapshot differs from original signed revision"
                    );
                    catalog
                }
                mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(_) => sources
                    .control
                    .catalog_paged_checkpoint_legacy_revision(owner, key.revision_id)?
                    .context("checkpoint has no retained original legacy conversion")?,
                _ => anyhow::bail!("checkpoint lookup returned a nonrevision record"),
            };
            sources.control.$publish(
                retention,
                &record,
                &catalog,
                || Ok::<_, anyhow::Error>(()),
            )?;
            let opened = crate::PagedPrivateMetadata::open_local_snapshot(
                sources.keys,
                &catalog,
                catalog.bundle.scope,
            )?;
            let private = opened
                .private
                .context("retained private snapshot is unavailable")?;
            anyhow::ensure!(
                opened.state == mb_store::CatalogBundleState::Published
                    && opened.revision.value.guild_id == guild_id
                    && (FULL || private.git.is_none()),
                "restore requires compatible published private roots"
            );
            let mut recover = |sector: &SectorId| -> Result<Vec<u8>> {
                let original = sources
                    .control
                    .native_file_catalog_source(catalog.bundle.id, *sector)?
                    .context("recovery source lacks original signed authority")?;
                if let Ok(bytes) = (sources.local)(sector) {
                    anyhow::ensure!(
                        merkle_commit(&bytes)? == original.commitment,
                        "local recovery source differs from its signed commitment"
                    );
                    return Ok(bytes);
                }
                super::checkpoint_recovery::recover_source(
                    &original,
                    catalog.bundle.scope,
                    budget,
                    |source| Ok(sources.control.$chunk(retention, source)?),
                    |group, work| Ok(sources.control.$group(retention, group, work)?),
                    |entry, index| {
                        let group = &entry.retained.group;
                        let role = &group.roles[usize::from(index)];
                        let (holder, commitment) = match role {
                            ShardRoleV2::Information(role) => (role.owner, &role.sector.commitment),
                            ShardRoleV2::Parity(role) => (role.holder, &role.commitment),
                        };
                        if holder == sources.keys.node_id()
                            && let Some(payload) = sources
                                .control
                                .catalog_paged_checkpoint_payload(owner, group.id, index)?
                        {
                            let transcript =
                                *blake3::hash(&canonical_bytes(&entry.transcript)?).as_bytes();
                            anyhow::ensure!(
                                payload.guild_id == guild_id
                                    && payload.holder == holder
                                    && payload.commitment == *commitment
                                    && payload.transcript_hash == transcript,
                                "retained READY role differs from its original witness"
                            );
                                match (sources.ready)(&payload) {
                                    Ok(bytes) => return Ok(Some(bytes)),
                                    Err(error) => tracing::warn!(group = %hex::encode(group.id), shard_index = index, %error,
                                        "retained local role is unavailable; trying original alternatives"),
                                }
                        }
                        fetch(entry, index)
                    },
                )
            };
            if FULL {
                crate::PagedPrivateMetadata::restore_retained_catalog_checked(
                    sources.control,
                    sources.keys,
                    (catalog.bundle.id, Some(operation)),
                    catalog.bundle.scope,
                    target,
                    &mut recover,
                    |publish| {
                        sources
                            .control
                            .$publish(retention, &record, &catalog, publish)
                    },
                )
            } else {
                crate::PagedPrivateMetadata::restore_retained_native_catalog_checked(
                    sources.control,
                    sources.keys,
                    (catalog.bundle.id, Some(operation)),
                    catalog.bundle.scope,
                    target,
                    &mut recover,
                    |publish| {
                        sources
                            .control
                            .$publish(retention, &record, &catalog, publish)
                    },
                )
            }
        }};
    }
    match layout {
        mb_core::PagedCheckpointLayout::Individual => restore!(
            catalog_paged_checkpoint_retention,
            catalog_paged_checkpoint_indexed_revision,
            publish_catalog_paged_checkpoint_revision_restore,
            catalog_paged_checkpoint_chunk_location,
            catalog_paged_checkpoint_indexed_group
        ),
        mb_core::PagedCheckpointLayout::Directory => restore!(
            catalog_paged_checkpoint_directory_retention,
            catalog_paged_checkpoint_directory_indexed_revision,
            publish_catalog_paged_checkpoint_directory_revision_restore,
            catalog_paged_checkpoint_directory_chunk_location,
            catalog_paged_checkpoint_directory_indexed_group
        ),
    }
}

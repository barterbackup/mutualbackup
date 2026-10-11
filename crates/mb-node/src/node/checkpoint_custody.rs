//! Shared original-authority and local private/READY custody for both public layouts.
use super::*;

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
     $retain:ident, $retain_revision:ident, $retain_payload:ident) => {
        impl Node {
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
    retain_catalog_paged_checkpoint_payload_checked
);
custody!(
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    mb_store::CatalogPagedCheckpointDirectoryRetention,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_revision,
    retain_paged_checkpoint_directory_local_payload,
    retain_catalog_paged_checkpoint_directory,
    retain_catalog_paged_checkpoint_directory_revision_checked,
    retain_catalog_paged_checkpoint_directory_payload_checked
);

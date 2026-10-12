//! Source-authorized construction without a catalog-wide chunk/slot vector.
//! Disposable allocation rows reproduce the original fresh allocator. Payload
//! sinks must retain their own durable ownership; no checkpoint is activated.

use super::*;
use mb_core::{
    CatalogCapacityPolicy, CatalogPackedSectorRecord, CatalogPackedSourceRecord,
    CatalogPackingDirectoryStreamBuilder, MERKLE_LEAF_SIZE, PackedSector, PackedSectorDescriptor,
    PackedSlot, PackedSourceChunk, SourceChunkId, merkle_commit, merkle_open_subtree, sector_root,
};

mod slots;
use slots::Slots;

const OWNERS: &str = "packing-producer-owner";
const BATCH: usize = 128;

/// Construction retains the independently authenticated source/candidate set.
/// Complete revalidation of the emitted pages is required before placements
/// can be used. The caller still owns staged pages, payloads and current trust.
pub struct CatalogProducedPackingDirectory {
    authority: CatalogPackingAuthority,
    manifest: CatalogPackingDirectoryValidation,
    budget: CatalogCodingTraversalBudget,
}

impl CatalogProducedPackingDirectory {
    pub fn manifest(&self) -> CatalogPackingDirectoryValidation {
        self.manifest
    }

    pub fn validate(
        self,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<CatalogCertifiedPackingDirectoryIndex, CatalogStoreError> {
        self.authority
            .validate_packing_directory(self.manifest, self.budget, fetch)
    }
}

#[derive(Serialize, Deserialize)]
struct OwnerCursor {
    source: CatalogPackedSourceId,
    chunk: u32,
}

fn authenticated_bytes(
    source: &CatalogPackingAuthorizedSource,
    bytes: &mut [u8],
    read: &mut impl FnMut(&CatalogPackingAuthorizedSource, &mut [u8]) -> Result<(), CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    // A short-writing callback cannot accidentally inherit a previous source.
    bytes.fill(0);
    read(source, bytes)?;
    if source.commitment.byte_len as usize != bytes.len()
        || merkle_commit(bytes).map_err(|_| DatabaseError::Integrity)? != source.commitment
        || sector_root(bytes) != source.flat_root
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

impl CatalogPackingAuthority {
    /// Stream original authenticated ciphertext through the sharded codec.
    /// Reserve the policy's complete declared packing construction plus source
    /// authority before any callback. The same admitted scratch index stores
    /// allocation state, and every read bounds key/value allocation. At most
    /// one source, one packed payload and one descriptor are materialized.
    ///
    /// Fresh placement preserves the existing round-robin owner order and
    /// cross-owner spare-slot rule. Incremental seek/edit and durable enclosing
    /// operation ownership remain required before normal backup switching.
    pub fn produce_packing_directory(
        self,
        policy: CatalogCapacityPolicy,
        budget: CatalogCodingTraversalBudget,
        callbacks: (
            impl FnMut(&CatalogPackingAuthorizedSource, &mut [u8]) -> Result<(), CatalogStoreError>,
            impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), CatalogStoreError>,
            impl FnMut(&PackedSector) -> Result<(), CatalogStoreError>,
        ),
    ) -> Result<CatalogProducedPackingDirectory, CatalogStoreError> {
        let plan = policy.plan()?;
        let prior = CatalogCodingTraversalBudget {
            bytes: self.bytes,
            page_occurrences: self.pages,
            records: self.records,
        };
        if self.sources > plan.retained_sources || self.authenticated != self.sources {
            return Err(DatabaseError::Conflict.into());
        }
        let remaining = budget.remaining_after(prior)?;
        remaining.remaining_after(plan.packing_coding.packing.work)?;
        let profile = policy.packing_profile;
        let width = profile
            .slots_per_sector()
            .map_err(|_| CatalogError::InvalidPage)?;
        let scope = CatalogScope::Guild {
            guild_id: self.base.guild_id,
        };
        let mut builder = CatalogPackingDirectoryStreamBuilder::new(
            scope,
            3,
            profile,
            plan.retained_sources,
            policy.packed_sectors,
            remaining,
        )?;
        for kind in [
            OWNERS,
            slots::ASSIGNMENTS,
            slots::STATES,
            slots::MIXED,
            slots::SINGLE,
            slots::FILLABLE,
            slots::EMPTY,
        ] {
            if self
                .store
                .next_record_metadata_bounded(kind, None, 100)?
                .is_some()
            {
                return Err(DatabaseError::Conflict.into());
            }
        }
        let (mut render, mut stage, mut payload) = callbacks;
        let mut bytes = vec![0; V1_SECTOR_SIZE];
        let mut after = None;
        let mut sources = 0;
        while let Some(source) = self.next_source(after)? {
            authenticated_bytes(&source, &mut bytes, &mut render)?;
            unwrap_stream(builder.push_source(
                &CatalogPackedSourceRecord::Source {
                    format_version: 1,
                    id: source.id,
                    commitment: source.commitment.clone(),
                },
                &mut stage,
            ))?;
            for first in (0..width).step_by(mb_core::CATALOG_PACKED_SOURCE_PROOFS) {
                let mut roots = Vec::with_capacity(mb_core::CATALOG_PACKED_SOURCE_PROOFS);
                for chunk in first..width.min(first + mb_core::CATALOG_PACKED_SOURCE_PROOFS as u32)
                {
                    let start = chunk as usize * profile.slot_size as usize;
                    roots.push(
                        merkle_open_subtree(
                            &bytes[start..start + profile.slot_size as usize],
                            0,
                            profile.slot_size / MERKLE_LEAF_SIZE as u32,
                        )
                        .map_err(|_| DatabaseError::Integrity)?
                        .subtree_root,
                    );
                }
                unwrap_stream(builder.push_source(
                    &CatalogPackedSourceRecord::Subtrees {
                        first_chunk: first,
                        roots,
                    },
                    &mut stage,
                ))?;
            }
            // Only the first source initializes an owner's bounded cursor.
            // This source scan is already in strict owner/root/object order.
            if read::<OwnerCursor>(&self.store, OWNERS, &source.id.owner.0)?.is_none() {
                insert(
                    &self.store,
                    OWNERS,
                    &source.id.owner.0,
                    &OwnerCursor {
                        source: source.id,
                        chunk: 0,
                    },
                    ROW_BYTES,
                )?;
            }
            after = Some(source.id);
            sources += 1;
        }
        if sources != self.sources {
            return Err(DatabaseError::Integrity.into());
        }
        let mut allocation = Slots::new(&self.store, width, policy.packed_sectors);
        let mut owner_after: Option<Vec<u8>> = None;
        let mut allocated = 0_u64;
        loop {
            let mut complete = false;
            self.store
                .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                    for _ in 0..BATCH {
                        let row = self.store.next_record_bounded(
                            OWNERS,
                            owner_after.as_deref(),
                            32,
                            ROW_BYTES,
                        )?;
                        let row = if row.is_none() {
                            owner_after = None;
                            self.store
                                .next_record_bounded(OWNERS, None, 32, ROW_BYTES)?
                        } else {
                            row
                        };
                        let Some((owner, previous)) = row else {
                            complete = true;
                            break;
                        };
                        let mut cursor: OwnerCursor = decode_canonical(&previous)?;
                        if owner != cursor.source.owner.0
                            || encoded(&cursor, ROW_BYTES)? != previous
                            || cursor.chunk >= width
                        {
                            return Err(DatabaseError::Integrity.into());
                        }
                        allocation.assign(cursor.source.chunk(cursor.chunk))?;
                        allocated = allocated.checked_add(1).ok_or(CatalogError::Bounds)?;
                        cursor.chunk += 1;
                        if cursor.chunk == width {
                            match self.next_source(Some(cursor.source))? {
                                Some(next) if next.id.owner == cursor.source.owner => {
                                    cursor = OwnerCursor {
                                        source: next.id,
                                        chunk: 0,
                                    };
                                }
                                _ => {
                                    self.store
                                        .delete_record_if_value(OWNERS, &owner, &previous)?;
                                    if self
                                        .store
                                        .get_record_bounded(OWNERS, &owner, ROW_BYTES)?
                                        .is_some()
                                    {
                                        return Err(DatabaseError::Integrity.into());
                                    }
                                    owner_after = Some(owner);
                                    continue;
                                }
                            }
                        }
                        replace(&self.store, OWNERS, &owner, &previous, &cursor)?;
                        owner_after = Some(owner);
                    }
                    Ok(())
                })?;
            if complete {
                break;
            }
        }
        if allocated
            != self
                .sources
                .checked_mul(u64::from(width))
                .ok_or(CatalogError::Bounds)?
        {
            return Err(DatabaseError::Integrity.into());
        }
        let mut cached = None;
        for sector in 0..allocation.sectors() {
            let sector_index = u32::try_from(sector).map_err(|_| CatalogError::Bounds)?;
            let mut sector_bytes = vec![0; V1_SECTOR_SIZE];
            let mut sector_slots = Vec::with_capacity(width as usize);
            for slot in 0..width {
                let Some(id) = allocation.at(sector_index, slot)? else {
                    sector_slots.push(PackedSlot::VirtualZero { source: None });
                    continue;
                };
                let object = CatalogPackedSourceId {
                    owner: id.owner,
                    protected_root: id.protected_root,
                    object_id: id.object_id,
                };
                if cached != Some(object) {
                    let original = source(&self.store, object)?.0;
                    let authorized = CatalogPackingAuthorizedSource {
                        id: original.id,
                        flat_root: original.flat_root,
                        commitment: original.commitment.ok_or(DatabaseError::Integrity)?,
                    };
                    authenticated_bytes(&authorized, &mut bytes, &mut render)?;
                    cached = Some(object);
                }
                let start = id.chunk_index as usize * profile.slot_size as usize;
                let chunk = &bytes[start..start + profile.slot_size as usize];
                let chunk_source = PackedSourceChunk {
                    id,
                    source_offset: start as u64,
                    logical_len: profile.slot_size,
                    content_hash: *blake3::hash(chunk).as_bytes(),
                };
                if chunk.iter().all(|byte| *byte == 0) {
                    sector_slots.push(PackedSlot::VirtualZero {
                        source: Some(chunk_source),
                    });
                } else {
                    let start = slot as usize * profile.slot_size as usize;
                    sector_bytes[start..start + chunk.len()].copy_from_slice(chunk);
                    sector_slots.push(PackedSlot::Data(chunk_source));
                }
            }
            let commitment = merkle_commit(&sector_bytes).map_err(|_| DatabaseError::Integrity)?;
            let mut descriptor = PackedSectorDescriptor {
                id: [0; 32],
                sector_index,
                flat_root: commitment.root,
                commitment,
                slots: sector_slots,
            };
            descriptor.id = descriptor
                .calculate_id(profile)
                .map_err(|_| DatabaseError::Integrity)?;
            // The payload owner is established before its metadata is emitted.
            let sector = PackedSector {
                descriptor,
                bytes: sector_bytes,
            };
            payload(&sector)?;
            let descriptor = &sector.descriptor;
            unwrap_stream(builder.push_sector(
                &CatalogPackedSectorRecord::Header {
                    format_version: 1,
                    id: descriptor.id,
                    sector_index,
                    flat_root: descriptor.flat_root,
                    commitment: descriptor.commitment.clone(),
                },
                &mut stage,
            ))?;
            for (index, slots) in descriptor
                .slots
                .chunks(mb_core::CATALOG_PACKED_SLOTS)
                .enumerate()
            {
                unwrap_stream(builder.push_sector(
                    &CatalogPackedSectorRecord::Slots {
                        offset: (index * mb_core::CATALOG_PACKED_SLOTS) as u32,
                        slots: slots.to_vec(),
                    },
                    &mut stage,
                ))?;
            }
        }
        let directory = unwrap_stream(builder.finish(&mut stage))?;
        if directory.summary.sources != sources || directory.summary.source_chunks != allocated {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(CatalogProducedPackingDirectory {
            authority: self,
            manifest: CatalogPackingDirectoryValidation {
                format_version: 1,
                scope,
                directory,
            },
            budget,
        })
    }
}

#[cfg(test)]
mod tests;

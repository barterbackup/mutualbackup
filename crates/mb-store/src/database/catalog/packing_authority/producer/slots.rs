//! Fresh stable allocation using point rows and ordered classification indexes.
//! Every sector's assigned positions form a prefix, so no free-slot bitmap or
//! catalog-sized vector is needed. One source is assigned per owner per round.

use super::*;

pub(super) const ASSIGNMENTS: &str = "packing-producer-slot";
pub(super) const STATES: &str = "packing-producer-state";
pub(super) const MIXED: &str = "packing-producer-mixed";
pub(super) const SINGLE: &str = "packing-producer-single";
pub(super) const FILLABLE: &str = "packing-producer-fillable";
pub(super) const EMPTY: &str = "packing-producer-empty";

#[derive(Serialize, Deserialize)]
struct State {
    filled: u32,
    owner: Option<NodeId>,
    mixed: bool,
}

pub(super) struct Slots<'a> {
    store: &'a RecordScratchStore,
    width: u32,
    limit: u64,
    sectors: u64,
}

fn owner_key(owner: NodeId, sector: u32) -> [u8; 36] {
    let mut key = [0; 36];
    key[..32].copy_from_slice(&owner.0);
    key[32..].copy_from_slice(&sector.to_be_bytes());
    key
}
fn slot_key(sector: u32, slot: u32) -> [u8; 8] {
    let mut key = [0; 8];
    key[..4].copy_from_slice(&sector.to_be_bytes());
    key[4..].copy_from_slice(&slot.to_be_bytes());
    key
}

impl<'a> Slots<'a> {
    pub(super) fn new(store: &'a RecordScratchStore, width: u32, limit: u64) -> Self {
        Self {
            store,
            width,
            limit,
            sectors: 0,
        }
    }
    pub(super) fn sectors(&self) -> u64 {
        self.sectors
    }

    fn first(
        &self,
        kind: &str,
        after: Option<&[u8]>,
        owner: Option<NodeId>,
    ) -> Result<Option<u32>, CatalogStoreError> {
        let owner_index = matches!(kind, SINGLE | FILLABLE);
        let Some((key, bytes)) =
            self.store
                .next_record_bounded(kind, after, if owner_index { 36 } else { 4 }, 0)?
        else {
            return Ok(None);
        };
        if !bytes.is_empty() || key.len() != if owner_index { 36 } else { 4 } {
            return Err(DatabaseError::Integrity.into());
        }
        if let Some(owner) = owner
            && key[..32] != owner.0
        {
            return Ok(None);
        }
        let index = u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap());
        if u64::from(index) >= self.sectors {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(index))
    }
    fn other(&self, owner: NodeId) -> Result<Option<u32>, CatalogStoreError> {
        let Some((key, bytes)) = self.store.next_record_bounded(SINGLE, None, 36, 0)? else {
            return Ok(None);
        };
        if key.len() != 36 || !bytes.is_empty() {
            return Err(DatabaseError::Integrity.into());
        }
        if key[..32] != owner.0 {
            self.first(SINGLE, None, None)
        } else {
            self.first(SINGLE, Some(&owner_key(owner, u32::MAX)), None)
        }
    }
    fn classification(
        &self,
        sector: u32,
        state: &State,
        mut change: impl FnMut(&str, &[u8]) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        if state.filled == self.width {
            return Ok(());
        }
        if state.mixed {
            change(MIXED, &sector.to_be_bytes())?;
        } else if let Some(owner) = state.owner {
            let key = owner_key(owner, sector);
            change(SINGLE, &key)?;
            if self.width - state.filled > 1 {
                change(FILLABLE, &key)?;
            }
        } else {
            change(EMPTY, &sector.to_be_bytes())?;
        }
        Ok(())
    }
    pub(super) fn assign(&mut self, id: SourceChunkId) -> Result<(), CatalogStoreError> {
        let selected = self
            .first(MIXED, None, None)?
            .or(self.other(id.owner)?)
            .or(self.first(FILLABLE, Some(&id.owner.0), Some(id.owner))?)
            .or(self.first(EMPTY, None, None)?);
        let (sector, mut state, previous) = match selected {
            Some(sector) => {
                let (state, previous) = read::<State>(self.store, STATES, &sector.to_be_bytes())?
                    .ok_or(DatabaseError::Integrity)?;
                if state.filled >= self.width
                    || (state.filled == 0) != state.owner.is_none()
                    || state.mixed && state.owner.is_none()
                {
                    return Err(DatabaseError::Integrity.into());
                }
                (sector, state, Some(previous))
            }
            None => {
                if self.width == 0 || self.sectors >= self.limit {
                    return Err(CatalogError::Bounds.into());
                }
                let sector = u32::try_from(self.sectors).map_err(|_| CatalogError::Bounds)?;
                self.sectors += 1;
                (
                    sector,
                    State {
                        filled: 0,
                        owner: None,
                        mixed: false,
                    },
                    None,
                )
            }
        };
        if previous.is_some() {
            self.classification(sector, &state, |kind, key| {
                self.store.delete_record_if_value(kind, key, &[])?;
                if self.store.get_record_bounded(kind, key, 0)?.is_some() {
                    return Err(DatabaseError::Integrity.into());
                }
                Ok(())
            })?;
        }
        insert(
            self.store,
            ASSIGNMENTS,
            &slot_key(sector, state.filled),
            &id,
            ROW_BYTES,
        )?;
        state.mixed |= state.owner.is_some_and(|owner| owner != id.owner);
        state.owner = Some(state.owner.unwrap_or(id.owner));
        state.filled += 1;
        if let Some(previous) = previous {
            replace(self.store, STATES, &sector.to_be_bytes(), &previous, &state)?;
        } else {
            insert(self.store, STATES, &sector.to_be_bytes(), &state, ROW_BYTES)?;
        }
        self.classification(sector, &state, |kind, key| {
            if !self.store.put_record_if_absent(kind, key, &[])?
                || self.store.get_record_bounded(kind, key, 0)?.as_deref() != Some(&[])
            {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(())
        })
    }
    pub(super) fn at(
        &self,
        sector: u32,
        slot: u32,
    ) -> Result<Option<SourceChunkId>, CatalogStoreError> {
        if u64::from(sector) >= self.sectors || slot >= self.width {
            return Err(CatalogError::Bounds.into());
        }
        let Some((id, _)) =
            read::<SourceChunkId>(self.store, ASSIGNMENTS, &slot_key(sector, slot))?
        else {
            return Ok(None);
        };
        if id.chunk_index >= self.width {
            return Err(DatabaseError::Integrity.into());
        }
        CatalogPackedSourceId {
            owner: id.owner,
            protected_root: id.protected_root,
            object_id: id.object_id,
        }
        .validate()
        .map_err(|_| DatabaseError::Integrity)?;
        Ok(Some(id))
    }
}

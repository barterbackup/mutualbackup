//! Decoder for the experimental v1 process-owner envelope. A PID from an
//! unknown namespace never proves abandonment. Keep old declarations as debt
//! until their original owner cleans them up. This old envelope also lacks
//! filesystem provenance: another device/inode can be an alias, not a copy.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Owner {
    boot: Uuid,
    pid: u32,
    start: u64,
    instance: Uuid,
    device: u64,
    inode: u64,
}

impl Owner {
    pub(super) fn validate(self) -> Result<(), CatalogStoreError> {
        if self.boot.is_nil() || self.pid == 0 || self.instance.is_nil() || self.inode == 0 {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }
}

//! Bounded locators for original public evidence. A receipt is a local custody
//! fence; rebuilding the original full proof remains the caller's obligation.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointRecoverySource {
    pub owner: Uuid,
    pub certificate: CatalogPublicCheckpoint,
    pub trust_hash: [u8; 32],
    pub proof_work: Work,
    pub budget: Work,
    pub parent: Option<CatalogCheckpointRecoveryTip>,
    pub archived: bool,
}
fn read(
    cx: &Connection,
    id: Uuid,
) -> Result<Option<CatalogCheckpointRecoverySource>, CatalogStoreError> {
    let tip = recovery_tip::read(cx)?;
    ancestry::recovery_source(cx, id, tip.is_some_and(|tip| tip.owner == id))
}
impl ControlStore {
    /// Read one original source in selected recovery progress or its independently
    /// owned ancestry. This neither reconstructs a proof nor changes progress.
    pub fn checkpoint_recovery_source(
        &self,
        id: Uuid,
    ) -> Result<Option<CatalogCheckpointRecoverySource>, CatalogStoreError> {
        if !self.connection.is_autocommit() {
            return read(&self.connection, id);
        }
        let tx = self.read_snapshot()?;
        let value = read(&tx, id)?;
        tx.commit()?;
        Ok(value)
    }
    /// Recheck exact immutable custody and independently derived original trust.
    /// This composes with an enclosing writer without nesting transactions.
    pub fn check_checkpoint_recovery_source(
        &self,
        source: &CatalogCheckpointRecoverySource,
        trust: &PagedCheckpointTrust,
    ) -> Result<(), CatalogStoreError> {
        let check = |cx: &Connection| -> Result<(), CatalogStoreError> {
            if read(cx, source.owner)?.as_ref() != Some(source)
                || super::super::checkpoint_transition::snapshot_hash(trust)? != source.trust_hash
            {
                return Err(DatabaseError::Conflict.into());
            }
            Ok(())
        };
        if !self.connection.is_autocommit() {
            return check(&self.connection);
        }
        let tx = self.read_snapshot()?;
        check(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

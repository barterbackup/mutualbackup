//! Durable transitive metadata ownership for completed sharded packing/coding.
//! Certified checkpoint activation and payload custody remain external guards.

use super::packing_validation::unwrap_stream;
use super::retention_journal::{self as journal, Dependency, Retention};
use super::*;
use mb_core::{
    CatalogCodingDirectoryReader, CatalogCodingTraversalBudget, CatalogPackingDirectoryReader,
    CatalogPackingDirectoryRecord,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingCodingDirectoriesRetention {
    pub id: Uuid,
    pub manifest: CatalogPackingCodingDirectoriesValidation,
    pub budget: CatalogCodingTraversalBudget,
}
pub use journal::CatalogRetentionState as CatalogPackingCodingDirectoriesRetentionState;

impl CatalogPackingCodingDirectoriesRetention {
    fn scope(self) -> CatalogScope {
        self.manifest.packing.scope
    }
    fn initial(self) -> [Dependency; 2] {
        [
            Dependency {
                scope: self.scope(),
                section: CatalogSection::Packing,
                root: self.manifest.packing.directory.records.page,
            },
            Dependency {
                scope: self.scope(),
                section: CatalogSection::Coding,
                root: self.manifest.coding.records.page,
            },
        ]
    }
}

impl Retention for CatalogPackingCodingDirectoriesRetention {
    const JOURNAL: &'static str = "catalog-packing-directories-retention-v1";
    const JOURNAL_BYTES: usize = 8192;
    const DEPENDENCIES: &'static str = "catalog-packing-directories-dependency-v1";
    const PIN_PREFIX: u8 = 5;
    fn id(self) -> Uuid {
        self.id
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        self.manifest.validate(self.budget)
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        let work = self
            .manifest
            .represented_work()?
            .remaining_after(self.manifest.prior_work)?;
        Ok((work.bytes, work.page_occurrences))
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        scope == self.scope() && matches!(section, CatalogSection::Packing | CatalogSection::Coding)
    }
}

impl ControlStore {
    /// Keep original staging owners until successful handoff. Pin both
    /// directories in one writer, then each exact admitted nested root before
    /// evidence I/O. Complete every EOF before publishing; interruption replays
    /// the immutable proof. Walkers hold no production writer transaction.
    /// This owns metadata only; current checkpoint and payload guards still
    /// govern activation and retirement.
    pub fn retain_catalog_packing_directories(
        &self,
        id: Uuid,
        proof: &CatalogPackingCodingDirectoriesIndex,
    ) -> Result<CatalogPackingCodingDirectoriesRetention, CatalogStoreError> {
        proof.require_complete()?;
        let retention = CatalogPackingCodingDirectoriesRetention {
            id,
            manifest: proof.manifest(),
            budget: proof.budget(),
        };
        retention.validate()?;
        {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            if journal::begin(&transaction, retention)?
                == CatalogPackingCodingDirectoriesRetentionState::Published
            {
                return Ok(retention);
            }
            for dependency in retention.initial() {
                journal::retain(&transaction, retention, dependency)?;
            }
            transaction.commit()?;
        }
        let result = (|| {
            let pin = |section, root| {
                let transaction =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                journal::retain(
                    &transaction,
                    retention,
                    Dependency {
                        scope: retention.scope(),
                        section,
                        root,
                    },
                )?;
                transaction.commit()?;
                Ok::<_, CatalogStoreError>(())
            };
            let mut part = |record| {
                pin(
                    CatalogSection::Packing,
                    match record {
                        CatalogPackingDirectoryRecord::Sources(part) => part.root.records.page,
                        CatalogPackingDirectoryRecord::Sectors(part) => part.root.records.page,
                    },
                )
            };
            let mut packing = CatalogPackingDirectoryReader::new(
                retention.scope(),
                retention.manifest.packing.directory,
                retention.manifest.packing_budget(retention.budget)?,
            )?;
            let mut fetch =
                |page| self.catalog_page(retention.scope(), CatalogSection::Packing, page);
            while unwrap_stream(packing.next_source_with_part(&mut fetch, &mut part))?.is_some() {}
            while unwrap_stream(packing.next_sector_with_part(
                &mut fetch,
                &mut |key| proof.packing().source_id(key),
                &mut part,
            ))?
            .is_some()
            {}
            if !packing.is_complete() {
                return Err(DatabaseError::NotReady.into());
            }
            let mut coding = CatalogCodingDirectoryReader::new(
                retention.scope(),
                retention.manifest.coding,
                retention.manifest.coding_budget(retention.budget)?,
            )?;
            let mut fetch =
                |page| self.catalog_page(retention.scope(), CatalogSection::Coding, page);
            let mut forest = |root: &mb_core::CatalogCodingRoot| {
                for part in &root.parts {
                    pin(CatalogSection::Coding, part.page)?;
                }
                Ok::<_, CatalogStoreError>(())
            };
            while unwrap_stream(coding.next_group_with_forest(&mut fetch, &mut forest))?.is_some() {
            }
            proof.require_complete()?;
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::publish(&transaction, retention)?;
            transaction.commit()?;
            Ok(retention)
        })();
        if result.is_err() {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::cancel_building(&transaction, retention)?;
            transaction.commit()?;
        }
        result
    }

    pub fn catalog_packing_directories_retention(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(
            CatalogPackingCodingDirectoriesRetention,
            CatalogPackingCodingDirectoriesRetentionState,
        )>,
        CatalogStoreError,
    > {
        Ok(
            journal::read::<CatalogPackingCodingDirectoriesRetention>(&self.connection, id)?
                .map(|record| (record.retention, record.state)),
        )
    }
    pub fn cancel_catalog_packing_directories_retention(
        &self,
        id: Uuid,
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        journal::cancel::<CatalogPackingCodingDirectoriesRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }
    /// Release at most one cancelled root closure with its pin and counters.
    pub fn release_catalog_packing_directories_root(
        &self,
        id: Uuid,
    ) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let released =
            journal::release::<CatalogPackingCodingDirectoriesRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(released)
    }
}

#[cfg(test)]
mod tests;

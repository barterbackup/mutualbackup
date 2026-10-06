//! Bounded stable native/Git source regeneration under retained paged revisions.

use std::io::{Read, Seek, SeekFrom};

use anyhow::{Result, ensure};
use mb_core::{
    CatalogScope, CatalogSectorRecord, KeyMaterial, SectorPurpose, V1_SECTOR_SIZE,
    canonical_bytes_bounded, decode_canonical, encrypted_sector, make_content_sector_id,
    merkle_commit,
};
use mb_store::{ControlStore, StableAnchorFileLocator};
use serde::{Deserialize, Serialize};

use crate::PagedPrivateMetadata;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PagedAnchorSectorSource {
    pub locator: StableAnchorFileLocator,
    pub offset: u64,
}

impl PagedAnchorSectorSource {
    pub(super) fn render(
        &self,
        keys: &KeyMaterial,
        scope: CatalogScope,
        record: &CatalogSectorRecord,
    ) -> Result<Vec<u8>> {
        let CatalogScope::Dataset {
            guild_id,
            owner,
            protected_root_id,
        } = scope
        else {
            anyhow::bail!("stable data requires dataset scope");
        };
        let len = record.sector.logical_len as usize;
        ensure!(
            owner == keys.node_id()
                && len > 0
                && len <= V1_SECTOR_SIZE
                && !self.locator.anchor_id.is_nil(),
            "invalid stable data source owner or geometry"
        );
        let end = self
            .offset
            .checked_add(len as u64)
            .ok_or_else(|| anyhow::anyhow!("stable data range overflows"))?;
        let mut file = self.locator.open()?;
        ensure!(
            end <= file.metadata()?.len(),
            "stable source range exceeds its file"
        );
        file.seek(SeekFrom::Start(self.offset))?;
        let mut plaintext = vec![0; len];
        file.read_exact(&mut plaintext)?;
        let id = make_content_sector_id(
            &keys.guild_content_id_key(&guild_id),
            owner,
            guild_id,
            protected_root_id,
            SectorPurpose::Data,
            &plaintext,
        )?;
        ensure!(
            id == record.sector.id,
            "stable data differs from its scoped content address"
        );
        let (reference, ciphertext) =
            encrypted_sector(&keys.guild_data_key(&guild_id), id, &plaintext)?;
        ensure!(
            reference == record.sector && merkle_commit(&ciphertext)? == record.commitment,
            "stable source differs from its signed ciphertext commitments"
        );
        Ok(ciphertext)
    }
}

impl PagedPrivateMetadata {
    pub fn render_local_data_sector(
        control: &ControlStore,
        keys: &KeyMaterial,
        id: uuid::Uuid,
        sector: [u8; 32],
        expected_scope: CatalogScope,
    ) -> Result<Option<Vec<u8>>> {
        let Some(source) = control.paged_revision_data_source(id, sector)? else {
            return Ok(None);
        };
        Self::open_local_snapshot(keys, &source.catalog, expected_scope)?;
        let recipe: PagedAnchorSectorSource = decode_canonical(&source.recipe)?;
        ensure!(
            recipe.locator.anchor_id == source.anchor
                && canonical_bytes_bounded(&recipe, mb_store::PAGED_DATA_RECIPE_BYTES)?
                    == source.recipe,
            "stable source recipe differs from its retained anchor binding"
        );
        Ok(Some(recipe.render(
            keys,
            source.catalog.bundle.scope,
            &source.source,
        )?))
    }
}

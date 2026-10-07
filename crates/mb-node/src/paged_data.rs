//! Bounded stable native/Git source regeneration under retained paged revisions.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use anyhow::{Result, ensure};
use mb_core::{
    CatalogScope, CatalogSectorRecord, KeyMaterial, MerkleCommitment, SectorPurpose, SectorRef,
    SignedRecord, UserRevision, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_bytes_bounded,
    canonical_size_bounded, decode_canonical, encrypted_sector, make_content_sector_id,
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

/// Bounded proof of historical data membership. Construction verifies the old
/// owner/writer signatures; publication supplies the new certified authority.
/// This does not convert or approve the old private metadata schema.
pub struct PagedLegacyDataAuthority {
    scope: CatalogScope,
    revision: [u8; 32],
    sources: BTreeMap<[u8; 32], (SectorRef, Option<MerkleCommitment>)>,
}

pub(super) fn legacy_revision_scope(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<(CatalogScope, usize)> {
    let length = crate::snapshot::checked_metadata_length(revision)?;
    ensure!(
        revision.signature.len() == 64 && revision.value.writer_signature.len() == 64,
        "legacy revision exceeds bounded conversion geometry"
    );
    canonical_size_bounded(revision, V1_MAX_CATALOG_BYTES)?;
    crate::snapshot::validate_restore_revision(keys, guild_id, revision)?;
    ensure!(
        !revision.value.revision_id.is_nil()
            && !revision.value.protected_root_id.is_nil()
            && revision.value.sequence > 0
            && (revision.value.sequence == 1) == revision.value.parent.is_none(),
        "legacy revision has no protected dataset identity"
    );
    Ok((
        CatalogScope::Dataset {
            guild_id,
            owner: keys.node_id(),
            protected_root_id: revision.value.protected_root_id,
        },
        length,
    ))
}

impl PagedLegacyDataAuthority {
    pub(super) fn contains_data(&self, id: [u8; 32]) -> bool {
        self.sources.contains_key(&id)
    }

    pub fn new(
        keys: &KeyMaterial,
        guild_id: [u8; 32],
        revision: &SignedRecord<UserRevision>,
    ) -> Result<Self> {
        let (scope, _) = legacy_revision_scope(keys, guild_id, revision)?;
        let commitments = revision.value.sector_commitments.as_deref();
        if let Some(values) = commitments {
            ensure!(
                values.len()
                    == revision.value.metadata_sectors.len() + revision.value.data_sectors.len()
                    && values
                        .iter()
                        .all(|value| value.byte_len as usize == V1_SECTOR_SIZE
                            && value.validate().is_ok()),
                "legacy revision has malformed source commitments"
            );
        }
        let mut sources = BTreeMap::new();
        for (index, reference) in revision.value.data_sectors.iter().enumerate() {
            ensure!(
                reference.logical_len > 0 && reference.logical_len as usize <= V1_SECTOR_SIZE,
                "invalid signed legacy data geometry"
            );
            let value = (
                reference.clone(),
                commitments
                    .map(|values| values[revision.value.metadata_sectors.len() + index].clone()),
            );
            if let Some(previous) = sources.insert(reference.id, value.clone()) {
                ensure!(
                    previous == value,
                    "conflicting signed legacy data references"
                );
            }
        }
        ensure!(
            revision
                .value
                .metadata_sectors
                .iter()
                .all(|reference| !sources.contains_key(&reference.id)),
            "legacy metadata/data IDs overlap"
        );
        Ok(Self {
            scope,
            revision: revision.value.hash()?,
            sources,
        })
    }

    /// Authorize one exact old data reference, never an old metadata/bootstrap
    /// address. Missing old Merkle commitments are established from the source
    /// bytes during publication and retained in the new signed source catalog.
    pub fn bind(
        &self,
        anchor: PagedAnchorSectorSource,
        source: &CatalogSectorRecord,
    ) -> Result<PagedDataSource> {
        source.validate()?;
        let (reference, commitment) = self
            .sources
            .get(&source.sector.id)
            .ok_or_else(|| anyhow::anyhow!("source is not signed legacy data"))?;
        ensure!(
            reference == &source.sector
                && commitment
                    .as_ref()
                    .is_none_or(|value| value == &source.commitment),
            "source differs from authenticated legacy data"
        );
        Ok(PagedDataSource {
            anchor,
            legacy: Some(LegacyDataBinding {
                revision: self.revision,
                scope: self.scope,
                source: source.clone(),
            }),
        })
    }
}

/// A scoped content source, or an explicitly authenticated historical source.
/// Private fields prevent callers from bypassing historical membership checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedDataSource {
    anchor: PagedAnchorSectorSource,
    legacy: Option<LegacyDataBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyDataBinding {
    revision: [u8; 32],
    scope: CatalogScope,
    source: CatalogSectorRecord,
}

#[derive(Serialize, Deserialize)]
struct LegacyDataRecipe {
    version: u16,
    binding: LegacyDataBinding,
    anchor: PagedAnchorSectorSource,
}

impl From<PagedAnchorSectorSource> for PagedDataSource {
    fn from(anchor: PagedAnchorSectorSource) -> Self {
        Self {
            anchor,
            legacy: None,
        }
    }
}

impl PagedDataSource {
    pub(super) fn anchor_id(&self) -> uuid::Uuid {
        self.anchor.locator.anchor_id
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        if let Some(binding) = &self.legacy {
            Ok(canonical_bytes_bounded(
                &LegacyDataRecipe {
                    version: 1,
                    binding: binding.clone(),
                    anchor: self.anchor.clone(),
                },
                mb_store::PAGED_DATA_RECIPE_BYTES,
            )?)
        } else {
            // Preserve existing canonical scoped recipes and publication retries.
            Ok(canonical_bytes_bounded(
                &self.anchor,
                mb_store::PAGED_DATA_RECIPE_BYTES,
            )?)
        }
    }

    fn decode(bytes: &[u8], anchor_id: uuid::Uuid) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= mb_store::PAGED_DATA_RECIPE_BYTES,
            "invalid stable data recipe size"
        );
        let source = match bytes.first() {
            Some(1) => {
                let recipe: LegacyDataRecipe = decode_canonical(bytes)?;
                ensure!(
                    recipe.version == 1,
                    "unsupported legacy data recipe version"
                );
                Self {
                    anchor: recipe.anchor,
                    legacy: Some(recipe.binding),
                }
            }
            // The old two-field recipe begins with the UUID's 16-byte length.
            Some(16) => Self::from(decode_canonical::<PagedAnchorSectorSource>(bytes)?),
            _ => anyhow::bail!("unsupported stable data recipe encoding"),
        };
        ensure!(
            source.anchor_id() == anchor_id && source.encode()? == bytes,
            "stable source recipe differs from its retained anchor binding"
        );
        Ok(source)
    }

    pub(super) fn render(
        &self,
        keys: &KeyMaterial,
        scope: CatalogScope,
        record: &CatalogSectorRecord,
    ) -> Result<Vec<u8>> {
        self.render_at_hint(keys, scope, record, None, None)
            .map(|(bytes, _)| bytes)
    }

    fn render_at_hint(
        &self,
        keys: &KeyMaterial,
        scope: CatalogScope,
        record: &CatalogSectorRecord,
        hint: Option<&std::path::Path>,
        discovery: Option<&ControlStore>,
    ) -> Result<(Vec<u8>, std::path::PathBuf)> {
        if let Some(binding) = &self.legacy {
            ensure!(
                binding.scope == scope && &binding.source == record,
                "legacy data binding differs from its signed dataset source"
            );
        }
        self.anchor
            .render_with_binding(keys, scope, record, self.legacy.as_ref(), hint, discovery)
    }
}

impl PagedAnchorSectorSource {
    fn render_with_binding(
        &self,
        keys: &KeyMaterial,
        scope: CatalogScope,
        record: &CatalogSectorRecord,
        legacy: Option<&LegacyDataBinding>,
        hint: Option<&std::path::Path>,
        discovery: Option<&ControlStore>,
    ) -> Result<(Vec<u8>, std::path::PathBuf)> {
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
        let (mut file, resolved_area) = if let Some(control) = discovery {
            crate::snapshot::open_stable_anchor_with_discovery(control, &self.locator, hint)?
        } else {
            self.locator.open_with_area_hint(hint)?
        };
        ensure!(
            end <= file.metadata()?.len(),
            "stable source range exceeds its file"
        );
        file.seek(SeekFrom::Start(self.offset))?;
        let mut plaintext = vec![0; len];
        file.read_exact(&mut plaintext)?;
        if legacy.is_none() {
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
        }
        let (reference, ciphertext) = encrypted_sector(
            &keys.guild_data_key(&guild_id),
            record.sector.id,
            &plaintext,
        )?;
        ensure!(
            reference == record.sector && merkle_commit(&ciphertext)? == record.commitment,
            "stable source differs from its signed ciphertext commitments"
        );
        Ok((ciphertext, resolved_area))
    }
}

impl PagedPrivateMetadata {
    pub(super) fn native_data_source_available(
        control: &ControlStore,
        keys: &KeyMaterial,
        source: &mb_store::PagedCatalogDataSource,
    ) -> Result<bool> {
        let scope = source.catalog.bundle.scope;
        Self::open_local_snapshot(keys, &source.catalog, scope)?;
        let recipe = PagedDataSource::decode(&source.recipe, source.anchor)?;
        let hint = crate::snapshot::anchor_area_hint(control, recipe.anchor.locator.area.area_id)?;
        Ok(recipe
            .render_at_hint(keys, scope, &source.source, hint.as_deref(), None)
            .is_ok())
    }

    /// Historical data keeps its ordinary flat recovery recipe until native
    /// replacement transfers retained ownership. Scoped paged-only data has no
    /// such alternate authority and must use the replacement API directly.
    pub(super) fn has_legacy_data_binding(
        source: &mb_store::PagedCatalogDataSource,
        scope: CatalogScope,
    ) -> Result<bool> {
        let recipe = PagedDataSource::decode(&source.recipe, source.anchor)?;
        if let Some(binding) = recipe.legacy {
            ensure!(
                binding.scope == scope && binding.source == source.source,
                "legacy data binding differs from its signed dataset source"
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Rebind a lost local source to verified replacement anchor bytes. The
    /// writer rechecks ownership/generation before authentication and pin transfer.
    pub fn replace_local_data_source(
        control: &ControlStore,
        keys: &KeyMaterial,
        expected: &mb_store::PagedCatalogDataSource,
        expected_scope: CatalogScope,
        replacement: &PagedAnchorSectorSource,
    ) -> Result<mb_store::PagedCatalogDataSource> {
        Self::open_local_snapshot(keys, &expected.catalog, expected_scope)?;
        let mut source = PagedDataSource::decode(&expected.recipe, expected.anchor)?;
        source.anchor = replacement.clone();
        let recipe = source.encode()?;
        control.replace_paged_revision_data_source_checked(
            expected,
            replacement.locator.anchor_id,
            &recipe,
            |current| -> Result<()> {
                Self::open_local_snapshot(keys, &current.catalog, expected_scope)?;
                source.render(keys, current.catalog.bundle.scope, &current.source)?;
                Ok(())
            },
        )
    }

    /// Read retained data using saved location hints without updating the catalog.
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
        Ok(Some(Self::render_data_source(
            control,
            keys,
            &source,
            expected_scope,
            false,
        )?))
    }

    pub(super) fn render_data_source(
        control: &ControlStore,
        keys: &KeyMaterial,
        source: &mb_store::PagedCatalogDataSource,
        expected_scope: CatalogScope,
        update_area_hint: bool,
    ) -> Result<Vec<u8>> {
        let opened = Self::open_local_snapshot(keys, &source.catalog, expected_scope)?;
        let recipe = PagedDataSource::decode(&source.recipe, source.anchor)?;
        let area_id = recipe.anchor.locator.area.area_id;
        let hint = crate::snapshot::anchor_area_hint(control, area_id)?;
        let rendered = recipe.render_at_hint(
            keys,
            source.catalog.bundle.scope,
            &source.source,
            hint.as_deref(),
            update_area_hint.then_some(control),
        );
        let (ciphertext, resolved) = match rendered {
            Ok(value) => value,
            Err(error) => {
                if !Self::has_legacy_data_binding(source, expected_scope)? {
                    return Err(error);
                }
                // Ordinary recovery may have downloaded an Inline recipe or
                // installed a replacement native recipe. Authenticate it against
                // this live signed owner before using it; arbitrary flat rows
                // never override scoped paged sources or their commitments.
                let ciphertext = crate::snapshot::render_flat_sector_with_hint_update(
                    control,
                    keys,
                    &source.source.sector.id,
                    Some(&opened.revision.value.guild_id),
                    Some(&source.source.sector),
                    update_area_hint,
                )?;
                ensure!(
                    merkle_commit(&ciphertext)? == source.source.commitment
                        && mb_core::sector_root(&ciphertext) == source.source.sector.root,
                    "flat recovery source differs from its retained commitments"
                );
                return Ok(ciphertext);
            }
        };
        if update_area_hint && hint.as_ref() != Some(&resolved) {
            crate::snapshot::remember_anchor_area_location(control, area_id, &resolved)?;
        }
        Ok(ciphertext)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use mb_core::{Seed, canonical_bytes};
    use uuid::Uuid;

    #[test]
    fn paged_data_recipe_preserves_frozen_scoped_bytes_and_rejects_ambiguous_legacy_encodings() {
        // Immutable two-field Linux recipe, before historical addressing existed.
        let frozen = [
            16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, b'/', b'a', b'r', b'e', b'a', 1,
            1, b'/', 16, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, b'f', b'i', b'l', b'e',
            3,
        ];
        let anchor_id = Uuid::from_bytes([2; 16]);
        let scoped = PagedDataSource::decode(&frozen, anchor_id).unwrap();
        assert!(scoped.legacy.is_none());
        assert_eq!(scoped.anchor.offset, 3);
        assert_eq!(
            scoped.anchor.locator.area.area_id,
            Uuid::from_bytes([1; 16])
        );
        assert_eq!(scoped.encode().unwrap(), frozen);
        assert!(PagedDataSource::decode(&frozen, Uuid::new_v4()).is_err());
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([71; 32]));
        let (sector, ciphertext) =
            encrypted_sector(&keys.guild_data_key(&[73; 32]), [82; 32], b"old").unwrap();
        let legacy = PagedDataSource {
            anchor: scoped.anchor.clone(),
            legacy: Some(LegacyDataBinding {
                revision: [3; 32],
                scope: CatalogScope::Dataset {
                    guild_id: [73; 32],
                    owner: keys.node_id(),
                    protected_root_id: Uuid::from_bytes([74; 16]),
                },
                source: CatalogSectorRecord {
                    format_version: 1,
                    sector,
                    commitment: merkle_commit(&ciphertext).unwrap(),
                },
            }),
        };
        let encoded = legacy.encode().unwrap();
        assert_eq!(encoded[0], 1);
        assert_eq!(
            PagedDataSource::decode(&encoded, anchor_id).unwrap(),
            legacy
        );
        assert_eq!(canonical_bytes(&scoped.anchor).unwrap(), frozen);
        for bytes in [&frozen[..], &encoded[..]] {
            for length in 0..bytes.len() {
                assert!(PagedDataSource::decode(&bytes[..length], anchor_id).is_err());
            }
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(PagedDataSource::decode(&trailing, anchor_id).is_err());
            for version in [0, 2, 6, 7, 8, 17, 129] {
                let mut unknown = bytes.to_vec();
                unknown[0] = version;
                assert!(PagedDataSource::decode(&unknown, anchor_id).is_err());
            }
        }
        let mut overlong_version = vec![0x81, 0];
        overlong_version.extend_from_slice(&encoded[1..]);
        assert!(PagedDataSource::decode(&overlong_version, anchor_id).is_err());
        assert!(
            PagedDataSource::decode(&vec![1; mb_store::PAGED_DATA_RECIPE_BYTES + 1], anchor_id)
                .is_err()
        );
    }
}

//! Recover private pages from original signed encrypted source commitments.
//! Bootstrap authentication precedes trusting any private root or page address.

use crate::{PagedCatalogIntents, PagedPrivateMetadata};
use anyhow::{Context, Result, ensure};
use mb_core::{
    CatalogPageContents, CatalogPageRef, CatalogReader, CatalogScope, CatalogSection,
    CatalogSectorRecord, KeyMaterial, PagedUserRevision, SectorId, SignedRecord, WriterFence,
    canonical_bytes, merkle_commit,
};
use mb_store::{CatalogBundle, CatalogIntent, CatalogIntentState, ControlStore};

type Guard<'a> = dyn FnMut(&CatalogBundle) -> Result<()> + 'a;

pub(crate) fn recover(
    control: &ControlStore,
    keys: &KeyMaterial,
    identity: (&SignedRecord<PagedUserRevision>, uuid::Uuid),
    original: &[u8],
    mut source: impl FnMut(SectorId) -> Result<Option<CatalogSectorRecord>>,
    mut load: impl FnMut(&CatalogSectorRecord) -> Result<Vec<u8>>,
    callbacks: (&mut Guard<'_>, &mut Guard<'_>, &mut Guard<'_>),
) -> Result<()> {
    let (signed, owner) = identity;
    let (begin, finish, guard) = callbacks;
    let private = PagedPrivateMetadata::open(keys, signed.value.guild_id, signed, original)?;
    let scope = signed.value.scope();
    if let Some(existing) = control.paged_revision_catalog(signed.value.revision_id)? {
        ensure!(
            existing.state == mb_store::CatalogBundleState::Published
                && existing.bundle.descriptor == canonical_bytes(signed)?,
            "existing private recovery differs from its original revision"
        );
        PagedPrivateMetadata::open_local_snapshot(keys, &existing, scope)?;
        finish(&existing.bundle)?;
        return guard(&existing.bundle);
    }
    let intent = |role: u8, section: CatalogSection| -> Result<CatalogIntent> {
        let mut hash =
            blake3::Hasher::new_derive_key("mutualbackup recovered private catalog intent v1");
        hash.update(&canonical_bytes(&(
            owner,
            signed.value.hash()?,
            role,
            section,
        ))?);
        let mut id = [0; 16];
        id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
        Ok(CatalogIntent {
            id: uuid::Uuid::from_bytes(id),
            scope,
            section,
        })
    };
    let intents = PagedCatalogIntents {
        native: [
            intent(0, CatalogSection::FileMetadata)?,
            intent(1, CatalogSection::FileMetadata)?,
        ],
        sources: intent(2, CatalogSection::SectorReferences)?,
        git: private
            .git
            .as_ref()
            .map(|_| -> Result<_> {
                Ok([
                    intent(3, CatalogSection::GitGraph)?,
                    intent(4, CatalogSection::GitGraph)?,
                    intent(5, CatalogSection::GitGraph)?,
                ])
            })
            .transpose()?,
    };
    let bundle = private.local_bundle(signed, intents)?;
    begin(&bundle)?;
    for member in &bundle.roots {
        let state = control.catalog_intent_state(member.intent)?;
        match state {
            CatalogIntentState::Building => stage_tree(
                control,
                keys,
                scope,
                member.intent,
                member.root,
                0,
                &mut source,
                &mut load,
                &bundle,
                guard,
            )?,
            CatalogIntentState::Published(root) if root == member.root => {}
            _ => anyhow::bail!("recovered private intent differs from its original root"),
        }
        // Verify complete stream EOF even if a shared root was already staged.
        let mut reader = CatalogReader::new(scope, member.intent.section, member.root)?;
        while reader
            .next_leaf(&mut |page| control.catalog_page(scope, member.intent.section, page))?
            .is_some()
        {}
    }
    let fence = WriterFence {
        owner: signed.value.owner,
        epoch: signed.value.writer_epoch,
        public_key: signed.value.writer_public_key,
    };
    private.publish_local_catalog_with_operation(
        control,
        keys,
        signed,
        &fence,
        intents,
        (|_| Ok(None), || finish(&bundle), || guard(&bundle)),
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_tree(
    control: &ControlStore,
    keys: &KeyMaterial,
    scope: CatalogScope,
    intent: CatalogIntent,
    page: CatalogPageRef,
    depth: u8,
    source: &mut impl FnMut(SectorId) -> Result<Option<CatalogSectorRecord>>,
    load: &mut impl FnMut(&CatalogSectorRecord) -> Result<Vec<u8>>,
    bundle: &CatalogBundle,
    guard: &mut Guard<'_>,
) -> Result<()> {
    ensure!(
        depth <= mb_core::CATALOG_MAX_HEIGHT,
        "private page recovery exceeds its original depth"
    );
    guard(bundle)?;
    let bytes = if intent.section.is_private() {
        let CatalogScope::Dataset { guild_id, .. } = scope else {
            anyhow::bail!("private recovery lacks dataset scope")
        };
        let id =
            page.private_sector_id(&keys.guild_content_id_key(&guild_id), scope, intent.section)?;
        let original = source(id)?.context("private page lacks an original signed source")?;
        let ciphertext = load(&original)?;
        ensure!(
            merkle_commit(&ciphertext)? == original.commitment,
            "private page ciphertext differs from its original commitment"
        );
        page.open_private_page(
            &keys.guild_content_id_key(&guild_id),
            &keys.guild_data_key(&guild_id),
            scope,
            intent.section,
            &original.sector,
            &ciphertext,
        )?
    } else {
        control.catalog_page(scope, intent.section, page)?
    };
    if let CatalogPageContents::Index(children) = page.verify_page(scope, intent.section, &bytes)? {
        for child in children {
            stage_tree(
                control,
                keys,
                scope,
                intent,
                child,
                depth + 1,
                source,
                load,
                bundle,
                guard,
            )?;
        }
    }
    guard(bundle)?;
    control.stage_catalog_page(intent, page, &bytes)?;
    Ok(())
}

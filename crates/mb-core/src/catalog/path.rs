//! Bounded authenticated paths for fetching a page from an already trusted root.

use super::*;
use serde::de::DeserializeSeed;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPagePath {
    pub scope: CatalogScope,
    pub section: CatalogSection,
    #[serde(deserialize_with = "decode_pages")]
    pub pages: Vec<CatalogPageRef>,
}

fn decode_pages<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<CatalogPageRef>, D::Error> {
    crate::bounded::VecSeed::new(usize::from(CATALOG_MAX_HEIGHT) + 1).deserialize(decoder)
}

impl CatalogPagePath {
    pub fn validate(&self) -> Result<(), CatalogError> {
        self.scope.validate(self.section)?;
        if self.pages.is_empty() || self.pages.len() > usize::from(CATALOG_MAX_HEIGHT) + 1 {
            return Err(CatalogError::Bounds);
        }
        for page in &self.pages {
            page.validate()?;
        }
        if self
            .pages
            .windows(2)
            .any(|pair| pair[0].height.checked_sub(1) != Some(pair[1].height))
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    /// The caller must authenticate the first reference as an owned/signed root.
    /// Verify every parent edge before fetching its child, and return only the
    /// original encoded target page. A path never authenticates its own root.
    pub fn read<E>(
        &self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Vec<u8>, CatalogStreamError<E>> {
        self.validate()?;
        for (index, page) in self.pages.iter().copied().enumerate() {
            let bytes = fetch(page).map_err(CatalogStreamError::Storage)?;
            let contents = page.verify_page(self.scope, self.section, &bytes)?;
            let Some(next) = self.pages.get(index + 1) else {
                return Ok(bytes);
            };
            if !matches!(contents, CatalogPageContents::Index(children) if children.contains(next))
            {
                return Err(CatalogError::InvalidPage.into());
            }
        }
        Err(CatalogError::InvalidPage.into())
    }
}

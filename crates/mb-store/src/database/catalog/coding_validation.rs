//! Complete coding evidence traversal followed by exact local bundle binding.
//! This does not activate a checkpoint, authorize delegation by itself or own
//! physical source/parity payloads. Current authority joins remain external.

use mb_core::{
    CATALOG_CODING_MAX_BYTES, CATALOG_CODING_ROOT_BYTES, CatalogCodingEntry, CatalogCodingReader,
    CatalogCodingRoot, canonical_bytes_bounded, canonical_size_bounded,
};

use super::*;

const MANIFEST_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingValidation {
    pub format_version: u16,
    pub scope: CatalogScope,
    pub root: CatalogCodingRoot,
}

impl CatalogCodingValidation {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > MANIFEST_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate()?;
        if canonical_bytes_bounded(&manifest, MANIFEST_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), CatalogStoreError> {
        self.scope.validate(CatalogSection::Coding)?;
        self.root.validate()?;
        if self.format_version != 1
            || !matches!(self.scope, CatalogScope::Guild { guild_id } if guild_id != [0; 32])
        {
            return Err(DatabaseError::Integrity.into());
        }
        let bytes = self.root.represented_bytes()?
            - canonical_size_bounded(&self.root, CATALOG_CODING_ROOT_BYTES)? as u64
            + canonical_size_bounded(self, MANIFEST_BYTES)? as u64;
        if bytes > CATALOG_CODING_MAX_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        Ok(())
    }
}

/// Constructible only after complete typed/replayed EOF and every required
/// external group authorization. This token binds immutable metadata bytes;
/// live authority and current checkpoint checks still precede activation.
pub struct CatalogValidatedCoding {
    manifest: CatalogCodingValidation,
}

impl CatalogValidatedCoding {
    /// The required callback must check certified delegation/membership/domains,
    /// source/packing coverage and retained lifecycle authority. It must use
    /// read-only state or a disposable job so failure cannot publish a prefix.
    /// This traversal holds no production SQL writer or whole-catalog vector.
    pub fn verify(
        manifest: CatalogCodingValidation,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(&CatalogCodingEntry) -> Result<(), CatalogStoreError>,
    ) -> Result<Self, CatalogStoreError> {
        manifest.validate()?;
        let mut reader = CatalogCodingReader::new(manifest.scope, manifest.root.clone())?;
        while let Some(entry) =
            super::packing_validation::unwrap_stream(reader.next_group(&mut fetch))?
        {
            authorize(&entry)?;
        }
        Ok(Self { manifest })
    }

    pub fn manifest(&self) -> &CatalogCodingValidation {
        &self.manifest
    }

    /// Bind exactly the complete forest parts in directory order. Publication
    /// uses the existing atomic bundle journal and rechecks every intent. Empty
    /// forests need no page pins and travel in the enclosing descriptor only.
    pub fn as_local_bundle(
        &self,
        id: Uuid,
        intents: &[CatalogIntent],
    ) -> Result<Option<CatalogBundle>, CatalogStoreError> {
        if id.is_nil() || intents.len() != self.manifest.root.parts.len() {
            return Err(DatabaseError::Conflict.into());
        }
        for intent in intents {
            if intent.scope != self.manifest.scope || intent.section != CatalogSection::Coding {
                return Err(DatabaseError::Conflict.into());
            }
        }
        if intents.is_empty() {
            return Ok(None);
        }
        let bundle = CatalogBundle {
            id,
            scope: self.manifest.scope,
            roots: intents
                .iter()
                .zip(&self.manifest.root.parts)
                .map(|(intent, part)| CatalogBundleRoot {
                    intent: *intent,
                    root: part.page,
                })
                .collect(),
            descriptor: canonical_bytes_bounded(&self.manifest, MANIFEST_BYTES)?,
        };
        bundle.validate()?;
        Ok(Some(bundle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{
        CatalogCodingBuilder, CatalogCodingSummary, CodingVerificationTranscript, KeyMaterial,
        RetainedCodingGroup, Seed, SignedRecord,
    };
    use std::collections::HashMap;

    fn keys() -> KeyMaterial {
        KeyMaterial::from_seed(&Seed::from_bytes([48; 32]))
    }
    fn scope() -> CatalogScope {
        CatalogScope::Guild { guild_id: [37; 32] }
    }
    struct Fixture {
        manifest: CatalogCodingValidation,
        intents: Vec<CatalogIntent>,
        pages: HashMap<[u8; 32], Vec<u8>>,
    }

    impl Fixture {
        fn new(store: &ControlStore) -> Self {
            let witnesses: Vec<SignedRecord<CodingVerificationTranscript>> = decode_canonical(
                &hex::decode(
                    include_str!(
                        "../../../../../protocol/vectors/coding-transcripts-v1.postcard.hex"
                    )
                    .trim(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(witnesses.len(), 4);
            let mut parts = Vec::new();
            let mut intents = Vec::new();
            let mut pages = HashMap::new();
            let mut summary = CatalogCodingSummary::default();
            for (index, transcript) in witnesses.into_iter().enumerate() {
                let intent = CatalogIntent {
                    id: Uuid::from_u128(10 + index as u128),
                    scope: scope(),
                    section: CatalogSection::Coding,
                };
                store.begin_catalog(intent).unwrap();
                intents.push(intent);
                let entry = CatalogCodingEntry {
                    retained: RetainedCodingGroup {
                        group: transcript.value.manifest.value.group.clone(),
                        added_at_event: 1,
                        retired_at_event: None,
                        retain_through_event: None,
                    },
                    transcript,
                };
                let mut builder = CatalogCodingBuilder::new(scope(), i64::MAX as u64).unwrap();
                let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| {
                    store.stage_catalog_page(intent, page, &bytes)?;
                    pages.insert(page.hash, bytes);
                    Ok::<_, CatalogStoreError>(())
                };
                builder.push_group(&entry, &mut sink).unwrap();
                let root = builder.finish(&mut sink).unwrap();
                summary.groups += root.summary.groups;
                summary.retired_groups += root.summary.retired_groups;
                summary.information_roles += root.summary.information_roles;
                summary.parity_roles += root.summary.parity_roles;
                summary.transcript_bytes += root.summary.transcript_bytes;
                summary.fragments += root.summary.fragments;
                parts.extend(root.parts);
            }
            let root = CatalogCodingRoot {
                format_version: 1,
                guild_event_sequence: i64::MAX as u64,
                parts,
                summary,
            };
            assert_eq!(
                canonical_bytes(&root).unwrap(),
                hex::decode(
                    include_str!("../../../../../protocol/vectors/coding-evidence-v1.postcard.hex")
                        .trim()
                )
                .unwrap()
            );
            Self {
                manifest: CatalogCodingValidation {
                    format_version: 1,
                    scope: scope(),
                    root,
                },
                intents,
                pages,
            }
        }

        fn verify(&self, store: &ControlStore) -> CatalogValidatedCoding {
            let mut count = 0;
            let checked = CatalogValidatedCoding::verify(
                self.manifest.clone(),
                |page| store.catalog_page(scope(), CatalogSection::Coding, page),
                |_| {
                    count += 1;
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(count, 4);
            checked
        }
    }

    #[test]
    fn verified_coding_forest_reopens_atomic_bundles_and_retains_shared_page_owners() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let mut store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = Fixture::new(&store);
        let verified = fixture.verify(&store);
        let bundle = verified
            .as_local_bundle(Uuid::from_u128(20), &fixture.intents)
            .unwrap()
            .unwrap();
        assert_eq!(
            CatalogCodingValidation::decode(&bundle.descriptor).unwrap(),
            fixture.manifest
        );
        store.publish_catalog_bundle(&bundle).unwrap();
        for intent in &fixture.intents {
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        let successor_intents = fixture
            .intents
            .iter()
            .enumerate()
            .map(|(index, intent)| CatalogIntent {
                id: Uuid::from_u128(30 + index as u128),
                ..*intent
            })
            .collect::<Vec<_>>();
        for (intent, part) in successor_intents.iter().zip(&fixture.manifest.root.parts) {
            store.begin_catalog(*intent).unwrap();
            let bytes = store
                .catalog_page(scope(), CatalogSection::Coding, part.page)
                .unwrap();
            store
                .stage_catalog_page(*intent, part.page, &bytes)
                .unwrap();
        }
        let successor = verified
            .as_local_bundle(Uuid::from_u128(40), &successor_intents)
            .unwrap()
            .unwrap();
        store.publish_catalog_bundle(&successor).unwrap();
        drop(store);
        store = ControlStore::open(&path, &keys()).unwrap();
        assert_eq!(
            store.catalog_bundle(bundle.id).unwrap(),
            Some((bundle.clone(), CatalogBundleState::Published))
        );
        fixture.verify(&store);
        store.cancel_catalog_bundle(bundle.id).unwrap();
        for intent in &fixture.intents {
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        fixture.verify(&store);
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        store.cancel_catalog_bundle(successor.id).unwrap();
        for intent in &successor_intents {
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        assert!(
            CatalogValidatedCoding::verify(
                fixture.manifest,
                |page| store.catalog_page(scope(), CatalogSection::Coding, page),
                |_| Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn rejected_authority_late_fetch_and_cancelled_parts_cannot_publish_a_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = Fixture::new(&store);
        let mut count = 0;
        assert!(
            CatalogValidatedCoding::verify(
                fixture.manifest.clone(),
                |page| Ok(fixture.pages[&page.hash].clone()),
                |_| {
                    count += 1;
                    if count == 4 {
                        Err(DatabaseError::Conflict.into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_eq!(count, 4);
        let last = fixture.manifest.root.parts[3].page.hash;
        assert!(
            CatalogValidatedCoding::verify(
                fixture.manifest.clone(),
                |page| if page.hash == last {
                    Err(DatabaseError::NotReady.into())
                } else {
                    Ok(fixture.pages[&page.hash].clone())
                },
                |_| Ok(())
            )
            .is_err()
        );
        let checked = fixture.verify(&store);
        assert!(
            checked
                .as_local_bundle(Uuid::new_v4(), &fixture.intents[..3])
                .is_err()
        );
        let mut wrong = fixture.intents.clone();
        wrong[0].section = CatalogSection::Packing;
        assert!(checked.as_local_bundle(Uuid::new_v4(), &wrong).is_err());
        wrong[0] = wrong[1];
        assert!(checked.as_local_bundle(Uuid::new_v4(), &wrong).is_err());
        let bundle = checked
            .as_local_bundle(Uuid::from_u128(50), &fixture.intents)
            .unwrap()
            .unwrap();
        store.cancel_catalog(fixture.intents[3]).unwrap();
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
        for intent in &fixture.intents[..3] {
            assert_eq!(
                store.catalog_intent_state(*intent).unwrap(),
                CatalogIntentState::Building
            );
        }
        let mut empty = fixture.manifest;
        empty.root.parts.clear();
        empty.root.summary = CatalogCodingSummary::default();
        let checked = CatalogValidatedCoding::verify(
            empty.clone(),
            |_| panic!("empty forest fetched a page"),
            |_| panic!("empty forest authorized a group"),
        )
        .unwrap();
        assert!(
            checked
                .as_local_bundle(Uuid::new_v4(), &[])
                .unwrap()
                .is_none()
        );
        assert_eq!(checked.manifest(), &empty);
        assert!(CatalogCodingValidation::decode(&vec![0; MANIFEST_BYTES + 1]).is_err());
    }
}

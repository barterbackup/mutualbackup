//! Decode original intent layouts without migration, replay or filesystem I/O.
use super::*;
use serde::de::DeserializeOwned;

pub(crate) struct PreservedCaptureIntent {
    pub record_format: u16,
    pub guild_id: [u8; 32],
    pub revision_id: Uuid,
    pub sequence: Option<u64>,
    pub parent: Option<[u8; 32]>,
    pub captured_change_sequence: Option<u64>,
    pub requested_source: PathBuf,
    pub plan: SourceCapturePlan,
    pub replaced_anchor: Option<mb_store::StableAnchorManifest>,
}

fn original<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = decode_canonical(bytes)?;
    ensure!(
        canonical_bytes_bounded(&value, V1_MAX_CATALOG_BYTES)? == bytes,
        "preserved record is not canonical in its original layout"
    );
    Ok(value)
}

pub(crate) fn decode_capture_intent(
    kind: &str,
    key: &[u8],
    bytes: &[u8],
) -> Result<PreservedCaptureIntent> {
    let (version, _) = postcard::take_from_bytes::<u16>(bytes)
        .context("preserved capture intent version is undecodable")?;
    let intent = match (kind, version) {
        ("capture-intent", 1) => {
            let old: LegacyCaptureIntentV1 = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 1,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                sequence: Some(old.sequence),
                parent: old.parent,
                captured_change_sequence: None,
                requested_source: old.requested_source,
                plan: SourceCapturePlan::ReflinkV1(old.plan),
                replaced_anchor: None,
            }
        }
        ("capture-intent", 2) => {
            let old: LegacyCaptureIntentV2 = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 2,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                sequence: Some(old.sequence),
                parent: old.parent,
                captured_change_sequence: old.captured_change_sequence,
                requested_source: old.requested_source,
                plan: SourceCapturePlan::ReflinkV1(old.plan),
                replaced_anchor: None,
            }
        }
        ("capture-intent", 3) => {
            let current: CaptureIntent = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 3,
                guild_id: current.guild_id,
                revision_id: current.revision_id,
                sequence: Some(current.sequence),
                parent: current.parent,
                captured_change_sequence: current.captured_change_sequence,
                requested_source: current.requested_source,
                plan: current.plan,
                replaced_anchor: None,
            }
        }
        (RECOVERY_ANCHOR_INTENT_KIND, 1) => {
            let old: LegacyRecoveryAnchorIntentV1 = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 1,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                sequence: None,
                parent: None,
                captured_change_sequence: None,
                requested_source: old.source_root,
                plan: SourceCapturePlan::ReflinkV1(old.plan),
                replaced_anchor: old.replaced_anchor,
            }
        }
        (RECOVERY_ANCHOR_INTENT_KIND, 2) => {
            let current: RecoveryAnchorIntent = original(bytes)?;
            PreservedCaptureIntent {
                record_format: 2,
                guild_id: current.guild_id,
                revision_id: current.revision_id,
                sequence: None,
                parent: None,
                captured_change_sequence: None,
                requested_source: current.source_root,
                plan: current.plan,
                replaced_anchor: current.replaced_anchor,
            }
        }
        _ => bail!("unsupported preserved capture intent kind/version"),
    };
    ensure!(
        !intent.revision_id.is_nil() && key == intent.revision_id.as_bytes(),
        "preserved capture intent key differs from its revision ID"
    );
    Ok(intent)
}

pub(crate) struct PreservedGitGraphIntent {
    pub record_format: u16,
    pub guild_id: [u8; 32],
    pub revision_id: Uuid,
    pub protected_root_id: Uuid,
    pub graph: GitGraphSource,
    pub head_branch: String,
    pub head_branch_recorded: bool,
}

pub(crate) fn decode_git_graph_intent(key: &[u8], bytes: &[u8]) -> Result<PreservedGitGraphIntent> {
    let (version, _) = postcard::take_from_bytes::<u16>(bytes)?;
    let intent = match version {
        1 => {
            let old: LegacyGitGraphIntentV1 = original(bytes)?;
            PreservedGitGraphIntent {
                record_format: 1,
                guild_id: old.guild_id,
                revision_id: old.revision_id,
                protected_root_id: old.protected_root_id,
                graph: old.graph,
                head_branch: "main".to_owned(),
                head_branch_recorded: false,
            }
        }
        2 => {
            let current: GitGraphIntent = original(bytes)?;
            PreservedGitGraphIntent {
                record_format: 2,
                guild_id: current.guild_id,
                revision_id: current.revision_id,
                protected_root_id: current.protected_root_id,
                graph: current.graph,
                head_branch: current.head_branch,
                head_branch_recorded: true,
            }
        }
        _ => bail!("unsupported preserved Git graph intent version"),
    };
    ensure!(
        !intent.revision_id.is_nil()
            && key == intent.revision_id.as_bytes()
            && !intent.protected_root_id.is_nil()
            && intent.graph.repository_id == intent.protected_root_id,
        "invalid preserved Git graph intent identity"
    );
    for blob in &intent.graph.blobs {
        blob.anchor.preserved_ownership()?;
    }
    intent.graph.validate_metadata(&intent.head_branch)?;
    Ok(intent)
}

pub(crate) const PRESERVED_AREA_LOCATION_BYTES: usize = MAX_ENCODED_ANCHOR_LOCATION_BYTES;

pub(crate) fn decode_area_location(bytes: &[u8]) -> Result<PathBuf> {
    let path: RawLocalPath = original(bytes)?;
    ensure!(
        path.0.as_os_str().as_encoded_bytes().len() <= MAX_ANCHOR_LOCATION_BYTES
            && !path.0.as_os_str().as_encoded_bytes().contains(&0),
        "invalid preserved anchor area location"
    );
    Ok(path.0)
}

/// Metadata only; inline plaintext and anchor/page payloads are never returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyLocalSectorRecipe {
    pub guild_id: String,
    pub sector_id: String,
    pub ciphertext_root: String,
    pub logical_len: u32,
    pub source: LegacyLocalSectorSource,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyLocalSectorSource {
    Anchor {
        area_id: Uuid,
        area_path_hint_hex: String,
        area_path_hint_is_absolute: bool,
        anchor_id: Uuid,
        relative_path_hex: String,
        offset: u64,
    },
    StableAnchor {
        area_id: Uuid,
        area_path_hint_hex: String,
        area_path_hint_is_absolute: bool,
        recorded_filesystem_id: u64,
        volume_root_hint_hex: String,
        anchor_id: Uuid,
        relative_path_hex: String,
        offset: u64,
    },
    Inline {
        byte_length: u32,
    },
    CatalogPage {
        scope: CatalogScope,
        section: CatalogSection,
        page: CatalogPageRef,
    },
}

pub(crate) struct PreservedLocalSectorRecipe(LocalSectorRecipe);

impl PreservedLocalSectorRecipe {
    pub(crate) fn for_each_path(&self, mut visit: impl FnMut(&Path) -> Result<()>) -> Result<()> {
        let path = match &self.0.source {
            LocalPlaintextSource::AnchorFile { locator, .. } => Some(&locator.area.path_hint),
            LocalPlaintextSource::StableAnchorFile { locator, .. } => Some(&locator.area.path_hint),
            _ => None,
        };
        if let Some(path) = path.filter(|path| path.is_absolute()) {
            visit(path)?;
        }
        Ok(())
    }

    pub(crate) fn report(&self) -> LegacyLocalSectorRecipe {
        use std::os::unix::ffi::OsStrExt;
        let source = match &self.0.source {
            LocalPlaintextSource::AnchorFile { locator, offset } => {
                LegacyLocalSectorSource::Anchor {
                    area_id: locator.area.area_id,
                    area_path_hint_hex: hex::encode(locator.area.path_hint.as_os_str().as_bytes()),
                    area_path_hint_is_absolute: locator.area.path_hint.is_absolute(),
                    anchor_id: locator.anchor_id,
                    relative_path_hex: hex::encode(locator.relative_path.as_bytes()),
                    offset: *offset,
                }
            }
            LocalPlaintextSource::StableAnchorFile { locator, offset } => {
                LegacyLocalSectorSource::StableAnchor {
                    area_id: locator.area.area_id,
                    area_path_hint_hex: hex::encode(locator.area.path_hint.as_os_str().as_bytes()),
                    area_path_hint_is_absolute: locator.area.path_hint.is_absolute(),
                    recorded_filesystem_id: locator.area.filesystem_id,
                    volume_root_hint_hex: hex::encode(
                        locator.area.volume_root_hint.as_os_str().as_bytes(),
                    ),
                    anchor_id: locator.anchor_id,
                    relative_path_hex: hex::encode(locator.relative_path.as_os_str().as_bytes()),
                    offset: *offset,
                }
            }
            LocalPlaintextSource::Inline(bytes) => LegacyLocalSectorSource::Inline {
                byte_length: bytes.len() as u32,
            },
            LocalPlaintextSource::CatalogPage {
                scope,
                section,
                page,
            } => LegacyLocalSectorSource::CatalogPage {
                scope: *scope,
                section: *section,
                page: *page,
            },
        };
        LegacyLocalSectorRecipe {
            guild_id: hex::encode(self.0.guild_id),
            sector_id: hex::encode(self.0.reference.id),
            ciphertext_root: hex::encode(self.0.reference.root),
            logical_len: self.0.reference.logical_len,
            source,
            payloads_verified: false,
        }
    }
}

pub(crate) fn decode_local_sector(key: &[u8], bytes: &[u8]) -> Result<PreservedLocalSectorRecipe> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        bytes.len() <= V1_SECTOR_SIZE + 4096,
        "preserved local sector recipe exceeds its row budget"
    );
    let recipe: LocalSectorRecipe = original(bytes)?;
    ensure!(
        key == recipe.reference.id
            && recipe.guild_id != [0; 32]
            && recipe.reference.id != [0; 32]
            && recipe.reference.root != [0; 32]
            && recipe.reference.logical_len as usize <= V1_SECTOR_SIZE,
        "invalid preserved local sector recipe identity or geometry"
    );
    let validate_hint = |path: &Path| -> Result<()> {
        ensure!(
            !path.as_os_str().as_bytes().contains(&0),
            "invalid preserved sector area path hint"
        );
        Ok(())
    };
    let validate_anchor =
        |area_id: Uuid, anchor_id: Uuid, relative: &Path, offset: u64| -> Result<()> {
            ensure!(
                !area_id.is_nil() && !anchor_id.is_nil(),
                "invalid preserved sector anchor identity"
            );
            ensure!(
                !relative.as_os_str().is_empty()
                    && !relative.as_os_str().as_bytes().contains(&0)
                    && relative
                        .components()
                        .all(|component| matches!(component, std::path::Component::Normal(_)))
                    && relative.components().collect::<PathBuf>().as_os_str()
                        == relative.as_os_str(),
                "unsafe preserved sector anchor relative path"
            );
            ensure!(
                offset
                    .checked_add(u64::from(recipe.reference.logical_len))
                    .is_some_and(|end| end <= i64::MAX as u64),
                "preserved sector anchor range overflows"
            );
            Ok(())
        };
    match &recipe.source {
        LocalPlaintextSource::AnchorFile { locator, offset } => {
            validate_hint(&locator.area.path_hint)?;
            validate_anchor(
                locator.area.area_id,
                locator.anchor_id,
                Path::new(&locator.relative_path),
                *offset,
            )?;
        }
        LocalPlaintextSource::StableAnchorFile { locator, offset } => {
            validate_hint(&locator.area.path_hint)?;
            validate_hint(&locator.area.volume_root_hint)?;
            ensure!(
                locator.area.filesystem_id != 0,
                "invalid preserved sector filesystem identity"
            );
            validate_anchor(
                locator.area.area_id,
                locator.anchor_id,
                &locator.relative_path,
                *offset,
            )?;
        }
        LocalPlaintextSource::Inline(plaintext) => {
            // Empty Inline recipes are the original synthetic filler encoding.
            ensure!(
                plaintext.len() == recipe.reference.logical_len as usize,
                "preserved inline recipe length differs from its reference"
            );
        }
        LocalPlaintextSource::CatalogPage {
            scope,
            section,
            page,
        } => {
            scope.validate(*section)?;
            page.validate()?;
            let scope_guild = match scope {
                CatalogScope::Dataset { guild_id, .. } | CatalogScope::Guild { guild_id } => {
                    guild_id
                }
            };
            ensure!(
                section.is_private()
                    && *scope_guild == recipe.guild_id
                    && page.encoded_len == recipe.reference.logical_len,
                "preserved page recipe differs from its private scope or geometry"
            );
        }
    }
    Ok(PreservedLocalSectorRecipe(recipe))
}

#[cfg(test)]
pub(crate) fn local_sector_test_records(base: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    tests::recipes(base)
        .into_iter()
        .map(|recipe| {
            (
                recipe.reference.id.to_vec(),
                canonical_bytes(&recipe).unwrap(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    pub(super) fn recipes(base: &Path) -> Vec<LocalSectorRecipe> {
        let reference = SectorRef {
            id: [102; 32],
            root: [103; 32],
            logical_len: 4,
        };
        let legacy = LocalSectorRecipe {
            guild_id: [101; 32],
            reference: reference.clone(),
            source: LocalPlaintextSource::AnchorFile {
                locator: AnchorFileLocator {
                    area: mb_store::AnchorAreaLocator {
                        area_id: Uuid::from_u128(1),
                        path_hint: base.join("legacy-area"),
                    },
                    anchor_id: Uuid::from_u128(2),
                    relative_path: "file".to_owned(),
                },
                offset: 7,
            },
        };
        let stable = LocalSectorRecipe {
            reference: SectorRef {
                id: [104; 32],
                ..reference.clone()
            },
            source: LocalPlaintextSource::StableAnchorFile {
                locator: StableAnchorFileLocator {
                    area: mb_store::StableAnchorAreaLocator {
                        area_id: Uuid::from_u128(3),
                        path_hint: base.join(OsString::from_vec(b"raw-area-\xff".to_vec())),
                        filesystem_id: 42,
                        volume_root_hint: PathBuf::from(OsString::from_vec(
                            b"/old-volume-\xfe".to_vec(),
                        )),
                    },
                    anchor_id: Uuid::from_u128(4),
                    relative_path: PathBuf::from(OsString::from_vec(b"file-\xfd".to_vec())),
                },
                offset: 9,
            },
            ..legacy.clone()
        };
        let inline = LocalSectorRecipe {
            reference: SectorRef {
                id: [105; 32],
                ..reference.clone()
            },
            source: LocalPlaintextSource::Inline(b"hide".to_vec()),
            ..legacy.clone()
        };
        let filler = LocalSectorRecipe {
            reference: SectorRef {
                id: [106; 32],
                logical_len: 0,
                ..reference.clone()
            },
            source: LocalPlaintextSource::Inline(Vec::new()),
            ..legacy.clone()
        };
        let page = LocalSectorRecipe {
            reference: SectorRef {
                id: [107; 32],
                logical_len: 100,
                ..reference.clone()
            },
            source: LocalPlaintextSource::CatalogPage {
                scope: CatalogScope::Dataset {
                    guild_id: legacy.guild_id,
                    owner: mb_core::NodeId([108; 32]),
                    protected_root_id: Uuid::from_u128(5),
                },
                section: CatalogSection::FileMetadata,
                page: CatalogPageRef {
                    hash: [109; 32],
                    encoded_len: 100,
                    height: 0,
                    byte_len: 4,
                    page_occurrences: 1,
                },
            },
            ..legacy.clone()
        };
        let mut relative = stable.clone();
        relative.reference.id = [110; 32];
        let LocalPlaintextSource::StableAnchorFile { locator, .. } = &mut relative.source else {
            unreachable!()
        };
        locator.area.path_hint = PathBuf::from("old-cwd/area");
        vec![legacy, stable, inline, filler, page, relative]
    }

    #[test]
    fn legacy_export_local_sector_decoder_rejects_malformed_original_recipes() {
        let area = tempfile::tempdir().unwrap();
        for recipe in recipes(area.path()) {
            let bytes = canonical_bytes(&recipe).unwrap();
            let mut wrong = recipe.reference.id;
            wrong[0] ^= 1;
            assert!(decode_local_sector(&wrong, &bytes).is_err());
            assert!(decode_local_sector(&recipe.reference.id, &[bytes, vec![0]].concat()).is_err());
            assert!(
                decode_local_sector(&recipe.reference.id, &vec![0; V1_SECTOR_SIZE + 4097]).is_err()
            );
            let mut invalid = recipe.clone();
            match &mut invalid.source {
                LocalPlaintextSource::AnchorFile { locator, .. } => {
                    locator.relative_path = "../escape".to_owned()
                }
                LocalPlaintextSource::StableAnchorFile { offset, .. } => *offset = u64::MAX,
                LocalPlaintextSource::Inline(plaintext) => plaintext.push(1),
                LocalPlaintextSource::CatalogPage { section, .. } => {
                    *section = CatalogSection::Checkpoint
                }
            }
            assert!(
                decode_local_sector(&invalid.reference.id, &canonical_bytes(&invalid).unwrap())
                    .is_err()
            );
        }
        let mut invalid = recipes(area.path()).remove(1);
        let LocalPlaintextSource::StableAnchorFile { locator, .. } = &mut invalid.source else {
            unreachable!()
        };
        locator.area.path_hint = PathBuf::from(OsString::from_vec(b"/nul\0area".to_vec()));
        assert!(
            decode_local_sector(&invalid.reference.id, &canonical_bytes(&invalid).unwrap())
                .is_err()
        );
    }

    #[test]
    fn legacy_export_local_sector_inventory_preserves_original_sources_and_inline_privacy() {
        for mode in ["closed", "wal-only", "live"] {
            let area = tempfile::tempdir().unwrap();
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([100; 32]));
            let database = area.path().join("control.db");
            let control = ControlStore::open(&database, &keys).unwrap();
            let fixtures = recipes(area.path());
            for recipe in &fixtures {
                control
                    .put_record(
                        "local-sector",
                        &recipe.reference.id,
                        &canonical_bytes(recipe).unwrap(),
                    )
                    .unwrap();
            }
            let mut writer = Some(control);
            if mode == "closed" {
                drop(writer.take());
            }
            if mode == "wal-only" {
                fs::remove_file(database.with_extension("db-shm")).unwrap();
            }
            let names = || {
                let mut names = fs::read_dir(area.path())
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>();
                names.sort();
                names
            };
            let before_names = names();
            let before_main = fs::read(&database).unwrap();
            let before_wal = fs::read(database.with_extension("db-wal")).ok();
            let report =
                crate::inventory_withdrawn_revisions_from_catalog(&keys, area.path()).unwrap();
            assert_eq!(report.format_version, 14);
            assert!(!report.retained_history_complete);
            let entries = &report.local_state.local_sectors;
            assert_eq!(entries.len(), fixtures.len());
            for recipe in &fixtures {
                let entry = entries
                    .iter()
                    .find(|entry| entry.sector_id == hex::encode(recipe.reference.id))
                    .unwrap();
                assert_eq!(entry.guild_id, hex::encode(recipe.guild_id));
                assert_eq!(entry.ciphertext_root, hex::encode(recipe.reference.root));
                assert_eq!(entry.logical_len, recipe.reference.logical_len);
                assert!(!entry.payloads_verified);
            }
            assert!(entries.iter().any(|entry| matches!(
                &entry.source,
                LegacyLocalSectorSource::Inline { byte_length: 0 }
            )));
            assert!(entries.iter().any(|entry| matches!(
                &entry.source,
                LegacyLocalSectorSource::StableAnchor {
                    area_path_hint_is_absolute: false,
                    ..
                }
            )));
            let stable = entries
                .iter()
                .find_map(|entry| match &entry.source {
                    LegacyLocalSectorSource::StableAnchor {
                        area_path_hint_hex,
                        area_path_hint_is_absolute: true,
                        relative_path_hex,
                        ..
                    } => Some((area_path_hint_hex, relative_path_hex)),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                *stable.0,
                hex::encode(
                    area.path()
                        .join(OsString::from_vec(b"raw-area-\xff".to_vec()))
                        .as_os_str()
                        .as_bytes()
                )
            );
            assert_eq!(*stable.1, hex::encode(b"file-\xfd"));
            let json = serde_json::to_vec(&report).unwrap();
            assert_eq!(
                serde_json::from_slice::<crate::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            let text = std::str::from_utf8(&json).unwrap();
            assert!(!text.contains("hide") && !text.contains(&hex::encode(b"hide")));
            assert_eq!(names(), before_names, "{mode}");
            assert_eq!(fs::read(&database).unwrap(), before_main, "{mode}");
            assert_eq!(
                fs::read(database.with_extension("db-wal")).ok(),
                before_wal,
                "{mode}"
            );
            drop(writer);
        }
    }
}

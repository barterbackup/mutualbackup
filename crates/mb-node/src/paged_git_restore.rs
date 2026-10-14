//! Complete paged Git payload recovery inside an inode-owned restore tree.
//! Only one page, reference fragment and plaintext sector are retained at once.

use std::io::{self, Read};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use mb_core::{CatalogScope, CatalogSection, KeyMaterial, SectorId, SectorRef, merkle_commit};
use mb_git::{GitBlobCatalogReader, GitBlobRecord, GitCatalogRoot, GitRepository};
use mb_store::{ControlStore, ImportedBlobCapturePlan, PinnedDirectory};
use uuid::Uuid;

struct Blobs<'a, F> {
    control: &'a ControlStore,
    revision: Uuid,
    scope: CatalogScope,
    reader: GitBlobCatalogReader,
    pending: Option<GitBlobRecord>,
    encryption: [u8; 32],
    load: &'a mut F,
}

impl<F: FnMut(&SectorId) -> Result<Vec<u8>>> Blobs<'_, F> {
    fn next(&mut self) -> Result<Option<GitBlobRecord>> {
        if let Some(record) = self.pending.take() {
            return Ok(Some(record));
        }
        Ok(self.reader.next_record(&mut |page| {
            self.control
                .catalog_page(self.scope, CatalogSection::GitGraph, page)
        })?)
    }

    fn header(&mut self, oid: [u8; 20]) -> Result<u64> {
        let Some(GitBlobRecord::Blob {
            oid: expected,
            logical_len,
            ..
        }) = self.next()?
        else {
            anyhow::bail!("Git recovery lacks its original blob header");
        };
        ensure!(expected == oid, "Git recovery blob order/identity differs");
        Ok(logical_len)
    }

    fn boundary(&mut self) -> Result<()> {
        match self.next()? {
            Some(record @ GitBlobRecord::Blob { .. }) => self.pending = Some(record),
            None => {}
            _ => anyhow::bail!("Git blob recipe has unconsumed extents or references"),
        }
        Ok(())
    }

    fn plaintext(&mut self, reference: &SectorRef) -> Result<Vec<u8>> {
        let source = self
            .control
            .native_file_catalog_source(self.revision, reference.id)?
            .context("Git blob lacks a verified original source")?;
        ensure!(
            source.sector == *reference,
            "Git blob differs from the original signed source"
        );
        crate::snapshot::decrypt_reference(&self.encryption, reference, &mut |id| {
            let bytes = (self.load)(id)?;
            ensure!(
                merkle_commit(&bytes)? == source.commitment,
                "Git blob ciphertext commitment differs"
            );
            Ok(bytes)
        })
    }
}

struct BlobReader<'a, 'b, F> {
    blobs: &'a mut Blobs<'b, F>,
    length: u64,
    position: u64,
    extent: Option<(u64, u64)>,
    references: Vec<SectorRef>,
    reference: usize,
    plaintext: Vec<u8>,
    consumed: usize,
    trailing_hole: bool,
    complete: bool,
}

impl<'a, 'b, F: FnMut(&SectorId) -> Result<Vec<u8>>> BlobReader<'a, 'b, F> {
    fn new(blobs: &'a mut Blobs<'b, F>, length: u64) -> Self {
        Self {
            blobs,
            length,
            position: 0,
            extent: None,
            references: Vec::new(),
            reference: 0,
            plaintext: Vec::new(),
            consumed: 0,
            trailing_hole: false,
            complete: false,
        }
    }

    fn finish(&mut self) -> Result<()> {
        ensure!(
            self.position == self.length
                && self.consumed == self.plaintext.len()
                && self.reference == self.references.len()
                && self.extent.is_none_or(|(_, end)| end == self.position),
            "Git blob plaintext/recipe is incomplete"
        );
        if !self.complete {
            if !self.trailing_hole {
                self.blobs.boundary()?;
            }
            self.complete = true;
        }
        Ok(())
    }

    fn read_checked(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.position == self.length {
            self.finish()?;
            return Ok(0);
        }
        loop {
            if self.consumed < self.plaintext.len() {
                let size = output.len().min(self.plaintext.len() - self.consumed);
                output[..size]
                    .copy_from_slice(&self.plaintext[self.consumed..self.consumed + size]);
                self.consumed += size;
                self.position += size as u64;
                return Ok(size);
            }
            if self.trailing_hole {
                let size = (self.length - self.position).min(output.len() as u64) as usize;
                output[..size].fill(0);
                self.position += size as u64;
                return Ok(size);
            }
            if let Some((start, end)) = self.extent {
                if self.position < start {
                    let size = (start - self.position).min(output.len() as u64) as usize;
                    output[..size].fill(0);
                    self.position += size as u64;
                    return Ok(size);
                }
                if self.position == end {
                    ensure!(
                        self.reference == self.references.len(),
                        "Git extent has extra sector references"
                    );
                    self.extent = None;
                    self.references.clear();
                    self.reference = 0;
                    continue;
                }
                ensure!(self.position < end, "Git extent plaintext overflow");
                if self.reference < self.references.len() {
                    let reference = self.references[self.reference].clone();
                    self.reference += 1;
                    self.plaintext = self.blobs.plaintext(&reference)?;
                    self.consumed = 0;
                    ensure!(
                        !self.plaintext.is_empty()
                            && self.plaintext.len() as u64 <= end - self.position,
                        "Git sector exceeds its original extent"
                    );
                    continue;
                }
                let Some(GitBlobRecord::Sectors { references, .. }) = self.blobs.next()? else {
                    anyhow::bail!("Git extent is missing its sector fragment");
                };
                self.references = references;
                self.reference = 0;
                continue;
            }
            match self.blobs.next()? {
                Some(GitBlobRecord::Extent {
                    offset,
                    logical_len,
                    ..
                }) => {
                    let end = offset
                        .checked_add(logical_len)
                        .context("Git extent end overflow")?;
                    ensure!(
                        offset >= self.position && end <= self.length,
                        "Git extent is outside its original blob"
                    );
                    self.extent = Some((offset, end));
                }
                Some(record @ GitBlobRecord::Blob { .. }) => {
                    self.blobs.pending = Some(record);
                    self.trailing_hole = true;
                }
                None => self.trailing_hole = true,
                _ => anyhow::bail!("Git sector fragment has no extent"),
            }
        }
    }
}

impl<F: FnMut(&SectorId) -> Result<Vec<u8>>> Read for BlobReader<'_, '_, F> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.read_checked(output).map_err(io::Error::other)
    }
}

pub(crate) fn restore(
    control: &ControlStore,
    keys: &KeyMaterial,
    original: (Uuid, CatalogScope, &GitCatalogRoot),
    output: (&PinnedDirectory, &Path),
    load: &mut impl FnMut(&SectorId) -> Result<Vec<u8>>,
) -> Result<()> {
    let (revision, scope, git) = original;
    let (root, target) = output;
    let CatalogScope::Dataset {
        guild_id,
        protected_root_id,
        owner,
    } = scope
    else {
        anyhow::bail!("Git restore requires dataset scope");
    };
    ensure!(
        git.repository_id == protected_root_id && owner == keys.node_id(),
        "Git restore belongs to another owner/root"
    );
    let repository = GitRepository::init(
        root.descriptor_path(),
        git.repository_id,
        &mb_git::catalog_key(keys, git.repository_id),
    )?;
    let directory = root
        .open_child_directory(mb_store::GIT_CATALOG_DIRECTORY)?
        .context("restored Git catalog disappeared")?;
    // The import root's external anchor area is its parent, the private Git
    // catalog. Every completed/partial payload therefore stays inside this
    // restore job's inode-owned tree and follows its existing retry cleanup.
    let source = directory.create_child_directory("recovered-blob-source")?;
    directory.sync_all()?;
    let source_path = source.descriptor_path().canonicalize()?;
    let scratch =
        crate::volume::paged_scratch_store(control, mb_core::CATALOG_MAX_STREAM_BYTES * 4)?;
    let mut blobs = Blobs {
        control,
        revision,
        scope,
        reader: GitBlobCatalogReader::new(scope, git.blobs)?,
        pending: None,
        encryption: keys.guild_data_key(&guild_id),
        load,
    };
    repository.import_paged_backup_for_rename(
        scope,
        git,
        &scratch,
        target,
        |page| Ok(control.catalog_page(scope, CatalogSection::GitGraph, page)?),
        |oid| {
            let length = blobs.header(oid)?;
            let plan = ImportedBlobCapturePlan::plan(&source_path, length)?;
            let mut reader = BlobReader::new(&mut blobs, length);
            let manifest = plan.capture(&mut reader)?;
            reader.finish()?;
            Ok(manifest)
        },
    )?;
    ensure!(
        blobs.next()?.is_none(),
        "Git recovery did not authenticate complete blob EOF"
    );
    source.sync_all()?;
    directory.sync_all()?;
    root.sync_all()?;
    Ok(())
}

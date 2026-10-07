//! Streaming graph validation with bounded semantic parsing and an encrypted
//! disposable disk index for edges, reachability and DFS frames.

use anyhow::{Context, Result, ensure};
use git2::{ObjectType, Oid, Repository};
use mb_core::{
    CATALOG_MAX_RECORDS, CatalogPageRef, CatalogScope, CatalogSection, canonical_bytes_bounded,
    decode_canonical,
};
use mb_store::RecordScratchStore;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use uuid::Uuid;

use crate::{
    GIT_REF_NAME_BYTES, GitBlobCatalogReader, GitBlobRecord, GitCatalogRoot,
    GitObjectCatalogReader, GitObjectRecord, GitRefCatalogReader,
};

const ROW_BYTES: usize = GIT_REF_NAME_BYTES + 128;
const NODES: &str = "git-graph-node";
const EDGES: &str = "git-graph-edge";
const STACK: &str = "git-graph-stack";
const NAMES: &str = "git-graph-tree-name";

#[derive(Serialize, Deserialize)]
struct Node {
    kind: u8,
    logical_len: u64,
    edges: u64,
    state: u8,
    longest_path: u64,
    unsafe_root: bool,
    tag_name_hash: [u8; 32],
    tag_name_len: u64,
}

#[derive(Serialize, Deserialize)]
struct Edge {
    target: [u8; 20],
    kind: u8,
    name: Vec<u8>,
    symlink: bool,
}

#[derive(Serialize, Deserialize)]
struct Frame {
    oid: [u8; 20],
    next: u64,
    longest: u64,
}

fn oid_bytes(oid: Oid) -> [u8; 20] {
    oid.as_bytes().try_into().expect("SHA-1 Git object")
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(canonical_bytes_bounded(value, ROW_BYTES)?)
}

fn put(store: &RecordScratchStore, kind: &str, key: &[u8], bytes: &[u8]) -> Result<()> {
    ensure!(
        store.put_record_if_absent(kind, key, bytes)?,
        "duplicate graph identity"
    );
    ensure!(
        store.get_record_bounded(kind, key, ROW_BYTES)?.as_deref() == Some(bytes),
        "graph index insertion was ignored"
    );
    Ok(())
}

fn row<T: serde::de::DeserializeOwned + Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
) -> Result<(T, Vec<u8>)> {
    let bytes = store
        .get_record_bounded(kind, key, ROW_BYTES)?
        .context("Git graph references a missing object or edge")?;
    let value = decode_canonical(&bytes)?;
    ensure!(encode(&value)? == bytes, "noncanonical graph index row");
    Ok((value, bytes))
}

fn edge_key(oid: &[u8; 20], index: u64) -> [u8; 28] {
    let mut key = [0; 28];
    key[..20].copy_from_slice(oid);
    key[20..].copy_from_slice(&index.to_be_bytes());
    key
}

struct GraphIndex<'a> {
    store: &'a RecordScratchStore,
    edge_count: u64,
}

impl GraphIndex<'_> {
    fn edge(&mut self, oid: &[u8; 20], node: &mut Node, edge: Edge) -> Result<()> {
        self.edge_count = self
            .edge_count
            .checked_add(1)
            .context("edge count overflow")?;
        ensure!(
            self.edge_count <= CATALOG_MAX_RECORDS,
            "Git graph edge limit exceeded"
        );
        put(
            self.store,
            EDGES,
            &edge_key(oid, node.edges),
            &encode(&edge)?,
        )?;
        node.edges += 1;
        Ok(())
    }

    fn tree_entry(
        &mut self,
        parser: &Repository,
        oid: &[u8; 20],
        node: &mut Node,
        bytes: &[u8],
    ) -> Result<()> {
        // Parse one complete entry with libgit2. The authenticated record reader
        // separately verifies the original whole tree's streaming object hash.
        let odb = git2::Odb::new()?;
        let _pack = odb.add_new_mempack_backend(1000)?;
        parser.set_odb(&odb)?;
        let id = odb.write(ObjectType::Tree, bytes)?;
        let tree = parser.find_tree(id)?;
        ensure!(tree.len() == 1, "invalid Git tree entry framing");
        let entry = tree.get(0).context("missing Git tree entry")?;
        let name = entry.name_bytes();
        ensure!(
            !name.is_empty()
                && name.len() <= crate::stage::MAX_STAGE_PATH_BYTES
                && !matches!(name, b"." | b"..")
                && !name.contains(&b'/')
                && !name.contains(&0),
            "unsafe Git tree component"
        );
        node.unsafe_root |= matches!(name, b".git" | b".mutualbackup");
        let mut name_key = oid.to_vec();
        name_key.extend_from_slice(name);
        put(self.store, NAMES, &name_key, &[])?;
        let kind = match (entry.kind(), entry.filemode()) {
            (Some(ObjectType::Tree), 0o040000) => 2,
            (Some(ObjectType::Blob), 0o100644 | 0o100755 | 0o120000) => 4,
            _ => anyhow::bail!("unsupported Git tree entry kind or mode"),
        };
        self.edge(
            oid,
            node,
            Edge {
                target: oid_bytes(entry.id()),
                kind,
                name: name.to_vec(),
                symlink: entry.filemode() == 0o120000,
            },
        )
    }

    fn push(&self, oid: [u8; 20], depth: u64) -> Result<()> {
        ensure!(
            depth <= CATALOG_MAX_RECORDS,
            "Git graph traversal depth limit exceeded"
        );
        let (mut node, bytes): (Node, _) = row(self.store, NODES, &oid)?;
        ensure!(node.state == 0, "Git graph contains a cycle");
        node.state = 1;
        self.store
            .replace_record_if_value(NODES, &oid, &bytes, &encode(&node)?)?;
        put(
            self.store,
            STACK,
            &depth.to_be_bytes(),
            &encode(&Frame {
                oid,
                next: 0,
                longest: 0,
            })?,
        )
    }

    fn visit(&self, oid: [u8; 20]) -> Result<()> {
        let (node, _): (Node, _) = row(self.store, NODES, &oid)?;
        if node.state == 2 {
            return Ok(());
        }
        let mut depth = 1_u64;
        self.push(oid, depth)?;
        while depth != 0 {
            let key = depth.to_be_bytes();
            let (mut frame, frame_bytes): (Frame, _) = row(self.store, STACK, &key)?;
            let (mut node, node_bytes): (Node, _) = row(self.store, NODES, &frame.oid)?;
            if frame.next == node.edges {
                node.state = 2;
                node.longest_path = frame.longest;
                self.store.replace_record_if_value(
                    NODES,
                    &frame.oid,
                    &node_bytes,
                    &encode(&node)?,
                )?;
                self.store
                    .delete_record_if_value(STACK, &key, &frame_bytes)?;
                depth -= 1;
                continue;
            }
            ensure!(frame.next < node.edges, "invalid graph traversal cursor");
            let (edge, _): (Edge, _) = row(self.store, EDGES, &edge_key(&frame.oid, frame.next))?;
            let (target, _): (Node, _) = row(self.store, NODES, &edge.target)?;
            ensure!(
                target.kind == edge.kind,
                "Git edge target has the wrong object kind"
            );
            ensure!(
                !edge.symlink || (1..=4095).contains(&target.logical_len),
                "invalid symlink target length"
            );
            ensure!(
                node.kind != 1 || target.kind != 2 || !target.unsafe_root,
                "unsafe Git root tree"
            );
            match target.state {
                0 => {
                    depth += 1;
                    self.push(edge.target, depth)?;
                    continue;
                }
                1 => anyhow::bail!("Git graph contains a cycle"),
                2 => {}
                _ => anyhow::bail!("invalid graph visitation state"),
            }
            if node.kind == 2 {
                let suffix = if target.kind == 2 && target.longest_path != 0 {
                    1 + target.longest_path
                } else {
                    0
                };
                frame.longest = frame.longest.max(edge.name.len() as u64 + suffix);
                ensure!(
                    frame.longest <= crate::stage::MAX_STAGE_PATH_BYTES as u64,
                    "Git tree path limit exceeded"
                );
            }
            frame.next += 1;
            self.store
                .replace_record_if_value(STACK, &key, &frame_bytes, &encode(&frame)?)?;
        }
        Ok(())
    }
}

// Matches libgit2's signature admission: the last angle brackets delimit
// email, and an optional decimal timestamp must fit i64. Names, email, leading
// zeros and ignored timezone suffixes can be arbitrarily long without buffering.
#[derive(Default)]
struct SignatureState {
    less: bool,
    angles: bool,
    suffix: u64,
    phase: u8,
    negative: bool,
    digits: bool,
    number: u64,
    overflow: bool,
}
impl SignatureState {
    fn byte(&mut self, byte: u8) {
        if byte == b'<' {
            self.less = true;
            self.angles = false;
            return;
        }
        if byte == b'>' {
            let less = self.less;
            *self = Self::default();
            self.less = less;
            self.angles = less;
            return;
        }
        if !self.angles {
            return;
        }
        self.suffix += 1;
        if self.suffix == 1 || self.phase >= 3 {
            return;
        }
        if self.phase == 0 && matches!(byte, b' ' | b'\t' | b'\r' | 0x0b | 0x0c) {
            return;
        }
        if self.phase == 0 && matches!(byte, b'+' | b'-') {
            self.negative = byte == b'-';
            self.phase = 1;
            return;
        }
        if byte.is_ascii_digit() {
            self.digits = true;
            self.phase = 2;
            let limit = if self.negative {
                1_u64 << 63
            } else {
                i64::MAX as u64
            };
            match self
                .number
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            {
                Some(value) if value <= limit => self.number = value,
                _ => self.overflow = true,
            }
        } else {
            self.phase = if self.digits { 3 } else { 4 };
        }
    }
    fn valid(&self) -> bool {
        self.angles && (self.suffix <= 1 || self.digits && !self.overflow && self.phase != 4)
    }
}

struct TextParser {
    phase: u8,
    line: Vec<u8>,
    length: u64,
    signature: SignatureState,
    tag_hash: blake3::Hasher,
    tag_length: u64,
    tag_target: [u8; 20],
    extra_tag_header: bool,
}
impl TextParser {
    fn new() -> Self {
        Self {
            phase: 0,
            line: Vec::new(),
            length: 0,
            signature: SignatureState::default(),
            tag_hash: blake3::Hasher::new(),
            tag_length: 0,
            tag_target: [0; 20],
            extra_tag_header: false,
        }
    }
    fn object_id(&self, prefix: &[u8]) -> Result<[u8; 20]> {
        ensure!(
            self.length == (prefix.len() + 40) as u64 && self.line.starts_with(prefix),
            "invalid Git object header"
        );
        Ok(oid_bytes(Oid::from_str(std::str::from_utf8(
            &self.line[prefix.len()..],
        )?)?))
    }
    fn signature(&self, prefix: &[u8]) -> Result<()> {
        ensure!(
            self.line.starts_with(prefix) && self.signature.valid(),
            "invalid Git signature header"
        );
        Ok(())
    }
    fn line(&mut self, graph: &mut GraphIndex<'_>, oid: &[u8; 20], node: &mut Node) -> Result<()> {
        if node.kind == 1 {
            match self.phase {
                0 => {
                    let target = self.object_id(b"tree ")?;
                    graph.edge(
                        oid,
                        node,
                        Edge {
                            target,
                            kind: 2,
                            name: Vec::new(),
                            symlink: false,
                        },
                    )?;
                    self.phase = 1;
                }
                1 if self.line.starts_with(b"parent ") => {
                    let target = self.object_id(b"parent ")?;
                    graph.edge(
                        oid,
                        node,
                        Edge {
                            target,
                            kind: 1,
                            name: Vec::new(),
                            symlink: false,
                        },
                    )?;
                }
                1 => {
                    self.signature(b"author ")?;
                    self.phase = 2;
                }
                2 if self.line.starts_with(b"author ") => {
                    self.signature(b"author ")?;
                }
                2 => {
                    self.signature(b"committer ")?;
                    self.phase = 3;
                }
                3 if self.length == 0 => self.phase = 4,
                3 | 4 => {}
                _ => anyhow::bail!("invalid commit parser state"),
            }
        } else {
            match self.phase {
                0 => {
                    self.tag_target = self.object_id(b"object ")?;
                    self.phase = 1;
                }
                1 => {
                    let kind = match self.line.as_slice() {
                        b"type commit" if self.length == 11 => 1,
                        b"type tag" if self.length == 8 => 3,
                        _ => anyhow::bail!("annotated tag must target a commit or tag"),
                    };
                    graph.edge(
                        oid,
                        node,
                        Edge {
                            target: self.tag_target,
                            kind,
                            name: Vec::new(),
                            symlink: false,
                        },
                    )?;
                    self.phase = 2;
                }
                2 => {
                    ensure!(self.line.starts_with(b"tag "), "missing Git tag name");
                    node.tag_name_hash = *self.tag_hash.finalize().as_bytes();
                    node.tag_name_len = self.tag_length;
                    self.phase = 3;
                }
                3 if self.length == 0 => self.phase = 5,
                3 => {
                    self.signature(b"tagger ")?;
                    self.phase = 4;
                }
                4 if self.length == 0 => self.phase = 5,
                4 => self.extra_tag_header = true,
                5 => {}
                _ => anyhow::bail!("invalid tag parser state"),
            }
        }
        self.line.clear();
        self.length = 0;
        self.signature = SignatureState::default();
        Ok(())
    }
    fn feed(
        &mut self,
        bytes: &[u8],
        graph: &mut GraphIndex<'_>,
        oid: &[u8; 20],
        node: &mut Node,
    ) -> Result<()> {
        for &byte in bytes {
            if node.kind == 1 && self.phase == 4 || node.kind == 3 && self.phase == 5 {
                break;
            }
            if byte == b'\n' {
                self.line(graph, oid, node)?;
                continue;
            }
            if node.kind == 3 && self.phase == 2 && self.length >= 4 {
                ensure!(byte != 0, "NUL in Git tag name");
                self.tag_hash.update(&[byte]);
                self.tag_length += 1;
            }
            self.signature.byte(byte);
            if self.line.len() < 64 {
                self.line.push(byte);
            }
            self.length += 1;
        }
        Ok(())
    }
    fn finish(&self, kind: u8) -> Result<()> {
        ensure!(
            if kind == 1 {
                self.phase >= 3
            } else {
                self.phase == 5
                    || self.phase == 3 && self.length == 0
                    || self.phase == 4 && self.length == 0 && !self.extra_tag_header
            },
            "incomplete Git metadata headers"
        );
        Ok(())
    }
}

#[derive(Default)]
struct TreeParser {
    mode: u32,
    digits: u64,
    phase: u8,
    name: Vec<u8>,
    target: [u8; 20],
    consumed: usize,
}
impl TreeParser {
    fn feed(
        &mut self,
        bytes: &[u8],
        graph: &mut GraphIndex<'_>,
        oid: &[u8; 20],
        node: &mut Node,
        parser: &Repository,
    ) -> Result<()> {
        for &byte in bytes {
            match self.phase {
                0 if byte == b' ' => {
                    ensure!(self.digits != 0, "missing tree entry mode");
                    self.phase = 1;
                }
                0 => {
                    ensure!((b'0'..=b'7').contains(&byte), "invalid tree entry mode");
                    self.mode = self
                        .mode
                        .checked_mul(8)
                        .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                        .context("tree mode overflow")?;
                    self.digits += 1;
                }
                1 if byte == 0 => self.phase = 2,
                1 => {
                    ensure!(
                        self.name.len() < crate::stage::MAX_STAGE_PATH_BYTES,
                        "Git tree component limit exceeded"
                    );
                    self.name.push(byte);
                }
                2 => {
                    self.target[self.consumed] = byte;
                    self.consumed += 1;
                    if self.consumed == 20 {
                        let mut entry = format!("{:o} ", self.mode).into_bytes();
                        entry.extend(&self.name);
                        entry.push(0);
                        entry.extend(self.target);
                        graph.tree_entry(parser, oid, node, &entry)?;
                        self.mode = 0;
                        self.digits = 0;
                        self.phase = 0;
                        self.name.clear();
                        self.consumed = 0;
                    }
                }
                _ => anyhow::bail!("invalid tree parser state"),
            }
        }
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        ensure!(
            self.phase == 0 && self.digits == 0,
            "incomplete Git tree entry"
        );
        Ok(())
    }
}

struct PendingObject {
    oid: [u8; 20],
    length: u64,
    consumed: u64,
    node: Node,
    text: TextParser,
    tree: TreeParser,
}
impl PendingObject {
    fn new(oid: [u8; 20], kind: u8, length: u64) -> Self {
        Self {
            oid,
            length,
            consumed: 0,
            node: Node {
                kind,
                logical_len: length,
                edges: 0,
                state: 0,
                longest_path: 0,
                unsafe_root: false,
                tag_name_hash: [0; 32],
                tag_name_len: 0,
            },
            text: TextParser::new(),
            tree: TreeParser::default(),
        }
    }
    fn feed(
        &mut self,
        bytes: &[u8],
        graph: &mut GraphIndex<'_>,
        parser: &Repository,
    ) -> Result<()> {
        self.consumed = self
            .consumed
            .checked_add(bytes.len() as u64)
            .context("Git object length overflow")?;
        ensure!(self.consumed <= self.length, "oversized Git object");
        if self.node.kind == 2 {
            self.tree
                .feed(bytes, graph, &self.oid, &mut self.node, parser)
        } else {
            self.text.feed(bytes, graph, &self.oid, &mut self.node)
        }
    }
    fn finish(self, graph: &GraphIndex<'_>) -> Result<()> {
        ensure!(self.consumed == self.length, "incomplete Git object");
        if self.node.kind == 2 {
            self.tree.finish()?;
        } else {
            self.text.finish(self.node.kind)?;
        }
        put(graph.store, NODES, &self.oid, &encode(&self.node)?)
    }
}

impl GitCatalogRoot {
    /// Validate complete ref/commit/tree/tag reachability and blob membership
    /// with disk-backed joins. Blob plaintext OIDs and symlink target bytes
    /// must also be authenticated by the enclosing capture/restore consumer.
    pub fn validate_graph(
        &self,
        scope: CatalogScope,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
    ) -> Result<()> {
        self.validate()?;
        scope.validate(CatalogSection::GitGraph)?;
        // Explicit per-job ceiling, not aggregate physical-space admission.
        let store = RecordScratchStore::new(mb_core::CATALOG_MAX_STREAM_BYTES * 4)?;
        let odb = git2::Odb::new()?;
        let _pack = odb.add_new_mempack_backend(1000)?;
        let parser = Repository::from_odb(odb)?;
        store.with_record_transaction(|| {
            self.validate_graph_index(scope, &mut fetch, &store, &parser)
        })
    }

    fn validate_graph_index(
        &self,
        scope: CatalogScope,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
        store: &RecordScratchStore,
        parser: &Repository,
    ) -> Result<()> {
        let mut graph = GraphIndex {
            store,
            edge_count: 0,
        };
        let mut blobs = GitBlobCatalogReader::new(scope, self.blobs)?;
        while let Some(record) = blobs.next_record(fetch)? {
            if let GitBlobRecord::Blob {
                oid, logical_len, ..
            } = record
            {
                put(
                    store,
                    NODES,
                    &oid,
                    &encode(&Node {
                        kind: 4,
                        logical_len,
                        edges: 0,
                        state: 0,
                        longest_path: 0,
                        unsafe_root: false,
                        tag_name_hash: [0; 32],
                        tag_name_len: 0,
                    })?,
                )?;
            }
        }
        let mut objects = GitObjectCatalogReader::new(scope, self.objects)?;
        let mut pending: Option<PendingObject> = None;
        while let Some(record) = objects.next_record(fetch)? {
            match record {
                GitObjectRecord::Header {
                    oid,
                    kind,
                    byte_len,
                    ..
                } => {
                    if let Some(object) = pending.take() {
                        object.finish(&graph)?;
                    }
                    pending = Some(PendingObject::new(oid, kind, byte_len));
                }
                GitObjectRecord::Fragment { bytes, .. } => {
                    pending
                        .as_mut()
                        .context("Git fragment lacks a header")?
                        .feed(&bytes, &mut graph, parser)?;
                }
            }
        }
        if let Some(object) = pending {
            object.finish(&graph)?;
        }
        let mut refs = GitRefCatalogReader::new(scope, self.refs.clone())?;
        while let Some(reference) = refs.next_ref(fetch)? {
            let (node, _): (Node, _) = row(store, NODES, &reference.oid)?;
            ensure!(
                node.kind == 1 || node.kind == 3 && reference.name.starts_with(b"refs/tags/"),
                "invalid Git ref target"
            );
            if node.kind == 3 {
                ensure!(
                    node.tag_name_len == (reference.name.len() - b"refs/tags/".len()) as u64
                        && node.tag_name_hash
                            == *blake3::hash(&reference.name[b"refs/tags/".len()..]).as_bytes(),
                    "annotated tag name differs from ref"
                );
            }
            graph.visit(reference.oid)?;
        }
        store.for_each_record_bounded(NODES, 20, ROW_BYTES, |key, bytes| -> Result<bool> {
            ensure!(key.len() == 20, "invalid graph object index key");
            let node: Node = decode_canonical(bytes)?;
            ensure!(
                node.state == 2,
                "Git catalog contains unreachable objects or blobs"
            );
            Ok(true)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        GitBlobCatalogBuilder, GitObjectCatalogBuilder, GitRefCatalogBuilder, GitRefRecord,
    };
    use mb_core::V1_MAX_CATALOG_BYTES;

    type Object = (u8, [u8; 20], Vec<u8>);
    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: mb_core::NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn object(kind: u8, bytes: Vec<u8>) -> Object {
        let ty = match kind {
            1 => ObjectType::Commit,
            2 => ObjectType::Tree,
            3 => ObjectType::Tag,
            _ => unreachable!(),
        };
        (
            kind,
            oid_bytes(Oid::hash_object(ty, &bytes).unwrap()),
            bytes,
        )
    }

    fn tree(name: &[u8], blob: [u8; 20], mode: &[u8]) -> Object {
        let mut bytes = mode.to_vec();
        bytes.push(b' ');
        bytes.extend(name);
        bytes.push(0);
        bytes.extend(blob);
        object(2, bytes)
    }

    fn commit(tree: [u8; 20], parent: Option<[u8; 20]>, message: &[u8]) -> Object {
        let mut bytes = format!("tree {}\n", Oid::from_bytes(&tree).unwrap());
        if let Some(parent) = parent {
            bytes.push_str(&format!("parent {}\n", Oid::from_bytes(&parent).unwrap()));
        }
        bytes.push_str(
            "author Author <a@example.test> 0 +0000\ncommitter Author <a@example.test> 0 +0000\n\n",
        );
        let mut bytes = bytes.into_bytes();
        bytes.extend(message);
        object(1, bytes)
    }

    fn tag(target: [u8; 20], kind: &str, name: &str) -> Object {
        object(3, format!("object {}\ntype {kind}\ntag {name}\ntagger Author <a@example.test> 0 +0000\n\ntag\n", Oid::from_bytes(&target).unwrap()).into_bytes())
    }

    fn catalog(
        mut objects: Vec<Object>,
        mut refs: Vec<(&[u8], [u8; 20])>,
        mut blobs: Vec<([u8; 20], u64)>,
    ) -> (GitCatalogRoot, Pages) {
        let mut pages = HashMap::new();
        let mut sink = |page: CatalogPageRef, bytes| -> Result<()> {
            pages.insert(page.hash, bytes);
            Ok(())
        };
        let mut builder = GitObjectCatalogBuilder::new(scope()).unwrap();
        objects.sort_by_key(|object| object.1);
        for (kind, oid, bytes) in objects {
            builder
                .push_object(
                    oid,
                    kind,
                    bytes.len() as u64,
                    &mut bytes.as_slice(),
                    &mut sink,
                )
                .unwrap();
        }
        let objects = builder.finish(&mut sink).unwrap();
        refs.sort_by(|left, right| crate::git_ref_name_order(left.0, right.0));
        let mut builder = GitRefCatalogBuilder::new(scope(), b"main").unwrap();
        for (name, oid) in refs {
            builder
                .push_ref(
                    &GitRefRecord {
                        format_version: 1,
                        name: name.to_vec(),
                        oid,
                    },
                    &mut sink,
                )
                .unwrap();
        }
        let refs = builder.finish(&mut sink).unwrap();
        blobs.sort_by_key(|entry| entry.0);
        let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
        for (oid, logical_len) in blobs {
            builder
                .push_record(
                    &GitBlobRecord::Blob {
                        format_version: 1,
                        oid,
                        logical_len,
                        extents: 0,
                        sectors: 0,
                    },
                    &mut sink,
                )
                .unwrap();
        }
        let blobs = builder.finish(&mut sink).unwrap();
        (
            GitCatalogRoot {
                format_version: 1,
                repository_id: Uuid::from_bytes([3; 16]),
                refs,
                objects,
                blobs,
            },
            pages,
        )
    }

    fn verify(root: &GitCatalogRoot, pages: &Pages) -> Result<()> {
        root.validate_graph(scope(), |page| {
            pages
                .get(&page.hash)
                .cloned()
                .context("missing fixture page")
        })
    }

    #[test]
    fn paged_graph_validates_shared_dags_nested_tags_raw_names_and_unborn_heads() {
        let blob = oid_bytes(Oid::hash_object(ObjectType::Blob, b"raw\r\n\0").unwrap());
        let subtree = tree(b"raw-\xff", blob, b"100644");
        let outer = tree(b"nested", subtree.1, b"40000");
        let first = commit(outer.1, None, b"one\n");
        let second = commit(outer.1, Some(first.1), b"two\n");
        let inner = tag(second.1, "commit", "inner");
        let outer_tag = tag(inner.1, "tag", "release");
        let (root, pages) = catalog(
            vec![
                subtree,
                outer,
                first,
                second.clone(),
                inner,
                outer_tag.clone(),
            ],
            vec![
                (b"refs/heads/main", second.1),
                (b"refs/tags/release", outer_tag.1),
            ],
            vec![(blob, 6)],
        );
        verify(&root, &pages).unwrap();
        let (mut root, pages) = catalog(Vec::new(), Vec::new(), Vec::new());
        root.refs.head_branch = b"new-unborn".to_vec();
        verify(&root, &pages).unwrap();
    }

    #[test]
    fn paged_graph_rejects_wrong_kinds_missing_or_unreachable_members_and_tag_names() {
        let blob = oid_bytes(Oid::hash_object(ObjectType::Blob, b"bytes").unwrap());
        let tree = tree(b"payload", blob, b"100644");
        let first = commit(tree.1, None, b"message\n");
        let tagged = tag(first.1, "commit", "release");
        for fault in 0..9 {
            let mut objects = vec![tree.clone(), first.clone()];
            let mut refs: Vec<(&[u8], [u8; 20])> = vec![(b"refs/heads/main", first.1)];
            let mut blobs = vec![(blob, 5)];
            match fault {
                0 => {
                    objects.remove(0);
                }
                1 => {
                    blobs.clear();
                }
                2 => {
                    refs[0].1 = tree.1;
                }
                3 => {
                    blobs.push(([23; 20], 0));
                }
                4 => {
                    objects.push(commit(tree.1, None, b"orphan\n"));
                }
                5 => {
                    objects.push(tagged.clone());
                    refs[0].1 = tagged.1;
                }
                6 => {
                    objects.push(tagged.clone());
                    refs.push((b"refs/tags/other", tagged.1));
                }
                7 => {
                    let bad = commit(tree.1, Some(tree.1), b"wrong parent\n");
                    objects[1] = bad.clone();
                    refs[0].1 = bad.1;
                }
                8 => {
                    let bad = tag(tree.1, "tree", "release");
                    objects.push(bad.clone());
                    refs.push((b"refs/tags/release", bad.1));
                }
                _ => unreachable!(),
            }
            let (root, pages) = catalog(objects, refs, blobs);
            assert!(verify(&root, &pages).is_err(), "fault {fault}");
        }
    }

    #[test]
    fn paged_graph_rejects_unsafe_or_conflicting_tree_entries_and_invalid_symlink_lengths() {
        let blob = oid_bytes(Oid::hash_object(ObjectType::Blob, b"target").unwrap());
        for fault in 0..8 {
            let (name, mode): (&[u8], &[u8]) = match fault {
                0 => (b"..", b"100644"),
                1 => (b"a/b", b"100644"),
                2 => (b".git", b"100644"),
                3 => (b"submodule", b"160000"),
                5 | 6 => (b"link", b"120000"),
                _ => (b"same", b"100644"),
            };
            let mut entry = tree(name, blob, mode);
            if fault == 4 {
                let mut bytes = entry.2.clone();
                bytes.extend(&entry.2);
                entry = object(2, bytes);
            }
            if fault == 7 {
                entry = object(2, b"malformed tree".to_vec());
            }
            let first = commit(entry.1, None, b"message\n");
            let length = if fault == 5 {
                0
            } else if fault == 6 {
                4096
            } else {
                6
            };
            let (root, pages) = catalog(
                vec![entry, first.clone()],
                vec![(b"refs/heads/main", first.1)],
                vec![(blob, length)],
            );
            assert!(verify(&root, &pages).is_err(), "fault {fault}");
        }
    }

    #[test]
    fn paged_graph_rejects_expanded_paths_and_corrupt_or_unavailable_pages() {
        let blob = oid_bytes(Oid::hash_object(ObjectType::Blob, b"x").unwrap());
        let mut objects = vec![tree(b"file", blob, b"100644")];
        for _ in 0..17 {
            objects.push(tree(&vec![b'x'; 250], objects.last().unwrap().1, b"40000"));
        }
        let first = commit(objects.last().unwrap().1, None, b"message\n");
        objects.push(first.clone());
        let (root, pages) = catalog(
            objects,
            vec![(b"refs/heads/main", first.1)],
            vec![(blob, 1)],
        );
        assert!(
            verify(&root, &pages)
                .unwrap_err()
                .to_string()
                .contains("path limit")
        );
        assert!(
            root.validate_graph(scope(), |_| anyhow::bail!("offline"))
                .is_err()
        );
        assert!(
            root.validate_graph(scope(), |page| {
                let mut bytes = pages[&page.hash].clone();
                bytes[0] ^= 1;
                Ok(bytes)
            })
            .is_err()
        );
    }

    #[test]
    fn paged_graph_disk_traversal_rejects_cycles_and_ignored_index_writes() {
        let store = RecordScratchStore::new(64 * 1024 * 1024).unwrap();
        let mut graph = GraphIndex {
            store: &store,
            edge_count: 0,
        };
        for (oid, target) in [([1; 20], [2; 20]), ([2; 20], [1; 20])] {
            let mut node = Node {
                kind: 1,
                logical_len: 0,
                edges: 0,
                state: 0,
                longest_path: 0,
                unsafe_root: false,
                tag_name_hash: [0; 32],
                tag_name_len: 0,
            };
            graph
                .edge(
                    &oid,
                    &mut node,
                    Edge {
                        target,
                        kind: 1,
                        name: Vec::new(),
                        symlink: false,
                    },
                )
                .unwrap();
            put(&store, NODES, &oid, &encode(&node).unwrap()).unwrap();
        }
        assert!(
            graph
                .visit([1; 20])
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        store.database_shell_statement("CREATE TEMP TRIGGER ignore_node BEFORE INSERT ON protocol_records WHEN NEW.kind = 'git-graph-node' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
        assert!(put(&store, NODES, &[3; 20], &[0]).is_err());
    }

    #[test]
    fn paged_graph_streams_graphs_and_individual_metadata_objects_above_the_flat_limit() {
        let empty = object(2, Vec::new());
        let first = commit(empty.1, None, &vec![b'x'; V1_MAX_CATALOG_BYTES / 2 + 1]);
        let second = commit(
            empty.1,
            Some(first.1),
            &vec![b'y'; V1_MAX_CATALOG_BYTES / 2 + 1],
        );
        let (root, pages) = catalog(
            vec![empty.clone(), first, second.clone()],
            vec![(b"refs/heads/main", second.1)],
            Vec::new(),
        );
        assert!(root.objects.object_bytes > V1_MAX_CATALOG_BYTES as u64);
        verify(&root, &pages).unwrap();
        drop(pages);
        let oversized = commit(empty.1, None, &vec![b'x'; V1_MAX_CATALOG_BYTES]);
        let (root, pages) = catalog(
            vec![empty, oversized.clone()],
            vec![(b"refs/heads/main", oversized.1)],
            Vec::new(),
        );
        verify(&root, &pages).unwrap();
    }

    #[test]
    fn paged_graph_streaming_text_admission_matches_libgit2_across_fragment_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(temp.path().join("parser")).unwrap();
        let odb = git2::Odb::new().unwrap();
        let _pack = odb.add_new_mempack_backend(1000).unwrap();
        repository.set_odb(&odb).unwrap();
        let store = RecordScratchStore::new(64 * 1024 * 1024).unwrap();
        let mut graph = GraphIndex {
            store: &store,
            edge_count: 0,
        };
        let zero = "0".repeat(40);
        let mut signatures = vec![
            b"Name <a@example.test> 0 +0000".to_vec(),
            b"<e>".to_vec(),
            b"<>".to_vec(),
            b"Name <e>x".to_vec(),
            b"Name <e> 9223372036854775807 +0000".to_vec(),
            b"Name <e> -9223372036854775808 +0000".to_vec(),
            b"Name <e> 9223372036854775808 +0000".to_vec(),
            b"Name <e> -9223372036854775809 +0000".to_vec(),
            b"Name <e> invalid".to_vec(),
            b"Name <e>  ".to_vec(),
            b"Name <e> + +0000".to_vec(),
            b"Name >e<".to_vec(),
            b"Name <e> 1 malformed timezone".to_vec(),
            b"Name <e> 1<later>".to_vec(),
            b"Name\xff <e> 0 +0000".to_vec(),
        ];
        let mut long = b"Name <e> ".to_vec();
        long.extend(vec![b'0'; 70_000]);
        long.extend(b"1 +0000");
        signatures.push(long);
        let mut cases = Vec::new();
        for signature in signatures {
            let mut bytes = format!("tree {zero}\nauthor ").into_bytes();
            bytes.extend(&signature);
            bytes.extend(b"\ncommitter Name <e> 0 +0000\n\nbody\0bytes");
            cases.push((1, bytes));
        }
        for suffix in [
            b"".as_slice(),
            b"tagger Name <e> 0 +0000\n",
            b"\nbody",
            b"tagger Name <e> 0 +0000\nextra\n\nbody",
            b"unexpected\n",
            b"tagger Name <e> invalid\n",
        ] {
            let mut bytes = format!("object {zero}\ntype commit\ntag name\n").into_bytes();
            bytes.extend(suffix);
            cases.push((3, bytes));
        }
        for (index, (kind, bytes)) in cases.into_iter().enumerate() {
            let ty = if kind == 1 {
                ObjectType::Commit
            } else {
                ObjectType::Tag
            };
            let id = odb.write(ty, &bytes).unwrap();
            let expected = if kind == 1 {
                repository.find_commit(id).is_ok()
            } else {
                repository.find_tag(id).is_ok()
            };
            for (iteration, chunk) in [1, 7, crate::GIT_OBJECT_FRAGMENT_BYTES]
                .into_iter()
                .enumerate()
            {
                let mut identity = [0; 20];
                identity[..8].copy_from_slice(&(index as u64).to_be_bytes());
                identity[8] = iteration as u8;
                let mut pending = PendingObject::new(identity, kind, bytes.len() as u64);
                let result = (|| -> Result<()> {
                    for bytes in bytes.chunks(chunk) {
                        pending.feed(bytes, &mut graph, &repository)?;
                        assert!(pending.text.line.len() <= 64);
                    }
                    pending.finish(&graph)
                })();
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "case {index}, chunk {chunk}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn paged_graph_streams_large_tree_entries_and_parent_lists_without_collecting_them() {
        let blob = oid_bytes(Oid::hash_object(ObjectType::Blob, b"x").unwrap());
        let mut bytes = Vec::new();
        for index in 0..1_200 {
            bytes.extend(format!("100644 name-{index:05}-{}\0", "x".repeat(24)).as_bytes());
            bytes.extend(blob);
        }
        assert!(bytes.len() > crate::GIT_OBJECT_FRAGMENT_BYTES);
        let tree = object(2, bytes);
        let mut objects = vec![tree.clone()];
        let mut previous = None;
        for index in 0..40 {
            let next = commit(tree.1, previous, format!("commit {index}\n").as_bytes());
            previous = Some(next.1);
            objects.push(next);
        }
        let (root, pages) = catalog(
            objects,
            vec![(b"refs/heads/main", previous.unwrap())],
            vec![(blob, 1)],
        );
        verify(&root, &pages).unwrap();
    }
}

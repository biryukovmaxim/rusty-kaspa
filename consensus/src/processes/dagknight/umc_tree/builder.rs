//! The UMC tree algorithm: one mutable working tree over any
//! [`UmcTreeStore`].
//!
//! The builder copies records on first edit (path copying), buffers them keyed
//! by coordinate, and publishes them as one immutable version. Child references
//! select exact records; updating one branch cannot alter another. The store is
//! a generic parameter, so the same algorithm runs over the exact memory store
//! in tests and the bounded facade in production.

use std::collections::HashMap;

use kaspa_consensus_core::KType;
use kaspa_database::prelude::StoreResult;

use super::api::{PublishedVersion, UmcTreeStore};
use super::records::{LeafScore, NodeCoord, NodeRecord, NodeRef, Score, VersionMetadata, bounds, child_of, collect_scores, min_opt};

/// One mutable working tree over any `UmcTreeStore`: copies records on first
/// edit, buffers them, and publishes them as one immutable version.
///
/// Reads through published records go to the store lazily; nothing is loaded at
/// `begin`. Publishing consumes the builder.
pub struct TreeBuilder<'a, T: Clone, S: Score, St: UmcTreeStore<T, S>> {
    /// Store the builder reads published records from and publishes into.
    store: &'a mut St,
    /// K-partition of every store query this builder issues.
    k: KType,
    /// Version id under which this builder's records will be published.
    version: u64,
    /// Published state this builder extends, or `None` for an initial state.
    anchor_version: Option<u64>,
    /// Copy-on-write buffer of records edited or created by this builder.
    buffer: HashMap<NodeCoord, NodeRecord<T, S>>,
    /// Working root; `None` while the tree is empty.
    root: Option<NodeRef>,
    /// Height of the working root.
    root_height: u16,
    /// Number of leaves appended so far, inherited ones included.
    blue_count: u64,
}

impl<'a, T: Clone, S: Score, St: UmcTreeStore<T, S>> TreeBuilder<'a, T, S, St> {
    /// Allocate a version and open a builder over `store`: from scratch, or
    /// extending the published `anchor_version` state.
    ///
    /// Panics when `anchor_version` names no published state of partition `k`
    /// (the builder expects anchor metadata to exist) or when the backing store
    /// read fails.
    pub(crate) fn begin(store: &'a mut St, k: KType, anchor_version: Option<u64>) -> Self {
        let metadata = anchor_version
            .map(|version| store.metadata(k, version).expect("anchor metadata read failed").expect("unknown anchor version"));
        let version = store.allocate_version().expect("version allocation failed");
        let (root_height, blue_count, root) = match &metadata {
            None => (0, 0, None),
            Some(m) => (m.root_height, m.blue_count, m.root_version.map(|v| NodeRef { version: v, h: m.root_height, j: 0 })),
        };
        TreeBuilder { store, k, version, anchor_version, buffer: HashMap::new(), root, root_height, blue_count }
    }

    /// Version id under which this builder's records will be published.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Number of leaves appended so far, inherited ones included.
    pub fn blue_count(&self) -> u64 {
        self.blue_count
    }

    /// Root minimum of the working tree; `None` when it has no leaves.
    pub fn minimum_score(&self) -> Option<S> {
        self.minimum_of(self.root)
    }

    /// Materialize all leaf scores without editing records; costs O(n).
    pub fn scores(&self) -> Vec<LeafScore<T, S>> {
        collect_scores(self.root, |r| Ok(self.load(r))).expect("loads inside one builder are infallible")
    }

    /// Add `delta` to every leaf score in `[a, b)`, lazily where whole subtrees are covered.
    pub fn range_add(&mut self, a: u64, b: u64, delta: S) {
        self.root = self.range_add_ref(self.root, a, b, delta);
    }

    /// Add `delta` at each leaf index in `holes` (sorted, duplicate-free) via one shared traversal.
    pub fn correct_holes(&mut self, holes: &[u64], delta: S) {
        if holes.is_empty() || delta.is_zero() {
            return;
        }
        let mut cursor = 0usize;
        self.root = self.visit_holes(self.root, holes, delta, &mut cursor);
        debug_assert_eq!(cursor, holes.len());
    }

    /// Visit `(leaf index, value)` pairs in `[a, b)` left to right, read-only.
    pub fn scan_leaves(&self, a: u64, b: u64, f: &mut impl FnMut(u64, &T)) {
        self.scan_ref(self.root, a, b, f);
    }

    /// Append `value` as a new leaf at index `blue_count`, starting at score zero.
    pub fn append_leaf(&mut self, value: T) {
        let i = self.blue_count;
        if i == 0 {
            self.root = Some(self.create(0, 0, NodeRecord::Leaf { minimum: S::zero(), value }));
            self.root_height = 0;
        } else {
            if i == 1u64 << self.root_height {
                self.grow_root();
            }
            let root = self.root.expect("grown tree has a root");
            self.root = Some(self.insert_leaf(Some(root), self.root_height, 0, i, &value));
        }
        self.blue_count += 1;
    }

    /// Publish buffered records as this builder's version, close it, and return
    /// the version id. Fails when the backing store write fails, in which case
    /// no new state is exposed.
    pub fn publish(mut self) -> StoreResult<u64> {
        let metadata = VersionMetadata {
            anchor_version: self.anchor_version,
            root_version: self.root.map(|r| r.version),
            root_height: self.root_height,
            blue_count: self.blue_count,
        };
        let publish = PublishedVersion { version: self.version, metadata, records: std::mem::take(&mut self.buffer) };
        self.store.publish(self.k, publish)?;
        Ok(self.version)
    }

    /// Record at `r`, owned: buffered ones clone out, published ones come from
    /// the store. Panics on a missing record (an internal invariant).
    fn load(&self, r: NodeRef) -> NodeRecord<T, S> {
        if r.version == self.version {
            self.buffer.get(&NodeCoord { h: r.h, j: r.j }).expect("buffered record").clone()
        } else {
            self.store.get_node(self.k, r).expect("published record read failed").expect("published record")
        }
    }

    /// Minimum of the subtree at `r`; `None` when it has no leaves.
    fn minimum_of(&self, r: Option<NodeRef>) -> Option<S> {
        match r {
            None => None,
            Some(r) => match self.load(r) {
                NodeRecord::Leaf { minimum, .. } => Some(minimum),
                NodeRecord::Internal { minimum, .. } => minimum,
            },
        }
    }

    /// Copy-on-write edit: clone the record into the working buffer, apply `f`, return the fresh ref.
    fn edit(&mut self, r: NodeRef, f: impl FnOnce(&mut NodeRecord<T, S>)) -> NodeRef {
        let mut record = self.load(r);
        f(&mut record);
        self.buffer.insert(NodeCoord { h: r.h, j: r.j }, record);
        NodeRef { version: self.version, h: r.h, j: r.j }
    }

    /// Buffer a fresh record at a coordinate absent from the working tree.
    fn create(&mut self, h: u16, j: u64, record: NodeRecord<T, S>) -> NodeRef {
        debug_assert!(!self.buffer.contains_key(&NodeCoord { h, j }), "coordinate already created");
        let r = NodeRef { version: self.version, h, j };
        self.buffer.insert(NodeCoord { h, j }, record);
        r
    }

    /// Add `delta` to the subtree at `r` if present; a zero delta is a no-op.
    fn add(&mut self, r: Option<NodeRef>, delta: S) -> Option<NodeRef> {
        let r = r?;
        if delta.is_zero() {
            return Some(r);
        }
        Some(self.edit(r, |n| match n {
            NodeRecord::Leaf { minimum, .. } => *minimum = *minimum + delta,
            NodeRecord::Internal { minimum, pending_addition, .. } => {
                *minimum = minimum.map(|m| m + delta);
                *pending_addition = *pending_addition + delta;
            }
        }))
    }

    /// Move an internal node's pending addition into its existing children; absent children stay absent.
    fn push(&mut self, r: NodeRef) -> NodeRef {
        if r.h == 0 {
            return r;
        }
        let (delta, lv, rv) = match self.load(r) {
            NodeRecord::Internal { pending_addition, left_version, right_version, .. } => {
                (pending_addition, left_version, right_version)
            }
            _ => unreachable!("internal node expected"),
        };
        if delta.is_zero() {
            return r;
        }
        // Later leaves must not inherit votes from events before their insertion.
        let left = self.add(child_of(r, lv, 0), delta).map(|c| c.version);
        let right = self.add(child_of(r, rv, 1), delta).map(|c| c.version);
        self.edit(r, move |n| {
            let NodeRecord::Internal { pending_addition, left_version, right_version, .. } = n else {
                unreachable!("internal node expected")
            };
            *pending_addition = S::zero();
            *left_version = left;
            *right_version = right;
        })
    }

    /// Recompute an internal node's minimum from its children; requires a zero pending addition.
    fn pull(&mut self, r: NodeRef) -> NodeRef {
        let (lv, rv) = match self.load(r) {
            NodeRecord::Internal { pending_addition, left_version, right_version, .. } => {
                debug_assert!(pending_addition.is_zero());
                (left_version, right_version)
            }
            _ => unreachable!("internal node expected"),
        };
        let minimum = min_opt(self.minimum_of(child_of(r, lv, 0)), self.minimum_of(child_of(r, rv, 1)));
        self.edit(r, move |n| {
            let NodeRecord::Internal { minimum: m, .. } = n else { unreachable!("internal node expected") };
            *m = minimum;
        })
    }

    /// Recursive range addition of `delta` over `[a, b)` into the subtree at
    /// `r`. Returns the updated subtree ref, or `None` when the subtree is absent.
    fn range_add_ref(&mut self, r: Option<NodeRef>, a: u64, b: u64, delta: S) -> Option<NodeRef> {
        let r = r?;
        if a == b || delta.is_zero() {
            return Some(r);
        }
        let (lo, hi) = bounds(r);
        if b <= lo || hi <= a {
            return Some(r);
        }
        if a <= lo && hi <= b {
            return self.add(Some(r), delta);
        }
        let r = self.push(r);
        let (lv, rv) = match self.load(r) {
            NodeRecord::Internal { left_version, right_version, .. } => (left_version, right_version),
            _ => unreachable!("internal node expected"),
        };
        let left = self.range_add_ref(child_of(r, lv, 0), a, b, delta);
        let right = self.range_add_ref(child_of(r, rv, 1), a, b, delta);
        let r = self.edit(r, move |n| {
            let NodeRecord::Internal { left_version, right_version, .. } = n else { unreachable!("internal node expected") };
            *left_version = left.map(|c| c.version);
            *right_version = right.map(|c| c.version);
        });
        Some(self.pull(r))
    }

    /// Recursive hole correction: add `delta` at each leaf of `holes` (sorted,
    /// duplicate-free) through one shared traversal. The shared `cursor`
    /// advances as holes are consumed; a subtree starting past the current hole
    /// is returned untouched.
    fn visit_holes(&mut self, r: Option<NodeRef>, holes: &[u64], delta: S, cursor: &mut usize) -> Option<NodeRef> {
        let r = r?;
        if *cursor == holes.len() {
            return Some(r);
        }
        let (lo, hi) = bounds(r);
        if holes[*cursor] >= hi {
            return Some(r);
        }
        debug_assert!(holes[*cursor] >= lo);
        if r.h == 0 {
            *cursor += 1;
            return self.add(Some(r), delta);
        }
        let r = self.push(r);
        let (lv, rv) = match self.load(r) {
            NodeRecord::Internal { left_version, right_version, .. } => (left_version, right_version),
            _ => unreachable!("internal node expected"),
        };
        let left = self.visit_holes(child_of(r, lv, 0), holes, delta, cursor);
        let right = self.visit_holes(child_of(r, rv, 1), holes, delta, cursor);
        let r = self.edit(r, move |n| {
            let NodeRecord::Internal { left_version, right_version, .. } = n else { unreachable!("internal node expected") };
            *left_version = left.map(|c| c.version);
            *right_version = right.map(|c| c.version);
        });
        Some(self.pull(r))
    }

    /// Read-only hash traversal of the subtree at `r` restricted to `[a, b)`:
    /// visits `(leaf index, value)` pairs left to right without pushing lazy
    /// additions.
    fn scan_ref(&self, r: Option<NodeRef>, a: u64, b: u64, f: &mut impl FnMut(u64, &T)) {
        let r = match r {
            Some(r) if a < b => r,
            _ => return,
        };
        let (lo, hi) = bounds(r);
        if b <= lo || hi <= a {
            return;
        }
        match self.load(r) {
            // Hash-only traversal ignores lazy additions and never pushes.
            NodeRecord::Leaf { value, .. } => f(r.j, &value),
            NodeRecord::Internal { left_version, right_version, .. } => {
                self.scan_ref(child_of(r, left_version, 0), a, b, f);
                self.scan_ref(child_of(r, right_version, 1), a, b, f);
            }
        }
    }

    /// Value at the rightmost populated leaf of the subtree at `r`, owned.
    fn rightmost_value(&self, mut r: NodeRef) -> T {
        loop {
            if r.h == 0 {
                return match self.load(r) {
                    NodeRecord::Leaf { value, .. } => value,
                    NodeRecord::Internal { .. } => unreachable!("leaf expected"),
                };
            }
            let next = match self.load(r) {
                NodeRecord::Internal { left_version, right_version, .. } => {
                    child_of(r, right_version, 1).or_else(|| child_of(r, left_version, 0))
                }
                _ => unreachable!("internal node expected"),
            };
            r = next.expect("internal node has a child");
        }
    }

    /// Migration to a bigger tree: wrap the full old root as the left child of a fresh root one level higher.
    ///
    /// The fresh root carries no pending addition, so the tags held below it
    /// cannot reach leaves populated after the migration.
    fn grow_root(&mut self) {
        let old = self.root.expect("full tree has a root");
        let boundary = self.rightmost_value(old);
        let minimum = self.minimum_of(Some(old));
        self.root_height += 1;
        self.root = Some(self.create(
            self.root_height,
            0,
            NodeRecord::Internal {
                minimum,
                pending_addition: S::zero(),
                boundary: Some(boundary),
                left_version: Some(old.version),
                right_version: None,
            },
        ));
    }

    /// Insert leaf `i` (value `value`) under the node at `(h, j)`, creating the
    /// absent internals along the path; the boundary is set exactly when `i`
    /// lands at the left half's last position.
    fn insert_leaf(&mut self, r: Option<NodeRef>, h: u16, j: u64, i: u64, value: &T) -> NodeRef {
        debug_assert!((j << h) <= i && i < (j + 1) << h);
        if h == 0 {
            debug_assert!(r.is_none());
            return self.create(0, j, NodeRecord::Leaf { minimum: S::zero(), value: value.clone() });
        }
        let r = match r {
            Some(r) => r,
            None => self.create(
                h,
                j,
                NodeRecord::Internal {
                    minimum: None,
                    pending_addition: S::zero(),
                    boundary: None,
                    left_version: None,
                    right_version: None,
                },
            ),
        };
        // Push into existing children BEFORE creating the missing child.
        let r = self.push(r);
        let split = (2 * j + 1) << (h - 1);
        let (lv, rv) = match self.load(r) {
            NodeRecord::Internal { left_version, right_version, .. } => (left_version, right_version),
            _ => unreachable!("internal node expected"),
        };
        let (left_side, child) = if i < split {
            (true, self.insert_leaf(child_of(r, lv, 0), h - 1, 2 * j, i, value))
        } else {
            (false, self.insert_leaf(child_of(r, rv, 1), h - 1, 2 * j + 1, i, value))
        };
        let is_boundary = i == split - 1;
        let child_version = child.version;
        let r = self.edit(r, move |n| {
            let NodeRecord::Internal { boundary, left_version, right_version, .. } = n else { unreachable!("internal node expected") };
            if left_side {
                *left_version = Some(child_version);
            } else {
                *right_version = Some(child_version);
            }
            if is_boundary {
                *boundary = Some(value.clone());
            }
        });
        self.pull(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    use super::super::api::UmcTreeStoreReader;
    use super::super::mem::MemoryUmcTreeStore;
    use super::super::stores::UmcTreeStores;

    type Store = MemoryUmcTreeStore<u64, i64>;

    fn leaf_scores(pairs: &[(u64, i64)]) -> Vec<LeafScore<u64, i64>> {
        pairs.iter().map(|&(value, score)| LeafScore { value, score }).collect()
    }

    /// A root-wide lazy addition adjusts the root only; leaf records stay untouched.
    #[test]
    fn lazy_root_addition_leaves_leaf_records_untouched() {
        let mut store = Store::new();
        let mut b = store.begin(0, None);
        for v in 0..4 {
            b.append_leaf(v);
        }
        // Scores [3,2,1,0].
        b.range_add(0, 1, 3);
        b.range_add(1, 2, 2);
        b.range_add(2, 3, 1);
        assert_eq!(b.scores(), leaf_scores(&[(0, 3), (1, 2), (2, 1), (3, 0)]));

        // A red under all four: one root-wide subtraction, leaf records unchanged.
        b.range_add(0, 4, -1);
        assert_eq!(b.scores(), leaf_scores(&[(0, 2), (1, 1), (2, 0), (3, -1)]));
        assert_eq!(b.minimum_score(), Some(-1));
        let NodeRecord::Internal { pending_addition, .. } = b.load(b.root.unwrap()) else { panic!("internal root") };
        assert_eq!(pending_addition, -1);
        let NodeRecord::Leaf { minimum, .. } = b.load(NodeRef { version: b.version(), h: 0, j: 2 }) else { panic!("leaf") };
        assert_eq!(minimum, 1);
    }

    /// Appending at capacity grows the root and pushes pendings into existing
    /// leaves only; the new leaf starts at zero.
    #[test]
    fn grow_root_migration_applies_pendings() {
        let mut store = Store::new();
        let mut b = store.begin(0, None);
        for v in 0..4 {
            b.append_leaf(v);
        }
        b.range_add(0, 1, 3);
        b.range_add(1, 2, 2);
        b.range_add(2, 3, 1);
        // Park a pending addition at the root before growing: effective [5,4,3,2].
        b.range_add(0, 4, 2);
        // Appending at capacity 4 triggers the migration to a height-3 tree.
        b.append_leaf(4);
        assert_eq!(b.blue_count(), 5);
        let NodeRecord::Internal { boundary, .. } = b.load(b.root.unwrap()) else { panic!("internal root") };
        assert_eq!(boundary, Some(3), "new root boundary is the old tree's rightmost value");
        // The migration pushed the pending addition into existing leaves only; the new leaf starts at zero.
        assert_eq!(b.scores(), leaf_scores(&[(0, 5), (1, 4), (2, 3), (3, 2), (4, 0)]));
        assert_eq!(b.minimum_score(), Some(0));
    }

    /// The K=1 worked example: subtract [0,3), undo the hole at 1.
    #[test]
    fn correct_holes_matches_spec_example() {
        let mut store = Store::new();
        let mut b = store.begin(0, None);
        for v in 0..4 {
            b.append_leaf(v);
        }
        // K=1 worked example: scores [3,1,1,0]; red x from c: subtract [0,3), undo the hole at 1.
        b.range_add(0, 1, 3);
        b.range_add(1, 2, 1);
        b.range_add(2, 3, 1);
        b.range_add(0, 3, -1);
        b.correct_holes(&[1], 1);
        assert_eq!(b.scores(), leaf_scores(&[(0, 2), (1, 1), (2, 0), (3, 0)]));
    }

    /// Publishing freezes an immutable version; a builder anchored at it
    /// inherits root, height and blue count, and the anchor's records stay
    /// unchanged.
    #[test]
    fn publish_and_anchor_inheritance() {
        let mut store = Store::new();
        let v0 = {
            let mut b = store.begin(0, None);
            b.append_leaf(10);
            b.append_leaf(11);
            b.range_add(0, 2, 5);
            assert_eq!(b.version(), 0);
            b.publish().unwrap()
        };
        assert_eq!(store.scores(0, v0).unwrap(), leaf_scores(&[(10, 5), (11, 5)]));
        assert_eq!(store.metadata(0, v0).unwrap().map(|m| m.blue_count), Some(2));

        let v1 = {
            let mut b = store.begin(0, Some(v0));
            b.append_leaf(12);
            assert_eq!(b.blue_count(), 3);
            b.publish().unwrap()
        };
        // The inherited pending addition reaches only the anchor's leaves.
        assert_eq!(store.scores(0, v1).unwrap(), leaf_scores(&[(10, 5), (11, 5), (12, 0)]));
        assert_eq!(store.minimum_score(0, v1).unwrap(), Some(0));
        assert_eq!(store.latest_version(0).unwrap(), Some(v1));

        // Newest-first reads: the latest version wins; v0's published records are unchanged.
        assert_eq!(store.latest_node(0, NodeCoord { h: 0, j: 0 }).unwrap().map(|vn| vn.version), Some(v0));
        assert_eq!(store.scores(0, v0).unwrap(), leaf_scores(&[(10, 5), (11, 5)]));
    }

    /// The hash-only range scan never pushes lazy additions.
    #[test]
    fn scan_leaves_reads_without_pushing() {
        let mut store = Store::new();
        let mut b = store.begin(0, None);
        for v in 0..4 {
            b.append_leaf(v);
        }
        b.range_add(0, 4, 7);
        let mut scanned = Vec::new();
        b.scan_leaves(1, 3, &mut |j, v| scanned.push((j, *v)));
        assert_eq!(scanned, vec![(1, 1), (2, 2)]);
    }

    /// The same algorithm runs unchanged over the facade backed by a temp DB,
    /// proving the `St: UmcTreeStore` abstraction end to end.
    #[test]
    fn algorithm_against_facade_over_temp_db() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = UmcTreeStores::<u64, i64>::new(db, 100, 100);
        let v0 = {
            let mut b = stores.begin(3, None);
            for v in 0..4 {
                b.append_leaf(v);
            }
            b.range_add(0, 1, 3);
            b.range_add(1, 2, 1);
            b.range_add(2, 3, 1);
            b.range_add(0, 3, -1);
            b.correct_holes(&[1], 1);
            b.publish().unwrap()
        };
        assert_eq!(stores.scores(3, v0).unwrap(), leaf_scores(&[(0, 2), (1, 1), (2, 0), (3, 0)]));
        let v1 = {
            let mut b = stores.begin(3, Some(v0));
            b.append_leaf(4);
            b.range_add(0, 5, 5);
            b.publish().unwrap()
        };
        assert_eq!(stores.scores(3, v1).unwrap(), leaf_scores(&[(0, 7), (1, 6), (2, 5), (3, 5), (4, 5)]));
        assert_eq!(stores.minimum_score(3, v1).unwrap(), Some(5));
        assert_eq!(stores.latest_version(3).unwrap(), Some(v1));
    }
}

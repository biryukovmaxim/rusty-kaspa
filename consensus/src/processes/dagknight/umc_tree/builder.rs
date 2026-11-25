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
#[cfg(test)]
use super::records::{LeafScore, collect_scores};
use super::records::{NodeCoord, NodeRecord, NodeRef, Score, VersionMetadata, bounds, child_of, min_opt};
use crate::model::stores::conflict_zone_coloring::ConflictZoneColoringKey;

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

/// One reachability probe: the leaf value `leaf` tested for ancestry of the incoming `block`.
pub struct AncestryProbe<'a, T> {
    /// Candidate leaf value.
    pub leaf: &'a T,
    /// Incoming block under test.
    pub block: &'a T,
}

/// One supplied block arrival: the block itself, its color, and the work-weighted
/// vote it contributes to every blue ancestor's score.
#[derive(Clone, Copy)]
pub struct Arrival<T, S> {
    /// The arriving block; a blue arrival appends it as the new leaf value.
    pub block: T,
    /// Supplied color: blue arrivals append a leaf and vote positively, red ones only vote.
    pub blue: bool,
    /// Weight added to (blue) or subtracted from (red) the score of each existing ancestor leaf.
    pub work: S,
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
    /// Test scaffolding: production receives the version id from the publish call.
    #[cfg(test)]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Number of leaves appended so far, inherited ones included.
    /// Test scaffolding: production reads the blue count from a published state's metadata.
    #[cfg(test)]
    pub fn blue_count(&self) -> u64 {
        self.blue_count
    }

    /// Root minimum of the working tree; `None` when it has no leaves.
    pub fn minimum_score(&self) -> Option<S> {
        self.minimum_of(self.root)
    }

    /// Materialize all leaf scores without editing records; costs O(n).
    /// Test scaffolding: production reads leaf scores of a published state through the store.
    #[cfg(test)]
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

    /// Index of the latest leaf that is a DAG ancestor of `x`, or `None` when no leaf qualifies. Read-only.
    ///
    /// Assumes the caller's blue set is a K-cluster: the ancestors of `x` form a prefix of the leaves with at most `k` holes, each within `2k-1` of the true answer.
    pub fn latest_blue_ancestor(&self, x: &T, is_ancestor: &impl Fn(AncestryProbe<'_, T>) -> bool) -> Option<u64> {
        if self.blue_count == 0 {
            return None;
        }
        let (lo, hi) = self.ancestor_bounds(x, is_ancestor);
        // The K-cluster bound puts any ancestor the descent stepped over within the next `2k` leaves past `hi`.
        let end = hi.saturating_add(2 * u64::from(self.k)).min(self.blue_count);
        self.last_ancestor_in(hi, end, x, is_ancestor).or(lo)
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

    /// Apply one supplied arrival and return whether the resulting state passes
    /// the UMC test at `deficit`.
    ///
    /// A blue arrival adds `work` to every existing leaf (its blue ancestors,
    /// repaired at the nonancestor holes of the last `2k-1` positions) and
    /// appends its own leaf at score zero. A red arrival subtracts `work` from
    /// the leaf prefix through its latest blue ancestor, repairing the holes of
    /// the `2k-1` positions before it; a red arrival with no blue ancestor
    /// changes nothing. At `k == 0` the hole window is empty by construction,
    /// so no scan runs.
    ///
    /// `deficit` is a nonnegative work allowance: the state qualifies when the
    /// root minimum is at least `-deficit`. It is a query parameter, not state,
    /// and a failed qualification never stops state maintenance; later arrivals
    /// may restore sufficient support.
    ///
    /// Probes `is_ancestor` O(k + log n) times.
    ///
    /// The blue set, the arrival included, must stay a K-cluster, and arrivals must come in
    /// topological order, so every old nonancestor of the arrival is incomparable with it.
    pub fn process_block(&mut self, arrival: Arrival<T, S>, deficit: S, is_ancestor: &impl Fn(AncestryProbe<'_, T>) -> bool) -> bool {
        if arrival.blue {
            let n = self.blue_count;
            let holes = self.holes_before(n, &arrival.block, is_ancestor);
            self.range_add(0, n, arrival.work);
            self.correct_holes(&holes, -arrival.work);
            self.append_leaf(arrival.block);
        } else if let Some(p) = self.latest_blue_ancestor(&arrival.block, is_ancestor) {
            let holes = self.holes_before(p, &arrival.block, is_ancestor);
            self.range_add(0, p + 1, -arrival.work);
            self.correct_holes(&holes, arrival.work);
        }
        self.qualifies(deficit)
    }

    /// Apply a run of arrivals in order and return whether the final state
    /// passes the UMC test at `deficit`.
    ///
    /// The run must be topologically ordered: each block already queryable
    /// through `is_ancestor` when it is applied.
    pub fn apply_delta(
        &mut self,
        events: impl IntoIterator<Item = Arrival<T, S>>,
        deficit: S,
        is_ancestor: &impl Fn(AncestryProbe<'_, T>) -> bool,
    ) -> bool {
        for arrival in events {
            self.process_block(arrival, deficit, is_ancestor);
        }
        self.qualifies(deficit)
    }

    /// Whether the working state passes the UMC test at `deficit`: the root
    /// minimum is at least `-deficit`; a tree with no leaves qualifies vacuously.
    pub fn qualifies(&self, deficit: S) -> bool {
        self.minimum_score().is_none_or(|m| m >= -deficit)
    }

    /// Publish buffered records as this builder's version, close it, and return
    /// the version id. The published state is registered under no anchor. Fails
    /// when the backing store write fails, in which case no new state is exposed.
    /// Test scaffolding: production callers register through `publish_as`.
    #[cfg(test)]
    pub fn publish(self) -> StoreResult<u64> {
        self.publish_with(None)
    }

    /// Publish buffered records as this builder's version, register the
    /// published state under `anchor`, close the builder, and return the
    /// version id. Fails like `publish`, and with `KeyAlreadyExists` when
    /// `anchor` already names a published state; no new state is exposed
    /// either way; panics when `anchor` names another `k`.
    pub fn publish_as(self, anchor: ConflictZoneColoringKey) -> StoreResult<u64> {
        self.publish_with(Some(anchor))
    }

    /// Shared publish tail: validates nothing and hands the state and its anchor
    /// to the store's one publish call, which rejects an already-registered key
    /// before it writes anything.
    fn publish_with(mut self, anchor: Option<ConflictZoneColoringKey>) -> StoreResult<u64> {
        let metadata = VersionMetadata {
            anchor_version: self.anchor_version,
            root_version: self.root.map(|r| r.version),
            root_height: self.root_height,
            blue_count: self.blue_count,
        };
        let publish = PublishedVersion { version: self.version, metadata, records: std::mem::take(&mut self.buffer), anchor };
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

    /// Adjacent bounds around the latest ancestor leaf: `lo` is the largest known ancestor index, `None` until one is found; `hi` is the smallest known non-ancestor index.
    fn ancestor_bounds(&self, x: &T, is_ancestor: &impl Fn(AncestryProbe<'_, T>) -> bool) -> (Option<u64>, u64) {
        let n = self.blue_count;
        // `lo` is the largest known ancestor index, `None` until one is found; `hi` is the smallest known non-ancestor index.
        let mut lo = None;
        let mut hi = n;
        let mut r = self.root.expect("populated tree has a root");
        let mut h = self.root_height;
        let mut j = 0u64;
        // `l < hi` is a maintained invariant, so the subtraction cannot underflow.
        while lo.map_or(hi > 0, |l| hi - l > 1) {
            if h == 0 {
                let value = match self.load(r) {
                    NodeRecord::Leaf { value, .. } => value,
                    _ => unreachable!("leaf expected"),
                };
                if is_ancestor(AncestryProbe { leaf: &value, block: x }) {
                    lo = Some(j);
                } else {
                    hi = j;
                }
                break;
            }
            let split = (2 * j + 1) << (h - 1);
            let (boundary, lv, rv) = match self.load(r) {
                NodeRecord::Internal { boundary, left_version, right_version, .. } => (boundary, left_version, right_version),
                _ => unreachable!("internal node expected"),
            };
            if split >= n {
                // The right half holds no leaf; every leaf sits in the left half.
                r = child_of(r, lv, 0).expect("populated left child");
                j *= 2;
            } else if is_ancestor(AncestryProbe { leaf: &boundary.expect("left half is full at an inner split"), block: x }) {
                lo = Some(split - 1);
                r = child_of(r, rv, 1).expect("populated right child at an inner split");
                j = 2 * j + 1;
            } else {
                hi = split - 1;
                r = child_of(r, lv, 0).expect("populated left child");
                j *= 2;
            }
            h -= 1;
        }
        (lo, hi)
    }

    /// Latest ancestor leaf in `[a, b)`, or `None` when the range holds none.
    fn last_ancestor_in(&self, a: u64, b: u64, x: &T, is_ancestor: &impl Fn(AncestryProbe<'_, T>) -> bool) -> Option<u64> {
        let mut latest = None;
        self.scan_leaves(a, b, &mut |i, value| {
            if is_ancestor(AncestryProbe { leaf: value, block: x }) {
                latest = Some(i);
            }
        });
        latest
    }

    /// Nonancestor leaf indices inside the `2k-1` positions ending at `end`
    /// (exclusive); at `k == 0` the window is empty and nothing is scanned.
    fn holes_before(&self, end: u64, block: &T, is_ancestor: &impl Fn(AncestryProbe<'_, T>) -> bool) -> Vec<u64> {
        let start = end.saturating_sub((2 * u64::from(self.k)).saturating_sub(1));
        let mut holes = Vec::new();
        self.scan_leaves(start, end, &mut |i, leaf| {
            if !is_ancestor(AncestryProbe { leaf, block }) {
                holes.push(i);
            }
        });
        holes
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
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use kaspa_math::Uint192;

    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;
    use rand::rngs::SmallRng;
    use rand::seq::SliceRandom;
    use rand::{Rng, SeedableRng};

    use super::super::api::UmcTreeStoreReader;
    use super::super::mem::MemoryUmcTreeStore;
    use super::super::stores::{Capacities, UmcTreeStores};
    use super::super::test_support::{AnchorInput, anchor_key};
    use crate::processes::dagknight::umc_voting::SignedWork;

    type Store = MemoryUmcTreeStore<u64, i64>;

    fn leaf_scores(pairs: &[(u64, i64)]) -> Vec<LeafScore<u64, i64>> {
        pairs.iter().map(|&(value, score)| LeafScore { value, score }).collect()
    }

    /// Query sentinel: never a leaf value, so only the closure decides ancestry.
    const QUERY: u64 = u64::MAX;

    /// Ancestry closure over leaf values: the leaf is an ancestor of the query
    /// iff its value is `<= p` and not one of `holes`. `p = -1` makes nothing
    /// an ancestor.
    fn ancestry(p: i64, holes: &[u64]) -> impl Fn(AncestryProbe<'_, u64>) -> bool {
        let holes = holes.to_vec();
        move |AncestryProbe { leaf, .. }| (*leaf as i64) <= p && !holes.contains(leaf)
    }

    /// Builder over a working tree of `n` leaves with values `0..n`.
    fn tree_with_leaves<'a>(store: &'a mut Store, k: KType, n: u64) -> TreeBuilder<'a, u64, i64, Store> {
        let mut b = store.begin(k, None);
        for v in 0..n {
            b.append_leaf(v);
        }
        b
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

    /// `publish_as` registers the published state under its key, so a later
    /// builder opens it through `resolve_anchor`; a plain publish registers
    /// nothing; two publishes under two keys register independent states.
    #[test]
    fn publish_as_registers_anchor() {
        let mut store = Store::new();
        let v0 = {
            let mut b = store.begin(0, None);
            b.append_leaf(1);
            b.publish().unwrap()
        };
        let unregistered = anchor_key(AnchorInput { root: 1, pov: 1, k: 0 });
        assert_eq!(store.resolve_anchor(&unregistered).unwrap(), None, "a plain publish registers nothing");

        let first = anchor_key(AnchorInput { root: 1, pov: 2, k: 0 });
        let v1 = {
            let mut b = store.begin(0, Some(v0));
            b.append_leaf(2);
            b.publish_as(first.clone()).unwrap()
        };
        let second = anchor_key(AnchorInput { root: 1, pov: 3, k: 0 });
        let v2 = {
            let mut b = store.begin(0, Some(v1));
            b.append_leaf(3);
            b.publish_as(second.clone()).unwrap()
        };
        assert_eq!(store.resolve_anchor(&first).unwrap(), Some(v1));
        assert_eq!(store.resolve_anchor(&second).unwrap(), Some(v2));
        assert_eq!(store.scores(0, v1).unwrap(), leaf_scores(&[(1, 0), (2, 0)]), "the first registered state is unchanged");
        let resumed = store.resolve_anchor(&first).unwrap();
        let b = store.begin(0, resumed);
        assert_eq!(b.scores(), leaf_scores(&[(1, 0), (2, 0)]));
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
        let mut stores = UmcTreeStores::<u64, i64>::new(db, Capacities { nodes: 100, metadata: 100, anchors: 0 });
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

    /// An empty tree has no blue ancestor to find, whatever the closure says.
    #[test]
    fn latest_blue_ancestor_empty_tree_is_none() {
        let mut store = Store::new();
        let b = tree_with_leaves(&mut store, 2, 0);
        assert_eq!(b.latest_blue_ancestor(&QUERY, &|_: AncestryProbe<'_, u64>| true), None);
    }

    /// A single-leaf tree returns that leaf or `None` depending on ancestry;
    /// the leaf probe at height 0 feeds both the `lo` and `hi` sentinel.
    #[test]
    fn latest_blue_ancestor_single_leaf() {
        let mut store = Store::new();
        let b = tree_with_leaves(&mut store, 2, 1);
        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(0, &[])), Some(0));
        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(-1, &[])), None);
    }

    /// Without holes the prefix ancestor set is answered exactly, at every tree
    /// shape from height 2 to 4, including grown roots with an empty right half.
    #[test]
    fn latest_blue_ancestor_prefix_without_holes() {
        for &n in &[3u64, 4, 5, 8, 9] {
            for p in 0..n {
                let mut store = Store::new();
                let b = tree_with_leaves(&mut store, 2, n);
                assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(p as i64, &[])), Some(p), "n={n} p={p}");
            }
        }
    }

    /// A non-ancestor boundary hides later ancestors from the descent; the scan
    /// past the boundary repairs the answer.
    ///
    /// Leaves 0..=4 and 6 are ancestors, leaf 5 is not. By construction the
    /// descent alone must stop at 4: leaf 5 is the boundary of the [4,8)
    /// subtree, so the probe sets hi=5, and leaf 4 is the boundary of the [4,6)
    /// subtree, so the probe sets lo=4 even though leaf 6 is an ancestor. Only
    /// the correction scan reaches 6.
    #[test]
    fn latest_blue_ancestor_correction_scan_repairs_descent() {
        let mut store = Store::new();
        let b = tree_with_leaves(&mut store, 2, 8);
        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(6, &[5])), Some(6));

        // With the hole before a probed boundary (leaf 5 is the [4,8) boundary
        // and an ancestor), the descent alone already lands on the answer.
        let mut store = Store::new();
        let b = tree_with_leaves(&mut store, 2, 8);
        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(5, &[4])), Some(5));
    }

    /// K=0 empties the correction window, so the descent's answer stands even
    /// when a later leaf is an ancestor: keeping the blue set a K-cluster is the
    /// caller's responsibility, not the search's.
    #[test]
    fn latest_blue_ancestor_k0_correction_window_is_empty() {
        let mut store = Store::new();
        let b = tree_with_leaves(&mut store, 0, 8);
        // Leaf 6 is an ancestor, but the hole at 5 is illegal at K=0: the
        // descent stops at lo=4 and the scan window [5,5) is empty.
        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(6, &[5])), Some(4));
    }

    /// With no ancestor at all, the -1 sentinel survives both the descent and
    /// the scan and surfaces as `None`.
    #[test]
    fn latest_blue_ancestor_without_ancestors_is_none() {
        let mut store = Store::new();
        let b = tree_with_leaves(&mut store, 2, 8);
        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(-1, &[])), None);
    }

    /// The search is read-only: a parked root-wide lazy addition stays parked,
    /// no records join the buffer, and scores are unchanged.
    #[test]
    fn latest_blue_ancestor_is_read_only() {
        let mut store = Store::new();
        let mut b = store.begin(2, None);
        for v in 0..4 {
            b.append_leaf(v);
        }
        b.range_add(0, 1, 3);
        // Park a root-wide lazy addition: leaf records stay at [3,0,0,0].
        b.range_add(0, 4, 7);
        let scores = b.scores();
        let minimum = b.minimum_score();
        let buffer_len = b.buffer.len();
        let root = b.root.unwrap();
        let NodeRecord::Internal { pending_addition: parked, .. } = b.load(root) else { panic!("internal root") };

        assert_eq!(b.latest_blue_ancestor(&QUERY, &ancestry(1, &[])), Some(1));

        assert_eq!(b.scores(), scores);
        assert_eq!(b.minimum_score(), minimum);
        assert_eq!(b.buffer.len(), buffer_len, "the search must not buffer records");
        let NodeRecord::Internal { pending_addition, .. } = b.load(root) else { panic!("internal root") };
        assert_eq!(pending_addition, parked, "the search must not push lazy additions");
    }

    /// Randomized oracle: hole placements drawn freely inside the legal window
    /// (at most K holes, each within 2K-1 of the last ancestor, including the
    /// left edge and adjacent pairs) always match a brute-force scan.
    #[test]
    fn latest_blue_ancestor_matches_brute_force() {
        for k in 0u16..=4 {
            for seed in 0u64..24 {
                let mut rng = SmallRng::seed_from_u64(1000 * u64::from(k) + seed + 1);
                let n = rng.gen_range(0..=40u64);
                let p: i64 = if n == 0 || rng.gen_bool(0.2) { -1 } else { rng.gen_range(0..n) as i64 };
                let window_lo = (p - (2 * i64::from(k) - 1)).max(0);
                let mut holes: Vec<u64> = (window_lo..p).map(|i| i as u64).collect();
                let hole_count = rng.gen_range(0..=k as usize).min(holes.len());
                holes.shuffle(&mut rng);
                holes.truncate(hole_count);
                holes.sort_unstable();

                let mut store = Store::new();
                let b = tree_with_leaves(&mut store, k, n);
                let expected = (0..n).filter(|&i| (i as i64) <= p && !holes.contains(&i)).max();
                assert_eq!(
                    b.latest_blue_ancestor(&QUERY, &ancestry(p, &holes)),
                    expected,
                    "k={k} seed={seed} n={n} p={p} holes={holes:?}"
                );
            }
        }
    }

    /// Shortcut for building one recorded arrival.
    fn event(block: u64, blue: bool, work: i64) -> Arrival<u64, i64> {
        Arrival { block, blue, work }
    }

    /// Brute-force DAG oracle: it stores each block's full strict-ancestor set
    /// and recomputes every blue score by summing the signed work of its strict
    /// descendants. It shares no logic with the tree: no segment structure, no
    /// hole windows, no ancestor search.
    /// The oracle keeps its tables behind `RefCell` so a shared ancestry
    /// closure can stay alive across later `add` calls.
    #[derive(Default)]
    struct DagOracle {
        past: RefCell<Vec<Vec<u64>>>,
    }

    impl DagOracle {
        /// Admit the next block with `parents`: its strict ancestors are each parent
        /// plus each parent's ancestors.
        fn add(&self, parents: &[u64]) {
            let mut ancestors = BTreeSet::new();
            for &parent in parents {
                ancestors.insert(parent);
                ancestors.extend(self.past.borrow()[parent as usize].iter().copied());
            }
            self.past.borrow_mut().push(ancestors.into_iter().collect());
        }

        /// Id the next admitted block will carry.
        fn next_id(&self) -> u64 {
            self.past.borrow().len() as u64
        }

        /// Whether `ancestor` is a strict ancestor of `block`.
        fn is_ancestor(&self, ancestor: u64, block: u64) -> bool {
            self.past.borrow()[block as usize].contains(&ancestor)
        }

        /// Ancestry closure for the builder: maps the leaf and arrival values
        /// through the oracle.
        fn probe(&self) -> impl Fn(AncestryProbe<'_, u64>) -> bool + '_ {
            move |AncestryProbe { leaf, block }| self.is_ancestor(*leaf, *block)
        }

        /// Ancestry closure that records each `(leaf, block)` pair it is asked into `queries`,
        /// then answers through the oracle.
        fn recording_probe<'a>(&'a self, queries: &'a RefCell<Vec<(u64, u64)>>) -> impl Fn(AncestryProbe<'_, u64>) -> bool + 'a {
            move |AncestryProbe { leaf, block }| {
                queries.borrow_mut().push((*leaf, *block));
                self.is_ancestor(*leaf, *block)
            }
        }

        /// Blue leaves in arrival order, each scored by the signed work of its
        /// strict descendants.
        fn scores(&self, events: &[Arrival<u64, i64>]) -> Vec<LeafScore<u64, i64>> {
            events
                .iter()
                .filter(|e| e.blue)
                .map(|e| LeafScore {
                    value: e.block,
                    score: events
                        .iter()
                        .filter(|d| self.is_ancestor(e.block, d.block))
                        .map(|d| if d.blue { d.work } else { -d.work })
                        .sum(),
                })
                .collect()
        }

        /// Minimum blue score, or `None` while no blue has arrived.
        fn minimum(&self, events: &[Arrival<u64, i64>]) -> Option<i64> {
            self.scores(events).iter().map(|leaf| leaf.score).min()
        }

        /// K-cluster guard: `block` may turn blue when every blue, itself
        /// included, keeps at most `k` incomparable blues, two blocks being
        /// incomparable when neither is a strict ancestor of the other.
        fn may_add_blue(&self, events: &[Arrival<u64, i64>], block: u64, k: KType) -> bool {
            let blues: Vec<u64> = events.iter().filter(|e| e.blue).map(|e| e.block).chain([block]).collect();
            blues.iter().all(|&a| {
                blues.iter().filter(|&&b| b != a && !self.is_ancestor(a, b) && !self.is_ancestor(b, a)).count() <= usize::from(k)
            })
        }
    }

    /// The parent set of `block` when it extends only `block - 1` in a chain;
    /// block 0 has no parents.
    fn chain_parents(block: u64) -> Vec<u64> {
        (block > 0).then(|| block - 1).into_iter().collect()
    }

    /// Ancestry closure over a chain DAG: a block is an ancestor of exactly the
    /// later blocks.
    fn chain_ancestry(AncestryProbe { leaf, block }: AncestryProbe<'_, u64>) -> bool {
        *leaf < *block
    }

    /// Compare the whole working state against the oracle: leaf count, score
    /// vector, root minimum, and qualification at several deficits. Reads must
    /// not edit or buffer any record.
    fn check_builder(b: &TreeBuilder<'_, u64, i64, Store>, oracle: &DagOracle, events: &[Arrival<u64, i64>]) {
        let expected = oracle.scores(events);
        let minimum = expected.iter().map(|leaf| leaf.score).min();
        assert_eq!(b.blue_count(), expected.len() as u64);
        let buffer_before = b.buffer.clone();
        assert_eq!(b.scores(), expected, "leaf scores diverged from direct sums");
        assert_eq!(b.minimum_score(), minimum);
        for deficit in [0, 1, 7] {
            assert_eq!(b.qualifies(deficit), minimum.is_none_or(|m| m >= -deficit), "deficit {deficit}");
        }
        assert_eq!(b.buffer, buffer_before, "reading pushed or rewrote a record");
    }

    /// Compare a published state against the oracle: scores, root minimum, blue
    /// count, and qualification at several deficits.
    fn check_published(store: &Store, k: KType, version: u64, oracle: &DagOracle, events: &[Arrival<u64, i64>]) {
        let expected = oracle.scores(events);
        let minimum = expected.iter().map(|leaf| leaf.score).min();
        assert_eq!(store.scores(k, version).unwrap(), expected, "version {version}");
        assert_eq!(store.minimum_score(k, version).unwrap(), minimum, "version {version}");
        assert_eq!(store.metadata(k, version).unwrap().map(|m| m.blue_count), Some(expected.len() as u64));
        for deficit in [0, 1, 7] {
            assert_eq!(
                store.qualifies(k, version, deficit).unwrap(),
                minimum.is_none_or(|m| m >= -deficit),
                "version {version} deficit {deficit}"
            );
        }
    }

    /// Apply one weighted arrival, record it, and check the working state
    /// against the oracle: the returned qualification must match the oracle
    /// minimum at `deficit`.
    fn process_weighted(
        b: &mut TreeBuilder<'_, u64, i64, Store>,
        oracle: &DagOracle,
        events: &mut Vec<Arrival<u64, i64>>,
        e: Arrival<u64, i64>,
        deficit: i64,
        probe: &impl Fn(AncestryProbe<'_, u64>) -> bool,
    ) -> bool {
        events.push(e);
        let result = b.process_block(e, deficit, probe);
        let minimum = oracle.minimum(events);
        assert_eq!(result, minimum.is_none_or(|m| m >= -deficit), "block {} answered {result} at minimum {minimum:?}", e.block);
        check_builder(b, oracle, events);
        result
    }

    /// Randomized batches and forks across fixed seeds and k values, with every
    /// block carrying its own nonzero work: every intermediate working tree and
    /// every published history matches direct descendant-work sums in scores,
    /// minimum, and qualification.
    #[test]
    fn randomized_batches_and_forks_match_direct_scores() {
        for &k in &[0u16, 1, 3, 8] {
            for seed in 0u64..6 {
                let mut rng = SmallRng::seed_from_u64(100 * u64::from(k) + seed);
                let oracle = DagOracle::default();
                let mut store = Store::new();
                let mut histories: HashMap<Option<u64>, Vec<Arrival<u64, i64>>> = HashMap::from([(None, Vec::new())]);
                let mut anchor = None;
                for batch in 0..12 {
                    if batch % 3 == 2 {
                        let keys: Vec<Option<u64>> = histories.keys().copied().collect();
                        anchor = keys[rng.gen_range(0..keys.len())];
                    }
                    let mut events = histories[&anchor].clone();
                    let mut b = store.begin(k, anchor);
                    check_builder(&b, &oracle, &events);
                    for _ in 0..rng.gen_range(0..=7) {
                        let block = oracle.next_id();
                        let visible: Vec<u64> = events.iter().map(|e| e.block).collect();
                        let parents: Vec<u64> = if visible.is_empty() {
                            Vec::new()
                        } else if rng.gen_bool(0.35) {
                            visible[visible.len().saturating_sub(6)..].to_vec()
                        } else {
                            let pool = &visible[visible.len().saturating_sub(8)..];
                            let count = rng.gen_range(1..=pool.len().min(3));
                            pool.choose_multiple(&mut rng, count).copied().collect()
                        };
                        oracle.add(&parents);
                        let work = rng.gen_range(1..=9i64);
                        let blue = rng.gen_bool(0.7) && oracle.may_add_blue(&events, block, k);
                        let deficit = rng.gen_range(0..=10i64);
                        process_weighted(&mut b, &oracle, &mut events, event(block, blue, work), deficit, &oracle.probe());
                    }
                    anchor = Some(b.publish().unwrap());
                    histories.insert(anchor, events);
                }
                for (version, events) in &histories {
                    if let Some(version) = version {
                        check_published(&store, k, *version, &oracle, events);
                    }
                }
            }
        }
    }

    /// An empty tree qualifies vacuously, a red-only run never grows a tree no
    /// matter the work its reds carry, and a blue over red-only history starts
    /// a fresh tree whose single leaf scores zero because earlier reds cannot
    /// be its ancestors. A red with no blue ancestor over that non-empty tree
    /// still changes nothing.
    #[test]
    fn empty_and_red_only_states_qualify() {
        let oracle = DagOracle::default();
        let mut store = Store::new();
        let mut events = Vec::new();
        let mut b = store.begin(0, None);
        check_builder(&b, &oracle, &events);
        assert!(b.apply_delta(std::iter::empty(), 0, &oracle.probe()));
        let empty = b.publish().unwrap();
        check_published(&store, 0, empty, &oracle, &events);
        assert_eq!(store.metadata(0, empty).unwrap().expect("empty metadata").root_version, None);

        let mut b = store.begin(0, Some(empty));
        for block in 0..6u64 {
            oracle.add(&chain_parents(block));
            assert!(process_weighted(&mut b, &oracle, &mut events, event(block, false, 3 + block as i64), 0, &oracle.probe()));
        }
        let red_only = b.publish().unwrap();
        assert_eq!(store.metadata(0, red_only).unwrap().expect("red-only metadata").root_version, None);
        check_published(&store, 0, red_only, &oracle, &events);

        // The first blue leaf is not an ancestor of the earlier reds, so the
        // tree starts fresh at zero.
        let mut b = store.begin(0, Some(red_only));
        oracle.add(&[5]);
        assert!(process_weighted(&mut b, &oracle, &mut events, event(6, true, 7), 0, &oracle.probe()));
        assert_eq!(b.scores(), leaf_scores(&[(6, 0)]));
        // A red whose only parent is an old red has no blue ancestor even over
        // a non-empty tree: nothing changes.
        oracle.add(&[5]);
        assert!(process_weighted(&mut b, &oracle, &mut events, event(7, false, 9), 0, &oracle.probe()));
        assert_eq!(b.scores(), leaf_scores(&[(6, 0)]));
        let version = b.publish().unwrap();
        check_published(&store, 0, version, &oracle, &events);
    }

    /// A blue arrival finds its nonancestor holes by scanning only the bounded
    /// suffix window: every ancestry probe touches a leaf within `2k-1`
    /// positions of the new leaf and the arriving block itself.
    #[test]
    fn blue_shortcut_only_queries_the_bounded_suffix() {
        for &k in &[0u16, 1, 2, 4] {
            for n in [0u64, 1, 3, 4, 9] {
                let oracle = DagOracle::default();
                let mut store = Store::new();
                let mut events = Vec::new();
                let queries = RefCell::new(Vec::new());
                let probe = oracle.recording_probe(&queries);
                let mut b = store.begin(k, None);
                for block in 0..n {
                    oracle.add(&chain_parents(block));
                    process_weighted(&mut b, &oracle, &mut events, event(block, true, 1), 0, &probe);
                }
                let anchor = b.publish().unwrap();
                let mut b = store.begin(k, Some(anchor));
                oracle.add(&chain_parents(n));
                queries.borrow_mut().clear();
                process_weighted(&mut b, &oracle, &mut events, event(n, true, 1), 0, &probe);

                let bound = n.min((2 * i64::from(k) - 1).max(0) as u64);
                let probed = queries.borrow();
                assert!(probed.len() <= bound as usize, "k={k} n={n} probed {probed:?}");
                assert!(
                    probed.iter().all(|&(leaf, block)| leaf >= n - bound && leaf < n && block == n),
                    "k={k} n={n} probed {probed:?}"
                );
            }
        }
    }

    /// A hole exactly at the window's left edge is repaired: with two parallel
    /// k-long blue chains over a shared prefix, the new right tip adds its work
    /// to its ancestors only, the left chain's head sits exactly `2k-1`
    /// positions before it and keeps its score, and the prefix leaves are never
    /// probed.
    #[test]
    fn blue_hole_at_the_left_edge_of_the_shortcut_window() {
        for &k in &[1u16, 2, 3, 5] {
            let oracle = DagOracle::default();
            let mut store = Store::new();
            let mut events = Vec::new();
            for i in 0..4u64 {
                oracle.add(&chain_parents(i));
                events.push(event(i, true, 1 + i as i64));
            }
            // Two parallel k-long chains over the prefix tip give every block
            // exactly k incomparable blues.
            for &base in &[4u64, 4 + u64::from(k)] {
                for i in 0..u64::from(k) {
                    let block = base + i;
                    let parents = if i == 0 { vec![3] } else { vec![block - 1] };
                    oracle.add(&parents);
                    if base != 4 + u64::from(k) || i < u64::from(k) - 1 {
                        events.push(event(block, true, 2 + i as i64));
                    }
                }
            }
            let new_blue = 4 + 2 * u64::from(k) - 1;
            assert!(oracle.may_add_blue(&events, new_blue, k), "k={k}");

            let queries = RefCell::new(Vec::new());
            let probe = oracle.recording_probe(&queries);
            let mut b = store.begin(k, None);
            b.apply_delta(events.iter().copied(), 0, &probe);
            let anchor = b.publish().unwrap();
            let old_events = events.clone();
            let mut b = store.begin(k, Some(anchor));
            queries.borrow_mut().clear();
            process_weighted(&mut b, &oracle, &mut events, event(new_blue, true, 6), 0, &probe);

            let probed = queries.borrow();
            assert!(probed.contains(&(4, new_blue)), "the left-edge hole must be probed: {probed:?}");
            assert!(probed.len() < 2 * usize::from(k), "k={k} probed {probed:?}");
            assert!(probed.iter().all(|&(leaf, _)| !(0..4).contains(&leaf)), "prefix leaves must not be probed: {probed:?}");
            assert_eq!(b.scores().last(), Some(&LeafScore { value: new_blue, score: 0 }));
            drop(probed);
            let updated = b.publish().unwrap();
            check_published(&store, k, anchor, &oracle, &old_events);
            check_published(&store, k, updated, &oracle, &events);
        }
    }

    /// A blue adds its work to every existing leaf, yet the appended leaf
    /// starts at zero: old leaves gain the work, the new leaf nothing, and the
    /// root grows one level exactly when the old tree was full.
    #[test]
    fn blue_root_addition_does_not_leak_into_the_appended_leaf() {
        for n in [1u64, 3, 4, 5, 8] {
            let oracle = DagOracle::default();
            let mut store = Store::new();
            let mut events = Vec::new();
            let mut b = store.begin(0, None);
            for block in 0..n + 6 {
                oracle.add(&chain_parents(block));
                process_weighted(&mut b, &oracle, &mut events, event(block, block < n, 1 + block as i64), 0, &oracle.probe());
            }
            let anchor = b.publish().unwrap();
            let old_events = events.clone();
            let old_scores = store.scores(0, anchor).unwrap();
            let old_height = store.metadata(0, anchor).unwrap().expect("anchor metadata").root_height;

            let mut b = store.begin(0, Some(anchor));
            let new_blue = n + 6;
            oracle.add(&[new_blue - 1]);
            let work = 4;
            process_weighted(&mut b, &oracle, &mut events, event(new_blue, true, work), 0, &oracle.probe());
            let mut expected: Vec<_> =
                old_scores.iter().map(|leaf| LeafScore { value: leaf.value, score: leaf.score + work }).collect();
            expected.push(LeafScore { value: new_blue, score: 0 });
            assert_eq!(b.scores(), expected, "n={n}");
            let updated = b.publish().unwrap();

            let grew = n & (n - 1) == 0;
            assert_eq!(
                store.metadata(0, updated).unwrap().expect("updated metadata").root_height,
                old_height + u16::from(grew),
                "n={n}"
            );
            check_published(&store, 0, anchor, &oracle, &old_events);
            check_published(&store, 0, updated, &oracle, &events);
        }
    }

    /// A red with no blue ancestor over a non-empty tree is a no-op: nothing is
    /// buffered, and the published state keeps the anchor's root and lineage.
    #[test]
    fn red_without_blue_ancestors_keeps_inherited_root() {
        let oracle = DagOracle::default();
        oracle.add(&[]);
        oracle.add(&[0]);
        oracle.add(&[0]);
        let events = vec![event(0, false, 5), event(1, true, 3)];
        let mut store = Store::new();
        let anchor = {
            let mut b = store.begin(0, None);
            b.apply_delta(events.iter().copied(), 0, &oracle.probe());
            b.publish().unwrap()
        };

        let mut b = store.begin(0, Some(anchor));
        let mut events = events.clone();
        process_weighted(&mut b, &oracle, &mut events, event(2, false, 7), 0, &oracle.probe());
        assert!(b.buffer.is_empty(), "a no-op red must not touch any record");
        let version = b.publish().unwrap();
        assert_eq!(
            store.metadata(0, version).unwrap().expect("version metadata").root_version,
            store.metadata(0, anchor).unwrap().expect("anchor metadata").root_version
        );
        assert_eq!(store.metadata(0, version).unwrap().expect("version metadata").anchor_version, Some(anchor));
        check_published(&store, 0, anchor, &oracle, &events);
        check_published(&store, 0, version, &oracle, &events);
    }

    /// Two builders extending the same anchor with divergent deltas put their
    /// own leaf values at the same coordinates and keep independent scores; the
    /// anchor's published state answers unchanged.
    #[test]
    fn forks_get_different_leaves_at_same_coordinates() {
        let oracle = DagOracle::default();
        for (_, parents) in [(0u64, vec![]), (1, vec![0]), (2, vec![1]), (3, vec![0]), (4, vec![2]), (5, vec![3])] {
            oracle.add(&parents);
        }
        let mut store = Store::new();
        let base = vec![event(0, true, 2), event(1, true, 3)];
        let anchor = {
            let mut b = store.begin(1, None);
            b.apply_delta(base.iter().copied(), 0, &oracle.probe());
            b.publish().unwrap()
        };
        let mut left_events = base.clone();
        let left_version = {
            let mut b = store.begin(1, Some(anchor));
            process_weighted(&mut b, &oracle, &mut left_events, event(2, true, 5), 0, &oracle.probe());
            process_weighted(&mut b, &oracle, &mut left_events, event(4, false, 4), 0, &oracle.probe());
            b.publish().unwrap()
        };
        let mut right_events = base.clone();
        let right_version = {
            let mut b = store.begin(1, Some(anchor));
            process_weighted(&mut b, &oracle, &mut right_events, event(3, true, 6), 0, &oracle.probe());
            process_weighted(&mut b, &oracle, &mut right_events, event(5, false, 8), 0, &oracle.probe());
            b.publish().unwrap()
        };
        assert_ne!(left_version, right_version);
        assert_eq!(store.scores(1, left_version).unwrap()[2].value, 2);
        assert_eq!(store.scores(1, right_version).unwrap()[2].value, 3);
        check_published(&store, 1, anchor, &oracle, &base);
        check_published(&store, 1, left_version, &oracle, &left_events);
        check_published(&store, 1, right_version, &oracle, &right_events);
    }

    /// A negative root minimum is not terminal: a blue descendant restores its
    /// ancestors' scores. After a red drags the minimum to minus its own work,
    /// a blue child adds its work back to every ancestor leaf, and its own zero
    /// leaf lifts the minimum to zero.
    #[test]
    fn negative_root_recovers_on_blue_descendant() {
        let oracle = DagOracle::default();
        let mut store = Store::new();
        let mut events = Vec::new();
        let mut b = store.begin(1, None);
        oracle.add(&[]);
        assert!(process_weighted(&mut b, &oracle, &mut events, event(0, true, 1), 0, &oracle.probe()));
        assert_eq!(b.minimum_score(), Some(0));

        oracle.add(&[0]);
        assert!(!process_weighted(&mut b, &oracle, &mut events, event(1, false, 3), 0, &oracle.probe()));
        assert_eq!(b.minimum_score(), Some(-3), "the red drags the root minimum to minus its work");

        oracle.add(&[1]);
        assert!(process_weighted(&mut b, &oracle, &mut events, event(2, true, 5), 0, &oracle.probe()));
        assert_eq!(b.scores(), leaf_scores(&[(0, 2), (2, 0)]));
        assert_eq!(b.minimum_score(), Some(0), "the blue descendant restores the minimum");
    }

    /// `qualifies` is a pure query parameter: the same state answers
    /// differently per deficit without changing a single score, and a tree with
    /// no leaves qualifies vacuously at every deficit.
    #[test]
    fn qualifies_is_a_pure_query_parameter() {
        let oracle = DagOracle::default();
        let mut store = Store::new();
        let mut events = Vec::new();
        let mut b = store.begin(1, None);
        oracle.add(&[]);
        oracle.add(&[0]);
        process_weighted(&mut b, &oracle, &mut events, event(0, true, 2), 0, &oracle.probe());
        process_weighted(&mut b, &oracle, &mut events, event(1, false, 5), 0, &oracle.probe());
        // The blue leaf scores -5: its own work never reaches it, the red's does.
        let scores = b.scores();
        let buffer = b.buffer.clone();
        assert_eq!(b.minimum_score(), Some(-5));
        assert!(!b.qualifies(0));
        assert!(!b.qualifies(4), "-5 is below the allowance -4");
        assert!(b.qualifies(5), "-5 exactly meets the allowance -5");
        assert!(b.qualifies(100));
        assert_eq!(b.scores(), scores, "qualification queries must not mutate the tree");
        assert_eq!(b.buffer, buffer, "qualification queries must not buffer records");
        drop(b);

        let b = store.begin(1, None);
        for deficit in [0, 5, 1000] {
            assert!(b.qualifies(deficit), "an empty tree qualifies at deficit {deficit}");
        }
    }

    /// Feeding a run of arrivals through `apply_delta` lands on the same state
    /// as feeding them one by one through `process_block`: a mid-run failed
    /// qualification does not stop maintenance, and a later blue descendant
    /// restores it.
    #[test]
    fn apply_delta_matches_stepwise_process_block() {
        let oracle = DagOracle::default();
        for (_, parents) in [(0u64, vec![]), (1, vec![0]), (2, vec![0]), (3, vec![1, 2]), (4, vec![2]), (5, vec![3, 4])] {
            oracle.add(&parents);
        }
        let run =
            vec![event(0, true, 1), event(1, true, 2), event(2, true, 2), event(3, true, 2), event(4, false, 9), event(5, true, 8)];
        let mut store = Store::new();
        let (stepwise_scores, stepwise_minimum, stepwise_version) = {
            let mut b = store.begin(1, None);
            let mut events = Vec::new();
            let mut results = Vec::new();
            for &e in &run {
                results.push(process_weighted(&mut b, &oracle, &mut events, e, 0, &oracle.probe()));
            }
            assert_eq!(results, vec![true, true, true, true, false, true], "a failed qualification must not stop maintenance");
            let scores = b.scores();
            let minimum = b.minimum_score();
            (scores, minimum, b.publish().unwrap())
        };
        let batch_version = {
            let mut b = store.begin(1, None);
            assert!(b.apply_delta(run.iter().copied(), 0, &oracle.probe()));
            assert_eq!(b.scores(), stepwise_scores);
            assert_eq!(b.minimum_score(), stepwise_minimum);
            for deficit in [0, 1, 7] {
                assert_eq!(b.qualifies(deficit), stepwise_minimum.is_none_or(|m| m >= -deficit), "deficit {deficit}");
            }
            b.publish().unwrap()
        };
        check_published(&store, 1, stepwise_version, &oracle, &run);
        check_published(&store, 1, batch_version, &oracle, &run);
    }

    /// Signed 192-bit work arithmetic end to end: the path exercises negation
    /// through range additions and the negated zero allowance in the deficit
    /// comparison.
    #[test]
    fn signed_work_scores_negate_end_to_end() {
        let work = |n: u64| SignedWork::from(Uint192::from_u64(n));
        let mut store = MemoryUmcTreeStore::<u64, SignedWork>::new();
        let mut b = store.begin(1, None);
        assert!(b.process_block(Arrival { block: 0, blue: true, work: work(7) }, work(0), &chain_ancestry));
        assert!(b.process_block(Arrival { block: 1, blue: true, work: work(3) }, work(0), &chain_ancestry));
        // A red over both blues subtracts its full work from each of them.
        assert!(!b.process_block(Arrival { block: 2, blue: false, work: work(5) }, work(3), &chain_ancestry));
        assert_eq!(
            b.scores(),
            vec![LeafScore { value: 0, score: work(0) - work(2) }, LeafScore { value: 1, score: work(0) - work(5) }]
        );
        assert_eq!(b.minimum_score(), Some(work(0) - work(5)));
        assert!(!b.qualifies(work(3)));
        assert!(b.qualifies(work(5)));
    }
}

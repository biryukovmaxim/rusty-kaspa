//! Bounded-memory UMC tree store with transparent DB fallback: the production
//! singleton across all k.
//!
//! A concrete struct (like `SmtStores`), single-writer: `begin` takes `&mut self`
//! and yields one builder at a time. Callers wrap in `RwLock` when parallel
//! readers appear, as consensus storage already does for its stores.
//!
//! # Newest-suffix invariant
//!
//! The caches are designed so that, for every coordinate `(k, h, j)`, the set of
//! versions retained in the node cache is an up-set of that coordinate's
//! published history ordered by version: if version V at `(k, h, j)` is cached,
//! then every published version V' > V at that coordinate is also cached.
//! Equivalently, the first entry of the coordinate's newest-first cache range is
//! the coordinate's globally newest published record, so
//! [`UmcTreeStores::latest_node`] may return a cache hit as authoritative
//! without consulting the DB. It rests on:
//!
//! 1. **Write-through on publish.** Every record and the metadata of a published
//!    version are inserted into the caches in the same `publish` call that
//!    commits the DB batch. No published record is ever DB-only while its
//!    version could still be cached.
//! 2. **Version-ordered eviction.** Both capacity eviction and
//!    `BoundedCache::evict_below_version` remove the globally lowest-version
//!    entries first. A higher version at any coordinate is never evicted before
//!    a lower one, so per-coordinate eviction always carves a prefix
//!    (oldest-first) out of the coordinate's history and what remains is an
//!    up-set.
//! 3. **Admission guard.** An insert whose version is strictly below the cache's
//!    current global minimum version is not admitted: it would itself be the
//!    next eviction candidate, and admitting it could leave an older version
//!    cached while a newer version of the same coordinate lives only in the DB.
//!    Publish inserts are monotone (each version is allocated after every cached
//!    one), so the guard never rejects a publish.
//! 4. **No read-refill, cold start.** Reads do not insert into the caches, so
//!    only write-through inserts contend with eviction. After a restart the
//!    caches are empty and all published records are DB-only; the weaker
//!    post-restart invariant (an up-set of versions written since the last
//!    clear) plus DB fallback keeps reads correct. A cache miss is always
//!    answered by the DB range scan (`seek_latest` + coordinate-prefix walk),
//!    the same newest-first query shape at both levels, so fallback needs no
//!    extra machinery.
//!
//! The metadata cache satisfies the analogous per-k property
//! (`latest_version(k)` cache hit is authoritative) by the same argument with
//! `VersionKey`.
//!
//! Never evicted: the open builder's working buffer lives in the builder and
//! never enters the store (evicting or persisting it piecemeal would expose a
//! partial state and break publish atomicity), and the version counter is a
//! single durable u64 under the meta key, advanced inside the publish batch.

use std::sync::Arc;

use kaspa_consensus_core::KType;
use kaspa_database::prelude::{DB, StoreResult};

use super::api::{PublishedVersion, UmcTreeStore, UmcTreeStoreReader};
use super::builder::TreeBuilder;
use super::db::DbUmcTreeStore;
use super::keys::{NodeKey, VersionKey};
use super::mem::BoundedCache;
use super::records::{NodeCoord, NodeRecord, NodeRef, Score, ScoreWire, ValueWire, VersionMetadata, VersionedNode};

/// Bounded-memory UMC tree store with DB fallback: the production singleton across all k.
pub struct UmcTreeStores<T, S> {
    /// DB level answering every cache miss.
    db: DbUmcTreeStore<T, S>,
    /// Node-record cache; a miss falls back to a DB point get.
    nodes: BoundedCache<NodeKey, NodeRecord<T, S>>,
    /// Version-metadata cache; a miss falls back to a DB point get.
    versions: BoundedCache<VersionKey, VersionMetadata>,
    /// Version-id allocator image; `None` until the first allocation reads the DB meta key.
    next_version_id: Option<u64>,
}

impl<T: Clone + ValueWire, S: Score + ScoreWire> UmcTreeStores<T, S> {
    /// Facade over `db` caching at most `node_capacity` node records and
    /// `metadata_capacity` metadata entries.
    ///
    /// Capacities count entries (at the `T = Hash`, `S = SignedWork`
    /// instantiation one node entry costs roughly 250 to 350 bytes across both
    /// cache indexes).
    // TODO(dk): switch to byte budgets if profiling demands it
    pub fn new(db: Arc<DB>, node_capacity: usize, metadata_capacity: usize) -> Self {
        Self {
            db: DbUmcTreeStore::new(db),
            nodes: BoundedCache::new(node_capacity),
            versions: BoundedCache::new(metadata_capacity),
            next_version_id: None,
        }
    }

    /// Start a working tree in partition `k` from scratch, or extending the
    /// published `anchor_version` state; panics on an unknown anchor version.
    /// The builder captures `k` and routes every query through it.
    pub fn begin(&mut self, k: KType, anchor_version: Option<u64>) -> TreeBuilder<'_, T, S, Self> {
        TreeBuilder::begin(self, k, anchor_version)
    }
}

impl<T: Clone + ValueWire, S: Score + ScoreWire> UmcTreeStoreReader<T, S> for UmcTreeStores<T, S> {
    fn get_node(&self, k: KType, node: NodeRef) -> StoreResult<Option<NodeRecord<T, S>>> {
        let key = NodeKey::new(self.db.node_prefix, k, node.h, node.j, node.version);
        if let Some(record) = self.nodes.get(&key) {
            return Ok(Some(record.clone()));
        }
        self.db.get_node(k, node)
    }

    fn latest_node(&self, k: KType, coord: NodeCoord) -> StoreResult<Option<VersionedNode<T, S>>> {
        let seek = NodeKey::seek_latest(self.db.node_prefix, k, coord.h, coord.j);
        // Cache hit is authoritative per the newest-suffix invariant.
        if let Some((key, record)) = self.nodes.latest_matching(&seek, NodeKey::COORDINATE_PREFIX_LEN) {
            return Ok(Some(VersionedNode { version: key.version(), record: record.clone() }));
        }
        self.db.latest_node(k, coord)
    }

    fn metadata(&self, k: KType, version: u64) -> StoreResult<Option<VersionMetadata>> {
        let key = VersionKey::new(self.db.version_prefix, k, version);
        if let Some(metadata) = self.versions.get(&key) {
            return Ok(Some(metadata.clone()));
        }
        self.db.metadata(k, version)
    }

    fn latest_version(&self, k: KType) -> StoreResult<Option<u64>> {
        let seek = VersionKey::seek_latest(self.db.version_prefix, k);
        // Cache hit is authoritative per the per-k analogue of the invariant.
        if let Some((key, _)) = self.versions.latest_matching(&seek, VersionKey::K_PREFIX_LEN) {
            return Ok(Some(key.version()));
        }
        self.db.latest_version(k)
    }
}

impl<T: Clone + ValueWire, S: Score + ScoreWire> UmcTreeStore<T, S> for UmcTreeStores<T, S> {
    fn allocate_version(&mut self) -> StoreResult<u64> {
        let next = match self.next_version_id {
            Some(next) => next,
            None => self.db.read_counter()?,
        };
        self.next_version_id = Some(next + 1);
        Ok(next)
    }

    fn publish(&mut self, k: KType, publish: PublishedVersion<T, S>) -> StoreResult<()> {
        // DB batch first; a failed batch exposes no new state.
        let counter = publish.version + 1;
        self.db.commit_publish(k, &publish, counter)?;
        // Write-through inserts; eviction is a pure drop because the DB copy is durable.
        for (coord, record) in publish.records.iter() {
            self.nodes.insert(NodeKey::new(self.db.node_prefix, k, coord.h, coord.j, publish.version), record.clone());
        }
        self.versions.insert(VersionKey::new(self.db.version_prefix, k, publish.version), publish.metadata.clone());
        self.next_version_id = Some(self.next_version_id.map_or(counter, |next| next.max(counter)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, StoreError};

    use super::super::mem::MemoryUmcTreeStore;
    use super::super::records::LeafScore;

    type Facade = UmcTreeStores<u64, i64>;

    fn leaf_scores(pairs: &[(u64, i64)]) -> Vec<LeafScore<u64, i64>> {
        pairs.iter().map(|&(value, score)| LeafScore { value, score }).collect()
    }

    /// Publish one version anchoring at `anchor` and appending the new leaves
    /// `first..=last` (inherited ones are already in the anchor).
    fn publish_leaves<St: UmcTreeStore<u64, i64>>(store: &mut St, k: KType, anchor: Option<u64>, first: u64, last: u64) -> u64 {
        let mut b = TreeBuilder::begin(store, k, anchor);
        for value in first..=last {
            b.append_leaf(value);
        }
        b.publish().unwrap()
    }

    /// Tiny capacities force eviction of both caches; reads then fall back to
    /// the DB and return values equal to the cache-path ones.
    #[test]
    fn publish_write_through_evict_then_fallback() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 2, 1);
        let mut anchor = None;
        let mut versions = Vec::new();
        for value in 0..4u64 {
            let version = publish_leaves(&mut stores, 0, anchor, value, value);
            versions.push(version);
            anchor = Some(version);
        }
        for (i, &version) in versions.iter().enumerate() {
            let expected: Vec<LeafScore<u64, i64>> = (0..=i as u64).map(|value| LeafScore { value, score: 0 }).collect();
            assert_eq!(stores.scores(0, version).unwrap(), expected, "version {version}");
        }
        assert_eq!(stores.latest_version(0).unwrap(), Some(*versions.last().unwrap()));
    }

    /// The facade's authoritative cache hits agree with an exact memory store
    /// fed the same publish sequence.
    #[test]
    fn latest_node_cache_hit_authoritative() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut facade = Facade::new(db, 100, 100);
        let mut memory = MemoryUmcTreeStore::<u64, i64>::new();
        let mut anchor_f = None;
        let mut anchor_m = None;
        for step in 0..3u64 {
            anchor_f = Some(publish_leaves(&mut facade, 2, anchor_f, step * 2, step * 2 + 1));
            anchor_m = Some(publish_leaves(&mut memory, 2, anchor_m, step * 2, step * 2 + 1));
        }
        for coord in [NodeCoord { h: 0, j: 0 }, NodeCoord { h: 0, j: 1 }, NodeCoord { h: 1, j: 0 }] {
            let f = facade.latest_node(2, coord).unwrap().map(|vn| vn.version);
            let m = memory.latest_node(2, coord).unwrap().map(|vn| vn.version);
            assert_eq!(f, m, "latest_node at {coord:?}");
        }
        let f = facade.latest_version(2).unwrap().unwrap();
        let m = memory.latest_version(2).unwrap().unwrap();
        assert_eq!(f, m);
        assert_eq!(facade.scores(2, f).unwrap(), memory.scores(2, m).unwrap());
    }

    /// Two trees, one store, no cross-talk: separate leaf sequences, metadata
    /// and latest versions per k.
    #[test]
    fn two_ks_one_facade() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 100, 100);
        let v0 = {
            let mut b = stores.begin(0, None);
            b.append_leaf(10);
            b.append_leaf(11);
            b.range_add(0, 2, 5);
            b.publish().unwrap()
        };
        let w0 = publish_leaves(&mut stores, 1, None, 20, 21);
        assert_eq!(stores.scores(0, v0).unwrap(), leaf_scores(&[(10, 5), (11, 5)]));
        assert_eq!(stores.scores(1, w0).unwrap(), leaf_scores(&[(20, 0), (21, 0)]));
        assert_eq!(stores.latest_version(0).unwrap(), Some(v0));
        assert_eq!(stores.latest_version(1).unwrap(), Some(w0));
        // k1 extends its own anchor without seeing k0's leaves.
        let w1 = publish_leaves(&mut stores, 1, Some(w0), 22, 22);
        assert_eq!(stores.scores(1, w1).unwrap(), leaf_scores(&[(20, 0), (21, 0), (22, 0)]));
        assert_eq!(stores.scores(0, v0).unwrap(), leaf_scores(&[(10, 5), (11, 5)]));
    }

    /// An anchor of a different k is unknown in this k's partition.
    #[test]
    #[should_panic(expected = "unknown anchor version")]
    fn anchor_from_other_k_rejected() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 100, 100);
        let v0 = publish_leaves(&mut stores, 0, None, 0, 0);
        let _ = publish_leaves(&mut stores, 1, Some(v0), 5, 5);
    }

    /// Metadata eviction is transparent: an evicted version's metadata is
    /// served by the DB fallback.
    #[test]
    fn metadata_eviction_fallback() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 100, 1);
        let v0 = publish_leaves(&mut stores, 0, None, 0, 0);
        let v1 = publish_leaves(&mut stores, 0, Some(v0), 1, 1);
        let v2 = publish_leaves(&mut stores, 0, Some(v1), 2, 2);
        assert_eq!(stores.metadata(0, v0).unwrap().map(|m| m.blue_count), Some(1));
        assert_eq!(stores.metadata(0, v1).unwrap().map(|m| m.blue_count), Some(2));
        assert_eq!(stores.metadata(0, v2).unwrap().map(|m| m.blue_count), Some(3));
    }

    /// Unknown versions read as errors, never as empty state: `minimum_score`,
    /// `scores` and `qualifies` answer `DataInconsistency` for an unpublished version.
    #[test]
    fn unknown_version_reads_error() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 10, 10);
        let v0 = publish_leaves(&mut stores, 0, None, 1, 1);
        let error = stores.minimum_score(0, v0 + 1).unwrap_err();
        assert!(matches!(error, StoreError::DataInconsistency(ref message) if message.contains("unknown umc version")));
        let error = stores.scores(0, v0 + 1).unwrap_err();
        assert!(matches!(error, StoreError::DataInconsistency(ref message) if message.contains("unknown umc version")));
        let error = stores.qualifies(0, v0 + 1, 0).unwrap_err();
        assert!(matches!(error, StoreError::DataInconsistency(ref message) if message.contains("unknown umc version")));
        // A published version still reads normally next to the error path.
        assert_eq!(stores.scores(0, v0).unwrap(), leaf_scores(&[(1, 0)]));
    }

    /// The open builder's working buffer never enters the store: a buffer far
    /// larger than the cache capacity survives cache churn and publishes whole.
    #[test]
    fn eviction_never_touches_open_buffer() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 3, 3);
        // Churn the caches with earlier publishes.
        let mut anchor = None;
        for value in 0..4u64 {
            anchor = Some(publish_leaves(&mut stores, 0, anchor, value, value));
        }
        let version = {
            let mut b = stores.begin(0, anchor);
            for value in 100..112u64 {
                b.append_leaf(value);
            }
            b.range_add(0, 16, 7);
            b.publish().unwrap()
        };
        let mut expected: Vec<LeafScore<u64, i64>> = (0..4u64).map(|value| LeafScore { value, score: 7 }).collect();
        expected.extend((100..112u64).map(|value| LeafScore { value, score: 7 }));
        assert_eq!(stores.scores(0, version).unwrap(), expected);
    }

    /// Root and near-root records evicted by later publishes never corrupt
    /// reads: every level's `latest_node` stays authoritative, a full cache
    /// clear serves identical answers from the DB alone, and a builder
    /// anchored at an evicted branch continues correctly.
    #[test]
    fn root_record_eviction_db_fallback() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 3, 2);
        // v0: six leaves under a height-3 root (eleven records, over capacity).
        let v0 = publish_leaves(&mut stores, 0, None, 0, 5);
        // v1: two more leaves plus a root-wide addition; its inserts evict every v0 record.
        let v1 = {
            let mut b = stores.begin(0, Some(v0));
            b.append_leaf(6);
            b.append_leaf(7);
            b.range_add(0, 8, 5);
            b.publish().unwrap()
        };
        // v2: root growth to height 4, two more leaves, another root-wide addition.
        let v2 = {
            let mut b = stores.begin(0, Some(v1));
            b.append_leaf(8);
            b.append_leaf(9);
            b.range_add(0, 10, 3);
            b.publish().unwrap()
        };
        let v0_scores = leaf_scores(&[(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)]);
        let v1_scores = leaf_scores(&[(0, 5), (1, 5), (2, 5), (3, 5), (4, 5), (5, 5), (6, 5), (7, 5)]);
        let v2_scores = leaf_scores(&[(0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (6, 8), (7, 8), (8, 3), (9, 3)]);
        assert_eq!(stores.scores(0, v0).unwrap(), v0_scores);
        assert_eq!(stores.scores(0, v1).unwrap(), v1_scores);
        assert_eq!(stores.scores(0, v2).unwrap(), v2_scores);
        assert_eq!(stores.minimum_score(0, v2).unwrap(), Some(3));
        assert_eq!(stores.latest_version(0).unwrap(), Some(v2));
        // Latest records at three heights written by three different versions: the
        // v2 growth root, the subtree last rewritten by v1's inserts, and a v0 pair.
        assert_eq!(stores.latest_node(0, NodeCoord { h: 4, j: 0 }).unwrap().unwrap().version, v2);
        assert_eq!(stores.latest_node(0, NodeCoord { h: 2, j: 1 }).unwrap().unwrap().version, v1);
        assert_eq!(stores.latest_node(0, NodeCoord { h: 1, j: 1 }).unwrap().unwrap().version, v0);
        // Clear both caches entirely: every answer must come from the DB alone.
        stores.nodes.evict_below_version(u64::MAX);
        stores.versions.evict_below_version(u64::MAX);
        assert_eq!(stores.nodes.len(), 0);
        assert_eq!(stores.versions.len(), 0);
        assert_eq!(stores.scores(0, v0).unwrap(), v0_scores);
        assert_eq!(stores.scores(0, v1).unwrap(), v1_scores);
        assert_eq!(stores.scores(0, v2).unwrap(), v2_scores);
        assert_eq!(stores.minimum_score(0, v2).unwrap(), Some(3));
        assert_eq!(stores.latest_version(0).unwrap(), Some(v2));
        assert_eq!(stores.latest_node(0, NodeCoord { h: 2, j: 1 }).unwrap().unwrap().version, v1);
        // A builder anchored at the evicted v1 branch (not the newest v2) continues correctly.
        let v3 = {
            let mut b = stores.begin(0, Some(v1));
            b.append_leaf(10);
            b.range_add(0, 9, 1);
            b.publish().unwrap()
        };
        let mut v3_scores = leaf_scores(&[(0, 6), (1, 6), (2, 6), (3, 6), (4, 6), (5, 6), (6, 6), (7, 6)]);
        v3_scores.extend(leaf_scores(&[(10, 1)]));
        assert_eq!(stores.scores(0, v3).unwrap(), v3_scores);
        // The sibling branch v2 is untouched by the v3 publication.
        assert_eq!(stores.scores(0, v2).unwrap(), v2_scores);
    }

    /// A capacity-1 cache under repeated publishes rewriting the same
    /// coordinate: `latest_node` must always answer with the newest record,
    /// never a stale hit, while untouched coordinates keep their original
    /// versions and older versions stay readable through the DB.
    #[test]
    fn same_coordinate_publishes_never_stale_at_capacity_one() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 1, 1);
        let v0 = publish_leaves(&mut stores, 0, None, 0, 1);
        let mut anchor = Some(v0);
        for step in 1..=12u64 {
            // Each publish adds one to leaf 0 only, rewriting coordinate (0, 0).
            let version = {
                let mut b = stores.begin(0, anchor);
                b.range_add(0, 1, 1);
                b.publish().unwrap()
            };
            anchor = Some(version);
            let latest = stores.latest_node(0, NodeCoord { h: 0, j: 0 }).unwrap().unwrap();
            assert_eq!(latest.version, version, "step {step}: stale latest_node");
            assert!(
                matches!(latest.record, NodeRecord::Leaf { minimum, value: 0 } if minimum == step as i64),
                "step {step}: wrong latest record {latest:?}"
            );
            // The untouched sibling keeps v0's record (path sharing).
            assert_eq!(stores.latest_node(0, NodeCoord { h: 0, j: 1 }).unwrap().unwrap().version, v0);
            assert_eq!(stores.latest_version(0).unwrap(), Some(version));
            assert_eq!(stores.scores(0, version).unwrap(), leaf_scores(&[(0, step as i64), (1, 0)]));
            // The previous version still decodes with its historical score.
            if step > 1 {
                assert_eq!(stores.scores(0, version - 1).unwrap(), leaf_scores(&[(0, step as i64 - 1), (1, 0)]));
            }
        }
    }

    /// A builder whose anchor records are fully evicted (both caches cleared
    /// between publishes, the strongest possible mid-open eviction) descends
    /// through anchor records via DB fallback and matches an exact memory
    /// oracle fed the same ops.
    #[test]
    fn cleared_caches_anchor_builder_descends_via_db() {
        /// Eight leaves plus a root-wide lazy addition, published from scratch.
        fn build_v0<St: UmcTreeStore<u64, i64>>(store: &mut St, k: KType) -> u64 {
            let mut b = TreeBuilder::begin(store, k, None);
            for value in 0..8u64 {
                b.append_leaf(value);
            }
            b.range_add(0, 8, 3);
            b.publish().unwrap()
        }
        /// An append through the evicted anchor, a range addition and hole repair.
        fn build_v1<St: UmcTreeStore<u64, i64>>(store: &mut St, k: KType, anchor: Option<u64>) -> u64 {
            let mut b = TreeBuilder::begin(store, k, anchor);
            b.append_leaf(8);
            b.range_add(0, 9, 2);
            b.correct_holes(&[0, 3], 1);
            b.publish().unwrap()
        }
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 4, 2);
        let mut oracle = MemoryUmcTreeStore::<u64, i64>::new();
        let v0 = build_v0(&mut stores, 0);
        let o0 = build_v0(&mut oracle, 0);
        assert_eq!(v0, o0);
        // Evict everything the builder is about to lazily load, metadata included.
        stores.nodes.evict_below_version(u64::MAX);
        stores.versions.evict_below_version(u64::MAX);
        assert_eq!(stores.nodes.len(), 0);
        assert_eq!(stores.versions.len(), 0);
        let v1 = build_v1(&mut stores, 0, Some(v0));
        let o1 = build_v1(&mut oracle, 0, Some(o0));
        assert_eq!(v1, o1);
        assert_eq!(stores.scores(0, v1).unwrap(), oracle.scores(0, o1).unwrap());
        assert_eq!(stores.minimum_score(0, v1).unwrap(), oracle.minimum_score(0, o1).unwrap());
        assert_eq!(stores.scores(0, v0).unwrap(), oracle.scores(0, o0).unwrap());
        let metadata = stores.metadata(0, v1).unwrap().unwrap();
        let oracle_metadata = oracle.metadata(0, o1).unwrap().unwrap();
        assert_eq!((metadata.blue_count, metadata.root_height), (oracle_metadata.blue_count, oracle_metadata.root_height));
        assert_eq!(stores.latest_version(0).unwrap(), Some(v1));
    }

    /// Hot publishing on one k evicts a cold k's records and metadata
    /// globally; the cold k's reads fall back to the DB and its later
    /// continuation sees only its own history.
    #[test]
    fn cross_k_eviction_keeps_cold_k_correct() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 2, 1);
        // k1 publishes first and then goes cold.
        let w0 = {
            let mut b = stores.begin(1, None);
            b.append_leaf(20);
            b.append_leaf(21);
            b.range_add(0, 2, 4);
            b.publish().unwrap()
        };
        // k0 churns: six publishes, each writing enough records to evict k1's.
        let mut anchor = None;
        let mut hot_last = None;
        for step in 0..6u64 {
            let version = {
                let mut b = stores.begin(0, anchor);
                b.append_leaf(100 + step);
                b.range_add(0, 1 + step, 1);
                b.publish().unwrap()
            };
            anchor = Some(version);
            hot_last = Some(version);
        }
        // k1's records and metadata are long evicted; reads still work.
        assert_eq!(stores.scores(1, w0).unwrap(), leaf_scores(&[(20, 4), (21, 4)]));
        assert_eq!(stores.minimum_score(1, w0).unwrap(), Some(4));
        assert_eq!(stores.latest_version(1).unwrap(), Some(w0));
        assert_eq!(stores.latest_node(1, NodeCoord { h: 0, j: 0 }).unwrap().unwrap().version, w0);
        // k1 continues from its own anchor; k0 is unaffected.
        let w1 = publish_leaves(&mut stores, 1, Some(w0), 22, 22);
        assert_eq!(stores.scores(1, w1).unwrap(), leaf_scores(&[(20, 4), (21, 4), (22, 0)]));
        assert_eq!(stores.scores(1, w0).unwrap(), leaf_scores(&[(20, 4), (21, 4)]));
        assert_eq!(stores.latest_version(1).unwrap(), Some(w1));
        assert_eq!(stores.latest_version(0).unwrap(), hot_last);
        assert_eq!(
            stores.scores(0, hot_last.unwrap()).unwrap(),
            leaf_scores(&[(100, 6), (101, 5), (102, 4), (103, 3), (104, 2), (105, 1)])
        );
    }

    /// Deterministic randomized op sequences (append, range addition, hole
    /// repair, anchor-chained publishes) through a tiny-cache facade must
    /// match an unbounded memory oracle exactly after every publish.
    #[test]
    fn randomized_ops_match_unbounded_oracle() {
        /// Xorshift64 state; a fixed seed keeps failures reproducible.
        struct Rng(u64);
        impl Rng {
            /// Next raw u64.
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            /// Uniform value in 0..n (n must be positive).
            fn below(&mut self, n: u64) -> u64 {
                self.next() % n
            }
        }
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut stores = Facade::new(db, 5, 2);
        let mut oracle = MemoryUmcTreeStore::<u64, i64>::new();
        let mut rng = Rng(0x5EED_CAFE_F00D_1234);
        let mut anchor = None;
        let mut next_value = 0u64;
        for _cycle in 0..60 {
            let (version, oracle_version) = {
                let mut b = stores.begin(2, anchor);
                let mut oracle_builder = oracle.begin(2, anchor);
                for _op in 0..(1 + rng.below(6)) {
                    let leaves = b.blue_count();
                    match rng.below(4) {
                        0 | 3 => {
                            b.append_leaf(next_value);
                            oracle_builder.append_leaf(next_value);
                            next_value += 1;
                        }
                        1 if leaves > 0 => {
                            let a = rng.below(leaves + 1);
                            let span = rng.below(leaves + 1 - a);
                            let delta = (rng.below(11) as i64) - 5;
                            b.range_add(a, a + span, delta);
                            oracle_builder.range_add(a, a + span, delta);
                        }
                        2 if leaves > 0 => {
                            let count = rng.below(4);
                            let mut holes: Vec<u64> = (0..count).map(|_| rng.below(leaves)).collect();
                            holes.sort_unstable();
                            holes.dedup();
                            let delta = (rng.below(7) as i64) - 3;
                            b.correct_holes(&holes, delta);
                            oracle_builder.correct_holes(&holes, delta);
                        }
                        _ => {}
                    }
                }
                (b.publish().unwrap(), oracle_builder.publish().unwrap())
            };
            assert_eq!(version, oracle_version);
            anchor = Some(version);
            assert_eq!(
                stores.scores(2, version).unwrap(),
                oracle.scores(2, oracle_version).unwrap(),
                "scores after version {version}"
            );
            assert_eq!(
                stores.minimum_score(2, version).unwrap(),
                oracle.minimum_score(2, oracle_version).unwrap(),
                "minimum after version {version}"
            );
            assert_eq!(stores.latest_version(2).unwrap(), Some(version));
            let metadata = stores.metadata(2, version).unwrap().unwrap();
            let oracle_metadata = oracle.metadata(2, oracle_version).unwrap().unwrap();
            assert_eq!(
                (metadata.blue_count, metadata.root_height, metadata.root_version),
                (oracle_metadata.blue_count, oracle_metadata.root_height, oracle_metadata.root_version),
                "metadata after version {version}"
            );
        }
    }
}

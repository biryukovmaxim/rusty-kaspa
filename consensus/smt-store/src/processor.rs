//! `SmtProcessor` — two-phase SMT lane processing.
//!
//! **Phase 1 — Accumulation** (`update_lane` / `expire_lane`):
//! Collects lane updates and expirations into [`BlockLaneChanges`].
//!
//! **Phase 2 — Build & Persist** (`build` then `flush`):
//! `build()` derives leaf hashes, calls [`compute_root_update`] against an
//! immutable DB reader, and returns an [`SmtBuild`] with the root and changed
//! branches. `flush()` persists to a `WriteBatch`; the caller commits atomically.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{ControlFlow, RangeInclusive};
use std::sync::Arc;

use parking_lot::Mutex;

use kaspa_database::prelude::{BatchDbWriter, DB, DirectDbWriter, StoreError, StoreResult};
use kaspa_hashes::{Hash, SeqCommitActiveNode, ZERO_HASH};
use kaspa_seq_commit::hashing::smt_leaf_hash;
use kaspa_seq_commit::types::SmtLeafInput;
use kaspa_smt::SmtHasher;
use kaspa_smt::proof::OwnedSmtProof;
use kaspa_smt::store::{BranchKey, Node, SmtStore, SortedLeafUpdates};
use kaspa_smt::tree::{SmtNodeChanges, SparseMerkleTree, compute_root_update};
use rocksdb::WriteBatch;

use crate::branch_version_store::DbBranchVersionStore;
use crate::cache::{BranchEntity, BranchVersionCache, LaneVersionCache};
use crate::lane_version_store::DbLaneVersionStore;
use crate::maybe_fork::Verified;
use crate::score_index::DbScoreIndex;
use crate::values::LaneTipHash;
use crate::{BlockHash, LaneKey};

struct VersionedBranchReader<'a, F: Fn(Hash) -> bool> {
    stores: &'a SmtStores,
    bounds: SmtReadBounds,
    is_canonical: F,
}

/// Given the cache's last-visited `(score, bh)`, return the smallest
/// `(score', bh')` that sorts strictly after `(score, bh)` in the DB's
/// descending-blue-score, ascending-block_hash key order: same-score with
/// `bh+1`, or on `bh` overflow drop to `(score - 1, [0; 32])`.
///
/// Returns `None` when there is no "after" — the whole byte-increment
/// overflows (i.e. last-visited was at `(0, [0xFF; 32])`).
///
/// The returned `bh` is an *inclusive* seek start: `[0; 32]` is a real
/// possible block_hash in the DB (not a sentinel), and the DB store builds
/// the seek key via `BranchVersionKey::new` / `LaneVersionKey::new` so the
/// entry at exactly `(score', [0; 32])` is reachable.
fn next_dbentry_after(score: u64, bh: Hash) -> Option<(u64, Hash)> {
    let mut bytes = bh.as_bytes();
    for byte in bytes.iter_mut().rev() {
        if *byte < 0xFF {
            *byte += 1;
            return Some((score, Hash::from_bytes(bytes)));
        }
        *byte = 0;
    }
    // bh overflow: drop to the next lower score at bh = [0; 32] (inclusive).
    score.checked_sub(1).map(|s| (s, Hash::from_bytes([0; 32])))
}

/// Translate the cache's last-visited cursor into a DB seek starting point.
///
/// - `None` last_visited → fresh start at `(target_blue_score, [0; 32])`
///   (the pre-optimization behaviour).
/// - `Some((s, bh))` → the smallest key strictly after `(s, bh)`, clamped to
///   the window's `min_blue_score`. Returns `None` if the DB has nothing
///   more to scan in the window (seek would fall below `min_blue_score` or
///   underflow).
fn resume_db_seek(last_visited: Option<(u64, Hash)>, bounds: SmtReadBounds) -> Option<(u64, Hash)> {
    let (start_score, start_bh) = match last_visited {
        None => (bounds.target_blue_score, Hash::from_bytes([0; 32])),
        Some((s, bh)) => next_dbentry_after(s, bh)?,
    };
    (start_score >= bounds.min_blue_score).then_some((start_score, start_bh))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmtReadBounds {
    /// Inclusive upper bound blue score to start the scan from (high to low)
    pub target_blue_score: u64,
    /// Inclusive lower bound blue score below which entries are out of scope/inactive
    pub min_blue_score: u64,
}

impl SmtReadBounds {
    pub const fn new(target_blue_score: u64, min_blue_score: u64) -> Self {
        Self { target_blue_score, min_blue_score }
    }

    pub const fn for_pov(pov_blue_score: u64, inactivity_threshold: u64) -> Self {
        Self { target_blue_score: pov_blue_score, min_blue_score: pov_blue_score.saturating_sub(inactivity_threshold) }
    }
}

impl From<RangeInclusive<u64>> for SmtReadBounds {
    fn from(range: RangeInclusive<u64>) -> Self {
        Self::new(*range.end(), *range.start())
    }
}

impl<F: Fn(Hash) -> bool> SmtStore for VersionedBranchReader<'_, F> {
    type Error = StoreError;

    fn get_node(&self, key: &BranchKey) -> Result<Option<Node>, StoreError> {
        let entity = BranchEntity { depth: key.depth, node_key: key.node_key };
        Ok(self.stores.get_node(entity, self.bounds, |bh| (self.is_canonical)(bh)).and_then(|v| *v.data()))
    }
}

/// All versioned SMT DB stores with in-memory caches.
pub struct SmtStores {
    pub branch_version: DbBranchVersionStore,
    pub lane_version: DbLaneVersionStore,
    pub score_index: DbScoreIndex,
    branch_cache: Mutex<BranchVersionCache>,
    lane_cache: Mutex<LaneVersionCache>,
}

struct PruneEntry {
    lane_key: Hash,
    blue_score: u64,
    block_hash: Hash,
}

impl SmtStores {
    pub fn new(db: Arc<DB>, branch_cache_capacity: usize, lane_cache_capacity: usize) -> Self {
        Self {
            branch_version: DbBranchVersionStore::new(db.clone()),
            lane_version: DbLaneVersionStore::new(db.clone()),
            score_index: DbScoreIndex::new(db),
            branch_cache: Mutex::new(BranchVersionCache::new(branch_cache_capacity)),
            lane_cache: Mutex::new(LaneVersionCache::new(lane_cache_capacity)),
        }
    }

    /// Find the latest canonical node version in `[min_blue_score, target_blue_score]`,
    /// checking cache first then DB. `target_blue_score` is the block at which the
    /// read is happening — it drives `get_at`'s seek so non-canonical future
    /// versions are skipped in O(log n) rather than scanned linearly.
    ///
    /// A cache hit is authoritative (no DB fallback) because of the
    /// newest-suffix invariant: the cache retains, per entity, a
    /// blue-score-newest suffix of the versions written through the
    /// incremental `flush` path. See the module doc in [`crate::cache`] for
    /// the full argument and the interaction with the IBD cache-bypass path.
    ///
    /// On a cache miss, instead of re-scanning the DB from `target_blue_score`
    /// (which would redo every row the cache already examined), this resumes
    /// DB iteration strictly *after* the cache's last-visited `(score, bh)` —
    /// see [`next_dbentry_after`].
    pub fn get_node(
        &self,
        entity: BranchEntity,
        bounds: SmtReadBounds,
        mut is_canonical: impl FnMut(Hash) -> bool,
    ) -> Option<Verified<Option<Node>>> {
        let last_visited = match self.branch_cache.lock().get_or_last_visited(
            entity,
            bounds.target_blue_score,
            bounds.min_blue_score,
            &mut is_canonical,
        ) {
            ControlFlow::Break((score, block_hash, value)) => return Some(Verified::new(value, score, block_hash)),
            ControlFlow::Continue(lv) => lv,
        };
        let (start_score, start_bh) = resume_db_seek(last_visited, bounds)?;
        self.branch_version
            .get_at_canonical_from(entity.depth, entity.node_key, start_score, start_bh, bounds.min_blue_score, is_canonical)
            .unwrap()
    }

    /// Find the latest canonical lane version in `[min_blue_score, target_blue_score]`,
    /// checking cache first then DB.
    ///
    /// A cache hit is authoritative for the same reason as [`Self::get_node`];
    /// see that method's doc and [`crate::cache`] for the newest-suffix
    /// invariant. On a cache miss, DB iteration resumes strictly after the
    /// cache's last-visited `(score, bh)` — see [`next_dbentry_after`].
    pub fn get_lane(
        &self,
        lane_key: LaneKey,
        bounds: SmtReadBounds,
        mut is_canonical: impl FnMut(Hash) -> bool,
    ) -> Option<Verified<LaneTipHash>> {
        let last_visited = match self.lane_cache.lock().get_or_last_visited(
            lane_key,
            bounds.target_blue_score,
            bounds.min_blue_score,
            &mut is_canonical,
        ) {
            ControlFlow::Break((score, block_hash, value)) => return Some(Verified::new(value, score, block_hash)),
            ControlFlow::Continue(lv) => lv,
        };
        let (start_score, start_bh) = resume_db_seek(last_visited, bounds)?;
        self.lane_version.get_at_canonical_from(lane_key, start_score, start_bh, bounds.min_blue_score, is_canonical).unwrap()
    }

    /// Read the lanes root hash from the branch store at depth=0.
    /// Returns the empty root if no root node exists.
    pub fn get_lanes_root(&self, bounds: SmtReadBounds, is_canonical: impl FnMut(Hash) -> bool) -> Hash {
        let root_entity = BranchEntity { depth: 0, node_key: Hash::from_bytes([0; 32]) };
        match self.get_node(root_entity, bounds, is_canonical) {
            Some(v) => match *v.data() {
                Some(Node::Internal(hash)) => hash,
                Some(Node::Collapsed(cl)) => {
                    kaspa_smt::hash_node::<kaspa_hashes::SeqCommitActiveCollapsedNode>(cl.lane_key, cl.leaf_hash)
                }
                None => kaspa_hashes::SeqCommitActiveNode::empty_root(),
            },
            None => kaspa_hashes::SeqCommitActiveNode::empty_root(),
        }
    }

    /// Generate an inclusion proof for `lane_key` in the canonical tree as of
    /// `target_blue_score`.
    pub fn prove_lane(
        &self,
        lane_key: &Hash,
        bounds: SmtReadBounds,
        is_canonical: impl Fn(Hash) -> bool,
    ) -> StoreResult<OwnedSmtProof> {
        let reader = VersionedBranchReader { stores: self, bounds, is_canonical };
        // Root value is unused by `prove` — it walks the store directly.
        let tree = SparseMerkleTree::<SeqCommitActiveNode, _>::with_store(reader);
        tree.prove(lane_key)
    }

    pub fn evict_caches_below_score(&self, min_score: u64) {
        self.branch_cache.lock().evict_below_score(min_score);
        self.lane_cache.lock().evict_below_score(min_score);
    }

    /// Prune all lane-version, branch-version, and score-index entries whose
    /// blue_score is at or below `cutoff_blue_score`.
    ///
    /// The score index is the discovery mechanism: it records which lane_keys
    /// were touched at each `(blue_score, block_hash)` pair (both `LeafUpdate`
    /// and `Structural` kinds). Since the score index already provides the full
    /// `(lane_key, blue_score, block_hash)` triple, we construct delete keys
    /// directly — no reads from lane_version or branch_version are needed.
    ///
    /// Work is batched into chunks of score-index entries to bound
    /// `WriteBatch` memory. After all chunks, the score index itself is
    /// range-deleted and caches are evicted.
    pub fn prune(&self, db: &DB, cutoff_blue_score: u64) {
        // Number of score-index entries to accumulate before flushing a WriteBatch.
        const CHUNK_ENTRIES: usize = 1024;

        let mut entries: Vec<PruneEntry> = Vec::new();
        let mut entries_in_chunk = 0usize;
        let mut total_lane_deletes = 0u64;
        let mut total_branch_deletes = 0u64;
        let mut chunks_written = 0u64;

        // Iterate both LeafUpdate and Structural entries at scores ≤ cutoff
        for entry in self.score_index.get_all(0..=cutoff_blue_score) {
            let entry = entry.unwrap();
            let blue_score = entry.blue_score();
            let block_hash = entry.block_hash();
            for lk in entry.data().iter() {
                entries.push(PruneEntry { lane_key: *lk, blue_score, block_hash });
            }
            entries_in_chunk += 1;

            if entries_in_chunk >= CHUNK_ENTRIES {
                let (ld, bd) = self.prune_chunk(db, &entries);
                total_lane_deletes += ld;
                total_branch_deletes += bd;
                chunks_written += 1;
                entries.clear();
                entries_in_chunk = 0;
            }
        }

        // Flush remaining entries
        if !entries.is_empty() {
            let (ld, bd) = self.prune_chunk(db, &entries);
            total_lane_deletes += ld;
            total_branch_deletes += bd;
            chunks_written += 1;
        }

        // Range-delete score-index entries at scores ≤ cutoff (single tombstone)
        self.score_index.delete_range(DirectDbWriter::new(db), cutoff_blue_score).unwrap();
        self.evict_caches_below_score(cutoff_blue_score);

        log::info!(
            "SMT pruning complete: {} chunks, {} lane version deletes, {} branch version deletes (cutoff={})",
            chunks_written,
            total_lane_deletes,
            total_branch_deletes,
            cutoff_blue_score
        );
    }

    /// Delete lane-version and branch-version entries directly from known keys,
    /// writing all deletes into a single `WriteBatch`. No DB reads required —
    /// keys are constructed from the score-index data.
    fn prune_chunk(&self, db: &DB, entries: &[PruneEntry]) -> (u64, u64) {
        let mut batch = WriteBatch::default();

        // Delete lane-version entries directly
        let lane_deletes = entries.len() as u64;
        for e in entries {
            self.lane_version.delete(BatchDbWriter::new(&mut batch), e.lane_key, e.blue_score, e.block_hash).unwrap();
        }

        // Derive branch keys at all 256 depths from each entry. BTreeSet
        // deduplicates: at low depths many lane_keys map to the same node_key
        // (e.g. depth 0 always maps to ZERO_HASH).
        let mut branch_keys: BTreeSet<(BranchKey, u64, Hash)> = BTreeSet::new();
        for e in entries {
            for depth in 0..=255u8 {
                branch_keys.insert((BranchKey::new(depth, &e.lane_key), e.blue_score, e.block_hash));
            }
        }

        let branch_deletes = branch_keys.len() as u64;
        for (bk, blue_score, block_hash) in &branch_keys {
            self.branch_version.delete(BatchDbWriter::new(&mut batch), bk.depth, bk.node_key, *blue_score, *block_hash).unwrap();
        }

        db.write(batch).unwrap();
        (lane_deletes, branch_deletes)
    }

    /// Clear all versioned SMT stores and caches. Used before IBD SMT sync
    /// to ensure that the caches are cold and the DB is empty, preserving
    /// the authoritative-read invariants when incremental processing resumes.
    pub fn clear_all(&self) {
        self.branch_version.delete_all();
        self.lane_version.delete_all();
        self.score_index.delete_all();
        self.branch_cache.lock().clear();
        self.lane_cache.lock().clear();
    }
}

/// Abstraction over lane change collections.
///
/// Lane changes within a single block. All lanes share the block's blue_score.
pub struct BlockLaneChanges {
    blue_score: u64,
    changes: BTreeMap<LaneKey, Option<LaneTipHash>>,
}

impl BlockLaneChanges {
    pub fn new(blue_score: u64) -> Self {
        Self { blue_score, changes: BTreeMap::new() }
    }

    pub fn expire(&mut self, lane_key: LaneKey) {
        self.changes.insert(lane_key, None);
    }

    pub fn update(&mut self, lane_key: LaneKey, lane_tip_hash: Hash) {
        self.changes.insert(lane_key, Some(lane_tip_hash));
    }

    pub fn to_leaf_updates(&self) -> SortedLeafUpdates {
        let bs = self.blue_score;
        SortedLeafUpdates::from_sorted_map(&self.changes, |key, change| match change {
            Some(tip) => smt_leaf_hash(&SmtLeafInput { lane_key: key, lane_tip: tip, blue_score: bs }),
            None => ZERO_HASH,
        })
    }

    pub fn flush_lanes(&self, stores: &SmtStores, batch: &mut WriteBatch, block_hash: BlockHash) -> StoreResult<()> {
        for (lane_key, tip) in &self.changes {
            if let Some(tip) = tip {
                stores.lane_version.put(BatchDbWriter::new(batch), *lane_key, self.blue_score, block_hash, tip)?;
            }
        }
        let mut lc = stores.lane_cache.lock();
        for (lane_key, tip) in &self.changes {
            if let Some(tip) = tip {
                lc.insert(*lane_key, self.blue_score, block_hash, *tip);
            }
        }
        Ok(())
    }

    pub fn flush_score_index(&self, stores: &SmtStores, batch: &mut WriteBatch, block_hash: BlockHash) -> StoreResult<()> {
        use crate::keys::ScoreIndexKind;
        let updated: Vec<LaneKey> = self.changes.iter().filter_map(|(k, v)| v.as_ref().map(|_| *k)).collect();
        let expired: Vec<LaneKey> = self.changes.iter().filter_map(|(k, v)| if v.is_none() { Some(*k) } else { None }).collect();
        if !updated.is_empty() {
            stores.score_index.put(BatchDbWriter::new(batch), self.blue_score, ScoreIndexKind::LeafUpdate, block_hash, &updated)?;
        }
        if !expired.is_empty() {
            stores.score_index.put(BatchDbWriter::new(batch), self.blue_score, ScoreIndexKind::Structural, block_hash, &expired)?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.changes.len()
    }
}

/// Accumulates SMT lane changes and builds the tree.
pub struct SmtProcessor<'a> {
    stores: &'a SmtStores,
    bounds: SmtReadBounds,
    current_lanes_root: Hash,
    lane_changes: BlockLaneChanges,
}

impl<'a> SmtProcessor<'a> {
    pub fn new(stores: &'a SmtStores, write_blue_score: u64, bounds: SmtReadBounds, current_lanes_root: Hash) -> Self {
        Self { stores, bounds, current_lanes_root, lane_changes: BlockLaneChanges::new(write_blue_score) }
    }

    pub fn update_lane(&mut self, lane_key: LaneKey, lane_tip_hash: Hash) {
        self.lane_changes.update(lane_key, lane_tip_hash);
    }

    pub fn expire_lane(&mut self, lane_key: LaneKey) {
        self.lane_changes.expire(lane_key);
    }

    pub fn build(self, is_canonical: impl Fn(Hash) -> bool) -> StoreResult<SmtBuild> {
        if self.lane_changes.is_empty() {
            return Ok(SmtBuild {
                root: self.current_lanes_root,
                node_changes: SmtNodeChanges::new(),
                lane_changes: self.lane_changes,
                payload_and_ctx_digest: ZERO_HASH,
                active_lanes_count: 0,
            });
        }

        let leaf_updates = self.lane_changes.to_leaf_updates();
        let reader = VersionedBranchReader { stores: self.stores, bounds: self.bounds, is_canonical };
        let (root, node_changes) = compute_root_update::<SeqCommitActiveNode, _>(&reader, self.current_lanes_root, leaf_updates)?;
        Ok(SmtBuild { root, node_changes, lane_changes: self.lane_changes, payload_and_ctx_digest: ZERO_HASH, active_lanes_count: 0 })
    }
}

/// Result of building an SMT: root hash + changed nodes + lane changes + metadata.
pub struct SmtBuild {
    pub root: Hash,
    node_changes: SmtNodeChanges,
    lane_changes: BlockLaneChanges,
    /// Set by `build_seq_commit` after computing the seq_commit components.
    pub payload_and_ctx_digest: Hash,
    pub active_lanes_count: u64,
}

impl SmtBuild {
    pub fn lane_update_count(&self) -> usize {
        self.lane_changes.len()
    }

    pub fn diff_branch_count(&self) -> usize {
        self.node_changes.len()
    }

    /// Persist the build's node/lane/score-index diff to a `WriteBatch` and populate caches.
    ///
    /// `branch_blue_score` versions the nodes and is the same blue_score used
    /// for lane/score-index writes inside `BlockLaneChanges`.
    /// Metadata is written separately by the caller via `DbSmtMetadataStore`.
    pub fn flush(
        self,
        stores: &SmtStores,
        batch: &mut WriteBatch,
        branch_blue_score: u64,
        block_hash: BlockHash,
    ) -> StoreResult<Hash> {
        let root = self.root;

        for (bk, node) in &self.node_changes {
            stores.branch_version.put(BatchDbWriter::new(batch), bk.depth, bk.node_key, branch_blue_score, block_hash, *node)?;
        }
        {
            let mut bc = stores.branch_cache.lock();
            for (bk, node) in &self.node_changes {
                bc.insert(BranchEntity { depth: bk.depth, node_key: bk.node_key }, branch_blue_score, block_hash, *node);
            }
        }

        self.lane_changes.flush_lanes(stores, batch, block_hash)?;
        self.lane_changes.flush_score_index(stores, batch, block_hash)?;

        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, DirectDbWriter};

    fn hash(v: u8) -> Hash {
        Hash::from_bytes([v; 32])
    }

    fn make_stores() -> (kaspa_database::utils::DbLifetime, Arc<DB>, SmtStores) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let stores = SmtStores::new(db.clone(), 16, 16);
        (lifetime, db, stores)
    }

    fn bounds(target: u64, min: u64) -> SmtReadBounds {
        SmtReadBounds::new(target, min)
    }

    fn internal(h: Hash) -> Option<Node> {
        Some(Node::Internal(h))
    }

    fn entity() -> BranchEntity {
        BranchEntity { depth: 7, node_key: hash(0xEE) }
    }

    // -------- get_node --------

    /// Cache hit is authoritative — the cache value is returned even when the
    /// DB has a different, older entry for the same entity. Verifies the
    /// fast-path short-circuits without falling back to DB.
    #[test]
    fn get_node_cache_hit_short_circuits() {
        let (_lt, db, stores) = make_stores();
        let e = entity();
        let cache_bh = hash(0xAA);
        let cache_node = internal(hash(0xCC));
        let db_bh = hash(0xBB);
        let db_node = internal(hash(0xDD));

        // Cache entry at score 100. A different DB-only entry at score 50 must
        // not be returned when the cache already has a canonical match.
        stores.branch_cache.lock().insert(e, 100, cache_bh, cache_node);
        stores.branch_version.put(DirectDbWriter::new(&db), e.depth, e.node_key, 50, db_bh, db_node).unwrap();

        let got = stores.get_node(e, bounds(200, 0), |_| true).unwrap();
        assert_eq!(got.blue_score(), 100);
        assert_eq!(got.block_hash(), cache_bh);
        assert_eq!(*got.data(), cache_node);
    }

    /// Correctness-critical: cache holds a non-canonical same-score sibling,
    /// DB holds the canonical same-score sibling that was evicted from cache.
    /// The optimization resumes DB iteration strictly after the cache's
    /// last-visited `(score, bh)` and must still find the canonical entry.
    #[test]
    fn get_node_cache_miss_continues_db_at_same_score() {
        let (_lt, db, stores) = make_stores();
        let e = entity();
        let non_canonical = hash(0x10);
        let canonical = hash(0x80);

        // Non-canonical at (100, 0x10) in cache only.
        stores.branch_cache.lock().insert(e, 100, non_canonical, internal(hash(0xAA)));
        // Canonical at (100, 0x80) in DB only.
        stores.branch_version.put(DirectDbWriter::new(&db), e.depth, e.node_key, 100, canonical, internal(hash(0xCC))).unwrap();

        let got = stores.get_node(e, bounds(200, 0), |bh| bh == canonical).unwrap();
        assert_eq!(got.blue_score(), 100);
        assert_eq!(got.block_hash(), canonical);
        assert_eq!(*got.data(), internal(hash(0xCC)));
    }

    /// Cache exhausts without a canonical match at score 100; DB continuation
    /// drops to the next lower score and finds the canonical entry there.
    #[test]
    fn get_node_cache_miss_continues_db_at_lower_score() {
        let (_lt, db, stores) = make_stores();
        let e = entity();
        let non_canonical = hash(0x10);
        let canonical = hash(0x55);

        stores.branch_cache.lock().insert(e, 100, non_canonical, internal(hash(0xAA)));
        stores.branch_version.put(DirectDbWriter::new(&db), e.depth, e.node_key, 50, canonical, internal(hash(0xDD))).unwrap();

        let got = stores.get_node(e, bounds(200, 0), |bh| bh == canonical).unwrap();
        assert_eq!(got.blue_score(), 50);
        assert_eq!(got.block_hash(), canonical);
    }

    /// Empty cache → DB-only lookup, same behaviour as before the
    /// optimization (seeks from `target_blue_score` at `[0; 32]`).
    #[test]
    fn get_node_empty_cache_falls_back_to_db() {
        let (_lt, db, stores) = make_stores();
        let e = entity();
        let canonical = hash(0x55);

        stores.branch_version.put(DirectDbWriter::new(&db), e.depth, e.node_key, 100, canonical, internal(hash(0xDD))).unwrap();

        let got = stores.get_node(e, bounds(200, 0), |bh| bh == canonical).unwrap();
        assert_eq!(got.blue_score(), 100);
        assert_eq!(got.block_hash(), canonical);
    }

    #[test]
    fn get_node_all_non_canonical_returns_none() {
        let (_lt, db, stores) = make_stores();
        let e = entity();

        stores.branch_cache.lock().insert(e, 100, hash(0x10), internal(hash(0xAA)));
        stores.branch_version.put(DirectDbWriter::new(&db), e.depth, e.node_key, 50, hash(0x20), internal(hash(0xBB))).unwrap();

        assert!(stores.get_node(e, bounds(200, 0), |_| false).is_none());
    }

    // -------- get_lane (same scenarios) --------

    fn lk() -> LaneKey {
        hash(0xEE)
    }

    #[test]
    fn get_lane_cache_hit_short_circuits() {
        let (_lt, db, stores) = make_stores();
        let cache_bh = hash(0xAA);
        let cache_tip = hash(0xCC);
        let db_bh = hash(0xBB);
        let db_tip = hash(0xDD);

        stores.lane_cache.lock().insert(lk(), 100, cache_bh, cache_tip);
        stores.lane_version.put(DirectDbWriter::new(&db), lk(), 50, db_bh, &db_tip).unwrap();

        let got = stores.get_lane(lk(), bounds(200, 0), |_| true).unwrap();
        assert_eq!(got.blue_score(), 100);
        assert_eq!(got.block_hash(), cache_bh);
        assert_eq!(*got.data(), cache_tip);
    }

    #[test]
    fn get_lane_cache_miss_continues_db_at_same_score() {
        let (_lt, db, stores) = make_stores();
        let non_canonical = hash(0x10);
        let canonical = hash(0x80);

        stores.lane_cache.lock().insert(lk(), 100, non_canonical, hash(0xAA));
        stores.lane_version.put(DirectDbWriter::new(&db), lk(), 100, canonical, &hash(0xCC)).unwrap();

        let got = stores.get_lane(lk(), bounds(200, 0), |bh| bh == canonical).unwrap();
        assert_eq!(got.blue_score(), 100);
        assert_eq!(got.block_hash(), canonical);
        assert_eq!(*got.data(), hash(0xCC));
    }

    #[test]
    fn get_lane_cache_miss_continues_db_at_lower_score() {
        let (_lt, db, stores) = make_stores();
        let non_canonical = hash(0x10);
        let canonical = hash(0x55);

        stores.lane_cache.lock().insert(lk(), 100, non_canonical, hash(0xAA));
        stores.lane_version.put(DirectDbWriter::new(&db), lk(), 50, canonical, &hash(0xDD)).unwrap();

        let got = stores.get_lane(lk(), bounds(200, 0), |bh| bh == canonical).unwrap();
        assert_eq!(got.blue_score(), 50);
        assert_eq!(got.block_hash(), canonical);
    }

    #[test]
    fn get_lane_empty_cache_falls_back_to_db() {
        let (_lt, db, stores) = make_stores();
        let canonical = hash(0x55);

        stores.lane_version.put(DirectDbWriter::new(&db), lk(), 100, canonical, &hash(0xDD)).unwrap();

        let got = stores.get_lane(lk(), bounds(200, 0), |bh| bh == canonical).unwrap();
        assert_eq!(got.blue_score(), 100);
        assert_eq!(got.block_hash(), canonical);
    }

    #[test]
    fn get_lane_all_non_canonical_returns_none() {
        let (_lt, db, stores) = make_stores();

        stores.lane_cache.lock().insert(lk(), 100, hash(0x10), hash(0xAA));
        stores.lane_version.put(DirectDbWriter::new(&db), lk(), 50, hash(0x20), &hash(0xBB)).unwrap();

        assert!(stores.get_lane(lk(), bounds(200, 0), |_| false).is_none());
    }

    // -------- next_dbentry_after / resume_db_seek --------

    #[test]
    fn next_dbentry_after_same_score_increments_bh() {
        let (score, bh) = next_dbentry_after(100, Hash::from_bytes([0x10; 32])).unwrap();
        assert_eq!(score, 100);
        let mut expected = [0x10u8; 32];
        expected[31] = 0x11;
        assert_eq!(bh, Hash::from_bytes(expected));
    }

    #[test]
    fn next_dbentry_after_bh_overflow_drops_score() {
        let (score, bh) = next_dbentry_after(100, Hash::from_bytes([0xFF; 32])).unwrap();
        assert_eq!(score, 99);
        assert_eq!(bh, Hash::from_bytes([0; 32]));
    }

    #[test]
    fn next_dbentry_after_score_underflow_returns_none() {
        // bh overflow AND score == 0 → nothing left to scan.
        assert!(next_dbentry_after(0, Hash::from_bytes([0xFF; 32])).is_none());
    }

    #[test]
    fn resume_db_seek_empty_cache_starts_fresh() {
        let b = bounds(200, 0);
        let (score, bh) = resume_db_seek(None, b).unwrap();
        assert_eq!(score, 200);
        assert_eq!(bh, Hash::from_bytes([0; 32]));
    }

    #[test]
    fn resume_db_seek_respects_min_blue_score() {
        // last_visited at (10, [0xFF; 32]) overflows to (9, [0; 32]); but
        // min=50 pushes that below the window, so no more scanning.
        let b = bounds(100, 50);
        assert!(resume_db_seek(Some((10, Hash::from_bytes([0xFF; 32]))), b).is_none());
    }
}

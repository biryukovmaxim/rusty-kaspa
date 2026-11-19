//! Memory representation of the UMC tree: a bounded cache shared by the facade
//! (as its cache level) and an exact unbounded store for tests and ephemeral use.
//!
//! The cache is keyed by the exact storage keys ([`NodeKey`]/[`VersionKey`]), so
//! memory ordering equals DB ordering and the same seek constants serve both levels.

use std::collections::BTreeMap;

use kaspa_consensus_core::KType;
use kaspa_database::prelude::StoreResult;
use kaspa_database::registry::DatabaseStorePrefixes;

use super::api::{PublishedVersion, UmcTreeStore, UmcTreeStoreReader};
use super::builder::TreeBuilder;
use super::keys::{NodeKey, VersionKey};
use super::records::{NodeCoord, NodeRecord, NodeRef, Score, VersionMetadata, VersionedNode};

/// Extracts the ordering version from a cache key.
pub(crate) trait HasVersion {
    /// Logical version driving eviction order.
    fn version(&self) -> u64;
}

impl HasVersion for NodeKey {
    fn version(&self) -> u64 {
        NodeKey::version(self)
    }
}

impl HasVersion for VersionKey {
    fn version(&self) -> u64 {
        VersionKey::version(self)
    }
}

/// BTreeMap keyed by the exact storage key (DB-shaped ordering) plus a
/// version-ordered eviction index. Capacity is an entry count.
///
/// Eviction removes the globally lowest version first; ties break by key bytes
/// ascending. An insert at capacity whose eviction-order key does not sort
/// strictly above the current minimum is not admitted (admission guard).
pub(crate) struct BoundedCache<K: Ord + Copy + HasVersion + AsRef<[u8]>, V> {
    /// Retained entries in storage-key order.
    entries: BTreeMap<K, V>,
    /// Eviction order: `(version, key)` ascending; the first entry evicts first.
    evict_order: BTreeMap<(u64, K), ()>,
    /// Maximum number of retained entries.
    capacity: usize,
}

impl<K: Ord + Copy + HasVersion + AsRef<[u8]>, V> BoundedCache<K, V> {
    /// Cache holding at most `capacity` entries; asserts `capacity > 0`.
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self { entries: BTreeMap::new(), evict_order: BTreeMap::new(), capacity }
    }

    /// Number of retained entries.
    pub(crate) fn len(&self) -> usize {
        debug_assert_eq!(self.entries.len(), self.evict_order.len(), "both indexes must agree");
        self.entries.len()
    }

    /// Entry at the exact `key`, or `None` on a miss.
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Insert with the admission guard and capacity eviction.
    ///
    /// At capacity, an entry whose eviction-order key `(version, key)` does not
    /// sort strictly above the current minimum is not admitted: it would itself
    /// be the next eviction candidate, and admitting it could leave an older
    /// version cached while a newer version of the same coordinate lives only
    /// in the DB. Otherwise the minimum entry is evicted to make room.
    /// Re-inserting an already-present key is a caller bug (asserted in debug
    /// builds); every write path inserts each exact key at most once.
    pub(crate) fn insert(&mut self, key: K, value: V) {
        debug_assert!(!self.entries.contains_key(&key), "duplicate cache key insert");
        let order = (key.version(), key);
        if self.len() >= self.capacity {
            let Some(first) = self.evict_order.first_entry() else {
                return;
            };
            if order <= *first.key() {
                // Do not admit an entry that would be the next eviction candidate.
                return;
            }
            let ((_, evicted), ()) = first.remove_entry();
            self.entries.remove(&evicted);
        }
        self.entries.insert(key, value);
        self.evict_order.insert(order, ());
    }

    /// First entry at or after `seek` whose key matches `prefix_len` bytes of
    /// `seek`; `None` when no such entry exists. This is the newest-first range
    /// probe both levels use for `latest_*` queries.
    pub(crate) fn latest_matching(&self, seek: &K, prefix_len: usize) -> Option<(&K, &V)> {
        self.entries.range(seek..).next().filter(|(k, _)| k.as_ref().get(..prefix_len) == seek.as_ref().get(..prefix_len))
    }

    /// Drop all entries with version < floor; returns the count evicted.
    // TODO(dk): DB-level reclamation (GC) will drive this hook once a retention policy lands
    #[allow(dead_code)]
    pub(crate) fn evict_below_version(&mut self, floor: u64) -> usize {
        let mut count = 0;
        while let Some((&(version, key), ())) = self.evict_order.first_key_value() {
            if version >= floor {
                break;
            }
            self.evict_order.remove(&(version, key));
            self.entries.remove(&key);
            count += 1;
        }
        count
    }
}

/// Exact unbounded in-memory store: the node and version maps are [`BoundedCache`]
/// instances with unlimited capacity, keyed exactly as the DB level keys them.
///
/// Reads never fail and nothing is ever evicted; the store suits tests and
/// ephemeral use. `begin` panics on an unknown anchor version (the builder
/// expects anchor metadata to exist), while the trait methods return
/// `Option`/`StoreResult`.
pub struct MemoryUmcTreeStore<T, S> {
    /// Version-id allocator image; ids are handed out monotonically and never reused.
    next_version_id: u64,
    /// Published node records keyed exactly as the DB level keys them.
    nodes: BoundedCache<NodeKey, NodeRecord<T, S>>,
    /// Published version metadata keyed exactly as the DB level keys it.
    versions: BoundedCache<VersionKey, VersionMetadata>,
}

impl<T, S> Default for MemoryUmcTreeStore<T, S> {
    fn default() -> Self {
        Self { next_version_id: 0, nodes: BoundedCache::new(usize::MAX), versions: BoundedCache::new(usize::MAX) }
    }
}

impl<T: Clone, S: Score> MemoryUmcTreeStore<T, S> {
    /// Empty store with the version counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a working tree in partition `k` from scratch, or extending the
    /// published `anchor_version` state; panics on an unknown anchor version.
    pub fn begin(&mut self, k: KType, anchor_version: Option<u64>) -> TreeBuilder<'_, T, S, Self> {
        TreeBuilder::begin(self, k, anchor_version)
    }
}

impl<T: Clone, S: Score> UmcTreeStoreReader<T, S> for MemoryUmcTreeStore<T, S> {
    fn get_node(&self, k: KType, node: NodeRef) -> StoreResult<Option<NodeRecord<T, S>>> {
        let key = NodeKey::new(DatabaseStorePrefixes::DagKnightUmcNodes.into(), k, node.h, node.j, node.version);
        Ok(self.nodes.get(&key).cloned())
    }

    fn latest_node(&self, k: KType, coord: NodeCoord) -> StoreResult<Option<VersionedNode<T, S>>> {
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let seek = NodeKey::seek_latest(prefix, k, coord.h, coord.j);
        Ok(self
            .nodes
            .latest_matching(&seek, NodeKey::COORDINATE_PREFIX_LEN)
            .map(|(key, record)| VersionedNode { version: key.version(), record: record.clone() }))
    }

    fn metadata(&self, k: KType, version: u64) -> StoreResult<Option<VersionMetadata>> {
        let key = VersionKey::new(DatabaseStorePrefixes::DagKnightUmcVersions.into(), k, version);
        Ok(self.versions.get(&key).cloned())
    }

    fn latest_version(&self, k: KType) -> StoreResult<Option<u64>> {
        let seek = VersionKey::seek_latest(DatabaseStorePrefixes::DagKnightUmcVersions.into(), k);
        Ok(self.versions.latest_matching(&seek, VersionKey::K_PREFIX_LEN).map(|(key, _)| key.version()))
    }
}

impl<T: Clone, S: Score> UmcTreeStore<T, S> for MemoryUmcTreeStore<T, S> {
    fn allocate_version(&mut self) -> StoreResult<u64> {
        let version = self.next_version_id;
        self.next_version_id += 1;
        Ok(version)
    }

    fn publish(&mut self, k: KType, publish: PublishedVersion<T, S>) -> StoreResult<()> {
        let node_prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        for (coord, record) in publish.records.iter() {
            self.nodes.insert(NodeKey::new(node_prefix, k, coord.h, coord.j, publish.version), record.clone());
        }
        self.versions
            .insert(VersionKey::new(DatabaseStorePrefixes::DagKnightUmcVersions.into(), k, publish.version), publish.metadata);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Versions of one coordinate, newest first, by repeated newest-first probes.
    fn coordinate_versions(cache: &BoundedCache<NodeKey, u64>, prefix: u8, k: u16, h: u16, j: u64) -> Vec<u64> {
        let mut seek = NodeKey::seek_latest(prefix, k, h, j);
        let mut out = Vec::new();
        while let Some((key, _)) = cache.latest_matching(&seek, NodeKey::COORDINATE_PREFIX_LEN) {
            let version = key.version();
            out.push(version);
            if version == 0 {
                break;
            }
            seek = NodeKey::new(prefix, k, h, j, version - 1);
        }
        out
    }

    /// Capacity eviction removes the globally lowest version first, keeps the
    /// coordinate's newest suffix, and never crosses the k partition.
    #[test]
    fn capacity_evicts_oldest_version_first() {
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let mut cache = BoundedCache::<NodeKey, u64>::new(3);
        for version in 0..3u64 {
            cache.insert(NodeKey::new(prefix, 0, 0, 0, version), version);
        }
        assert_eq!(cache.len(), 3);
        // Version 3 evicts version 0 (globally coldest).
        cache.insert(NodeKey::new(prefix, 0, 0, 0, 3), 3);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(&NodeKey::new(prefix, 0, 0, 0, 0)), None);
        // A k=1 coordinate evicts version 1 (next coldest), not the k=0 newest.
        cache.insert(NodeKey::new(prefix, 1, 0, 0, 4), 4);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(&NodeKey::new(prefix, 0, 0, 0, 1)), None);
        assert_eq!(coordinate_versions(&cache, prefix, 0, 0, 0), vec![3, 2]);
        assert_eq!(coordinate_versions(&cache, prefix, 1, 0, 0), vec![4]);
    }

    /// Newest-suffix (up-set) invariant under cross-k capacity pressure: for every
    /// coordinate, the retained versions are the newest suffix of that coordinate's
    /// publish history.
    #[test]
    fn newest_suffix_upset_under_cross_k_pressure() {
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let capacity = 6;
        let mut cache = BoundedCache::<NodeKey, u64>::new(capacity);
        // Interleaved publishes across ks and coordinates with globally ascending versions.
        let writes: &[(u16, u16, u64, u64)] = &[
            (0, 0, 0, 0),
            (1, 0, 0, 1),
            (0, 0, 1, 2),
            (2, 1, 5, 3),
            (1, 0, 1, 4),
            (0, 2, 0, 5),
            (2, 1, 5, 6),
            (0, 0, 0, 7),
            (1, 3, 2, 8),
            (2, 1, 6, 9),
        ];
        let mut histories: std::collections::BTreeMap<(u16, u16, u64), Vec<u64>> = std::collections::BTreeMap::new();
        for &(k, h, j, version) in writes {
            cache.insert(NodeKey::new(prefix, k, h, j, version), version);
            histories.entry((k, h, j)).or_default().push(version);
        }
        assert_eq!(cache.len(), capacity, "cache must be at capacity after more writes than capacity");
        for (&(k, h, j), history) in &histories {
            let retained = coordinate_versions(&cache, prefix, k, h, j);
            let expected: Vec<u64> = history.iter().rev().take(retained.len()).copied().collect();
            assert_eq!(
                retained, expected,
                "coordinate (k {k}, h {h}, j {j}): retained {retained:?} is not the newest suffix of history {history:?}"
            );
        }
    }

    /// An insert at capacity whose version is below the current global minimum
    /// is not admitted: it would be the next eviction candidate.
    #[test]
    fn insert_below_global_min_not_admitted() {
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let mut cache = BoundedCache::<NodeKey, u64>::new(2);
        cache.insert(NodeKey::new(prefix, 0, 0, 0, 5), 5);
        cache.insert(NodeKey::new(prefix, 0, 0, 0, 7), 7);
        cache.insert(NodeKey::new(prefix, 0, 0, 0, 3), 3);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&NodeKey::new(prefix, 0, 0, 0, 3)), None, "below-minimum insert must be rejected");
        assert_eq!(coordinate_versions(&cache, prefix, 0, 0, 0), vec![7, 5]);
    }

    /// evict_below_version removes exactly the entries strictly below the floor
    /// and reports their count.
    #[test]
    fn evict_below_version_returns_count() {
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let mut cache = BoundedCache::<NodeKey, u64>::new(100);
        for version in 1..=5u64 {
            cache.insert(NodeKey::new(prefix, version as u16, 0, version, version), version);
        }
        assert_eq!(cache.evict_below_version(3), 2);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.evict_below_version(u64::MAX), 3);
        assert_eq!(cache.len(), 0);
    }

    /// A capacity-1 cache repeatedly fed newer versions of one coordinate
    /// always answers `latest_matching` with the newest: each admission evicts
    /// the older version of the same coordinate, never the reverse.
    #[test]
    fn capacity_one_same_coordinate_always_newest() {
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let mut cache = BoundedCache::<NodeKey, u64>::new(1);
        for version in 0..6u64 {
            cache.insert(NodeKey::new(prefix, 0, 2, 1, version), version);
            let seek = NodeKey::seek_latest(prefix, 0, 2, 1);
            let (key, value) = cache.latest_matching(&seek, NodeKey::COORDINATE_PREFIX_LEN).unwrap();
            assert_eq!(key.version(), version);
            assert_eq!(*value, version);
            assert_eq!(cache.len(), 1);
        }
    }
}

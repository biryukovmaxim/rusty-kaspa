//! Versioned UMC segment tree storage: an ordinary binary min-tree with lazy
//! range additions, published as immutable k-partitioned records across three
//! storage levels.
//!
//! Nodes are identified by level `h` and position `j`; a node covers the leaf
//! range `[j << h, (j+1) << h)`. Records are immutable once published and live
//! in byte-keyed stores: keys are fixed-width big-endian zerocopy structs
//! partitioned by k, so bytewise order equals numeric order and a forward scan
//! at one coordinate yields its records newest first (versions are stored
//! reversed, `u64::MAX - version`).
//!
//! The levels:
//!
//! * memory ([`MemoryUmcTreeStore`]): exact and unbounded, for tests and ephemeral use;
//! * database ([`DbUmcTreeStore`]): rocksdb via the kaspa-database Stores API, fixed-layout zerocopy wire values;
//! * facade ([`UmcTreeStores`]): bounded caches with transparent DB fallback,
//!   the production singleton across all k. Its module doc carries the
//!   normative newest-suffix invariant that makes cache hits authoritative.
//!
//! [`TreeBuilder`] holds the tree algorithm (add/push/pull, range additions,
//! hole correction, leaf scans, root growth, publication) and is generic over
//! the store trait. Generic over the leaf value `T` and the score arithmetic
//! `S`; the Dagknight UMC instantiates `T = Hash` and `S = SignedWork`.

mod api;
mod builder;
mod db;
mod keys;
mod mem;
mod records;
mod stores;

pub use api::{PublishedVersion, UmcTreeStore, UmcTreeStoreReader};
pub use builder::{AncestryProbe, Arrival, TreeBuilder};
pub use db::DbUmcTreeStore;
pub use keys::{NodeKey, RevVersion, VersionKey};
pub use mem::MemoryUmcTreeStore;
pub use records::{
    LeafScore, NodeCoord, NodeRecord, NodeRef, Score, ScoreWire, SignedWorkWire, ValueWire, VersionMetadata, VersionedNode,
    collect_scores,
};
pub use stores::{Capacities, UmcTreeStores};

/// Test helpers for anchored states: the zone and block an anchor key names, the
/// key built from them, and a one-leaf state published and registered under it.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;

    use kaspa_consensus_core::KType;
    use kaspa_database::prelude::StoreResult;
    use kaspa_hashes::Hash;

    use super::{NodeCoord, NodeRecord, PublishedVersion, UmcTreeStore, VersionMetadata};
    use crate::model::stores::conflict_zone_coloring::ConflictZoneColoringKey;

    /// The zone and the block an anchor key names, as `u64` words.
    pub(crate) struct AnchorInput {
        /// Word the zone's root hash is built from.
        pub(crate) root: u64,
        /// Word the point-of-view block hash is built from.
        pub(crate) pov: u64,
        /// Partition of the zone.
        pub(crate) k: KType,
    }

    /// Committed anchor key of block `pov` in the zone rooted at `root` at `k`.
    pub(crate) fn anchor_key(input: AnchorInput) -> ConflictZoneColoringKey {
        ConflictZoneColoringKey::new(Hash::from_u64_word(input.root), Hash::from_u64_word(input.pov), input.k, false)
    }

    /// Publish, from scratch in partition `k`, the one-leaf state a builder
    /// writes for a tree's first leaf (of value `0`), registered under `anchor`;
    /// returns its version.
    pub(crate) fn register<St: UmcTreeStore<u64, i64>>(store: &mut St, k: KType, anchor: ConflictZoneColoringKey) -> StoreResult<u64> {
        let version = store.allocate_version()?;
        let publish = PublishedVersion {
            version,
            metadata: VersionMetadata { anchor_version: None, root_version: Some(version), root_height: 0, blue_count: 1 },
            records: HashMap::from([(NodeCoord { h: 0, j: 0 }, NodeRecord::Leaf { minimum: 0, value: 0 })]),
            anchor: Some(anchor),
        };
        store.publish(k, publish)?;
        Ok(version)
    }
}

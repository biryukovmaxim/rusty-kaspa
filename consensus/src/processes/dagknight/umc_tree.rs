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
pub use builder::TreeBuilder;
pub use db::DbUmcTreeStore;
pub use keys::{NodeKey, RevVersion, VersionKey};
pub use mem::MemoryUmcTreeStore;
pub use records::{
    LeafScore, NodeCoord, NodeRecord, NodeRef, Score, ScoreWire, SignedWorkWire, ValueWire, VersionMetadata, VersionedNode,
    collect_scores,
};
pub use stores::UmcTreeStores;

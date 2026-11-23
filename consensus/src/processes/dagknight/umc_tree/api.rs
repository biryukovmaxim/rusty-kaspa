//! The general UMC tree storage interface: working buffer, published versions
//! and the reader/store traits satisfied by the memory, database and facade
//! levels. Every query names its k partition directly.
//!
//! Static dispatch only (no `dyn` anywhere): [`crate::processes::dagknight::umc_tree::builder::TreeBuilder`]
//! is generic over `St: UmcTreeStore<T, S>`, so a trait bound falls out naturally
//! while algorithm tests keep instantiating the pure-memory store.

use std::collections::HashMap;

use kaspa_consensus_core::KType;
use kaspa_database::prelude::{StoreError, StoreResult};

use super::records::{LeafScore, NodeCoord, NodeRecord, NodeRef, Score, VersionMetadata, VersionedNode, collect_scores};

/// One immutable published version: metadata plus the frozen buffer contents.
///
/// The records map lives in the open builder until publication and never
/// enters a store before then, so storage-level eviction cannot observe or
/// drop a partial state.
#[derive(Clone, Debug)]
pub struct PublishedVersion<T, S> {
    /// Version id under which every contained record is keyed.
    pub version: u64,
    /// Published-state metadata of this version.
    pub metadata: VersionMetadata,
    /// Frozen working-buffer records keyed by tree coordinate, at most one per coordinate.
    pub records: HashMap<NodeCoord, NodeRecord<T, S>>,
}

/// Read-only storage contract for published UMC tree records; satisfied by the
/// memory, database and combined (facade) levels.
pub trait UmcTreeStoreReader<T: Clone, S: Score> {
    /// Exact record at `(k, node.h, node.j, node.version)`; `None` if absent.
    fn get_node(&self, k: KType, node: NodeRef) -> StoreResult<Option<NodeRecord<T, S>>>;

    /// Newest record at coordinate `(k, coord)`, newest-first scan; `None` if never written.
    fn latest_node(&self, k: KType, coord: NodeCoord) -> StoreResult<Option<VersionedNode<T, S>>>;

    /// Metadata of a published version; `None` for unknown versions.
    fn metadata(&self, k: KType, version: u64) -> StoreResult<Option<VersionMetadata>>;

    /// Most recently published version in partition `k`, or `None` if it is empty.
    fn latest_version(&self, k: KType) -> StoreResult<Option<u64>>;

    /// Root minimum of a published state; `None` only for a published state with
    /// no leaves. An unknown version is a `DataInconsistency` error, never a
    /// vacuous "no minimum" answer (the UMC qualification test reads this).
    fn minimum_score(&self, k: KType, version: u64) -> StoreResult<Option<S>> {
        let Some(metadata) = self.metadata(k, version)? else {
            return Err(StoreError::DataInconsistency(format!("unknown umc version {version} (k {k})")));
        };
        let Some(root) = metadata.root_version.map(|v| NodeRef { version: v, h: metadata.root_height, j: 0 }) else {
            return Ok(None);
        };
        match self.get_node(k, root)? {
            Some(NodeRecord::Leaf { minimum, .. }) => Ok(Some(minimum)),
            Some(NodeRecord::Internal { minimum, .. }) => Ok(minimum),
            None => Err(StoreError::DataInconsistency(format!("missing root record of version {version}"))),
        }
    }

    /// Whether the published state passes the UMC test at `deficit`: the root
    /// minimum is at least `-deficit`; a state with no leaves qualifies vacuously.
    /// An unknown version is a `DataInconsistency` error, never a vacuous pass.
    fn qualifies(&self, k: KType, version: u64, deficit: S) -> StoreResult<bool> {
        Ok(self.minimum_score(k, version)?.is_none_or(|m| m >= -deficit))
    }

    /// All leaf scores of a published state in leaf order; costs O(n). An unknown
    /// version is a `DataInconsistency` error, never an empty vector.
    fn scores(&self, k: KType, version: u64) -> StoreResult<Vec<LeafScore<T, S>>> {
        let Some(metadata) = self.metadata(k, version)? else {
            return Err(StoreError::DataInconsistency(format!("unknown umc version {version} (k {k})")));
        };
        let root = metadata.root_version.map(|v| NodeRef { version: v, h: metadata.root_height, j: 0 });
        collect_scores(root, |r| {
            self.get_node(k, r)?
                .ok_or_else(|| StoreError::DataInconsistency(format!("missing published record at ({}, {}, {})", r.h, r.j, r.version)))
        })
    }
}

/// Write-side contract: version allocation and atomic publication.
pub trait UmcTreeStore<T: Clone, S: Score>: UmcTreeStoreReader<T, S> {
    /// Reserve the next version id. Durable reservation commits with `publish`:
    /// the counter advance rides inside the publish batch, so the durable counter
    /// never lags a committed version id.
    fn allocate_version(&mut self) -> StoreResult<u64>;

    /// Freeze one immutable version into partition `k`: node records + metadata
    /// (+ counter advance) committed as one batch.
    fn publish(&mut self, k: KType, publish: PublishedVersion<T, S>) -> StoreResult<()>;
}

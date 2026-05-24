use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, DirectDbWriter, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Per-block SMT metadata stored alongside the seq_commit.
///
/// `payload_and_ctx_digest` is `H_seq(context_hash, payload_root)`, the inner
/// hash of `seq_state_root`. The `lanes_root` is stored in the branch version
/// store at depth=0 and read via `SmtStores::get_lanes_root`.
///
/// `payload_root` is kept so that an IBD importer can reconstruct
/// `payload_and_ctx_digest` from header fields paired with the derived
/// `inactivity_shortcut` and thereby authenticate the pruning-point header's
/// `seq_commit` (= `accepted_id_merkle_root`).
///
/// `inactivity_shortcut_block` is the block hash of the highest chain block
/// at `bs <= block_bs - finality_depth - 1`. The committed
/// `inactivity_shortcut` value (in `MergesetContext` and on the IBD wire) is
/// `headers_store(inactivity_shortcut_block).accepted_id_merkle_root`.
/// `ZERO_HASH` means we don't have the corresponding block
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtBlockMetadata {
    pub payload_and_ctx_digest: Hash,
    pub payload_root: Hash,
    pub active_lanes_count: u64,
    pub inactivity_shortcut_block: Hash,
}

impl SmtBlockMetadata {
    pub fn new(payload_and_ctx_digest: Hash, payload_root: Hash, active_lanes_count: u64, inactivity_shortcut_block: Hash) -> Self {
        Self { payload_and_ctx_digest, payload_root, active_lanes_count, inactivity_shortcut_block }
    }
}

impl MemSizeEstimator for SmtBlockMetadata {}

/// Block-hash-keyed metadata store with in-memory cache.
#[derive(Clone)]
pub struct DbSmtMetadataStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, SmtBlockMetadata, BlockHasher>,
}

impl DbSmtMetadataStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { access: CachedDbAccess::new(Arc::clone(&db), cache_policy, DatabaseStorePrefixes::SmtSeqCommitMeta.into()), db }
    }

    pub fn get(&self, block_hash: Hash) -> StoreResult<SmtBlockMetadata> {
        self.access.read(block_hash)
    }

    pub fn has(&self, block_hash: Hash) -> StoreResult<bool> {
        self.access.has(block_hash)
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, block_hash: Hash, metadata: SmtBlockMetadata) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block_hash, metadata)
    }

    pub fn delete_all(&self) -> StoreResult<()> {
        self.access.delete_all(DirectDbWriter::new(&self.db))
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block_hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block_hash)
    }
}

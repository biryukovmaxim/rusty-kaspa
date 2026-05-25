use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, DirectDbWriter, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Version suffix appended to every post-anchor `SmtBlockMetadata` row's DB key.
/// Pre-anchor rows (the 40-byte Toccata `[payload_and_ctx_digest, active_lanes_count]`
/// layout) have no suffix and are decoded through [`LegacySmtBlockMetadata`] by the
/// version-aware path in `CachedDbAccess`. See `DbUtxoDiffsStore` for the same pattern.
pub const POST_ANCHOR_SMT_METADATA_VERSION: u8 = 1;

/// Per-block SMT metadata stored alongside the seq_commit.
///
/// Two on-disk layouts coexist, distinguished by key version suffix:
/// - **`ToccataV0`** (no key suffix): the pre-anchor 40-byte `[payload_and_ctx_digest, active_lanes_count]`.
///   Read-only: decoded via [`LegacySmtBlockMetadata`] and converted in.
/// - **`ToccataV1`** (key suffix `POST_ANCHOR_SMT_METADATA_VERSION`): the new 3-field layout.
///   The only variant produced by new writes.
///
/// Accessor methods panic on variants that lack the requested field — the upgrade boundary
/// is enforced upstream, so callers reach for a field only after migration is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtBlockMetadata {
    ToccataV0 { payload_and_ctx_digest: Hash, active_lanes_count: u64 },
    ToccataV1 { payload_root: Hash, inactivity_shortcut_block: Hash, active_lanes_count: u64 },
}

impl SmtBlockMetadata {
    /// Construct a `ToccataV1` variant. The only variant new code ever writes.
    pub fn new(payload_root: Hash, inactivity_shortcut_block: Hash, active_lanes_count: u64) -> Self {
        Self::ToccataV1 { payload_root, inactivity_shortcut_block, active_lanes_count }
    }

    pub fn payload_root(&self) -> Hash {
        match self {
            Self::ToccataV1 { payload_root, .. } => *payload_root,
            Self::ToccataV0 { .. } => panic!("payload_root unavailable on ToccataV0 SmtBlockMetadata"),
        }
    }

    pub fn inactivity_shortcut_block(&self) -> Hash {
        match self {
            Self::ToccataV1 { inactivity_shortcut_block, .. } => *inactivity_shortcut_block,
            Self::ToccataV0 { .. } => panic!("inactivity_shortcut_block unavailable on ToccataV0 SmtBlockMetadata"),
        }
    }

    pub fn active_lanes_count(&self) -> u64 {
        match self {
            Self::ToccataV1 { active_lanes_count, .. } | Self::ToccataV0 { active_lanes_count, .. } => *active_lanes_count,
        }
    }
}

impl MemSizeEstimator for SmtBlockMetadata {}

/// Shadow type for decoding legacy (pre-anchor) on-disk rows. Matches the
/// ToccataV0 struct layout exactly. Constructed only by `CachedDbAccess`'s
/// version-aware read path; converted into [`SmtBlockMetadata::ToccataV0`].
#[derive(Clone, Deserialize)]
pub struct LegacySmtBlockMetadata {
    pub payload_and_ctx_digest: Hash,
    pub active_lanes_count: u64,
}

impl From<LegacySmtBlockMetadata> for SmtBlockMetadata {
    fn from(legacy: LegacySmtBlockMetadata) -> Self {
        SmtBlockMetadata::ToccataV0 {
            payload_and_ctx_digest: legacy.payload_and_ctx_digest,
            active_lanes_count: legacy.active_lanes_count,
        }
    }
}

/// Block-hash-keyed metadata store with in-memory cache.
///
/// Writes go under the post-anchor versioned key layout `[prefix || hash || 1]`.
/// Reads transparently handle both layouts: pre-anchor rows (no version suffix)
/// are decoded via [`LegacySmtBlockMetadata`] and converted to `SmtBlockMetadata::ToccataV0`.
#[derive(Clone)]
pub struct DbSmtMetadataStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, SmtBlockMetadata, BlockHasher, LegacySmtBlockMetadata>,
}

impl DbSmtMetadataStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            access: CachedDbAccess::new_with_version_suffix(
                Arc::clone(&db),
                cache_policy,
                DatabaseStorePrefixes::SmtSeqCommitMeta.into(),
                POST_ANCHOR_SMT_METADATA_VERSION,
            ),
            db,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, DbKey};

    fn legacy_row_key(hash: Hash) -> Vec<u8> {
        let mut key = vec![DatabaseStorePrefixes::SmtSeqCommitMeta.into()];
        key.extend_from_slice(hash.as_bytes().as_ref());
        key
    }

    fn versioned_row_key(hash: Hash) -> Vec<u8> {
        let mut key = legacy_row_key(hash);
        key.push(POST_ANCHOR_SMT_METADATA_VERSION);
        key
    }

    #[test]
    fn current_round_trip_uses_versioned_layout() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbSmtMetadataStore::new(Arc::clone(&db), CachePolicy::Count(16));

        let hash = Hash::from_u64_word(0xDEAD_BEEF);
        let meta = SmtBlockMetadata::new(Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32]), 42);

        let mut batch = WriteBatch::default();
        store.insert_batch(&mut batch, hash, meta).unwrap();
        db.write(batch).unwrap();

        assert!(db.get_pinned(versioned_row_key(hash)).unwrap().is_some());
        assert!(db.get_pinned(legacy_row_key(hash)).unwrap().is_none());

        assert_eq!(store.get(hash).unwrap(), meta);
    }

    #[test]
    fn decode_toccatav0_legacy_row() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbSmtMetadataStore::new(Arc::clone(&db), CachePolicy::Count(16));

        // Hand-craft the Toccata 40-byte payload: [payload_and_ctx_digest(32), active_lanes_count(8)].
        let hash = Hash::from_u64_word(0xABCD);
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&7u64.to_le_bytes());
        db.put(legacy_row_key(hash), bytes).unwrap();

        let decoded = store.get(hash).expect("decode legacy ToccataV0 row through the store");
        assert_eq!(
            decoded,
            SmtBlockMetadata::ToccataV0 { payload_and_ctx_digest: Hash::from_bytes([0xAA; 32]), active_lanes_count: 7 }
        );
        assert_eq!(decoded.active_lanes_count(), 7);
    }

    #[test]
    #[should_panic(expected = "payload_root unavailable")]
    fn toccatav0_payload_root_panics() {
        let m = SmtBlockMetadata::ToccataV0 { payload_and_ctx_digest: Hash::from_bytes([0; 32]), active_lanes_count: 0 };
        let _ = m.payload_root();
    }

    #[test]
    fn delete_clears_both_layouts() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbSmtMetadataStore::new(Arc::clone(&db), CachePolicy::Count(16));

        let hash_legacy = Hash::from_u64_word(1);
        let hash_versioned = Hash::from_u64_word(2);

        let mut legacy_bytes = Vec::with_capacity(40);
        legacy_bytes.extend_from_slice(&[0xAA; 32]);
        legacy_bytes.extend_from_slice(&7u64.to_le_bytes());
        db.put(legacy_row_key(hash_legacy), legacy_bytes).unwrap();

        let mut batch = WriteBatch::default();
        store.insert_batch(&mut batch, hash_versioned, SmtBlockMetadata::new(Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32]), 99)).unwrap();
        db.write(batch).unwrap();

        let mut batch = WriteBatch::default();
        store.delete_batch(&mut batch, hash_legacy).unwrap();
        store.delete_batch(&mut batch, hash_versioned).unwrap();
        db.write(batch).unwrap();

        assert!(db.get_pinned(legacy_row_key(hash_legacy)).unwrap().is_none());
        assert!(db.get_pinned(versioned_row_key(hash_versioned)).unwrap().is_none());
        let _ = DbKey::new(&[DatabaseStorePrefixes::SmtSeqCommitMeta.into()], hash_legacy);
    }
}

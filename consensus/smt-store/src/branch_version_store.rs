use std::sync::Arc;

use kaspa_database::prelude::{DB, DbWriter, StoreError, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use zerocopy::FromBytes;

use crate::keys::BranchVersionKey;
use crate::maybe_fork::{MaybeFork, Verified};
use kaspa_smt::store::Node;

/// Branch Versions.
///
/// One immutable entry per `(branch, block)` pair where the branch value
/// changed. Written once by `apply_block`, never modified.
pub struct DbBranchVersionStore {
    db: Arc<DB>,
    prefix: u8,
}

impl DbBranchVersionStore {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db, prefix: DatabaseStorePrefixes::SmtBranchVersions.into() }
    }

    pub fn delete_all(&self) {
        use kaspa_database::prelude::DirectDbWriter;
        DirectDbWriter::new(&self.db).delete_range(vec![self.prefix], vec![self.prefix + 1]).unwrap();
    }

    pub fn put(
        &self,
        mut writer: impl DbWriter,
        depth: u8,
        node_key: Hash,
        blue_score: u64,
        block_hash: Hash,
        value: Option<Node>,
    ) -> StoreResult<()> {
        let key = BranchVersionKey::new(self.prefix, depth, node_key, blue_score, block_hash);
        match value {
            Some(node) => writer.put(key, node.to_bytes()).map_err(StoreError::DbError),
            None => writer.put(key, []).map_err(StoreError::DbError),
        }
    }

    pub fn delete(&self, mut writer: impl DbWriter, depth: u8, node_key: Hash, blue_score: u64, block_hash: Hash) -> StoreResult<()> {
        let key = BranchVersionKey::new(self.prefix, depth, node_key, blue_score, block_hash);
        writer.delete(key).map_err(StoreError::DbError)
    }

    /// Find the latest canonical version in `[min_blue_score, target_blue_score]`.
    ///
    /// Iterates via `get_at` from `target_blue_score` downward, stopping at
    /// `min_blue_score`. Returns the first entry where `is_canonical(block_hash)`
    /// is true.
    pub fn get_at_canonical(
        &self,
        depth: u8,
        node_key: Hash,
        target_blue_score: u64,
        min_blue_score: u64,
        is_canonical: impl FnMut(Hash) -> bool,
    ) -> StoreResult<Option<Verified<Option<Node>>>> {
        self.get_at_canonical_from(depth, node_key, target_blue_score, Hash::from_bytes([0; 32]), min_blue_score, is_canonical)
    }

    /// Like [`Self::get_at_canonical`], but starts iteration inclusively at
    /// `(start_blue_score, start_block_hash)` instead of at the first entry
    /// of `start_blue_score`. Used by `SmtStores::get_node` to resume DB
    /// iteration after a cache miss, skipping DB rows the cache already
    /// examined.
    ///
    /// `start_block_hash == [0; 32]` is a real possible block_hash (not a
    /// sentinel), and this method treats it as an inclusive start — an entry
    /// at exactly `(start_blue_score, [0; 32])` is returned by this iterator.
    pub fn get_at_canonical_from(
        &self,
        depth: u8,
        node_key: Hash,
        start_blue_score: u64,
        start_block_hash: Hash,
        min_blue_score: u64,
        mut is_canonical: impl FnMut(Hash) -> bool,
    ) -> StoreResult<Option<Verified<Option<Node>>>> {
        for entry in self.get_at_from(depth, node_key, start_blue_score, start_block_hash, min_blue_score) {
            let entry = entry?;
            if is_canonical(entry.block_hash()) {
                return Ok(Some(entry.into_verified()));
            }
        }
        Ok(None)
    }

    /// Test helper: unbounded-target variant of [`Self::get_at_canonical`].
    #[cfg(test)]
    pub fn get(
        &self,
        depth: u8,
        node_key: Hash,
        min_blue_score: u64,
        is_canonical: impl FnMut(Hash) -> bool,
    ) -> StoreResult<Option<Verified<Option<Node>>>> {
        self.get_at_canonical(depth, node_key, u64::MAX, min_blue_score, is_canonical)
    }

    /// Iterate versions for `(depth, node_key)` from `target_blue_score` downward.
    ///
    /// Returns `MaybeFork<Node>` carrying both `score` and
    /// `block_hash` from the key. Caller verifies canonicality and
    /// picks the first match.
    pub fn get_at(
        &self,
        depth: u8,
        node_key: Hash,
        target_blue_score: u64,
        min_blue_score: u64,
    ) -> impl Iterator<Item = StoreResult<MaybeFork<Option<Node>>>> + '_ {
        self.get_at_from(depth, node_key, target_blue_score, Hash::from_bytes([0; 32]), min_blue_score)
    }

    /// Iterate versions for `(depth, node_key)` starting inclusively at
    /// `(start_blue_score, start_block_hash)` and descending by blue_score.
    ///
    /// Equivalent to [`Self::get_at`] when `start_block_hash == [0; 32]`. The
    /// extra parameter lets callers resume iteration at a specific point in
    /// the DB order — used by `SmtStores::get_node` after exhausting the
    /// cache, to avoid re-scanning DB rows the cache already visited.
    pub fn get_at_from(
        &self,
        depth: u8,
        node_key: Hash,
        start_blue_score: u64,
        start_block_hash: Hash,
        min_blue_score: u64,
    ) -> impl Iterator<Item = StoreResult<MaybeFork<Option<Node>>>> + '_ {
        let seek_key = BranchVersionKey::new(self.prefix, depth, node_key, start_blue_score, start_block_hash);
        let mut entity_prefix = [0u8; BranchVersionKey::ENTITY_PREFIX_LEN];
        entity_prefix.copy_from_slice(&seek_key.as_ref()[..BranchVersionKey::ENTITY_PREFIX_LEN]);

        let mut iter = self.db.raw_iterator();
        iter.seek(seek_key);

        let mut done = false;

        std::iter::from_fn(move || {
            if done {
                return None;
            }
            if !iter.valid() {
                done = true;
                return iter.status().err().map(|e| Err(StoreError::DbError(e)));
            }

            let result = (|| -> StoreResult<Option<MaybeFork<Option<Node>>>> {
                let key_bytes = match iter.key() {
                    Some(k) => k,
                    None => return Ok(None),
                };

                if !key_bytes.starts_with(&entity_prefix) {
                    return Ok(None);
                }

                let key = BranchVersionKey::ref_from_bytes(key_bytes)
                    .map_err(|e| StoreError::DataInconsistency(format!("branch version key: {e}")))?;
                let blue_score = key.rev_blue_score.blue_score();
                debug_assert!(blue_score <= start_blue_score);

                if blue_score < min_blue_score {
                    return Ok(None);
                }

                let value_bytes = match iter.value() {
                    Some(v) => v,
                    None => return Ok(None),
                };
                let node =
                    if value_bytes.is_empty() {
                        None
                    } else {
                        Some(Node::from_bytes(value_bytes).ok_or_else(|| {
                            StoreError::DataInconsistency(format!("invalid node value length: {}", value_bytes.len()))
                        })?)
                    };
                Ok(Some(MaybeFork::new(node, blue_score, key.block_hash)))
            })();

            match result {
                Ok(Some(fork)) => {
                    iter.next();
                    Some(Ok(fork))
                }
                Ok(None) => {
                    done = true;
                    None
                }
                Err(e) => {
                    done = true;
                    Some(Err(e))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, DirectDbWriter};

    fn make_store() -> (kaspa_database::utils::DbLifetime, DbBranchVersionStore) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        (lifetime, DbBranchVersionStore::new(db))
    }

    fn hash(v: u8) -> Hash {
        Hash::from_bytes([v; 32])
    }

    fn internal(hash: Hash) -> Option<Node> {
        Some(Node::Internal(hash))
    }

    #[test]
    fn put_and_get_at() {
        let (_lt, store) = make_store();
        let version = internal(hash(0xAA));

        store.put(DirectDbWriter::new(&store.db), 3, hash(0x11), 100, hash(0x22), version).unwrap();

        let first = store.get_at(3, hash(0x11), 100, 0).next().unwrap().unwrap();
        assert_eq!(first.block_hash(), hash(0x22));
        assert_eq!(first.blue_score(), 100);
        assert_eq!(*first.data(), internal(hash(0xAA)));
    }

    #[test]
    fn get_at_iterates_versions() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);

        for (score, bh) in [(50, hash(0xA0)), (100, hash(0xA1)), (200, hash(0xA2))] {
            let version = internal(hash(score as u8));
            store.put(DirectDbWriter::new(&store.db), 7, node_key, score, bh, version).unwrap();
        }

        // target_blue_score=150 → score=100 then score=50
        let results: Vec<_> = store.get_at(7, node_key, 150, 0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].block_hash(), hash(0xA1));
        assert_eq!(results[0].blue_score(), 100);
        assert_eq!(results[1].block_hash(), hash(0xA0));
        assert_eq!(results[1].blue_score(), 50);

        // target_blue_score=200 → all 3
        let results: Vec<_> = store.get_at(7, node_key, 200, 0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 3);

        // target_blue_score=49 → nothing
        assert!(store.get_at(7, node_key, 49, 0).next().is_none());

        // First result data
        let first = store.get_at(7, node_key, 150, 0).next().unwrap().unwrap();
        assert_eq!(*first.data(), internal(hash(100)));
    }

    #[test]
    fn delete_entry() {
        let (_lt, store) = make_store();
        let version = internal(hash(0xAA));
        store.put(DirectDbWriter::new(&store.db), 3, hash(0x11), 100, hash(0x22), version).unwrap();

        assert!(store.get_at(3, hash(0x11), 100, 0).next().is_some());

        store.delete(DirectDbWriter::new(&store.db), 3, hash(0x11), 100, hash(0x22)).unwrap();

        assert!(store.get_at(3, hash(0x11), 100, 0).next().is_none());
    }

    #[test]
    fn get_with_canonicality_filter() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);

        // Two blocks at score 100 (fork), one at score 50
        let canonical_bh = hash(0xA1);
        let fork_bh = hash(0xA2);
        let older_bh = hash(0xA0);

        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, canonical_bh, internal(hash(0xCC))).unwrap();
        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, fork_bh, internal(hash(0xEE))).unwrap();
        store.put(DirectDbWriter::new(&store.db), 7, node_key, 50, older_bh, internal(hash(0x11))).unwrap();

        // Finds canonical at score 100 (searching from MAX down to 0)
        let result = store.get(7, node_key, 0, |bh| bh == canonical_bh).unwrap().unwrap();
        assert_eq!(result.block_hash(), canonical_bh);
        assert_eq!(result.blue_score(), 100);
        assert_eq!(*result.data(), internal(hash(0xCC)));

        // Falls through to score 50 when score-100 blocks aren't canonical
        let result = store.get(7, node_key, 0, |bh| bh == older_bh).unwrap().unwrap();
        assert_eq!(result.blue_score(), 50);

        // min_blue_score=60 excludes score 50, so only score-100 candidates remain
        assert!(store.get(7, node_key, 60, |bh| bh == older_bh).unwrap().is_none());

        // No canonical match at all
        assert!(store.get(7, node_key, 0, |_| false).unwrap().is_none());
    }

    /// `get_at_from` starts iteration inclusively at `start_block_hash`, so
    /// same-score entries with `bh < start_block_hash` are skipped while those
    /// at `bh >= start_block_hash` are yielded in ascending-bh order.
    #[test]
    fn get_at_from_skips_entries_before_start_bh() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);

        for bh_byte in [0x10u8, 0x50, 0xA0] {
            store
                .put(DirectDbWriter::new(&store.db), 7, node_key, 100, Hash::from_bytes([bh_byte; 32]), internal(hash(bh_byte)))
                .unwrap();
        }

        let results: Vec<_> =
            store.get_at_from(7, node_key, 100, Hash::from_bytes([0x30; 32]), 0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].block_hash(), Hash::from_bytes([0x50; 32]));
        assert_eq!(results[1].block_hash(), Hash::from_bytes([0xA0; 32]));
    }

    /// On `bh` overflow the caller is expected to roll over to the next
    /// lower score at `[0; 32]`. `get_at_from` must treat that as an
    /// inclusive start and yield entries there.
    #[test]
    fn get_at_from_crosses_score_boundary_on_bh_overflow() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);

        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, Hash::from_bytes([0xA0; 32]), internal(hash(100))).unwrap();
        store.put(DirectDbWriter::new(&store.db), 7, node_key, 50, Hash::from_bytes([0x10; 32]), internal(hash(50))).unwrap();

        // Seek from (99, 0) — nothing at 99, must fall through to (50, 0x10).
        let results: Vec<_> = store.get_at_from(7, node_key, 99, Hash::from_bytes([0; 32]), 0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].blue_score(), 50);
        assert_eq!(results[0].block_hash(), Hash::from_bytes([0x10; 32]));
    }

    /// `block_hash == [0; 32]` is a real possible DB value, not a sentinel.
    /// Starting `get_at_from` at `(score, [0; 32])` must return the entry
    /// with `block_hash == [0; 32]` if one exists — the inclusive-start
    /// invariant that the cache→DB resume logic depends on.
    #[test]
    fn get_at_from_includes_entry_with_zero_block_hash() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);

        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, Hash::from_bytes([0; 32]), internal(hash(0xAA))).unwrap();

        let results: Vec<_> =
            store.get_at_from(7, node_key, 100, Hash::from_bytes([0; 32]), 0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].block_hash(), Hash::from_bytes([0; 32]));
    }

    /// `get_at_canonical_from` picks the first canonical entry that sorts
    /// at or after the given start point — i.e. it behaves as a
    /// DB-continuation of an already-started iteration.
    #[test]
    fn get_at_canonical_from_picks_sibling_after_start_bh() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);
        let non_canonical_bh = Hash::from_bytes([0x10; 32]);
        let canonical_bh = Hash::from_bytes([0x80; 32]);

        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, non_canonical_bh, internal(hash(0xAA))).unwrap();
        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, canonical_bh, internal(hash(0xCC))).unwrap();

        // Start from (100, 0x20) — past the non-canonical one — and pick
        // the canonical sibling.
        let result =
            store.get_at_canonical_from(7, node_key, 100, Hash::from_bytes([0x20; 32]), 0, |bh| bh == canonical_bh).unwrap().unwrap();
        assert_eq!(result.block_hash(), canonical_bh);
        assert_eq!(result.blue_score(), 100);
    }

    #[test]
    fn put_none_blocks_fallback_to_older_node() {
        let (_lt, store) = make_store();
        let node_key = hash(0x11);
        let older_bh = hash(0xA0);
        let delete_bh = hash(0xA1);

        store.put(DirectDbWriter::new(&store.db), 7, node_key, 100, older_bh, internal(hash(0xCC))).unwrap();
        store.put(DirectDbWriter::new(&store.db), 7, node_key, 200, delete_bh, None).unwrap();

        let deleted = store.get(7, node_key, 0, |bh| bh == delete_bh).unwrap().unwrap();
        assert_eq!(deleted.blue_score(), 200);
        assert_eq!(*deleted.data(), None);
    }
}

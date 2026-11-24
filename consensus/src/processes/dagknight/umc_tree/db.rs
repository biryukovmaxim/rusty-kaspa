//! RocksDB-backed store of published UMC tree records, partitioned by k via key
//! prefixes.
//!
//! Values are the fixed-layout zerocopy wire structs of `records.rs`: node
//! records and metadata encode/decode through `encode_node`/`decode_node` and
//! friends, and decode failures carry the key coordinates. Point reads decode a
//! missing key to `None`; newest-first queries use raw iterators with the same
//! seek keys as the memory level. Publication commits node puts, the metadata
//! put, the anchor entry and the counter advance as one atomic `WriteBatch`,
//! then takes the anchor into the map's cache.

use std::marker::PhantomData;
use std::sync::Arc;

use rocksdb::WriteBatch;
use zerocopy::{FromBytes, IntoBytes};

use kaspa_consensus_core::KType;
use kaspa_database::prelude::{BatchDbWriter, DB, DbWriter, StoreError, StoreResult, VersionMap};
use kaspa_database::registry::DatabaseStorePrefixes;

use super::api::{PublishedVersion, UmcTreeStore, UmcTreeStoreReader};
use super::keys::{NodeKey, VersionKey};
use super::records::{
    NodeCoord, NodeRecord, NodeRef, Score, ScoreWire, ValueWire, VersionMetadata, VersionedNode, decode_metadata, decode_node,
    encode_metadata, encode_node,
};
use crate::model::stores::conflict_zone_coloring::ConflictZoneColoringKey;

/// RocksDB-backed store of published UMC tree records, partitioned by k via key
/// prefixes.
///
/// Generic callers need `T`/`S` to round-trip through the wire encoding; the
/// store keeps only prefixes, the anchor map with its cache, and a
/// lazily-loaded image of the version counter besides the database handle.
pub struct DbUmcTreeStore<T, S> {
    /// Database handle shared with the owning consensus stores.
    db: Arc<DB>,
    /// Key prefix byte of the node-records namespace.
    pub(crate) node_prefix: u8,
    /// Key prefix byte of the version-metadata namespace.
    pub(crate) version_prefix: u8,
    /// Key prefix byte of the singleton counter namespace.
    pub(crate) meta_prefix: u8,
    /// Anchor map this store writes and reads; its cache is sized by `new`.
    pub(crate) anchors: VersionMap<ConflictZoneColoringKey>,
    /// In-memory image of the durable counter; `None` until the first read of the meta key.
    next_version_id: Option<u64>,
    /// Placeholder tying the generic parameters to the store type. Uses a
    /// function pointer so the store owns no `T`/`S`: no drop glue and no
    /// drop-check interaction regardless of the type parameters.
    marker: PhantomData<fn() -> (T, S)>,
}

impl<T, S> DbUmcTreeStore<T, S> {
    /// Store over `db` with the UMC tree's node, version and counter prefixes,
    /// and an anchor map caching at most `anchor_capacity` entries.
    pub fn new(db: Arc<DB>, anchor_capacity: usize) -> Self {
        Self {
            anchors: VersionMap::new(db.clone(), DatabaseStorePrefixes::DagKnightConflictZoneVersions.into(), anchor_capacity),
            db,
            node_prefix: DatabaseStorePrefixes::DagKnightUmcNodes.into(),
            version_prefix: DatabaseStorePrefixes::DagKnightUmcVersions.into(),
            meta_prefix: DatabaseStorePrefixes::DagKnightUmcMeta.into(),
            next_version_id: None,
            marker: PhantomData,
        }
    }
}

impl<T: Clone + ValueWire, S: Score + ScoreWire> DbUmcTreeStore<T, S> {
    /// Read the durable version counter; `0` when the meta key is absent.
    pub(crate) fn read_counter(&self) -> StoreResult<u64> {
        let Some(bytes) = self.db.get([self.meta_prefix]).map_err(StoreError::DbError)? else {
            return Ok(0);
        };
        let value: [u8; 8] =
            bytes.try_into().map_err(|_| StoreError::DataInconsistency("umc meta counter must be 8 big-endian bytes".to_string()))?;
        Ok(u64::from_be_bytes(value))
    }

    /// Commit one publication atomically: node puts, the version-metadata put,
    /// the anchor entry and the counter advance (`counter`) in a single
    /// `WriteBatch`; after that batch is written the anchor enters the map's
    /// cache. A rejected anchor leaves nothing written.
    pub(crate) fn commit_publish(&self, k: KType, publish: &PublishedVersion<T, S>, counter: u64) -> StoreResult<()> {
        let mut batch = WriteBatch::default();
        {
            let mut writer = BatchDbWriter::new(&mut batch);
            for (coord, record) in publish.records.iter() {
                let key = NodeKey::new(self.node_prefix, k, coord.h, coord.j, publish.version);
                writer.put(key, encode_node(record).as_bytes()).map_err(StoreError::DbError)?;
            }
            let vkey = VersionKey::new(self.version_prefix, k, publish.version);
            writer.put(vkey, encode_metadata(&publish.metadata).as_bytes()).map_err(StoreError::DbError)?;
            if let Some(anchor) = &publish.anchor {
                self.validate_anchor(k, anchor)?;
                self.anchors.put(&mut writer, anchor, publish.version)?;
            }
            writer.put([self.meta_prefix], counter.to_be_bytes()).map_err(StoreError::DbError)?;
        }
        self.db.write(batch).map_err(StoreError::DbError)?;
        if let Some(anchor) = &publish.anchor {
            self.anchors.write_through(anchor, publish.version);
        }
        Ok(())
    }
}

impl<T: Clone + ValueWire, S: Score + ScoreWire> UmcTreeStoreReader<T, S> for DbUmcTreeStore<T, S> {
    fn resolve_anchor(&self, anchor: &ConflictZoneColoringKey) -> StoreResult<Option<u64>> {
        self.anchors.get(anchor)
    }

    fn get_node(&self, k: KType, node: NodeRef) -> StoreResult<Option<NodeRecord<T, S>>> {
        let key = NodeKey::new(self.node_prefix, k, node.h, node.j, node.version);
        let Some(bytes) = self.db.get(key).map_err(StoreError::DbError)? else { return Ok(None) };
        let record = decode_node(&bytes).map_err(|e| {
            StoreError::DataInconsistency(format!(
                "umc node value at (k {k}, h {}, j {}, version {}): {e}",
                node.h, node.j, node.version
            ))
        })?;
        Ok(Some(record))
    }

    fn latest_node(&self, k: KType, coord: NodeCoord) -> StoreResult<Option<VersionedNode<T, S>>> {
        let seek = NodeKey::seek_latest(self.node_prefix, k, coord.h, coord.j);
        let mut iter = self.db.raw_iterator();
        iter.seek(seek);
        if !iter.valid() {
            iter.status().map_err(StoreError::DbError)?;
            return Ok(None);
        }
        let Some(key_bytes) = iter.key() else { return Ok(None) };
        if !key_bytes.starts_with(&seek.as_bytes()[..NodeKey::COORDINATE_PREFIX_LEN]) {
            return Ok(None);
        }
        let key = NodeKey::ref_from_bytes(key_bytes).map_err(|e| StoreError::DataInconsistency(format!("umc node key: {e}")))?;
        let Some(value_bytes) = iter.value() else { return Ok(None) };
        let record = decode_node(value_bytes).map_err(|e| {
            StoreError::DataInconsistency(format!(
                "umc node value at (k {k}, h {}, j {}, version {}): {e}",
                coord.h,
                coord.j,
                key.version()
            ))
        })?;
        Ok(Some(VersionedNode { version: key.version(), record }))
    }

    fn metadata(&self, k: KType, version: u64) -> StoreResult<Option<VersionMetadata>> {
        let key = VersionKey::new(self.version_prefix, k, version);
        let Some(bytes) = self.db.get(key).map_err(StoreError::DbError)? else { return Ok(None) };
        let metadata = decode_metadata(&bytes)
            .map_err(|e| StoreError::DataInconsistency(format!("umc version metadata at (k {k}, version {version}): {e}")))?;
        Ok(Some(metadata))
    }

    fn latest_version(&self, k: KType) -> StoreResult<Option<u64>> {
        let seek = VersionKey::seek_latest(self.version_prefix, k);
        let mut iter = self.db.raw_iterator();
        iter.seek(seek);
        if !iter.valid() {
            iter.status().map_err(StoreError::DbError)?;
            return Ok(None);
        }
        let Some(key_bytes) = iter.key() else { return Ok(None) };
        if !key_bytes.starts_with(&seek.as_bytes()[..VersionKey::K_PREFIX_LEN]) {
            return Ok(None);
        }
        let key = VersionKey::ref_from_bytes(key_bytes).map_err(|e| StoreError::DataInconsistency(format!("umc version key: {e}")))?;
        Ok(Some(key.version()))
    }
}

impl<T: Clone + ValueWire, S: Score + ScoreWire> UmcTreeStore<T, S> for DbUmcTreeStore<T, S> {
    fn allocate_version(&mut self) -> StoreResult<u64> {
        let next = match self.next_version_id {
            Some(next) => next,
            None => self.read_counter()?,
        };
        self.next_version_id = Some(next + 1);
        Ok(next)
    }

    fn publish(&mut self, k: KType, publish: PublishedVersion<T, S>) -> StoreResult<()> {
        let counter = publish.version + 1;
        self.commit_publish(k, &publish, counter)?;
        self.next_version_id = Some(self.next_version_id.map_or(counter, |next| next.max(counter)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, DbKey};

    use super::super::records::LeafScore;
    use super::super::test_support::{AnchorInput, anchor_key};

    type Store = DbUmcTreeStore<u64, i64>;

    fn make_store() -> (kaspa_database::utils::DbLifetime, Store) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        (lifetime, Store::new(db, 0))
    }

    /// One published leaf plus an internal root carrying a pending addition.
    fn sample_version(version: u64, value: u64) -> PublishedVersion<u64, i64> {
        let mut records = HashMap::new();
        records.insert(NodeCoord { h: 0, j: 0 }, NodeRecord::Leaf { minimum: 4, value });
        records.insert(
            NodeCoord { h: 1, j: 0 },
            NodeRecord::Internal {
                minimum: Some(4),
                pending_addition: -2,
                boundary: Some(value),
                left_version: Some(version),
                right_version: None,
            },
        );
        PublishedVersion {
            version,
            metadata: VersionMetadata { anchor_version: None, root_version: Some(version), root_height: 1, blue_count: 1 },
            records,
            anchor: None,
        }
    }

    fn leaf_scores(pairs: &[(u64, i64)]) -> Vec<LeafScore<u64, i64>> {
        pairs.iter().map(|&(value, score)| LeafScore { value, score }).collect()
    }

    /// Published records round-trip through the wire encoding and the key
    /// layout: point reads, newest-first reads, metadata and the default
    /// traversal methods.
    #[test]
    fn put_get_roundtrip() {
        let (_lt, mut store) = make_store();
        store.publish(0, sample_version(0, 42)).unwrap();

        let node = NodeRef { version: 0, h: 0, j: 0 };
        assert!(matches!(store.get_node(0, node).unwrap(), Some(NodeRecord::Leaf { minimum: 4, value: 42 })));
        assert!(store.get_node(0, NodeRef { version: 9, h: 0, j: 0 }).unwrap().is_none());
        assert_eq!(store.metadata(0, 0).unwrap().map(|m| m.blue_count), Some(1));
        assert!(store.metadata(0, 7).unwrap().is_none());
        assert_eq!(store.latest_version(0).unwrap(), Some(0));
        assert_eq!(store.latest_node(0, NodeCoord { h: 0, j: 0 }).unwrap().map(|vn| vn.version), Some(0));
        assert_eq!(store.minimum_score(0, 0).unwrap(), Some(4));
        assert_eq!(store.scores(0, 0).unwrap(), leaf_scores(&[(42, 2)]));
    }

    /// latest_node returns the newest record of a coordinate; older versions stay readable.
    #[test]
    fn latest_node_newest_first() {
        let (_lt, mut store) = make_store();
        store.publish(0, sample_version(0, 10)).unwrap();
        store.publish(0, sample_version(1, 11)).unwrap();

        let latest = store.latest_node(0, NodeCoord { h: 0, j: 0 }).unwrap().unwrap();
        assert_eq!(latest.version, 1);
        assert!(matches!(latest.record, NodeRecord::Leaf { value: 11, .. }));
        assert!(matches!(store.get_node(0, NodeRef { version: 0, h: 0, j: 0 }).unwrap(), Some(NodeRecord::Leaf { value: 10, .. })));
        assert!(store.latest_node(0, NodeCoord { h: 5, j: 3 }).unwrap().is_none());
    }

    /// Identical `(h, j, version)` under different ks stay distinct records and
    /// version counters per k.
    #[test]
    fn per_k_isolation() {
        let (_lt, mut store) = make_store();
        store.publish(0, sample_version(5, 100)).unwrap();
        store.publish(1, sample_version(5, 200)).unwrap();

        let v0 = store.get_node(0, NodeRef { version: 5, h: 0, j: 0 }).unwrap().unwrap();
        let v1 = store.get_node(1, NodeRef { version: 5, h: 0, j: 0 }).unwrap().unwrap();
        assert!(matches!(v0, NodeRecord::Leaf { value: 100, .. }));
        assert!(matches!(v1, NodeRecord::Leaf { value: 200, .. }));
        assert_eq!(store.latest_version(0).unwrap(), Some(5));
        assert_eq!(store.latest_version(1).unwrap(), Some(5));
        assert_eq!(store.latest_version(2).unwrap(), None);
    }

    /// Publication advances the durable counter inside its batch; a fresh store
    /// instance resumes from the advanced value.
    #[test]
    fn publish_batch_advances_counter() {
        let (lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut store = Store::new(db.clone(), 0);
        assert_eq!(store.allocate_version().unwrap(), 0);
        assert_eq!(store.allocate_version().unwrap(), 1);
        store.publish(0, sample_version(5, 1)).unwrap();

        let meta_prefix: u8 = DatabaseStorePrefixes::DagKnightUmcMeta.into();
        let raw = db.get([meta_prefix]).unwrap().unwrap();
        assert_eq!(raw, 6u64.to_be_bytes());
        // The in-memory image advanced past the published id.
        assert_eq!(store.allocate_version().unwrap(), 6);
        drop(store);
        // A fresh instance reads the durable counter.
        assert_eq!(Store::new(db, 0).allocate_version().unwrap(), 6);
        drop(lt);
    }

    /// A value that fails wire decode surfaces as `DataInconsistency` naming
    /// the record's key coordinates (k, h, j, version).
    #[test]
    fn decode_error_carries_key_context() {
        let (_lt, mut store) = make_store();
        store.publish(0, sample_version(0, 42)).unwrap();
        // Corrupt the leaf record value of (k 0, h 0, j 0, version 0) with an
        // invalid kind byte.
        let prefix: u8 = DatabaseStorePrefixes::DagKnightUmcNodes.into();
        let key = NodeKey::new(prefix, 0, 0, 0, 0);
        store.db.put(key, [9u8; 8].as_slice()).unwrap();
        let error = store.get_node(0, NodeRef { version: 0, h: 0, j: 0 }).unwrap_err();
        let StoreError::DataInconsistency(message) = &error else { panic!("expected DataInconsistency, got {error:?}") };
        assert!(
            message.contains("k 0") && message.contains("h 0") && message.contains("j 0") && message.contains("version 0"),
            "{message}"
        );
    }

    /// Publication writes the anchor entry inside the publish batch under the
    /// map's prefix; a fresh store over the same database resolves it, and a
    /// second registration of the key is rejected without writing.
    #[test]
    fn publish_batch_registers_anchor() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let key = anchor_key(AnchorInput { root: 1, pov: 2, k: 0 });
        // Version 1: its two byte orders differ, so the stored one is observable.
        let mut version = sample_version(1, 42);
        version.anchor = Some(key.clone());
        Store::new(db.clone(), 0).publish(0, version).unwrap();

        let prefix: u8 = DatabaseStorePrefixes::DagKnightConflictZoneVersions.into();
        let mut raw_key = vec![prefix];
        raw_key.extend_from_slice(key.as_ref());
        assert_eq!(db.get(raw_key).unwrap().unwrap(), 1u64.to_be_bytes());

        let mut again = sample_version(2, 43);
        again.anchor = Some(key.clone());
        let error = Store::new(db.clone(), 0).publish(0, again).unwrap_err();
        assert!(matches!(error, StoreError::KeyAlreadyExists(_)));
        let meta_prefix: u8 = DatabaseStorePrefixes::DagKnightUmcMeta.into();
        assert_eq!(
            db.get([meta_prefix]).unwrap(),
            Some(2u64.to_be_bytes().to_vec()),
            "a rejected publish leaves the counter where it was"
        );
        assert_eq!(Store::new(db.clone(), 0).metadata(0, 2).unwrap(), None, "a rejected publish writes nothing");
        assert_eq!(Store::new(db.clone(), 0).resolve_anchor(&key).unwrap(), Some(1));
        assert_eq!(
            Store::new(db, 0).scores(0, 1).unwrap(),
            leaf_scores(&[(42, 2)]),
            "the key resolves to the state published with it"
        );
    }

    /// An anchor of another k panics inside the batch block, before the batch
    /// is written: it leaves no metadata, no registration, no counter and no
    /// cached entry behind.
    #[test]
    fn anchor_of_other_k_is_rejected() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let key = anchor_key(AnchorInput { root: 1, pov: 1, k: 1 });
        let mut version = sample_version(1, 42);
        version.anchor = Some(key.clone());
        let mut store = Store::new(db.clone(), 2);
        let published = catch_unwind(AssertUnwindSafe(|| store.publish(0, version)));
        let payload = published.expect_err("an anchor of another k panics");
        assert!(payload.downcast_ref::<String>().is_some_and(|message| message.contains("names k 1")), "{payload:?}");

        let meta_prefix: u8 = DatabaseStorePrefixes::DagKnightUmcMeta.into();
        assert_eq!(db.get([meta_prefix]).unwrap(), None, "the counter did not move");
        assert_eq!(store.metadata(0, 1).unwrap(), None, "the state was not published");
        assert_eq!(store.resolve_anchor(&key).unwrap(), None, "the key was not registered");
        assert!(!store.anchors.is_cached(&key), "the cache holds no registration");
    }

    /// An anchor entry whose value is not eight bytes is a data inconsistency,
    /// never a missing key.
    #[test]
    fn malformed_anchor_value_reads_error() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let key = anchor_key(AnchorInput { root: 1, pov: 2, k: 0 });
        let mut version = sample_version(0, 42);
        version.anchor = Some(key.clone());
        Store::new(db.clone(), 0).publish(0, version).unwrap();

        let prefix: u8 = DatabaseStorePrefixes::DagKnightConflictZoneVersions.into();
        db.put(DbKey::new(&[prefix], key.as_ref()), [0u8; 7].as_slice()).unwrap();
        let error = Store::new(db, 0).resolve_anchor(&key).unwrap_err();
        assert!(matches!(error, StoreError::DataInconsistency(ref message) if message.contains("8 big-endian bytes")));
    }
}

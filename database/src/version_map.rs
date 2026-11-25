//! Insert-once map from a key to the `u64` version registered under it.

use std::sync::Arc;

use crate::prelude::{Cache, CachePolicy, DB, DbKey, DbWriter, StoreError, StoreResult};

/// Insert-once map from a key to the `u64` version registered under it: one
/// entry per key, `prefix | key` to the version as eight big-endian bytes.
///
/// A registration is put into the caller's batch, so it commits atomically with
/// the records of the version it names, and is taken into the cache only once
/// that batch committed. An entry never changes afterwards, so a cached entry
/// always equals the stored one, and a version read from the database enters
/// the cache as well. A clone is the same storage as its original: one
/// database namespace and one cache.
///
/// Keys that are equal must have equal bytes: the cache identifies a key by
/// `Hash` and `Eq`, the database by its bytes.
#[derive(Clone)]
pub struct VersionMap<K>
where
    K: Clone + std::hash::Hash + Eq + Send + Sync,
{
    /// Database holding the entries.
    db: Arc<DB>,
    /// Key prefix byte of the entries' namespace.
    prefix: u8,
    /// Bounded cache in front of the entries; holds nothing at capacity `0`.
    cache: Cache<K, u64>,
}

impl<K> VersionMap<K>
where
    K: Clone + std::hash::Hash + Eq + Send + Sync + AsRef<[u8]>,
{
    /// Map over `db` under `prefix`, caching at most `cache_capacity` entries.
    pub fn new(db: Arc<DB>, prefix: u8, cache_capacity: usize) -> Self {
        Self { db, prefix, cache: Cache::new(CachePolicy::Count(cache_capacity)) }
    }

    /// Version registered for `key`; `None` when no version claims it. A
    /// cached entry answers directly; any other key is read from the database
    /// and, when it has a version, enters the cache. A stored value that is
    /// not eight bytes is a `DataInconsistency`, never a missing key, and is
    /// not cached.
    pub fn get(&self, key: &K) -> StoreResult<Option<u64>> {
        if let Some(version) = self.cache.get(key) {
            return Ok(Some(version));
        }
        let Some(bytes) = self.db.get(DbKey::new(&[self.prefix], key.as_ref())).map_err(StoreError::DbError)? else {
            return Ok(None);
        };
        let value: [u8; 8] =
            bytes.try_into().map_err(|_| StoreError::DataInconsistency("version map entry must be 8 big-endian bytes".to_string()))?;
        let version = u64::from_be_bytes(value);
        self.cache.insert(key.clone(), version);
        Ok(Some(version))
    }

    /// Put the registration of `key` at `version` into `writer`. Nothing is
    /// visible until those writes commit. The entry is written as given: the
    /// caller rejects a key that is already registered before calling this,
    /// because an overwritten entry would leave every cache still holding the
    /// old version.
    pub fn put(&self, writer: &mut impl DbWriter, key: &K, version: u64) -> StoreResult<()> {
        writer.put(DbKey::new(&[self.prefix], key.as_ref()), version.to_be_bytes()).map_err(StoreError::DbError)
    }

    /// Take the registration of `key` at `version` into the cache. Call it only
    /// after the batch that put the entry committed: a cached registration that
    /// was never committed would resolve a version that does not exist.
    pub fn write_through(&self, key: &K, version: u64) {
        self.cache.insert(key.clone(), version);
    }

    /// Whether `key` is in the cache. Test introspection: production code
    /// observes the cache through read and write behavior, never directly.
    #[cfg(any(test, feature = "test-util"))]
    pub fn is_cached(&self, key: &K) -> bool {
        self.cache.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use rocksdb::WriteBatch;

    use super::VersionMap;
    use crate::prelude::{BatchDbWriter, ConnBuilder, DB, DbKey, StoreError};
    use crate::{create_temp_db, registry::DatabaseStorePrefixes};

    /// Test key type: eight bytes, the big-endian image of a `u64`.
    type Key = [u8; 8];

    /// Eight-byte key of `n`.
    fn key(n: u8) -> Key {
        (n as u64).to_be_bytes()
    }

    /// Register `key` at `version` through `map` in a batch of its own.
    fn commit(db: &DB, map: &VersionMap<Key>, key: &Key, version: u64) {
        let mut batch = WriteBatch::default();
        map.put(&mut BatchDbWriter::new(&mut batch), key, version).unwrap();
        db.write(batch).unwrap();
    }

    /// An entry is `prefix | key` to the version as eight big-endian bytes; a
    /// map opened later over the same database, with or without a cache, reads
    /// it, and an unknown key reads as absent.
    #[test]
    fn put_layout_and_restart() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let prefix: u8 = DatabaseStorePrefixes::DagKnightConflictZoneVersions.into();
        let map = VersionMap::new(db.clone(), prefix, 4);
        let version = 0x0102_0304_0506_0708;
        commit(&db, &map, &key(1), version);

        let mut raw = vec![prefix];
        raw.extend_from_slice(&key(1));
        assert_eq!(db.get(raw).unwrap().unwrap(), version.to_be_bytes());
        assert_eq!(map.get(&key(1)).unwrap(), Some(version));
        assert_eq!(map.get(&key(2)).unwrap(), None);
        assert_eq!(VersionMap::<Key>::new(db, prefix, 0).get(&key(1)).unwrap(), Some(version));
    }

    /// A stored value that is not eight bytes is a data inconsistency, never a missing key.
    #[test]
    fn malformed_value_reads_error() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let prefix: u8 = DatabaseStorePrefixes::DagKnightConflictZoneVersions.into();
        let map = VersionMap::new(db.clone(), prefix, 4);
        commit(&db, &map, &key(1), 1);
        db.put(DbKey::new(&[prefix], key(1)), [0u8; 7].as_slice()).unwrap();

        let error = map.get(&key(1)).unwrap_err();
        assert!(matches!(error, StoreError::DataInconsistency(ref message) if message.contains("8 big-endian bytes")));
    }

    /// The cache never exceeds its capacity. An entry it dropped is served by
    /// the database and re-enters the cache, and so does an entry read after
    /// the cache is emptied.
    #[test]
    fn cache_then_db_fallback_with_refill() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let prefix: u8 = DatabaseStorePrefixes::DagKnightConflictZoneVersions.into();
        let map = VersionMap::new(db.clone(), prefix, 2);
        let keys = [key(1), key(2), key(3)];
        for k in &keys {
            commit(&db, &map, k, 7);
            map.write_through(k, 7);
        }
        assert_eq!(keys.iter().filter(|k| map.is_cached(k)).count(), 2, "the cache never exceeds its capacity");
        let evicted = keys.iter().find(|k| !map.is_cached(k)).unwrap();
        assert_eq!(map.get(evicted).unwrap(), Some(7), "an evicted entry is served by the database");
        assert!(map.is_cached(evicted), "a read refills the cache");
        assert_eq!(keys.iter().filter(|k| map.is_cached(k)).count(), 2, "a refill never exceeds the capacity");

        map.cache.remove_all();
        assert!(keys.iter().all(|k| !map.is_cached(k)));
        assert_eq!(map.get(&keys[0]).unwrap(), Some(7), "an empty cache changes no answer");
        assert!(map.is_cached(&keys[0]), "a read after the cache is emptied refills it");
    }
}

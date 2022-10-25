use std::{fmt::Display, sync::Arc};

use super::{
    database::prelude::{BatchDbWriter, CachedDbAccessForCopy, DirectDbWriter},
    errors::{StoreError, StoreResult},
    DB,
};
use hashes::Hash;
use rocksdb::WriteBatch;

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct Key([u8; 8]);

impl From<u64> for Key {
    fn from(value: u64) -> Self {
        Self(value.to_le_bytes()) // TODO: Consider using big-endian for future ordering.
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from_le_bytes(self.0))
    }
}

pub trait PastPruningPointsStoreReader {
    fn get(&self, index: u64) -> StoreResult<Hash>;
}

pub trait PastPruningPointsStore: PastPruningPointsStoreReader {
    // This is append only
    fn insert(&self, index: u64, pruning_point: Hash) -> StoreResult<()>;
}

const STORE_PREFIX: &[u8] = b"past-pruning-points";

/// A DB + cache implementation of `PastPruningPointsStore` trait, with concurrency support.
#[derive(Clone)]
pub struct DbPastPruningPointsStore {
    raw_db: Arc<DB>,
    // `CachedDbAccess` is shallow cloned so no need to wrap with Arc
    cached_access: CachedDbAccessForCopy<Key, Hash>,
}

impl DbPastPruningPointsStore {
    pub fn new(db: Arc<DB>, cache_size: u64) -> Self {
        Self { raw_db: Arc::clone(&db), cached_access: CachedDbAccessForCopy::new(Arc::clone(&db), cache_size, STORE_PREFIX) }
    }

    pub fn clone_with_new_cache(&self, cache_size: u64) -> Self {
        Self::new(Arc::clone(&self.raw_db), cache_size)
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, index: u64, pruning_point: Hash) -> Result<(), StoreError> {
        if self.cached_access.has(index.into())? {
            return Err(StoreError::KeyAlreadyExists(index.to_string()));
        }
        self.cached_access.write(BatchDbWriter::new(batch), index.into(), pruning_point)?;
        Ok(())
    }
}

impl PastPruningPointsStoreReader for DbPastPruningPointsStore {
    fn get(&self, index: u64) -> StoreResult<Hash> {
        self.cached_access.read(index.into())
    }
}

impl PastPruningPointsStore for DbPastPruningPointsStore {
    fn insert(&self, index: u64, pruning_point: Hash) -> StoreResult<()> {
        if self.cached_access.has(index.into())? {
            return Err(StoreError::KeyAlreadyExists(index.to_string()));
        }
        self.cached_access.write(DirectDbWriter::new(&self.raw_db), index.into(), pruning_point)?;
        Ok(())
    }
}
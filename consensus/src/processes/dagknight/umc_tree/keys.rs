//! Byte-keyed storage layout of the UMC tree: zerocopy key structs shared by the
//! memory and database levels, so cache ordering equals DB ordering.
//!
//! All multi-byte fields are big-endian, so bytewise order equals numeric order.
//! Versions are stored reversed (`u64::MAX - version`), so a forward scan at one
//! coordinate or k-partition yields its records newest first. `k` is `KType` (`u16`,
//! two bytes). Namespace prefix bytes come from the `DatabaseStorePrefixes` registry.

use zerocopy::byteorder::big_endian::{U16, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use kaspa_consensus_core::KType;

/// Reversed version index: `u64::MAX - version` in big-endian.
///
/// The latest version sorts first under forward byte iteration, so seeking a
/// coordinate prefix and stepping forward walks its records newest first.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct RevVersion(U64);

impl RevVersion {
    /// Encode `version` in reversed ordering.
    #[inline]
    pub const fn new(version: u64) -> Self {
        Self(U64::new(u64::MAX - version))
    }

    /// Decode the logical (ascending) version.
    #[inline]
    pub const fn version(&self) -> u64 {
        u64::MAX - self.0.get()
    }
}

/// Node record key: `prefix(1) | k(2 BE) | h(2 BE) | j(8 BE) | rev_version(8 BE)` = 21 bytes.
///
/// All versions of one coordinate sort adjacently, newest first; coordinates sort
/// by k, then level, then position. A range scan from [`NodeKey::seek_latest`] yields
/// the coordinate's records newest first and stops at the first key outside the
/// [`NodeKey::COORDINATE_PREFIX_LEN`] prefix.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct NodeKey {
    /// Namespace prefix byte.
    prefix: u8,
    /// K-partition of the tree.
    k: U16,
    /// Level above the leaves.
    h: U16,
    /// Position within the level.
    j: U64,
    /// Reversed version of the record.
    rev_version: RevVersion,
}

impl NodeKey {
    /// Length of the coordinate identity `prefix | k | h | j`; keys sharing these
    /// bytes belong to the same coordinate.
    pub const COORDINATE_PREFIX_LEN: usize = 13;

    /// Exact key of the record at `(k, h, j, version)`.
    #[inline]
    pub const fn new(prefix: u8, k: KType, h: u16, j: u64, version: u64) -> Self {
        Self { prefix, k: U16::new(k), h: U16::new(h), j: U64::new(j), rev_version: RevVersion::new(version) }
    }

    /// Smallest key of coordinate `(k, h, j)`; a range scan from here yields its records newest first.
    #[inline]
    pub const fn seek_latest(prefix: u8, k: KType, h: u16, j: u64) -> Self {
        Self { prefix, k: U16::new(k), h: U16::new(h), j: U64::new(j), rev_version: RevVersion::new(u64::MAX) }
    }

    /// Logical (ascending) version encoded in the key.
    #[inline]
    pub const fn version(&self) -> u64 {
        self.rev_version.version()
    }
}

impl AsRef<[u8]> for NodeKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Version-metadata key: `prefix(1) | k(2 BE) | rev_version(8 BE)` = 11 bytes.
///
/// Newest-first per k; the first key of the `prefix | k` range names the most
/// recently published version of that k.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct VersionKey {
    /// Namespace prefix byte.
    prefix: u8,
    /// K-partition of the metadata entry.
    k: U16,
    /// Reversed published version.
    rev_version: RevVersion,
}

impl VersionKey {
    /// Length of the k-partition identity `prefix | k`; keys sharing these bytes
    /// belong to the same k.
    pub const K_PREFIX_LEN: usize = 3;

    /// Exact key of `version`'s metadata within `k`.
    #[inline]
    pub const fn new(prefix: u8, k: KType, version: u64) -> Self {
        Self { prefix, k: U16::new(k), rev_version: RevVersion::new(version) }
    }

    /// Smallest key of partition `k`; a range scan from here yields its versions newest first.
    #[inline]
    pub const fn seek_latest(prefix: u8, k: KType) -> Self {
        Self { prefix, k: U16::new(k), rev_version: RevVersion::new(u64::MAX) }
    }

    /// Logical (ascending) version encoded in the key.
    #[inline]
    pub const fn version(&self) -> u64 {
        self.rev_version.version()
    }
}

impl AsRef<[u8]> for VersionKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 21-byte layout: prefix, k, h, j, reversed version; newest-first and coordinate-major ordering.
    #[test]
    fn node_key_layout() {
        let key = NodeKey::new(82, 3, 4, 7, 1000);
        let bytes = key.as_bytes();
        assert_eq!(bytes.len(), 21);
        assert_eq!(bytes[0], 82);
        assert_eq!(&bytes[1..3], &3u16.to_be_bytes());
        assert_eq!(&bytes[3..5], &4u16.to_be_bytes());
        assert_eq!(&bytes[5..13], &7u64.to_be_bytes());
        assert_eq!(&bytes[13..21], &(u64::MAX - 1000).to_be_bytes());

        // Later versions sort first at the same coordinate.
        assert!(NodeKey::new(82, 3, 4, 7, 1001) < NodeKey::new(82, 3, 4, 7, 1000));
        // Coordinates sort by k, then level, then position.
        assert!(NodeKey::new(82, 3, 4, 7, 0) < NodeKey::new(82, 4, 1, 0, 0));
        assert!(NodeKey::new(82, 3, 4, 7, 0) < NodeKey::new(82, 3, 5, 1, 0));
        assert!(NodeKey::new(82, 3, 4, 7, 0) < NodeKey::new(82, 3, 4, 8, 0));
        // Seek lands at the newest possible version of the coordinate.
        assert!(NodeKey::seek_latest(82, 3, 4, 7) <= NodeKey::new(82, 3, 4, 7, u64::MAX));
        // The first 13 bytes identify the coordinate across versions.
        let a = NodeKey::new(82, 3, 4, 7, 1);
        let b = NodeKey::new(82, 3, 4, 7, 9);
        assert_eq!(&a.as_bytes()[..NodeKey::COORDINATE_PREFIX_LEN], &b.as_bytes()[..NodeKey::COORDINATE_PREFIX_LEN]);
        let c = NodeKey::new(82, 3, 4, 8, 1);
        assert_ne!(&a.as_bytes()[..NodeKey::COORDINATE_PREFIX_LEN], &c.as_bytes()[..NodeKey::COORDINATE_PREFIX_LEN]);
    }

    /// 11-byte layout: prefix, k, reversed version; newest-first per k, k-major across partitions.
    #[test]
    fn version_key_layout() {
        let key = VersionKey::new(83, 5, 42);
        let bytes = key.as_bytes();
        assert_eq!(bytes.len(), 11);
        assert_eq!(bytes[0], 83);
        assert_eq!(&bytes[1..3], &5u16.to_be_bytes());
        assert_eq!(&bytes[3..11], &(u64::MAX - 42).to_be_bytes());

        // Later versions sort first within one k.
        assert!(VersionKey::new(83, 5, 43) < VersionKey::new(83, 5, 42));
        // Partitions sort by k.
        assert!(VersionKey::new(83, 5, 0) < VersionKey::new(83, 6, 0));
        // The first 3 bytes identify the k partition across versions.
        let a = VersionKey::new(83, 5, 1);
        let b = VersionKey::new(83, 5, 9);
        assert_eq!(&a.as_bytes()[..VersionKey::K_PREFIX_LEN], &b.as_bytes()[..VersionKey::K_PREFIX_LEN]);
    }
}

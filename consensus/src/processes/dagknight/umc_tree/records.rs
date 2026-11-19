//! Domain types of the UMC tree: scores, coordinates, node records, published-state
//! metadata, the geometry helpers shared by every storage level, and the fixed-layout
//! zerocopy wire encoding the DB level persists.
//!
//! Records are immutable once published; a record is identified by the version that
//! wrote it plus its tree coordinate. `NodeRecord` and `VersionMetadata` are the
//! serialization units of the DB level: they encode into the padding-free wire
//! structs below ([`LeafWire`], [`InternalWire`], [`VersionMetadataWire`]) via the
//! [`ScoreWire`]/[`ValueWire`] codecs. Nothing in this module is serde.

use num_traits::Zero;
use zerocopy::byteorder::big_endian::{I64, U16, U64};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use kaspa_database::prelude::StoreResult;
use kaspa_hashes::Hash;
use kaspa_math::Uint192;

use crate::processes::dagknight::umc_voting::SignedWork;

/// Score arithmetic of the tree: ordered, signed quantities supporting `+` and `-` around a zero.
pub trait Score: Copy + Ord + Zero {}

impl<T> Score for T where T: Copy + Ord + Zero {}

/// Tree coordinate: level `h` and position `j`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct NodeCoord {
    /// Level above the leaves; `h == 0` is a leaf.
    pub h: u16,
    /// Position within the level; a node covers the leaf range `[j << h, (j+1) << h)`.
    pub j: u64,
}

/// Immutable handle to one node record: the version selects it, `h` and `j` give its geometry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeRef {
    /// Version whose publish wrote the referenced record.
    pub version: u64,
    /// Level above the leaves; `h == 0` is a leaf.
    pub h: u16,
    /// Position within the level.
    pub j: u64,
}

/// One blue leaf with its fully-resolved score.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeafScore<T, S> {
    /// Leaf value (the block hash at the Dagknight instantiation).
    pub value: T,
    /// Effective score including pending additions held on strict ancestors.
    pub score: S,
}

/// A node record paired with the version that wrote it.
#[derive(Clone, Debug)]
pub struct VersionedNode<T, S> {
    /// Version whose publish wrote `record`.
    pub version: u64,
    /// The record itself.
    pub record: NodeRecord<T, S>,
}

/// One tree node. Internal records hold child versions only; geometry supplies child coordinates.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeRecord<T, S> {
    Leaf {
        /// Minimum (and only) score of the leaf.
        minimum: S,
        /// Leaf value.
        value: T,
    },
    Internal {
        /// `None` while no leaf exists below this node (+infinity).
        minimum: Option<S>,
        /// Lazy addition owed to the whole subtree; pushed to children before they split.
        pending_addition: S,
        /// Value at the last position of the left half; `None` until that position arrives.
        boundary: Option<T>,
        /// Version of the left child at `(h-1, 2j)`, or `None` while absent.
        left_version: Option<u64>,
        /// Version of the right child at `(h-1, 2j+1)`, or `None` while absent.
        right_version: Option<u64>,
    },
}

/// Published-state metadata, one per version.
#[derive(Clone, Debug, PartialEq)]
pub struct VersionMetadata {
    /// Version this state extends, or `None` for an initial state.
    pub anchor_version: Option<u64>,
    /// Version of the root record, or `None` for an empty state.
    pub root_version: Option<u64>,
    /// Height of the root; `0` while the tree has at most one leaf.
    pub root_height: u16,
    /// Number of leaves, inherited ones included.
    pub blue_count: u64,
}

/// Fixed-layout storage encoding of a score: `Wire` is the padding-free,
/// byte-aligned zerocopy form persisted inside the record wire structs.
pub trait ScoreWire: Score {
    /// Stored form. Must be padding-free and byte-aligned: zerocopy's `IntoBytes`
    /// forbids padding (any padded layout cannot be written), so the wire type is
    /// byte-oriented.
    type Wire: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned;

    /// Encode into the wire form.
    fn to_wire(&self) -> Self::Wire;

    /// Decode from the wire form.
    fn from_wire(wire: &Self::Wire) -> Self;
}

/// Score wire of the test instantiation: big-endian `i64`.
impl ScoreWire for i64 {
    type Wire = I64;

    fn to_wire(&self) -> I64 {
        I64::new(*self)
    }

    fn from_wire(wire: &I64) -> Self {
        wire.get()
    }
}

/// 25-byte padding-free storage form of `SignedWork` (`SignedInteger<Uint192>`):
/// magnitude limbs least-significant first, each little-endian, then a sign byte.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SignedWorkWire {
    /// Magnitude: three `Uint192` limbs, each little-endian in-memory limb order.
    abs: [u8; 24],
    /// 1 when negative, 0 otherwise; negative zero is representable and compares
    /// equal to positive zero after decoding.
    negative: u8,
}

impl ScoreWire for SignedWork {
    type Wire = SignedWorkWire;

    fn to_wire(&self) -> SignedWorkWire {
        let mut abs = [0u8; 24];
        for (i, limb) in self.abs().0.iter().enumerate() {
            abs[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        SignedWorkWire { abs, negative: self.negative() as u8 }
    }

    fn from_wire(wire: &SignedWorkWire) -> Self {
        let mut limbs = [0u64; 3];
        let (chunks, _) = wire.abs.as_chunks::<8>();
        for (limb, chunk) in limbs.iter_mut().zip(chunks) {
            *limb = u64::from_le_bytes(*chunk);
        }
        let magnitude = SignedWork::from(Uint192(limbs));
        if wire.negative == 1 { SignedWork::zero() - magnitude } else { magnitude }
    }
}

/// Fixed-layout storage encoding of a leaf value: `Wire` is the padding-free,
/// byte-aligned zerocopy form persisted inside the record wire structs.
///
/// A raw `IntoBytes` bound on `T` is not enough: an aligned value field (say
/// `u64`) would pad the surrounding `#[repr(C)]` layout, which zerocopy forbids,
/// so values cross the storage boundary through a codec like scores do.
pub trait ValueWire: Clone {
    /// Stored form. Must be padding-free and byte-aligned like [`ScoreWire::Wire`].
    type Wire: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned;

    /// Encode into the wire form.
    fn to_wire(&self) -> Self::Wire;

    /// Decode from the wire form.
    fn from_wire(wire: &Self::Wire) -> Self;
}

/// Value wire of the test instantiation: big-endian `u64`, consistent with the keys.
impl ValueWire for u64 {
    type Wire = U64;

    fn to_wire(&self) -> U64 {
        U64::new(*self)
    }

    fn from_wire(wire: &U64) -> Self {
        wire.get()
    }
}

/// Value wire of the production instantiation: `Hash` is already a padding-free
/// zerocopy type behind the crate's `zerocopy` feature, so the codec is the identity.
impl ValueWire for Hash {
    type Wire = Hash;

    fn to_wire(&self) -> Hash {
        *self
    }

    fn from_wire(wire: &Hash) -> Self {
        *wire
    }
}

/// Kind discriminant of a node record value: the first byte of every node
/// encoding. `TryFromBytes` validates the discriminant, so a corrupt or foreign
/// tag is rejected at decode.
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum NodeKind {
    /// Leaf record: one score and one value.
    Leaf = 0,
    /// Internal record: children, lazy addition, boundary.
    Internal = 1,
}

impl NodeKind {
    /// Tag byte of [`NodeKind::Leaf`].
    const LEAF_TAG: u8 = NodeKind::Leaf as u8;

    /// Tag byte of [`NodeKind::Internal`].
    const INTERNAL_TAG: u8 = NodeKind::Internal as u8;
}

/// Presence bits of the optional fields of an internal record value. A clear bit
/// means the field is absent: absent child means missing subtree, absent minimum
/// means +infinity. The payload bytes of absent fields are written zeroed and
/// ignored by readers, so no sentinel values are burned.
mod record_flags {
    /// Internal minimum present.
    pub(super) const MINIMUM: u8 = 1 << 0;
    /// Boundary value present.
    pub(super) const BOUNDARY: u8 = 1 << 1;
    /// Left child version present.
    pub(super) const LEFT: u8 = 1 << 2;
    /// Right child version present.
    pub(super) const RIGHT: u8 = 1 << 3;
}

/// Presence bits of the optional fields of a version-metadata value.
mod metadata_flags {
    /// Anchor version present.
    pub(super) const ANCHOR: u8 = 1 << 0;
    /// Root version present.
    pub(super) const ROOT: u8 = 1 << 1;
}

/// Leaf record value: `kind(1) | minimum(|W|) | value(|V|)`, all fields
/// byte-aligned, so the `#[repr(C)]` layout is fixed and padding-free: 17 bytes
/// at the test instantiation (`u64`/`i64`), 58 at production (`Hash`/`SignedWork`).
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct LeafWire<W, V> {
    /// Kind discriminant; always [`NodeKind::Leaf`].
    kind: NodeKind,
    /// Minimum (and only) score of the leaf.
    minimum: W,
    /// Leaf value.
    value: V,
}

/// Internal record value: `kind(1) | flags(1) | minimum(|W|) | pending_addition(|W|)
/// | boundary(|V|) | left_version(8 BE) | right_version(8 BE)`, all fields
/// byte-aligned: 42 bytes at the test instantiation, 100 at production. Optional
/// fields ride the [`record_flags`] presence bitmap; absent payloads are written
/// zeroed and ignored on read.
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct InternalWire<W, V> {
    /// Kind discriminant; always [`NodeKind::Internal`].
    kind: NodeKind,
    /// Presence bits of the optional fields ([`record_flags`]).
    flags: u8,
    /// Subtree minimum; ignored unless `MINIMUM` is set (clear = +infinity).
    minimum: W,
    /// Lazy addition owed to the whole subtree.
    pending_addition: W,
    /// Value at the last position of the left half; ignored unless `BOUNDARY` is set.
    boundary: V,
    /// Version of the left child at `(h-1, 2j)`; ignored unless `LEFT` is set.
    left_version: U64,
    /// Version of the right child at `(h-1, 2j+1)`; ignored unless `RIGHT` is set.
    right_version: U64,
}

/// Version-metadata value: `flags(1) | anchor_version(8 BE) | root_version(8 BE)
/// | root_height(2 BE) | blue_count(8 BE)` = 27 bytes at every instantiation.
/// Optional fields ride the [`metadata_flags`] presence bitmap.
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct VersionMetadataWire {
    /// Presence bits of the optional fields ([`metadata_flags`]).
    flags: u8,
    /// Version this state extends; ignored unless `ANCHOR` is set.
    anchor_version: U64,
    /// Version of the root record; ignored unless `ROOT` is set.
    root_version: U64,
    /// Height of the root.
    root_height: U16,
    /// Number of leaves, inherited ones included.
    blue_count: U64,
}

/// Owned wire encoding of one node record: the fixed-layout leaf or internal
/// form, handing the writer its exact byte slice without allocation.
pub(crate) enum NodeWire<W, V> {
    /// Wire form of a leaf record.
    Leaf(LeafWire<W, V>),
    /// Wire form of an internal record.
    Internal(InternalWire<W, V>),
}

impl<W: IntoBytes + Immutable + Unaligned, V: IntoBytes + Immutable + Unaligned> NodeWire<W, V> {
    /// Wire bytes of the encoded record; writers persist exactly these.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            NodeWire::Leaf(wire) => wire.as_bytes(),
            NodeWire::Internal(wire) => wire.as_bytes(),
        }
    }
}

/// Wire form of an optional field: present values encode their payload, absent
/// ones write zeroes (readers ignore the payload when the flag bit is clear).
fn opt_wire<X, W: FromZeros>(field: &Option<X>, encode: impl FnOnce(&X) -> W) -> W {
    field.as_ref().map(encode).unwrap_or_else(W::new_zeroed)
}

/// Encode a node record into its fixed-layout wire form.
pub(crate) fn encode_node<T: ValueWire, S: ScoreWire>(record: &NodeRecord<T, S>) -> NodeWire<S::Wire, T::Wire> {
    match record {
        NodeRecord::Leaf { minimum, value } => {
            NodeWire::Leaf(LeafWire { kind: NodeKind::Leaf, minimum: minimum.to_wire(), value: T::to_wire(value) })
        }
        NodeRecord::Internal { minimum, pending_addition, boundary, left_version, right_version } => {
            let mut flags = 0;
            if minimum.is_some() {
                flags |= record_flags::MINIMUM;
            }
            if boundary.is_some() {
                flags |= record_flags::BOUNDARY;
            }
            if left_version.is_some() {
                flags |= record_flags::LEFT;
            }
            if right_version.is_some() {
                flags |= record_flags::RIGHT;
            }
            NodeWire::Internal(InternalWire {
                kind: NodeKind::Internal,
                flags,
                minimum: opt_wire(minimum, S::to_wire),
                pending_addition: pending_addition.to_wire(),
                boundary: opt_wire(boundary, T::to_wire),
                left_version: U64::new(left_version.unwrap_or(0)),
                right_version: U64::new(right_version.unwrap_or(0)),
            })
        }
    }
}

/// Decode a node record from its wire bytes: prefix-parse the known revision and
/// ignore any trailing bytes (append-only trailing-field evolution, so a newer
/// build may grow the record). Errors describe the layout fault; callers add the
/// key coordinates.
pub(crate) fn decode_node<T: ValueWire, S: ScoreWire>(bytes: &[u8]) -> Result<NodeRecord<T, S>, String> {
    let Some(&tag) = bytes.first() else { return Err("empty node record".to_string()) };
    match tag {
        NodeKind::LEAF_TAG => {
            let (wire, _tail) = LeafWire::<S::Wire, T::Wire>::try_read_from_prefix(bytes).map_err(|e| format!("leaf record: {e}"))?;
            Ok(NodeRecord::Leaf { minimum: S::from_wire(&wire.minimum), value: T::from_wire(&wire.value) })
        }
        NodeKind::INTERNAL_TAG => {
            let (wire, _tail) =
                InternalWire::<S::Wire, T::Wire>::try_read_from_prefix(bytes).map_err(|e| format!("internal record: {e}"))?;
            Ok(NodeRecord::Internal {
                minimum: (wire.flags & record_flags::MINIMUM != 0).then(|| S::from_wire(&wire.minimum)),
                pending_addition: S::from_wire(&wire.pending_addition),
                boundary: (wire.flags & record_flags::BOUNDARY != 0).then(|| T::from_wire(&wire.boundary)),
                left_version: (wire.flags & record_flags::LEFT != 0).then(|| wire.left_version.get()),
                right_version: (wire.flags & record_flags::RIGHT != 0).then(|| wire.right_version.get()),
            })
        }
        other => Err(format!("invalid node kind byte {other}")),
    }
}

/// Encode published-state metadata into its fixed-layout wire form.
pub(crate) fn encode_metadata(metadata: &VersionMetadata) -> VersionMetadataWire {
    let mut flags = 0;
    if metadata.anchor_version.is_some() {
        flags |= metadata_flags::ANCHOR;
    }
    if metadata.root_version.is_some() {
        flags |= metadata_flags::ROOT;
    }
    VersionMetadataWire {
        flags,
        anchor_version: U64::new(metadata.anchor_version.unwrap_or(0)),
        root_version: U64::new(metadata.root_version.unwrap_or(0)),
        root_height: U16::new(metadata.root_height),
        blue_count: U64::new(metadata.blue_count),
    }
}

/// Decode published-state metadata from its wire bytes, prefix-parsing the known
/// revision like [`decode_node`]. Errors describe the layout fault; callers add
/// the key coordinates.
pub(crate) fn decode_metadata(bytes: &[u8]) -> Result<VersionMetadata, String> {
    let (wire, _tail) = VersionMetadataWire::try_read_from_prefix(bytes).map_err(|e| format!("version metadata: {e}"))?;
    Ok(VersionMetadata {
        anchor_version: (wire.flags & metadata_flags::ANCHOR != 0).then(|| wire.anchor_version.get()),
        root_version: (wire.flags & metadata_flags::ROOT != 0).then(|| wire.root_version.get()),
        root_height: wire.root_height.get(),
        blue_count: wire.blue_count.get(),
    })
}

/// Leaf range covered by `r`: `[j << h, (j+1) << h)`.
#[inline]
pub(crate) fn bounds(r: NodeRef) -> (u64, u64) {
    (r.j << r.h, (r.j + 1) << r.h)
}

/// Child of an internal `parent` on `side` (0 = left, 1 = right), or `None` when absent.
#[inline]
pub(crate) fn child_of(parent: NodeRef, version: Option<u64>, side: u64) -> Option<NodeRef> {
    version.map(|version| NodeRef { version, h: parent.h - 1, j: parent.j * 2 + side })
}

/// Minimum of two optional scores, where `None` is +infinity.
#[inline]
pub(crate) fn min_opt<S: Score>(a: Option<S>, b: Option<S>) -> Option<S> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

/// Materialize leaf scores plus pending additions held on strict ancestors.
///
/// Walks the published tree rooted at `root` in leaf order, carrying each internal
/// node's pending addition down to its leaves. An absent root yields an empty vector.
/// `load` supplies an owned record per reference; a missing or failing load aborts
/// the walk with its error.
pub fn collect_scores<T: Clone, S: Score>(
    root: Option<NodeRef>,
    mut load: impl FnMut(NodeRef) -> StoreResult<NodeRecord<T, S>>,
) -> StoreResult<Vec<LeafScore<T, S>>> {
    /// Recursive worker carrying the accumulated pending addition `carry`.
    fn visit<T: Clone, S: Score>(
        load: &mut impl FnMut(NodeRef) -> StoreResult<NodeRecord<T, S>>,
        r: Option<NodeRef>,
        carry: S,
        out: &mut Vec<LeafScore<T, S>>,
    ) -> StoreResult<()> {
        let Some(r) = r else { return Ok(()) };
        match load(r)? {
            NodeRecord::Leaf { minimum, value } => out.push(LeafScore { value, score: minimum + carry }),
            NodeRecord::Internal { pending_addition, left_version, right_version, .. } => {
                let carry = carry + pending_addition;
                visit(load, child_of(r, left_version, 0), carry, out)?;
                visit(load, child_of(r, right_version, 1), carry, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(&mut load, root, S::zero(), &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire sizes are pinned: 17/42/27 bytes at the test instantiation,
    /// 58/100/27 at production, 25 for the SignedWork score wire.
    #[test]
    fn wire_sizes() {
        assert_eq!(std::mem::size_of::<LeafWire<I64, U64>>(), 17);
        assert_eq!(std::mem::size_of::<InternalWire<I64, U64>>(), 42);
        assert_eq!(std::mem::size_of::<VersionMetadataWire>(), 27);
        assert_eq!(std::mem::size_of::<SignedWorkWire>(), 25);
        assert_eq!(std::mem::size_of::<LeafWire<SignedWorkWire, Hash>>(), 58);
        assert_eq!(std::mem::size_of::<InternalWire<SignedWorkWire, Hash>>(), 100);
    }

    /// Exact byte layout of the internal record at the test instantiation:
    /// kind, flags, minimum, pending, boundary, left, right, all big-endian.
    #[test]
    fn internal_wire_offsets() {
        let record = NodeRecord::<u64, i64>::Internal {
            minimum: Some(1),
            pending_addition: 2,
            boundary: Some(3),
            left_version: Some(4),
            right_version: Some(5),
        };
        let wire = encode_node(&record);
        let bytes = wire.as_bytes();
        assert_eq!(bytes.len(), 42);
        assert_eq!(bytes[0], NodeKind::Internal as u8);
        assert_eq!(bytes[1], record_flags::MINIMUM | record_flags::BOUNDARY | record_flags::LEFT | record_flags::RIGHT);
        assert_eq!(&bytes[2..10], &1i64.to_be_bytes());
        assert_eq!(&bytes[10..18], &2i64.to_be_bytes());
        assert_eq!(&bytes[18..26], &3u64.to_be_bytes());
        assert_eq!(&bytes[26..34], &4u64.to_be_bytes());
        assert_eq!(&bytes[34..42], &5u64.to_be_bytes());
    }

    /// Every Option combination round-trips through the flags byte; clear flags
    /// write zeroed payloads and decode to `None` regardless of those bytes.
    #[test]
    fn option_flags_roundtrip_both_ways() {
        let leaf = NodeRecord::<u64, i64>::Leaf { minimum: -5, value: 7 };
        assert_eq!(decode_node(encode_node(&leaf).as_bytes()).unwrap(), leaf);
        for minimum in [None, Some(-7i64)] {
            for boundary in [None, Some(9u64)] {
                for left in [None, Some(11u64)] {
                    for right in [None, Some(13u64)] {
                        let record = NodeRecord::<u64, i64>::Internal {
                            minimum,
                            pending_addition: 5,
                            boundary,
                            left_version: left,
                            right_version: right,
                        };
                        assert_eq!(decode_node(encode_node(&record).as_bytes()).unwrap(), record);
                    }
                }
            }
        }
        // Absent payloads are written zeroed ...
        let record = NodeRecord::<u64, i64>::Internal {
            minimum: None,
            pending_addition: 5,
            boundary: None,
            left_version: None,
            right_version: Some(7),
        };
        let mut bytes = encode_node(&record).as_bytes().to_vec();
        assert_eq!(bytes[1], record_flags::RIGHT);
        assert_eq!(&bytes[2..10], &[0u8; 8]);
        assert_eq!(&bytes[18..26], &[0u8; 8]);
        assert_eq!(&bytes[26..34], &[0u8; 8]);
        // ... and a reader ignores whatever sits under a clear flag bit.
        bytes[2..10].fill(0xFF);
        bytes[18..26].fill(0xFF);
        bytes[26..34].fill(0xFF);
        assert_eq!(decode_node(&bytes).unwrap(), record);
        // Metadata flags round-trip the same way.
        for anchor in [None, Some(3u64)] {
            for root in [None, Some(4u64)] {
                let metadata = VersionMetadata { anchor_version: anchor, root_version: root, root_height: 5, blue_count: 6 };
                assert_eq!(decode_metadata(encode_metadata(&metadata).as_bytes()).unwrap(), metadata);
            }
        }
    }

    /// `TryFromBytes` rejects a corrupt kind tag, a tag/length mismatch, and
    /// truncated records.
    #[test]
    fn kind_tag_and_truncation_rejected() {
        let bytes = encode_node(&NodeRecord::<u64, i64>::Leaf { minimum: 1, value: 2 }).as_bytes().to_vec();
        let mut bad_tag = bytes.clone();
        bad_tag[0] = 9;
        assert!(decode_node::<u64, i64>(&bad_tag).is_err());
        // The internal tag on a leaf-sized buffer: the struct parse fails on size.
        let mut wrong_kind = bytes.clone();
        wrong_kind[0] = NodeKind::Internal as u8;
        assert!(decode_node::<u64, i64>(&wrong_kind).is_err());
        assert!(decode_node::<u64, i64>(&[]).is_err());
        for len in 0..bytes.len() {
            assert!(decode_node::<u64, i64>(&bytes[..len]).is_err(), "truncated at {len} must not decode");
        }
        let metadata = VersionMetadata { anchor_version: None, root_version: Some(1), root_height: 2, blue_count: 3 };
        assert!(decode_metadata(&encode_metadata(&metadata).as_bytes()[..26]).is_err());
    }

    /// Records only ever grow by appending trailing fields: the reader
    /// prefix-parses the known revision and ignores the tail; a shorter buffer
    /// is an error (covered by the truncation test).
    #[test]
    fn trailing_field_prefix_decode() {
        let record = NodeRecord::<u64, i64>::Internal {
            minimum: Some(-1),
            pending_addition: 2,
            boundary: Some(3),
            left_version: Some(4),
            right_version: None,
        };
        let mut bytes = encode_node(&record).as_bytes().to_vec();
        bytes.extend_from_slice(&[0xEE; 8]); // a future trailing field this build does not know
        assert_eq!(decode_node(&bytes).unwrap(), record);
        let metadata = VersionMetadata { anchor_version: Some(1), root_version: Some(2), root_height: 3, blue_count: 4 };
        let mut meta = encode_metadata(&metadata).as_bytes().to_vec();
        meta.push(0xAB);
        assert_eq!(decode_metadata(&meta).unwrap(), metadata);
    }

    /// The 25-byte SignedWork wire round-trips values across sign flips and the
    /// full magnitude range; negative zero keeps its sign byte yet compares
    /// equal to positive zero after decoding.
    #[test]
    fn signed_work_wire_roundtrip() {
        let magnitude = SignedWork::from(Uint192([u64::MAX, 0xFEDC_BA98_7654_3210, 0x0123_4567_89AB_CDEF]));
        let negated = SignedWork::zero() - magnitude;
        for value in [
            SignedWork::zero(),
            SignedWork::from(Uint192::from_u64(1)),
            SignedWork::from(Uint192::from_u64(u64::MAX)),
            magnitude,
            negated,
        ] {
            assert_eq!(SignedWork::from_wire(&value.to_wire()), value);
        }
        // Sign byte and limb order: limbs least-significant first, each little-endian.
        let wire = magnitude.to_wire();
        assert_eq!(wire.negative, 0);
        assert_eq!(negated.to_wire().negative, 1);
        assert_eq!(&wire.abs[0..8], &u64::MAX.to_le_bytes());
        assert_eq!(&wire.abs[8..16], &0xFEDC_BA98_7654_3210u64.to_le_bytes());
        assert_eq!(&wire.abs[16..24], &0x0123_4567_89AB_CDEFu64.to_le_bytes());
        // Negative zero: sign byte set, zero magnitude, equal to +0 after decoding.
        let neg_zero = SignedWork::zero() - SignedWork::from(Uint192::from_u64(7)) + SignedWork::from(Uint192::from_u64(7));
        assert!(neg_zero.negative());
        let neg_zero_wire = neg_zero.to_wire();
        assert_eq!(neg_zero_wire.abs, [0u8; 24]);
        assert_eq!(neg_zero_wire.negative, 1);
        assert_eq!(SignedWork::from_wire(&neg_zero_wire), neg_zero);
        assert_eq!(SignedWork::from_wire(&neg_zero_wire), SignedWork::zero());
    }

    /// The production instantiation (`T = Hash`, `S = SignedWork`) round-trips
    /// leaf and internal records at the pinned 58/100-byte sizes.
    #[test]
    fn production_instantiation_roundtrip() {
        let hash = Hash::from_bytes([0xA5; 32]);
        let leaf = NodeRecord::Leaf { minimum: SignedWork::from(Uint192::from_u64(42)), value: hash };
        let encoded = encode_node(&leaf);
        assert_eq!(encoded.as_bytes().len(), 58);
        assert_eq!(decode_node::<Hash, SignedWork>(encoded.as_bytes()).unwrap(), leaf);
        let internal = NodeRecord::Internal {
            minimum: Some(SignedWork::zero() - SignedWork::from(Uint192::from_u64(3))),
            pending_addition: SignedWork::from(Uint192([1, 2, 3])),
            boundary: Some(hash),
            left_version: Some(9),
            right_version: None,
        };
        let encoded = encode_node(&internal);
        assert_eq!(encoded.as_bytes().len(), 100);
        assert_eq!(decode_node::<Hash, SignedWork>(encoded.as_bytes()).unwrap(), internal);
    }
}

use std::marker::PhantomData;

// ---------------------------------------------------------------------------
// Type markers
// ---------------------------------------------------------------------------

/// Marker for a numeric stack element. `S` is the rest of the stack beneath it.
pub struct Num<S>(PhantomData<S>);

/// Marker for a boolean stack element. `S` is the rest of the stack beneath it.
pub struct Bool<S>(PhantomData<S>);

/// Marker for generic data (bytes) on the stack. `S` is the rest of the stack beneath it.
pub struct Data<S>(PhantomData<S>);

/// Marker for a 32-byte hash value on the stack. `S` is the rest of the stack beneath it.
pub struct Hash<S>(PhantomData<S>);

/// Marker for a BN254 field element on the stack. `S` is the rest of the stack beneath it.
pub struct Bn254Fr<S>(PhantomData<S>);

/// Marker for a Groth16 ZK proof tag byte on the stack. `S` is the rest of the stack beneath it.
pub struct Groth16Tag<S>(PhantomData<S>);

/// Marker for a RISC0 succinct ZK proof tag byte on the stack. `S` is the rest of the stack beneath it.
pub struct R0SuccinctTag<S>(PhantomData<S>);

/// RISC0 succinct seal (a sequence of `u32` words serialized as little-endian bytes).
pub struct R0SuccinctSeal<S>(PhantomData<S>);

/// RISC0 succinct claim digest (exactly 32 bytes).
pub struct R0SuccinctClaim<S>(PhantomData<S>);

/// RISC0 hash-function identifier (1 byte: 0=Blake2b, 1=Poseidon2, 2=Sha256).
pub struct R0SuccinctHashFn<S>(PhantomData<S>);

/// RISC0 Merkle-tree control index (4 bytes, little-endian `u32`).
pub struct R0SuccinctControlIndex<S>(PhantomData<S>);

/// RISC0 control digests (concatenated 32-byte digests; length must be a multiple of 32).
pub struct R0SuccinctControlDigests<S>(PhantomData<S>);

/// RISC0 journal digest (exactly 32 bytes, typically the SHA-256 of the journal).
pub struct R0SuccinctJournalDigest<S>(PhantomData<S>);

/// RISC0 image ID (exactly 32 bytes).
pub struct R0SuccinctImageId<S>(PhantomData<S>);

/// Groth16 verification key (variable-length bytes, unprepared compressed format).
pub struct G16Vk<S>(PhantomData<S>);

/// Groth16 proof (variable-length bytes).
pub struct G16Proof<S>(PhantomData<S>);

/// Marker for a fixed-count group of N elements of type T.
/// `S` is the rest of the stack beneath the consumed elements.
pub struct FixedNum<const N: usize, T, S>(PhantomData<(T, S)>);

// ---------------------------------------------------------------------------
// StackEntry trait (sealed, with GAT)
// ---------------------------------------------------------------------------

pub(crate) mod sealed {
    pub trait Sealed {}
    pub trait NotBn254Fr {}
}

/// Trait implemented by all type-level stack markers.
pub trait StackEntry: sealed::Sealed {
    type Rest;
    type Wrap<T>;
}

macro_rules! impl_stack_entry {
    ($($Marker:ident),*) => {$(
        impl<S> sealed::Sealed for $Marker<S> {}
        impl<S> StackEntry for $Marker<S> {
            type Rest = S;
            type Wrap<T> = $Marker<T>;
        }
    )*};
}
impl_stack_entry!(
    Num,
    Bool,
    Data,
    Hash,
    Bn254Fr,
    Groth16Tag,
    R0SuccinctTag,
    R0SuccinctSeal,
    R0SuccinctClaim,
    R0SuccinctHashFn,
    R0SuccinctControlIndex,
    R0SuccinctControlDigests,
    R0SuccinctJournalDigest,
    R0SuccinctImageId,
    G16Vk,
    G16Proof
);

impl<const N: usize, T, S> sealed::Sealed for FixedNum<N, T, S> {}
impl<const N: usize, T, S> StackEntry for FixedNum<N, T, S> {
    type Rest = S;
    type Wrap<U> = FixedNum<N, T, U>;
}
impl<const N: usize, T, S> sealed::NotBn254Fr for FixedNum<N, T, S> {}

macro_rules! impl_not_bn254fr {
    ($($Marker:ident),*) => {$(
        impl<S> sealed::NotBn254Fr for $Marker<S> {}
    )*};
}
impl_not_bn254fr!(
    Num,
    Bool,
    Data,
    Hash,
    Groth16Tag,
    R0SuccinctTag,
    R0SuccinctSeal,
    R0SuccinctClaim,
    R0SuccinctHashFn,
    R0SuccinctControlIndex,
    R0SuccinctControlDigests,
    R0SuccinctJournalDigest,
    R0SuccinctImageId,
    G16Vk,
    G16Proof
);
impl sealed::NotBn254Fr for () {}

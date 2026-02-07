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

/// Marker for a conditional branch in the Missing type.
/// `T` is the true-branch Missing, `F` is the false-branch Missing.
/// Used when a `Bool` comes from the sig script (not on the stack).
pub struct Or<T, F>(PhantomData<(T, F)>);

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

// ---------------------------------------------------------------------------
// AddToMissing trait — distributes new Missing layers into Or branches
// ---------------------------------------------------------------------------

/// Trait that enables adding a missing-input layer to a Missing type.
///
/// For simple types (`()`, `Num<M>`, etc.), this wraps normally.
/// For `Or<T, F>`, it distributes into both branches so that `Or` always
/// stays outermost — ensuring the sig builder's `choose_true()`/`choose_false()`
/// is called first (the Bool ends up on top of the stack).
pub trait AddToMissing {
    type WithNum;
    type WithBool;
    type WithData;
    type WithHash;
    type WithBn254Fr;
    type WithGroth16Tag;
    type WithR0SuccinctTag;
    type WithR0SuccinctSeal;
    type WithR0SuccinctClaim;
    type WithR0SuccinctHashFn;
    type WithR0SuccinctControlIndex;
    type WithR0SuccinctControlDigests;
    type WithR0SuccinctJournalDigest;
    type WithR0SuccinctImageId;
    type WithG16Vk;
    type WithG16Proof;
}

impl AddToMissing for () {
    type WithNum = Num<()>;
    type WithBool = Bool<()>;
    type WithData = Data<()>;
    type WithHash = Hash<()>;
    type WithBn254Fr = Bn254Fr<()>;
    type WithGroth16Tag = Groth16Tag<()>;
    type WithR0SuccinctTag = R0SuccinctTag<()>;
    type WithR0SuccinctSeal = R0SuccinctSeal<()>;
    type WithR0SuccinctClaim = R0SuccinctClaim<()>;
    type WithR0SuccinctHashFn = R0SuccinctHashFn<()>;
    type WithR0SuccinctControlIndex = R0SuccinctControlIndex<()>;
    type WithR0SuccinctControlDigests = R0SuccinctControlDigests<()>;
    type WithR0SuccinctJournalDigest = R0SuccinctJournalDigest<()>;
    type WithR0SuccinctImageId = R0SuccinctImageId<()>;
    type WithG16Vk = G16Vk<()>;
    type WithG16Proof = G16Proof<()>;
}

macro_rules! impl_add_to_missing {
    ($($Marker:ident),*) => {$(
        impl<M> AddToMissing for $Marker<M> {
            type WithNum = Num<$Marker<M>>;
            type WithBool = Bool<$Marker<M>>;
            type WithData = Data<$Marker<M>>;
            type WithHash = Hash<$Marker<M>>;
            type WithBn254Fr = Bn254Fr<$Marker<M>>;
            type WithGroth16Tag = Groth16Tag<$Marker<M>>;
            type WithR0SuccinctTag = R0SuccinctTag<$Marker<M>>;
            type WithR0SuccinctSeal = R0SuccinctSeal<$Marker<M>>;
            type WithR0SuccinctClaim = R0SuccinctClaim<$Marker<M>>;
            type WithR0SuccinctHashFn = R0SuccinctHashFn<$Marker<M>>;
            type WithR0SuccinctControlIndex = R0SuccinctControlIndex<$Marker<M>>;
            type WithR0SuccinctControlDigests = R0SuccinctControlDigests<$Marker<M>>;
            type WithR0SuccinctJournalDigest = R0SuccinctJournalDigest<$Marker<M>>;
            type WithR0SuccinctImageId = R0SuccinctImageId<$Marker<M>>;
            type WithG16Vk = G16Vk<$Marker<M>>;
            type WithG16Proof = G16Proof<$Marker<M>>;
        }
    )*};
}

impl_add_to_missing!(
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

impl<const N: usize, T, S> AddToMissing for FixedNum<N, T, S> {
    type WithNum = Num<FixedNum<N, T, S>>;
    type WithBool = Bool<FixedNum<N, T, S>>;
    type WithData = Data<FixedNum<N, T, S>>;
    type WithHash = Hash<FixedNum<N, T, S>>;
    type WithBn254Fr = Bn254Fr<FixedNum<N, T, S>>;
    type WithGroth16Tag = Groth16Tag<FixedNum<N, T, S>>;
    type WithR0SuccinctTag = R0SuccinctTag<FixedNum<N, T, S>>;
    type WithR0SuccinctSeal = R0SuccinctSeal<FixedNum<N, T, S>>;
    type WithR0SuccinctClaim = R0SuccinctClaim<FixedNum<N, T, S>>;
    type WithR0SuccinctHashFn = R0SuccinctHashFn<FixedNum<N, T, S>>;
    type WithR0SuccinctControlIndex = R0SuccinctControlIndex<FixedNum<N, T, S>>;
    type WithR0SuccinctControlDigests = R0SuccinctControlDigests<FixedNum<N, T, S>>;
    type WithR0SuccinctJournalDigest = R0SuccinctJournalDigest<FixedNum<N, T, S>>;
    type WithR0SuccinctImageId = R0SuccinctImageId<FixedNum<N, T, S>>;
    type WithG16Vk = G16Vk<FixedNum<N, T, S>>;
    type WithG16Proof = G16Proof<FixedNum<N, T, S>>;
}

impl<T: AddToMissing, F: AddToMissing> AddToMissing for Or<T, F> {
    type WithNum = Or<T::WithNum, F::WithNum>;
    type WithBool = Or<T::WithBool, F::WithBool>;
    type WithData = Or<T::WithData, F::WithData>;
    type WithHash = Or<T::WithHash, F::WithHash>;
    type WithBn254Fr = Or<T::WithBn254Fr, F::WithBn254Fr>;
    type WithGroth16Tag = Or<T::WithGroth16Tag, F::WithGroth16Tag>;
    type WithR0SuccinctTag = Or<T::WithR0SuccinctTag, F::WithR0SuccinctTag>;
    type WithR0SuccinctSeal = Or<T::WithR0SuccinctSeal, F::WithR0SuccinctSeal>;
    type WithR0SuccinctClaim = Or<T::WithR0SuccinctClaim, F::WithR0SuccinctClaim>;
    type WithR0SuccinctHashFn = Or<T::WithR0SuccinctHashFn, F::WithR0SuccinctHashFn>;
    type WithR0SuccinctControlIndex = Or<T::WithR0SuccinctControlIndex, F::WithR0SuccinctControlIndex>;
    type WithR0SuccinctControlDigests = Or<T::WithR0SuccinctControlDigests, F::WithR0SuccinctControlDigests>;
    type WithR0SuccinctJournalDigest = Or<T::WithR0SuccinctJournalDigest, F::WithR0SuccinctJournalDigest>;
    type WithR0SuccinctImageId = Or<T::WithR0SuccinctImageId, F::WithR0SuccinctImageId>;
    type WithG16Vk = Or<T::WithG16Vk, F::WithG16Vk>;
    type WithG16Proof = Or<T::WithG16Proof, F::WithG16Proof>;
}

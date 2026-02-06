use std::marker::PhantomData;

use ark_serialize::CanonicalSerialize;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::zk_precompiles::fields::Fr;
pub use kaspa_txscript::zk_precompiles::risc0::rcpt::HashFnId as R0SuccinctHashFnId;
use kaspa_txscript::zk_precompiles::tags::ZkTag;

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

// ---------------------------------------------------------------------------
// StackEntry trait (sealed, with GAT)
// ---------------------------------------------------------------------------

mod sealed {
    pub trait Sealed {}
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

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A script builder that tracks the stack state (`Stack`) and missing signature
/// inputs (`Missing`) at the type level.
///
/// - `Stack`: encodes what is currently on the stack.
///   `()` = empty, `Num<()>` = one number, `Num<Num<()>>` = two numbers, etc.
/// - `Missing`: encodes inputs that must be provided in the signature script.
///   `()` = nothing missing, `Num<()>` = need one number, etc.
pub struct TypedScriptBuilder<Stack, Missing> {
    builder: ScriptBuilder,
    _phantom: PhantomData<(Stack, Missing)>,
}

/// Builder for the signature script half. `Missing` tracks how many inputs
/// still need to be provided before `build()` becomes available.
pub struct ScriptSignatureBuilder<Missing> {
    redeem_script: Vec<u8>,
    builder: ScriptBuilder,
    _phantom: PhantomData<Missing>,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    /// Emit a raw opcode and transmute the phantom types.
    fn emit_op<S2, M2>(mut self, opcode: u8) -> TypedScriptBuilder<S2, M2> {
        self.builder.add_op(opcode).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl TypedScriptBuilder<(), ()> {
    pub fn new() -> Self {
        TypedScriptBuilder { builder: ScriptBuilder::new(), _phantom: PhantomData }
    }
}

impl Default for TypedScriptBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Blanket: push literals and data (available on every state)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    /// Push a number literal onto the stack.
    pub fn add_i64(mut self, val: i64) -> TypedScriptBuilder<Num<S>, M> {
        self.builder.add_i64(val).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push raw data bytes onto the stack.
    pub fn add_data(mut self, data: &[u8]) -> TypedScriptBuilder<Data<S>, M> {
        self.builder.add_data(data).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a hash value onto the stack.
    pub fn add_hash(mut self, hash: &kaspa_hashes::Hash) -> TypedScriptBuilder<Hash<S>, M> {
        self.builder.add_data(hash.as_ref()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a BN254 field element onto the stack.
    pub fn add_bn254_fr(mut self, fr: &Fr) -> TypedScriptBuilder<Bn254Fr<S>, M> {
        let mut bytes = Vec::new();
        fr.field().serialize_uncompressed(&mut bytes).expect("Fr serialization failed");
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a Groth16 ZK proof tag byte onto the stack.
    pub fn add_groth16_tag(mut self) -> TypedScriptBuilder<Groth16Tag<S>, M> {
        self.builder.add_data(&[ZkTag::Groth16 as u8]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 succinct ZK proof tag byte onto the stack.
    pub fn add_r0_succinct_tag(mut self) -> TypedScriptBuilder<R0SuccinctTag<S>, M> {
        self.builder.add_data(&[ZkTag::R0Succinct as u8]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    // -- RISC0 Succinct semantic pushers --

    /// Push a RISC0 succinct seal from `u32` words (each serialized as 4 LE bytes).
    pub fn add_r0_succinct_seal(mut self, seal_words: &[u32]) -> TypedScriptBuilder<R0SuccinctSeal<S>, M> {
        let bytes: Vec<u8> = seal_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 succinct seal from raw bytes (length must be a multiple of 4).
    pub fn add_r0_succinct_seal_bytes(mut self, bytes: &[u8]) -> TypedScriptBuilder<R0SuccinctSeal<S>, M> {
        assert!(bytes.len() % 4 == 0, "seal bytes length must be a multiple of 4, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 succinct claim digest (exactly 32 bytes).
    pub fn add_r0_succinct_claim(mut self, claim: &[u8]) -> TypedScriptBuilder<R0SuccinctClaim<S>, M> {
        assert!(claim.len() == 32, "claim must be exactly 32 bytes, got {}", claim.len());
        self.builder.add_data(claim).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 hash-function identifier from the `R0SuccinctHashFnId` enum.
    pub fn add_r0_succinct_hashfn(mut self, id: R0SuccinctHashFnId) -> TypedScriptBuilder<R0SuccinctHashFn<S>, M> {
        self.builder.add_data(&[u8::from(id)]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 hash-function identifier from a raw `u8` (must be 0, 1, or 2).
    pub fn add_r0_succinct_hashfn_raw(mut self, id: u8) -> TypedScriptBuilder<R0SuccinctHashFn<S>, M> {
        assert!(id <= 2, "hash function id must be 0, 1, or 2, got {id}");
        self.builder.add_data(&[id]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 hash-function identifier from raw bytes (exactly 1 byte).
    pub fn add_r0_succinct_hashfn_bytes(mut self, bytes: &[u8]) -> TypedScriptBuilder<R0SuccinctHashFn<S>, M> {
        assert!(bytes.len() == 1, "hashfn bytes must be exactly 1 byte, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 Merkle-tree control index from a `u32` (serialized as 4 LE bytes).
    pub fn add_r0_succinct_control_index(mut self, index: u32) -> TypedScriptBuilder<R0SuccinctControlIndex<S>, M> {
        self.builder.add_data(&index.to_le_bytes()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 Merkle-tree control index from raw bytes (exactly 4 bytes).
    pub fn add_r0_succinct_control_index_bytes(mut self, bytes: &[u8]) -> TypedScriptBuilder<R0SuccinctControlIndex<S>, M> {
        assert!(bytes.len() == 4, "control index must be exactly 4 bytes, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push RISC0 control digests (concatenated 32-byte digests; length must be a multiple of 32).
    pub fn add_r0_succinct_control_digests(mut self, digests: &[u8]) -> TypedScriptBuilder<R0SuccinctControlDigests<S>, M> {
        assert!(digests.len() % 32 == 0, "control digests length must be a multiple of 32, got {}", digests.len());
        self.builder.add_data(digests).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 journal digest (exactly 32 bytes).
    pub fn add_r0_succinct_journal_digest(mut self, digest: &[u8]) -> TypedScriptBuilder<R0SuccinctJournalDigest<S>, M> {
        assert!(digest.len() == 32, "journal digest must be exactly 32 bytes, got {}", digest.len());
        self.builder.add_data(digest).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 image ID (exactly 32 bytes).
    pub fn add_r0_succinct_image_id(mut self, image_id: &[u8]) -> TypedScriptBuilder<R0SuccinctImageId<S>, M> {
        assert!(image_id.len() == 32, "image ID must be exactly 32 bytes, got {}", image_id.len());
        self.builder.add_data(image_id).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    // -- Groth16 semantic pushers --

    /// Push a Groth16 verification key (variable-length bytes).
    pub fn add_g16_vk(mut self, vk: &[u8]) -> TypedScriptBuilder<G16Vk<S>, M> {
        self.builder.add_data(vk).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a Groth16 proof (variable-length bytes).
    pub fn add_g16_proof(mut self, proof: &[u8]) -> TypedScriptBuilder<G16Proof<S>, M> {
        self.builder.add_data(proof).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Downcast: safe type erasure — every stack element is bytes at runtime.
// No opcode is emitted.
// ---------------------------------------------------------------------------

impl<Top: StackEntry, M> TypedScriptBuilder<Top, M> {
    /// Safe type erasure — every stack element is bytes at runtime. No opcode is emitted.
    pub fn downcast(self) -> TypedScriptBuilder<Data<Top::Rest>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Upcast: unsafe reinterpretation from Data to typed markers.
// No opcode is emitted. If the data doesn't match the target type at runtime,
// the script will fail.
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Data<S>, M> {
    /// WARNING: No runtime validation. If the data cannot be deserialized as the
    /// target type, the script will fail at execution time. Prefer operations that
    /// naturally produce typed results, and use downcast when passing typed values
    /// to data-level operations.
    pub fn unsafe_interpret_as_num(self) -> TypedScriptBuilder<Num<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_bool(self) -> TypedScriptBuilder<Bool<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_hash(self) -> TypedScriptBuilder<Hash<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_bn254_fr(self) -> TypedScriptBuilder<Bn254Fr<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_seal(self) -> TypedScriptBuilder<R0SuccinctSeal<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_claim(self) -> TypedScriptBuilder<R0SuccinctClaim<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_hashfn(self) -> TypedScriptBuilder<R0SuccinctHashFn<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_control_index(self) -> TypedScriptBuilder<R0SuccinctControlIndex<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_control_digests(self) -> TypedScriptBuilder<R0SuccinctControlDigests<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_journal_digest(self) -> TypedScriptBuilder<R0SuccinctJournalDigest<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_image_id(self) -> TypedScriptBuilder<R0SuccinctImageId<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_g16_vk(self) -> TypedScriptBuilder<G16Vk<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_g16_proof(self) -> TypedScriptBuilder<G16Proof<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Semantic casts: Hash → R0Succinct types (zero-cost, no opcode)
// A 32-byte hash on the stack can be reinterpreted as a journal digest,
// image ID, or claim without emitting any opcodes.
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Hash<S>, M> {
    /// Reinterpret an on-stack SHA-256 hash as a RISC0 journal digest. No opcode emitted.
    pub fn into_r0_succinct_journal_digest(self) -> TypedScriptBuilder<R0SuccinctJournalDigest<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Reinterpret an on-stack SHA-256 hash as a RISC0 image ID. No opcode emitted.
    pub fn into_r0_succinct_image_id(self) -> TypedScriptBuilder<R0SuccinctImageId<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Reinterpret an on-stack SHA-256 hash as a RISC0 claim digest. No opcode emitted.
    pub fn into_r0_succinct_claim(self) -> TypedScriptBuilder<R0SuccinctClaim<S>, M> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ===========================================================================
// Operations
// ===========================================================================

// ---------------------------------------------------------------------------
// Arithmetic: Binary Num×Num → Num (full stack: 2+ nums)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<Num<S>>, M> {
    pub fn op_add(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAdd)
    }
    pub fn op_sub(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpSub)
    }
    pub fn op_mul(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpMul)
    }
    pub fn op_div(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpDiv)
    }
    pub fn op_mod(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpMod)
    }
    pub fn op_min(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpMin)
    }
    pub fn op_max(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpMax)
    }

    // Binary Num×Num → Bool
    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpNumEqual)
    }
    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpLessThan)
    }
    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpGreaterThan)
    }
    pub fn op_less_than_or_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpLessThanOrEqual)
    }
    pub fn op_greater_than_or_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpGreaterThanOrEqual)
    }
    pub fn op_num_not_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpNumNotEqual)
    }
    pub fn op_bool_and(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpBoolAnd)
    }
    pub fn op_bool_or(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpBoolOr)
    }

    // Verify Num×Num → removes both
    pub fn op_num_equal_verify(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpNumEqualVerify)
    }

    // Conversion: Num(size) × Num(value) → Data
    pub fn op_num2bin(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpNum2Bin)
    }
}

// ---------------------------------------------------------------------------
// Arithmetic: Binary Num×Num (partial: 1 on stack)
// ---------------------------------------------------------------------------

impl<M> TypedScriptBuilder<Num<()>, M> {
    pub fn op_add(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpAdd)
    }
    pub fn op_sub(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpSub)
    }
    pub fn op_mul(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpMul)
    }
    pub fn op_div(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpDiv)
    }
    pub fn op_mod(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpMod)
    }
    pub fn op_min(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpMin)
    }
    pub fn op_max(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpMax)
    }

    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpNumEqual)
    }
    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpLessThan)
    }
    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpGreaterThan)
    }
    pub fn op_less_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpLessThanOrEqual)
    }
    pub fn op_greater_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpGreaterThanOrEqual)
    }
    pub fn op_num_not_equal(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpNumNotEqual)
    }
    pub fn op_bool_and(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpBoolAnd)
    }
    pub fn op_bool_or(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpBoolOr)
    }
}

// ---------------------------------------------------------------------------
// Arithmetic: Binary Num×Num (empty stack: need 2 from sig)
// ---------------------------------------------------------------------------

impl<M> TypedScriptBuilder<(), M> {
    // Binary (need 2 from sig)
    pub fn op_add(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpAdd)
    }
    pub fn op_sub(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpSub)
    }
    pub fn op_mul(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpMul)
    }
    pub fn op_div(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpDiv)
    }
    pub fn op_mod(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpMod)
    }
    pub fn op_min(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpMin)
    }
    pub fn op_max(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpMax)
    }

    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpNumEqual)
    }
    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpLessThan)
    }
    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpGreaterThan)
    }
    pub fn op_less_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpLessThanOrEqual)
    }
    pub fn op_greater_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpGreaterThanOrEqual)
    }
    pub fn op_num_not_equal(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpNumNotEqual)
    }
    pub fn op_bool_and(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpBoolAnd)
    }
    pub fn op_bool_or(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpBoolOr)
    }

    // Unary (need 1 from sig)
    pub fn op_1_add(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(Op1Add)
    }
    pub fn op_1_sub(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(Op1Sub)
    }
    pub fn op_negate(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpNegate)
    }
    pub fn op_abs(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpAbs)
    }
    pub fn op_not(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpNot)
    }
    pub fn op_0_not_equal(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(Op0NotEqual)
    }

    // Data binary (need 2 from sig)
    pub fn op_cat(self) -> TypedScriptBuilder<Data<()>, Data<Data<M>>> {
        self.emit_op(OpCat)
    }
    pub fn op_and(self) -> TypedScriptBuilder<Data<()>, Data<Data<M>>> {
        self.emit_op(OpAnd)
    }
    pub fn op_or(self) -> TypedScriptBuilder<Data<()>, Data<Data<M>>> {
        self.emit_op(OpOr)
    }
    pub fn op_xor(self) -> TypedScriptBuilder<Data<()>, Data<Data<M>>> {
        self.emit_op(OpXor)
    }
    pub fn op_equal(self) -> TypedScriptBuilder<Bool<()>, Data<Data<M>>> {
        self.emit_op(OpEqual)
    }

    // Data unary (need 1 from sig)
    pub fn op_invert(self) -> TypedScriptBuilder<Data<()>, Data<M>> {
        self.emit_op(OpInvert)
    }
    pub fn op_size(self) -> TypedScriptBuilder<Num<Data<()>>, Data<M>> {
        self.emit_op(OpSize)
    }
    pub fn op_sha256(self) -> TypedScriptBuilder<Hash<()>, Data<M>> {
        self.emit_op(OpSHA256)
    }
    pub fn op_blake2b(self) -> TypedScriptBuilder<Hash<()>, Data<M>> {
        self.emit_op(OpBlake2b)
    }
    pub fn op_bin2num(self) -> TypedScriptBuilder<Num<()>, Data<M>> {
        self.emit_op(OpBin2Num)
    }

    // Signature ops (need 2 from sig)
    pub fn op_check_sig(self) -> TypedScriptBuilder<Bool<()>, Data<Data<M>>> {
        self.emit_op(OpCheckSig)
    }
    pub fn op_check_sig_ecdsa(self) -> TypedScriptBuilder<Bool<()>, Data<Data<M>>> {
        self.emit_op(OpCheckSigECDSA)
    }

    // Blake2b with key (need 2 from sig)
    pub fn op_blake2b_with_key(self) -> TypedScriptBuilder<Hash<()>, Data<Data<M>>> {
        self.emit_op(OpBlake2bWithKey)
    }

    // SeqCommit (need 1 Hash from sig)
    pub fn op_chainblock_seq_commit(self) -> TypedScriptBuilder<Hash<()>, Hash<M>> {
        self.emit_op(OpChainblockSeqCommit)
    }
}

// ---------------------------------------------------------------------------
// Unary ops: Num<S> (1+ nums on stack)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    pub fn op_1_add(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(Op1Add)
    }
    pub fn op_1_sub(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(Op1Sub)
    }
    pub fn op_negate(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpNegate)
    }
    pub fn op_abs(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAbs)
    }
    pub fn op_not(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpNot)
    }
    pub fn op_0_not_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(Op0NotEqual)
    }
}

// ---------------------------------------------------------------------------
// Ternary: op_within  Num×Num×Num → Bool
// ---------------------------------------------------------------------------

// Full stack: 3+ nums
impl<S, M> TypedScriptBuilder<Num<Num<Num<S>>>, M> {
    pub fn op_within(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpWithin)
    }
}

// Partial: 2 on stack
impl<M> TypedScriptBuilder<Num<Num<()>>, M> {
    pub fn op_within(self) -> TypedScriptBuilder<Bool<()>, Num<M>> {
        self.emit_op(OpWithin)
    }
}

// Partial: 1 on stack
impl<M> TypedScriptBuilder<Num<()>, M> {
    pub fn op_within(self) -> TypedScriptBuilder<Bool<()>, Num<Num<M>>> {
        self.emit_op(OpWithin)
    }
}

// Empty stack (already defined on `impl<M> TypedScriptBuilder<(), M>` would conflict,
// so we add it there)
// Note: op_within on empty stack needs 3 from sig — added below in a separate section

// ---------------------------------------------------------------------------
// op_within on empty stack (3 from sig)
// ---------------------------------------------------------------------------

// We can't add it to the existing `impl<M> TypedScriptBuilder<(), M>` because that's
// already defined above. Instead we use a trait-based approach or just add it there.
// Actually, we CAN add more methods to the same type in separate impl blocks.

impl<M> TypedScriptBuilder<(), M> {
    pub fn op_within(self) -> TypedScriptBuilder<Bool<()>, Num<Num<Num<M>>>> {
        self.emit_op(OpWithin)
    }
}

// ---------------------------------------------------------------------------
// Data operations: Data<Data<S>> (binary)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Data<Data<S>>, M> {
    pub fn op_cat(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpCat)
    }
    pub fn op_and(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpAnd)
    }
    pub fn op_or(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpOr)
    }
    pub fn op_xor(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpXor)
    }
    pub fn op_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpEqual)
    }

    // Verify Data×Data → removes both
    pub fn op_equal_verify(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpEqualVerify)
    }

    // Signature ops
    pub fn op_check_sig(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpCheckSig)
    }
    pub fn op_check_sig_ecdsa(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpCheckSigECDSA)
    }
    pub fn op_check_sig_verify(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpCheckSigVerify)
    }

    // Blake2b with key (pops key, then data)
    pub fn op_blake2b_with_key(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpBlake2bWithKey)
    }
}

// Partial: 1 Data on stack (need 1 more from sig)
impl<M> TypedScriptBuilder<Data<()>, M> {
    pub fn op_cat(self) -> TypedScriptBuilder<Data<()>, Data<M>> {
        self.emit_op(OpCat)
    }
    pub fn op_and(self) -> TypedScriptBuilder<Data<()>, Data<M>> {
        self.emit_op(OpAnd)
    }
    pub fn op_or(self) -> TypedScriptBuilder<Data<()>, Data<M>> {
        self.emit_op(OpOr)
    }
    pub fn op_xor(self) -> TypedScriptBuilder<Data<()>, Data<M>> {
        self.emit_op(OpXor)
    }
    pub fn op_equal(self) -> TypedScriptBuilder<Bool<()>, Data<M>> {
        self.emit_op(OpEqual)
    }
    pub fn op_check_sig(self) -> TypedScriptBuilder<Bool<()>, Data<M>> {
        self.emit_op(OpCheckSig)
    }
    pub fn op_check_sig_ecdsa(self) -> TypedScriptBuilder<Bool<()>, Data<M>> {
        self.emit_op(OpCheckSigECDSA)
    }
    pub fn op_blake2b_with_key(self) -> TypedScriptBuilder<Hash<()>, Data<M>> {
        self.emit_op(OpBlake2bWithKey)
    }
}

// ---------------------------------------------------------------------------
// Data operations: Data<S> (unary)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Data<S>, M> {
    pub fn op_invert(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpInvert)
    }

    /// Pushes the size of the top data element without popping it.
    pub fn op_size(self) -> TypedScriptBuilder<Num<Data<S>>, M> {
        self.emit_op(OpSize)
    }

    pub fn op_sha256(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpSHA256)
    }
    pub fn op_blake2b(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpBlake2b)
    }
    pub fn op_bin2num(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpBin2Num)
    }

    // Lock time operations
    pub fn op_check_lock_time_verify(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpCheckLockTimeVerify)
    }
    pub fn op_check_sequence_verify(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpCheckSequenceVerify)
    }
}

// ---------------------------------------------------------------------------
// OpSubstr: Num(end) × Num(start) × Data → Data
// ---------------------------------------------------------------------------

// Full: Num<Num<Data<S>>>
impl<S, M> TypedScriptBuilder<Num<Num<Data<S>>>, M> {
    pub fn op_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpSubstr)
    }
}

// Partial: 2 on stack (Num<Num<()>>) — need Data from sig
impl<M> TypedScriptBuilder<Num<Num<()>>, M> {
    pub fn op_substr(self) -> TypedScriptBuilder<Data<()>, Data<M>> {
        self.emit_op(OpSubstr)
    }
}

// Partial: 1 on stack (Num<()>) — need Num+Data from sig
// Note: this conflicts with the existing Num<()> impl, so we add it there
impl<M> TypedScriptBuilder<Num<()>, M> {
    pub fn op_substr(self) -> TypedScriptBuilder<Data<()>, Data<Num<M>>> {
        self.emit_op(OpSubstr)
    }
}

// Empty stack — need all 3: Data<Num<Num<M>>> (Data deepest, Nums on top)
impl<M> TypedScriptBuilder<(), M> {
    pub fn op_substr(self) -> TypedScriptBuilder<Data<()>, Data<Num<Num<M>>>> {
        self.emit_op(OpSubstr)
    }
}

// ---------------------------------------------------------------------------
// Conversion (covenant-only)
// ---------------------------------------------------------------------------

// op_num2bin on Num<Num<S>> already defined above in the Num<Num<S>> block

// op_bin2num on Data<S> already defined above in the Data<S> block

// ---------------------------------------------------------------------------
// Stack manipulation: Dup & Drop (generic via StackEntry)
// ---------------------------------------------------------------------------

impl<Top: StackEntry, M> TypedScriptBuilder<Top, M> {
    pub fn op_dup(self) -> TypedScriptBuilder<Top::Wrap<Top>, M> {
        self.emit_op(OpDup)
    }
    pub fn op_drop(self) -> TypedScriptBuilder<Top::Rest, M> {
        self.emit_op(OpDrop)
    }
}

// ---------------------------------------------------------------------------
// Stack manipulation: multi-element ops (generic via StackEntry)
// ---------------------------------------------------------------------------

// 2-element ops: top two elements can be any marker types
impl<Top, M> TypedScriptBuilder<Top, M>
where
    Top: StackEntry,
    Top::Rest: StackEntry,
{
    /// Swap the top two elements. `[A, B, rest]` → `[B, A, rest]`
    pub fn op_swap(self) -> TypedScriptBuilder<<Top::Rest as StackEntry>::Wrap<Top::Wrap<<Top::Rest as StackEntry>::Rest>>, M> {
        self.emit_op(OpSwap)
    }

    /// Remove the second-to-top element. `[A, B, rest]` → `[A, rest]`
    pub fn op_nip(self) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Rest>, M> {
        self.emit_op(OpNip)
    }

    /// Copy the second-to-top element to the top. `[A, B, rest]` → `[B, A, B, rest]`
    pub fn op_over(self) -> TypedScriptBuilder<<Top::Rest as StackEntry>::Wrap<Top>, M> {
        self.emit_op(OpOver)
    }

    /// Copy the top element below the second-to-top. `[A, B, rest]` → `[A, B, A, rest]`
    pub fn op_tuck(
        self,
    ) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Wrap<Top::Wrap<<Top::Rest as StackEntry>::Rest>>>, M> {
        self.emit_op(OpTuck)
    }

    /// Drop the top two elements. `[A, B, rest]` → `[rest]`
    pub fn op_2_drop(self) -> TypedScriptBuilder<<Top::Rest as StackEntry>::Rest, M> {
        self.emit_op(Op2Drop)
    }

    /// Duplicate the top two elements. `[A, B, rest]` → `[A, B, A, B, rest]`
    pub fn op_2_dup(self) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Wrap<Top>>, M> {
        self.emit_op(Op2Dup)
    }
}

// 3-element ops: top three elements can be any marker types
impl<Top, M> TypedScriptBuilder<Top, M>
where
    Top: StackEntry,
    Top::Rest: StackEntry,
    <Top::Rest as StackEntry>::Rest: StackEntry,
{
    /// Rotate the top three elements. `[A, B, C, rest]` → `[C, A, B, rest]`
    pub fn op_rot(
        self,
    ) -> TypedScriptBuilder<
        <<Top::Rest as StackEntry>::Rest as StackEntry>::Wrap<
            Top::Wrap<<Top::Rest as StackEntry>::Wrap<<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest>>,
        >,
        M,
    > {
        self.emit_op(OpRot)
    }

    /// Duplicate the top three elements. `[A, B, C, rest]` → `[A, B, C, A, B, C, rest]`
    pub fn op_3_dup(
        self,
    ) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Wrap<<<Top::Rest as StackEntry>::Rest as StackEntry>::Wrap<Top>>>, M>
    {
        self.emit_op(Op3Dup)
    }
}

// ---------------------------------------------------------------------------
// OpDepth (blanket)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    /// Push the current stack depth as a number.
    pub fn op_depth(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpDepth)
    }
}

// ---------------------------------------------------------------------------
// Verify: Bool<S> → S
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Bool<S>, M> {
    /// Pops the top Bool; errors if false at runtime.
    pub fn op_verify(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpVerify)
    }
}

// ---------------------------------------------------------------------------
// Constants (blanket)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    pub fn op_true(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpTrue)
    }
    pub fn op_false(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpFalse)
    }
    pub fn op_1_negate(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(Op1Negate)
    }

    /// Push Op2..Op16 onto the stack. Panics if n is not in 2..=16.
    pub fn op_n(self, n: u8) -> TypedScriptBuilder<Num<S>, M> {
        assert!((2..=16).contains(&n), "op_n requires n in 2..=16, got {n}");
        // Op2 = 0x52, Op3 = 0x53, ..., Op16 = 0x60
        let opcode = 0x50 + n;
        self.emit_op(opcode)
    }

    pub fn op_nop(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpNop)
    }
    pub fn op_return(self) -> TypedScriptBuilder<S, M> {
        self.emit_op(OpReturn)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: zero-input pushers (blanket)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    pub fn op_tx_input_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputCount)
    }
    pub fn op_tx_output_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxOutputCount)
    }
    pub fn op_tx_version(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxVersion)
    }
    pub fn op_tx_lock_time(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxLockTime)
    }
    pub fn op_tx_gas(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxGas)
    }
    pub fn op_tx_input_index(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputIndex)
    }
    pub fn op_tx_payload_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxPayloadLen)
    }
    pub fn op_tx_subnet_id(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxSubnetId)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: index-consuming (on Num<S>)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    // → Num<S>
    pub fn op_tx_input_amount(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputAmount)
    }
    pub fn op_tx_output_amount(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxOutputAmount)
    }
    pub fn op_outpoint_index(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpOutpointIndex)
    }
    pub fn op_tx_input_spk_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputSpkLen)
    }
    pub fn op_tx_output_spk_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxOutputSpkLen)
    }
    pub fn op_tx_input_script_sig_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputScriptSigLen)
    }

    // → Data<S>
    pub fn op_tx_input_spk(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputSpk)
    }
    pub fn op_tx_output_spk(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxOutputSpk)
    }
    pub fn op_tx_input_seq(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputSeq)
    }

    // → Hash<S>
    pub fn op_outpoint_tx_id(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpOutpointTxId)
    }

    // → Bool<S>
    pub fn op_tx_input_is_coinbase(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpTxInputIsCoinbase)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: substr from tx (on Num<Num<S>>)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<Num<S>>, M> {
    pub fn op_tx_payload_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxPayloadSubstr)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: substr with index (on Num<Num<Num<S>>>)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<Num<Num<S>>>, M> {
    pub fn op_tx_input_script_sig_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputScriptSigSubstr)
    }
    pub fn op_tx_input_spk_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputSpkSubstr)
    }
    pub fn op_tx_output_spk_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxOutputSpkSubstr)
    }
}

// ---------------------------------------------------------------------------
// Covenant operations
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    pub fn op_auth_output_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAuthOutputCount)
    }
}

impl<S, M> TypedScriptBuilder<Num<Num<S>>, M> {
    pub fn op_auth_output_idx(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAuthOutputIdx)
    }
}

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    /// Output is polymorphic (Hash or false at runtime), typed as Data.
    pub fn op_input_covenant_id(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpInputCovenantId)
    }
}

impl<S, M> TypedScriptBuilder<Hash<S>, M> {
    pub fn op_cov_input_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovInputCount)
    }
    pub fn op_cov_out_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovOutCount)
    }
}

impl<S, M> TypedScriptBuilder<Num<Hash<S>>, M> {
    pub fn op_cov_input_idx(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovInputIdx)
    }
    pub fn op_cov_output_idx(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovOutputIdx)
    }
}

// ---------------------------------------------------------------------------
// SeqCommit
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Hash<S>, M> {
    /// Pops block hash, pushes commitment hash.
    pub fn op_chainblock_seq_commit(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpChainblockSeqCommit)
    }
}

// ---------------------------------------------------------------------------
// ZK Precompile: RISC0 succinct verify (trait-based)
// ---------------------------------------------------------------------------

#[diagnostic::on_unimplemented(
    message = "the stack is not ready for `risc0_succinct_verify()`",
    label = "expected stack (top→bottom): R0SuccinctTag, R0SuccinctImageId, R0SuccinctJournalDigest, R0SuccinctControlDigests, R0SuccinctControlIndex, R0SuccinctHashFn, R0SuccinctClaim, R0SuccinctSeal",
    note = "push items bottom-to-top: .add_r0_succinct_seal().add_r0_succinct_claim().add_r0_succinct_hashfn().add_r0_succinct_control_index().add_r0_succinct_control_digests().add_r0_succinct_journal_digest().add_r0_succinct_image_id().add_r0_succinct_tag()"
)]
pub trait R0SuccinctVerify {
    type Rest;
    type Missing;
    fn risc0_succinct_verify(self) -> TypedScriptBuilder<Bool<Self::Rest>, Self::Missing>;
}

impl<S, M> R0SuccinctVerify
    for TypedScriptBuilder<
        R0SuccinctTag<
            R0SuccinctImageId<
                R0SuccinctJournalDigest<
                    R0SuccinctControlDigests<R0SuccinctControlIndex<R0SuccinctHashFn<R0SuccinctClaim<R0SuccinctSeal<S>>>>>,
                >,
            >,
        >,
        M,
    >
{
    type Rest = S;
    type Missing = M;
    fn risc0_succinct_verify(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpZkPrecompile)
    }
}

// ---------------------------------------------------------------------------
// ZK Precompile: Groth16 verify (trait-based)
// ---------------------------------------------------------------------------

#[diagnostic::on_unimplemented(
    message = "the stack is not ready for `groth16_verify()`",
    label = "expected stack (top→bottom): Groth16Tag, G16Vk, G16Proof, Num(n_inputs), Bn254Fr, ...",
    note = "push items bottom-to-top: .add_bn254_fr()...add_i64(n).add_g16_proof().add_g16_vk().add_groth16_tag()\n\nNote: the builder requires at least one Bn254Fr element but cannot verify the count matches n_inputs at compile time."
)]
pub trait G16Verify {
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, ()>;
}

impl<S, M> G16Verify for TypedScriptBuilder<Groth16Tag<G16Vk<G16Proof<Num<Bn254Fr<S>>>>>, M> {
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, ()> {
        self.emit_op(OpZkPrecompile)
    }
}

// ---------------------------------------------------------------------------
// ZK Precompile: inherent bridge methods
// These convert E0599 (method not found) into E0277 (trait bound not satisfied)
// so that #[diagnostic::on_unimplemented] messages actually appear.
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    /// Verifies a RISC0 succinct ZK proof.
    ///
    /// The stack (top→bottom) must be:
    /// `R0SuccinctTag`, `R0SuccinctImageId`, `R0SuccinctJournalDigest`,
    /// `R0SuccinctControlDigests`, `R0SuccinctControlIndex`, `R0SuccinctHashFn`,
    /// `R0SuccinctClaim`, `R0SuccinctSeal`.
    pub fn risc0_succinct_verify(
        self,
    ) -> TypedScriptBuilder<Bool<<Self as R0SuccinctVerify>::Rest>, <Self as R0SuccinctVerify>::Missing>
    where
        Self: R0SuccinctVerify,
    {
        R0SuccinctVerify::risc0_succinct_verify(self)
    }

    /// Verifies a Groth16 ZK proof.
    ///
    /// The stack (top→bottom) must be:
    /// `Groth16Tag`, `G16Vk`, `G16Proof`, `Num(n_inputs)`, then `Bn254Fr` elements.
    ///
    /// ```compile_fail
    /// use kaspa_txscript_typed_builder::TypedScriptBuilder;
    /// // Data instead of Bn254Fr — should not compile
    /// let _ = TypedScriptBuilder::new()
    ///     .add_data(&[0u8; 32])
    ///     .add_i64(1)
    ///     .add_g16_proof(&[])
    ///     .add_g16_vk(&[])
    ///     .add_groth16_tag()
    ///     .groth16_verify();
    /// ```
    ///
    /// ```compile_fail
    /// use kaspa_txscript_typed_builder::TypedScriptBuilder;
    /// // Zero fields — should not compile
    /// let _ = TypedScriptBuilder::new()
    ///     .add_i64(0)
    ///     .add_g16_proof(&[])
    ///     .add_g16_vk(&[])
    ///     .add_groth16_tag()
    ///     .groth16_verify();
    /// ```
    pub fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, ()>
    where
        Self: G16Verify,
    {
        G16Verify::groth16_verify(self)
    }
}

// ---------------------------------------------------------------------------
// Finalize (requires single Bool on stack)
// ---------------------------------------------------------------------------

impl<M> TypedScriptBuilder<Bool<()>, M> {
    /// Returns the redeem script bytes.
    pub fn redeem_script(&self) -> &[u8] {
        self.builder.script()
    }

    /// Consumes the builder and returns a signature builder that will collect
    /// the missing inputs described by `M`.
    pub fn into_sig_builder(mut self) -> ScriptSignatureBuilder<M> {
        let redeem_script = self.builder.drain();
        ScriptSignatureBuilder { redeem_script, builder: ScriptBuilder::new(), _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide a missing number
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Num<M>> {
    /// Provide the next missing number input.
    pub fn add_i64(mut self, val: i64) -> ScriptSignatureBuilder<M> {
        self.builder.add_i64(val).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing data
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Data<M>> {
    /// Provide the next missing data input.
    pub fn add_data(mut self, data: &[u8]) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(data).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing hash
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Hash<M>> {
    /// Provide the next missing hash input.
    pub fn add_hash(mut self, hash: kaspa_hashes::Hash) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(&hash.as_bytes()).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing Bn254Fr
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Bn254Fr<M>> {
    /// Provide the next missing BN254 field element.
    pub fn add_bn254_fr(mut self, fr: Fr) -> ScriptSignatureBuilder<M> {
        let mut bytes = Vec::new();
        fr.field().serialize_uncompressed(&mut bytes).expect("Fr serialization failed");
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing R0Succinct / G16 semantic types
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<R0SuccinctSeal<M>> {
    pub fn add_r0_succinct_seal(mut self, seal_words: &[u32]) -> ScriptSignatureBuilder<M> {
        let bytes: Vec<u8> = seal_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_seal_bytes(mut self, bytes: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(bytes.len() % 4 == 0, "seal bytes length must be a multiple of 4, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctClaim<M>> {
    pub fn add_r0_succinct_claim(mut self, claim: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(claim.len() == 32, "claim must be exactly 32 bytes, got {}", claim.len());
        self.builder.add_data(claim).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctHashFn<M>> {
    pub fn add_r0_succinct_hashfn(mut self, id: R0SuccinctHashFnId) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(&[u8::from(id)]).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_hashfn_raw(mut self, id: u8) -> ScriptSignatureBuilder<M> {
        assert!(id <= 2, "hash function id must be 0, 1, or 2, got {id}");
        self.builder.add_data(&[id]).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_hashfn_bytes(mut self, bytes: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(bytes.len() == 1, "hashfn bytes must be exactly 1 byte, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctControlIndex<M>> {
    pub fn add_r0_succinct_control_index(mut self, index: u32) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(&index.to_le_bytes()).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_control_index_bytes(mut self, bytes: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(bytes.len() == 4, "control index must be exactly 4 bytes, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctControlDigests<M>> {
    pub fn add_r0_succinct_control_digests(mut self, digests: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(digests.len() % 32 == 0, "control digests length must be a multiple of 32, got {}", digests.len());
        self.builder.add_data(digests).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctJournalDigest<M>> {
    pub fn add_r0_succinct_journal_digest(mut self, digest: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(digest.len() == 32, "journal digest must be exactly 32 bytes, got {}", digest.len());
        self.builder.add_data(digest).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctImageId<M>> {
    pub fn add_r0_succinct_image_id(mut self, image_id: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(image_id.len() == 32, "image ID must be exactly 32 bytes, got {}", image_id.len());
        self.builder.add_data(image_id).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<G16Vk<M>> {
    pub fn add_g16_vk(mut self, vk: &[u8]) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(vk).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<G16Proof<M>> {
    pub fn add_g16_proof(mut self, proof: &[u8]) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(proof).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — all inputs provided, build
// ---------------------------------------------------------------------------

impl ScriptSignatureBuilder<()> {
    /// All missing inputs have been provided. Appends the redeem script as a
    /// data push and returns the complete signature script bytes.
    pub fn build(mut self) -> Vec<u8> {
        self.builder.add_data(&self.redeem_script).expect("script size limit exceeded");
        self.builder.drain()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::{
        PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, UtxoEntry,
    };
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, pay_to_script_hash_script};

    #[test]
    fn test_push_and_arithmetic() {
        let typed = TypedScriptBuilder::new().add_i64(3).add_i64(5).op_add().add_i64(8).op_num_equal();

        let mut manual = ScriptBuilder::new();
        manual.add_i64(3).unwrap().add_i64(5).unwrap().add_op(OpAdd).unwrap().add_i64(8).unwrap().add_op(OpNumEqual).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_missing_inputs() {
        let typed = TypedScriptBuilder::new().op_add().op_num_equal();

        let sig = typed.into_sig_builder().add_i64(8).add_i64(5).add_i64(3).build();

        assert!(!sig.is_empty());
    }

    #[test]
    fn test_sig_builder_roundtrip() {
        let typed = TypedScriptBuilder::new().op_add().op_num_equal();

        let redeem = typed.redeem_script().to_vec();
        let sig = typed.into_sig_builder().add_i64(8).add_i64(5).add_i64(3).build();

        let mut manual_sig = ScriptBuilder::new();
        manual_sig.add_i64(8).unwrap().add_i64(5).unwrap().add_i64(3).unwrap().add_data(&redeem).unwrap();
        let expected_sig = manual_sig.drain();

        assert_eq!(sig, expected_sig);
    }

    #[test]
    fn test_unary_ops() {
        let typed = TypedScriptBuilder::new().add_i64(5).op_1_add().op_negate().op_abs().op_not();

        let mut manual = ScriptBuilder::new();
        manual.add_i64(5).unwrap().add_op(Op1Add).unwrap().add_op(OpNegate).unwrap().add_op(OpAbs).unwrap().add_op(OpNot).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_unary_on_empty_stack() {
        let typed = TypedScriptBuilder::new().op_1_add().op_not();

        let sig = typed.into_sig_builder().add_i64(0).build();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_comparison_ops() {
        let lt = TypedScriptBuilder::new().add_i64(3).add_i64(5).op_less_than();
        let mut manual_lt = ScriptBuilder::new();
        manual_lt.add_i64(3).unwrap().add_i64(5).unwrap().add_op(OpLessThan).unwrap();
        assert_eq!(lt.redeem_script(), manual_lt.script());

        let gt = TypedScriptBuilder::new().add_i64(5).add_i64(3).op_greater_than();
        let mut manual_gt = ScriptBuilder::new();
        manual_gt.add_i64(5).unwrap().add_i64(3).unwrap().add_op(OpGreaterThan).unwrap();
        assert_eq!(gt.redeem_script(), manual_gt.script());
    }

    #[test]
    fn test_sub_op() {
        let typed = TypedScriptBuilder::new().add_i64(10).add_i64(3).op_sub().add_i64(7).op_num_equal();

        let mut manual = ScriptBuilder::new();
        manual.add_i64(10).unwrap().add_i64(3).unwrap().add_op(OpSub).unwrap().add_i64(7).unwrap().add_op(OpNumEqual).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_data_ops() {
        // add_data, op_cat, op_equal, op_invert, op_and, op_or, op_xor
        let typed_cat =
            TypedScriptBuilder::new().add_data(&[1, 2, 3]).add_data(&[4, 5, 6]).op_cat().add_data(&[1, 2, 3, 4, 5, 6]).op_equal();

        let mut manual_cat = ScriptBuilder::new();
        manual_cat
            .add_data(&[1, 2, 3])
            .unwrap()
            .add_data(&[4, 5, 6])
            .unwrap()
            .add_op(OpCat)
            .unwrap()
            .add_data(&[1, 2, 3, 4, 5, 6])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_cat.redeem_script(), manual_cat.script());

        let typed_invert = TypedScriptBuilder::new().add_data(&[0xFF]).op_invert().add_data(&[0x00]).op_equal();

        let mut manual_invert = ScriptBuilder::new();
        manual_invert.add_data(&[0xFF]).unwrap().add_op(OpInvert).unwrap().add_data(&[0x00]).unwrap().add_op(OpEqual).unwrap();
        assert_eq!(typed_invert.redeem_script(), manual_invert.script());

        let typed_and = TypedScriptBuilder::new().add_data(&[0xFF]).add_data(&[0x0F]).op_and().add_data(&[0x0F]).op_equal();

        let mut manual_and = ScriptBuilder::new();
        manual_and
            .add_data(&[0xFF])
            .unwrap()
            .add_data(&[0x0F])
            .unwrap()
            .add_op(OpAnd)
            .unwrap()
            .add_data(&[0x0F])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_and.redeem_script(), manual_and.script());

        let typed_or = TypedScriptBuilder::new().add_data(&[0xF0]).add_data(&[0x0F]).op_or().add_data(&[0xFF]).op_equal();

        let mut manual_or = ScriptBuilder::new();
        manual_or
            .add_data(&[0xF0])
            .unwrap()
            .add_data(&[0x0F])
            .unwrap()
            .add_op(OpOr)
            .unwrap()
            .add_data(&[0xFF])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_or.redeem_script(), manual_or.script());

        let typed_xor = TypedScriptBuilder::new().add_data(&[0xFF]).add_data(&[0x0F]).op_xor().add_data(&[0xF0]).op_equal();

        let mut manual_xor = ScriptBuilder::new();
        manual_xor
            .add_data(&[0xFF])
            .unwrap()
            .add_data(&[0x0F])
            .unwrap()
            .add_op(OpXor)
            .unwrap()
            .add_data(&[0xF0])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_xor.redeem_script(), manual_xor.script());
    }

    #[test]
    fn test_hash_ops() {
        // op_sha256 and op_blake2b byte comparison
        let typed_sha = TypedScriptBuilder::new()
            .add_data(&[1, 2, 3])
            .op_sha256()
            .downcast()
            .add_data(&[4, 5, 6])
            .op_blake2b()
            .downcast()
            .op_swap()
            .op_drop()
            .add_data(&[0xAA; 32])
            .op_equal();

        let mut manual_sha = ScriptBuilder::new();
        manual_sha
            .add_data(&[1, 2, 3])
            .unwrap()
            .add_op(OpSHA256)
            .unwrap()
            .add_data(&[4, 5, 6])
            .unwrap()
            .add_op(OpBlake2b)
            .unwrap()
            .add_op(OpSwap)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_data(&[0xAA; 32])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_sha.redeem_script(), manual_sha.script());

        // add_hash + downcast + op_equal
        let h = kaspa_hashes::Hash::from_bytes([0xAB; 32]);
        let typed_hash = TypedScriptBuilder::new().add_data(&[0xAB; 32]).add_hash(&h).downcast().op_swap().op_equal();

        let mut manual_hash = ScriptBuilder::new();
        manual_hash.add_data(&[0xAB; 32]).unwrap().add_data(&h.as_bytes()).unwrap().add_op(OpSwap).unwrap().add_op(OpEqual).unwrap();
        assert_eq!(typed_hash.redeem_script(), manual_hash.script());
    }

    #[test]
    fn test_mul_div_mod_min_max() {
        let typed = TypedScriptBuilder::new()
            .add_i64(6).add_i64(7).op_mul()   // 42
            .add_i64(5).op_div()               // 8
            .add_i64(3).op_mod()               // 2
            .add_i64(10).op_min()              // 2
            .add_i64(2).op_num_equal();

        let mut manual = ScriptBuilder::new();
        manual
            .add_i64(6)
            .unwrap()
            .add_i64(7)
            .unwrap()
            .add_op(OpMul)
            .unwrap()
            .add_i64(5)
            .unwrap()
            .add_op(OpDiv)
            .unwrap()
            .add_i64(3)
            .unwrap()
            .add_op(OpMod)
            .unwrap()
            .add_i64(10)
            .unwrap()
            .add_op(OpMin)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_op(OpNumEqual)
            .unwrap();
        assert_eq!(typed.redeem_script(), manual.script());

        let typed_max = TypedScriptBuilder::new().add_i64(3).add_i64(7).op_max().add_i64(7).op_num_equal();

        let mut manual_max = ScriptBuilder::new();
        manual_max.add_i64(3).unwrap().add_i64(7).unwrap().add_op(OpMax).unwrap().add_i64(7).unwrap().add_op(OpNumEqual).unwrap();
        assert_eq!(typed_max.redeem_script(), manual_max.script());
    }

    #[test]
    fn test_within() {
        let typed = TypedScriptBuilder::new()
            .add_i64(5)   // value
            .add_i64(1)   // min
            .add_i64(10)  // max
            .op_within();

        let mut manual = ScriptBuilder::new();
        manual.add_i64(5).unwrap().add_i64(1).unwrap().add_i64(10).unwrap().add_op(OpWithin).unwrap();
        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_comparison_extras() {
        let typed_lte = TypedScriptBuilder::new().add_i64(3).add_i64(5).op_less_than_or_equal();
        let mut manual = ScriptBuilder::new();
        manual.add_i64(3).unwrap().add_i64(5).unwrap().add_op(OpLessThanOrEqual).unwrap();
        assert_eq!(typed_lte.redeem_script(), manual.script());

        let typed_gte = TypedScriptBuilder::new().add_i64(5).add_i64(3).op_greater_than_or_equal();
        let mut manual_gte = ScriptBuilder::new();
        manual_gte.add_i64(5).unwrap().add_i64(3).unwrap().add_op(OpGreaterThanOrEqual).unwrap();
        assert_eq!(typed_gte.redeem_script(), manual_gte.script());

        let typed_nne = TypedScriptBuilder::new().add_i64(3).add_i64(5).op_num_not_equal();
        let mut manual_nne = ScriptBuilder::new();
        manual_nne.add_i64(3).unwrap().add_i64(5).unwrap().add_op(OpNumNotEqual).unwrap();
        assert_eq!(typed_nne.redeem_script(), manual_nne.script());

        let typed_0ne = TypedScriptBuilder::new().add_i64(5).op_0_not_equal();
        let mut manual_0ne = ScriptBuilder::new();
        manual_0ne.add_i64(5).unwrap().add_op(Op0NotEqual).unwrap();
        assert_eq!(typed_0ne.redeem_script(), manual_0ne.script());
    }

    #[test]
    fn test_bool_logic() {
        let typed = TypedScriptBuilder::new().add_i64(1).add_i64(1).op_bool_and();
        let mut manual = ScriptBuilder::new();
        manual.add_i64(1).unwrap().add_i64(1).unwrap().add_op(OpBoolAnd).unwrap();
        assert_eq!(typed.redeem_script(), manual.script());

        let typed_or = TypedScriptBuilder::new().add_i64(0).add_i64(1).op_bool_or();
        let mut manual_or = ScriptBuilder::new();
        manual_or.add_i64(0).unwrap().add_i64(1).unwrap().add_op(OpBoolOr).unwrap();
        assert_eq!(typed_or.redeem_script(), manual_or.script());
    }

    #[test]
    fn test_stack_manipulation() {
        // op_dup
        let typed_dup = TypedScriptBuilder::new().add_i64(5).op_dup().op_add().add_i64(10).op_num_equal();
        let mut manual_dup = ScriptBuilder::new();
        manual_dup.add_i64(5).unwrap().add_op(OpDup).unwrap().add_op(OpAdd).unwrap().add_i64(10).unwrap().add_op(OpNumEqual).unwrap();
        assert_eq!(typed_dup.redeem_script(), manual_dup.script());

        // op_drop
        let typed_drop = TypedScriptBuilder::new().add_i64(99).add_i64(1).op_drop().add_i64(99).op_num_equal();
        let mut manual_drop = ScriptBuilder::new();
        manual_drop.add_i64(99).unwrap().add_i64(1).unwrap().add_op(OpDrop).unwrap().add_i64(99).unwrap().add_op(OpNumEqual).unwrap();
        assert_eq!(typed_drop.redeem_script(), manual_drop.script());

        // op_swap (Data) — swap [1],[2] → [2],[1], nip → [2], compare with [2]
        let typed_swap = TypedScriptBuilder::new().add_data(&[1]).add_data(&[2]).op_swap().op_nip().add_data(&[1]).op_equal();

        let mut manual_swap = ScriptBuilder::new();
        manual_swap
            .add_data(&[1])
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_op(OpSwap)
            .unwrap()
            .add_op(OpNip)
            .unwrap()
            .add_data(&[1])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_swap.redeem_script(), manual_swap.script());

        // op_rot (Data) — rot [1],[2],[3] → [2],[3],[1], 2_drop → [1], compare
        let typed_rot =
            TypedScriptBuilder::new().add_data(&[1]).add_data(&[2]).add_data(&[3]).op_rot().op_2_drop().add_data(&[1]).op_equal();

        let mut manual_rot = ScriptBuilder::new();
        manual_rot
            .add_data(&[1])
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_data(&[3])
            .unwrap()
            .add_op(OpRot)
            .unwrap()
            .add_op(Op2Drop)
            .unwrap()
            .add_data(&[1])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_rot.redeem_script(), manual_rot.script());

        // op_nip — [1],[2] → [2], compare with [2]
        let typed_nip = TypedScriptBuilder::new().add_data(&[1]).add_data(&[2]).op_nip().add_data(&[2]).op_equal();

        let mut manual_nip = ScriptBuilder::new();
        manual_nip
            .add_data(&[1])
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_op(OpNip)
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_nip.redeem_script(), manual_nip.script());

        // op_over — [1],[2] → [1],[2],[1], equal_verify top two, then compare remaining
        let typed_over = TypedScriptBuilder::new().add_data(&[1]).add_data(&[2]).op_over().op_nip().op_nip().add_data(&[1]).op_equal();

        let mut manual_over = ScriptBuilder::new();
        manual_over
            .add_data(&[1])
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_op(OpOver)
            .unwrap()
            .add_op(OpNip)
            .unwrap()
            .add_op(OpNip)
            .unwrap()
            .add_data(&[1])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_over.redeem_script(), manual_over.script());

        // op_tuck — [1],[2] → [2],[1],[2], 2_drop → [2], compare
        let typed_tuck = TypedScriptBuilder::new().add_data(&[1]).add_data(&[2]).op_tuck().op_2_drop().add_data(&[2]).op_equal();

        let mut manual_tuck = ScriptBuilder::new();
        manual_tuck
            .add_data(&[1])
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_op(OpTuck)
            .unwrap()
            .add_op(Op2Drop)
            .unwrap()
            .add_data(&[2])
            .unwrap()
            .add_op(OpEqual)
            .unwrap();
        assert_eq!(typed_tuck.redeem_script(), manual_tuck.script());
    }

    #[test]
    fn test_constants() {
        let typed_true = TypedScriptBuilder::new().op_true();
        let mut manual_true = ScriptBuilder::new();
        manual_true.add_op(OpTrue).unwrap();
        assert_eq!(typed_true.redeem_script(), manual_true.script());

        let typed_false = TypedScriptBuilder::new().op_false();
        let mut manual_false = ScriptBuilder::new();
        manual_false.add_op(OpFalse).unwrap();
        assert_eq!(typed_false.redeem_script(), manual_false.script());

        let typed_neg = TypedScriptBuilder::new().op_1_negate().add_i64(-1).op_num_equal();
        let mut manual_neg = ScriptBuilder::new();
        manual_neg.add_op(Op1Negate).unwrap().add_i64(-1).unwrap().add_op(OpNumEqual).unwrap();
        assert_eq!(typed_neg.redeem_script(), manual_neg.script());

        let typed_n = TypedScriptBuilder::new().op_n(5).add_i64(5).op_num_equal();
        let mut manual_n = ScriptBuilder::new();
        manual_n.add_op(0x55).unwrap().add_i64(5).unwrap().add_op(OpNumEqual).unwrap();
        assert_eq!(typed_n.redeem_script(), manual_n.script());
    }

    #[test]
    fn test_verify() {
        // op_verify
        let typed_verify = TypedScriptBuilder::new().add_i64(1).add_i64(1).op_num_equal()
            .op_dup() // duplicate the bool
            .op_verify(); // verify top, leaves the other

        let mut manual_verify = ScriptBuilder::new();
        manual_verify
            .add_i64(1)
            .unwrap()
            .add_i64(1)
            .unwrap()
            .add_op(OpNumEqual)
            .unwrap()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpVerify)
            .unwrap();
        assert_eq!(typed_verify.redeem_script(), manual_verify.script());

        // op_equal_verify
        let typed_eq_verify = TypedScriptBuilder::new().add_data(&[1, 2]).add_data(&[1, 2]).op_equal_verify().op_true();

        let mut manual_eq_verify = ScriptBuilder::new();
        manual_eq_verify.add_data(&[1, 2]).unwrap().add_data(&[1, 2]).unwrap().add_op(OpEqualVerify).unwrap().add_op(OpTrue).unwrap();
        assert_eq!(typed_eq_verify.redeem_script(), manual_eq_verify.script());

        // op_num_equal_verify
        let typed_neq_verify = TypedScriptBuilder::new().add_i64(42).add_i64(42).op_num_equal_verify().op_true();

        let mut manual_neq_verify = ScriptBuilder::new();
        manual_neq_verify.add_i64(42).unwrap().add_i64(42).unwrap().add_op(OpNumEqualVerify).unwrap().add_op(OpTrue).unwrap();
        assert_eq!(typed_neq_verify.redeem_script(), manual_neq_verify.script());
    }

    #[test]
    fn test_conversion() {
        // op_num2bin and op_bin2num
        let typed = TypedScriptBuilder::new().add_i64(255).add_i64(4).op_num2bin().op_bin2num().add_i64(255).op_num_equal();

        let mut manual = ScriptBuilder::new();
        manual
            .add_i64(255)
            .unwrap()
            .add_i64(4)
            .unwrap()
            .add_op(OpNum2Bin)
            .unwrap()
            .add_op(OpBin2Num)
            .unwrap()
            .add_i64(255)
            .unwrap()
            .add_op(OpNumEqual)
            .unwrap();
        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_downcast_upcast_zero_cost() {
        // downcast Num → Data → back via upcast → Num, then compare
        let roundtrip = TypedScriptBuilder::new().add_i64(42).downcast().unsafe_interpret_as_num().add_i64(42).op_num_equal();

        // The roundtrip script should be exactly: push(42), push(42), OpNumEqual
        // No extra opcodes emitted by downcast or upcast
        let mut expected = ScriptBuilder::new();
        expected.add_i64(42).unwrap().add_i64(42).unwrap().add_op(OpNumEqual).unwrap();
        assert_eq!(roundtrip.redeem_script(), expected.script());
    }

    #[test]
    fn test_sig_builder_data_hash() {
        // Redeem: op_equal (needs 2 Data from sig)
        let typed = TypedScriptBuilder::new().op_equal();
        let sig = typed.into_sig_builder().add_data(&[1, 2, 3]).add_data(&[1, 2, 3]).build();
        assert!(!sig.is_empty());

        // With Hash in signature
        let h = kaspa_hashes::Hash::from_bytes([0xCC; 32]);
        // Redeem: add_data(some_data) op_sha256 downcast op_equal
        // Needs 1 Hash from sig
        let typed2 = TypedScriptBuilder::new().add_data(&[0xCC; 32]).add_hash(&h).downcast().op_equal();
        // no sig needed — both on stack
        assert!(!typed2.redeem_script().is_empty());
    }

    #[test]
    fn test_introspection_ops() {
        let typed = TypedScriptBuilder::new().op_tx_input_count().op_tx_output_count().op_add().add_i64(0).op_greater_than();

        let mut manual = ScriptBuilder::new();
        manual
            .add_op(OpTxInputCount)
            .unwrap()
            .add_op(OpTxOutputCount)
            .unwrap()
            .add_op(OpAdd)
            .unwrap()
            .add_i64(0)
            .unwrap()
            .add_op(OpGreaterThan)
            .unwrap();
        assert_eq!(typed.redeem_script(), manual.script());

        // Index-consuming ops
        let typed2 = TypedScriptBuilder::new().add_i64(0).op_tx_input_amount().add_i64(0).op_greater_than_or_equal();

        let mut manual2 = ScriptBuilder::new();
        manual2.add_i64(0).unwrap().add_op(OpTxInputAmount).unwrap().add_i64(0).unwrap().add_op(OpGreaterThanOrEqual).unwrap();
        assert_eq!(typed2.redeem_script(), manual2.script());
    }

    #[test]
    fn test_check_sig_bytes() {
        let typed = TypedScriptBuilder::new().add_data(&[0xAA; 33]).add_data(&[0xBB; 64]).op_check_sig();

        let mut manual = ScriptBuilder::new();
        manual.add_data(&[0xAA; 33]).unwrap().add_data(&[0xBB; 64]).unwrap().add_op(OpCheckSig).unwrap();
        assert_eq!(typed.redeem_script(), manual.script());

        let typed_ecdsa = TypedScriptBuilder::new().add_data(&[0xAA; 33]).add_data(&[0xBB; 64]).op_check_sig_ecdsa();

        let mut manual_ecdsa = ScriptBuilder::new();
        manual_ecdsa.add_data(&[0xAA; 33]).unwrap().add_data(&[0xBB; 64]).unwrap().add_op(OpCheckSigECDSA).unwrap();
        assert_eq!(typed_ecdsa.redeem_script(), manual_ecdsa.script());
    }

    // -----------------------------------------------------------------------
    // P2SH engine execution tests
    // -----------------------------------------------------------------------

    fn make_p2sh_tx(redeem_script: &[u8], sig_script: Vec<u8>) -> (Transaction, UtxoEntry) {
        let script_pub_key = pay_to_script_hash_script(redeem_script);
        let tx = Transaction::new(
            1,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::default(), index: 0 },
                signature_script: sig_script,
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![],
            0,
            Default::default(),
            0,
            vec![],
        );
        let utxo = UtxoEntry::new(1000, script_pub_key, 0, false, None);
        (tx, utxo)
    }

    #[test]
    fn test_p2sh_engine_execution() {
        let typed = TypedScriptBuilder::new().op_add().op_num_equal();
        let redeem = typed.redeem_script().to_vec();
        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();

        // Correct case: a=8, b=5, c=3 → 5+3=8, 8==8 → true
        let correct_sig =
            TypedScriptBuilder::new().op_add().op_num_equal().into_sig_builder().add_i64(8).add_i64(5).add_i64(3).build();

        let (tx, utxo) = make_p2sh_tx(&redeem, correct_sig);
        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

        let mut vm = TxScriptEngine::from_transaction_input(
            &populated_tx,
            &populated_tx.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm.execute().expect("correct inputs should succeed");

        // Failing case: a=9
        let wrong_sig = TypedScriptBuilder::new().op_add().op_num_equal().into_sig_builder().add_i64(9).add_i64(5).add_i64(3).build();

        let (tx_bad, _) = make_p2sh_tx(&redeem, wrong_sig);
        let populated_tx_bad = PopulatedTransaction::new(&tx_bad, vec![utxo.clone()]);

        let mut vm_bad = TxScriptEngine::from_transaction_input(
            &populated_tx_bad,
            &populated_tx_bad.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm_bad.execute().expect_err("wrong inputs should fail");
    }

    #[test]
    fn test_p2sh_data_equal() {
        // Redeem: add_data([0xDE,0xAD]) op_equal (needs 1 Data from sig)
        let typed = TypedScriptBuilder::new().add_data(&[0xDE, 0xAD]).op_equal();

        let redeem = typed.redeem_script().to_vec();

        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();

        // Correct sig
        let correct_sig = typed.into_sig_builder().add_data(&[0xDE, 0xAD]).build();
        let (tx, utxo) = make_p2sh_tx(&redeem, correct_sig);
        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

        let mut vm = TxScriptEngine::from_transaction_input(
            &populated_tx,
            &populated_tx.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm.execute().expect("matching data should succeed");

        // Wrong sig
        let typed2 = TypedScriptBuilder::new().add_data(&[0xDE, 0xAD]).op_equal();
        let wrong_sig = typed2.into_sig_builder().add_data(&[0xBE, 0xEF]).build();
        let (tx_bad, _) = make_p2sh_tx(&redeem, wrong_sig);
        let populated_tx_bad = PopulatedTransaction::new(&tx_bad, vec![utxo.clone()]);

        let mut vm_bad = TxScriptEngine::from_transaction_input(
            &populated_tx_bad,
            &populated_tx_bad.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm_bad.execute().expect_err("wrong data should fail");
    }

    #[test]
    fn test_p2sh_hash_check() {
        use kaspa_txscript::hex;

        // Known SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let preimage = b"hello";
        let known_hash_bytes = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").unwrap();
        let known_hash = kaspa_hashes::Hash::from_slice(&known_hash_bytes);

        // Redeem: op_sha256 downcast add_hash(known_hash) downcast op_equal
        // Needs 1 Data from sig: the preimage
        let typed = TypedScriptBuilder::new().op_sha256().downcast().add_hash(&known_hash).downcast().op_equal();

        let redeem = typed.redeem_script().to_vec();

        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();

        // Correct: provide the right preimage
        let correct_sig = typed.into_sig_builder().add_data(preimage).build();
        let (tx, utxo) = make_p2sh_tx(&redeem, correct_sig);
        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

        let mut vm = TxScriptEngine::from_transaction_input(
            &populated_tx,
            &populated_tx.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm.execute().expect("correct preimage should succeed");

        // Wrong preimage
        let typed2 = TypedScriptBuilder::new().op_sha256().downcast().add_hash(&known_hash).downcast().op_equal();
        let wrong_sig = typed2.into_sig_builder().add_data(b"wrong").build();
        let (tx_bad, _) = make_p2sh_tx(&redeem, wrong_sig);
        let populated_tx_bad = PopulatedTransaction::new(&tx_bad, vec![utxo.clone()]);

        let mut vm_bad = TxScriptEngine::from_transaction_input(
            &populated_tx_bad,
            &populated_tx_bad.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm_bad.execute().expect_err("wrong preimage should fail");
    }

    #[test]
    fn test_p2sh_cat_equal() {
        // Redeem: op_cat add_data([1,2,3,4,5,6]) op_equal (needs 2 Data from sig)
        // OpCat requires covenants_enabled
        let typed = TypedScriptBuilder::new().op_cat().add_data(&[1, 2, 3, 4, 5, 6]).op_equal();

        let redeem = typed.redeem_script().to_vec();

        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();

        // Correct: [1,2,3] + [4,5,6] = [1,2,3,4,5,6]
        let correct_sig = typed.into_sig_builder().add_data(&[1, 2, 3]).add_data(&[4, 5, 6]).build();

        let (tx, utxo) = make_p2sh_tx(&redeem, correct_sig);
        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

        let mut vm = TxScriptEngine::from_transaction_input(
            &populated_tx,
            &populated_tx.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            EngineFlags { covenants_enabled: true },
        );
        vm.execute().expect("correct cat should succeed");
    }

    // -----------------------------------------------------------------------
    // ZK precompile execution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_zk_groth16_typed() {
        use kaspa_txscript::hex;
        use kaspa_txscript::zk_precompiles::tests::helpers::{build_groth_script, execute_zk_script};

        let unprepared_compressed_vk = hex::decode("e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e1933033e7fea1f40604eaacf699d4be9aacc577054a0db22d9129a1728ff85a01a1c3af829b62bf4914c0bcf2c81a4bd577190eff5f194ee9bac95faefd53cb0030600000000000000e43bdc655d0f9d730535554d9caa611ddd152c081a06a932a8e1d5dc259aac123f42a188f683d869873ccc4c119442e57b056e03e2fa92f2028c97bc20b9078747c30f85444697fdf436e348711c011115963f855197243e4b39e6cbe236ca8ba7f2042e11f9255afbb6c6e2c3accb88e401f2aac21c097c92b3fbdb99f98a9b0dcd6c075ada6ed0ddfece1d4a2d005f61a7d5df0b75c18a5b2374d64e495fab93d4c4b1200394d5253cce2f25a59b862ee8e4cd43686603faa09d5d0d3c1c8f").unwrap();
        let groth16_proof_bytes = hex::decode("570253c0c483a1b16460118e63c155f3684e784ae7d97e8fc3f544128b37fe15075eab5ac31150c8a44253d8525971241bbd7227fcefbae2db4ae71675c56a2e0eb9235136b15ab72f16e707832f3d6ae5b0ba7cca53ae17cb52b3201919eb9d908c16297abd90aa7e00267bc21a9a78116e717d4d76edd44e21cca17e3d592d").unwrap();
        let input0 = hex::decode("a54dc85ac99f851c92d7c96d7318af4100000000000000000000000000000000").unwrap();
        let input1 = hex::decode("dbe7c0194edfcc37eb4d422a998c1f5600000000000000000000000000000000").unwrap();
        let input2 = hex::decode("a95ac0b37bfedcd8136e6c1143086bf500000000000000000000000000000000").unwrap();
        let input3 = hex::decode("d223ffcb21c6ffcb7c8f60392ca49dde00000000000000000000000000000000").unwrap();
        let input4 = hex::decode("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404").unwrap();

        let typed = TypedScriptBuilder::new()
            .add_bn254_fr(&Fr::try_from(input4.as_slice()).unwrap())
            .add_bn254_fr(&Fr::try_from(input3.as_slice()).unwrap())
            .add_bn254_fr(&Fr::try_from(input2.as_slice()).unwrap())
            .add_bn254_fr(&Fr::try_from(input1.as_slice()).unwrap())
            .add_bn254_fr(&Fr::try_from(input0.as_slice()).unwrap())
            .add_i64(5)
            .add_g16_proof(&groth16_proof_bytes)
            .add_g16_vk(&unprepared_compressed_vk)
            .add_groth16_tag()
            .groth16_verify();

        let manual = build_groth_script();
        assert_eq!(typed.redeem_script(), manual.as_slice());

        // Execute
        let sig_cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        execute_zk_script(typed.redeem_script(), &sig_cache, &reused_values).unwrap();
    }

    #[test]
    fn test_zk_r0_succinct_typed() {
        use kaspa_txscript::zk_precompiles::tests::helpers::{build_stark_script, execute_zk_script, load_stark_fields};

        let (seal, claim, hashfn, control_index, control_digests, journal, image_id) = load_stark_fields();

        let typed = TypedScriptBuilder::new()
            .add_r0_succinct_seal_bytes(&seal)
            .add_r0_succinct_claim(&claim)
            .add_r0_succinct_hashfn_bytes(&hashfn)
            .add_r0_succinct_control_index_bytes(&control_index)
            .add_r0_succinct_control_digests(&control_digests)
            .add_r0_succinct_journal_digest(&journal)
            .add_r0_succinct_image_id(&image_id)
            .add_r0_succinct_tag()
            .risc0_succinct_verify();

        let manual = build_stark_script();
        assert_eq!(typed.redeem_script(), manual.as_slice());

        // Execute
        let sig_cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        execute_zk_script(typed.redeem_script(), &sig_cache, &reused_values).unwrap();
    }

    // -----------------------------------------------------------------------
    // SeqCommit execution test
    // -----------------------------------------------------------------------

    #[test]
    fn test_seq_commit_p2sh() {
        use kaspa_txscript::SeqCommitAccessor;

        const EXPECTED_INPUT_BLOCK_HASH: [u8; 32] = {
            let mut block = [b'f'; 32];
            let input = b"input_block";
            let mut i = 0;
            while i < input.len() {
                block[i] = input[i];
                i += 1;
            }
            block
        };

        const EXPECTED_OUTPUT_ROOT_HASH: [u8; 32] = {
            let mut block = [b'f'; 32];
            let input = b"output_root_hash";
            let mut i = 0;
            while i < input.len() {
                block[i] = input[i];
                i += 1;
            }
            block
        };

        struct MockSeqCommitAccessor;

        impl SeqCommitAccessor for MockSeqCommitAccessor {
            fn is_chain_ancestor_from_pov(&self, block_hash: kaspa_hashes::Hash) -> Option<bool> {
                (block_hash == kaspa_hashes::Hash::from(EXPECTED_INPUT_BLOCK_HASH)).then_some(true)
            }

            fn seq_commitment_within_depth(&self, block_hash: kaspa_hashes::Hash) -> Option<kaspa_hashes::Hash> {
                (block_hash == kaspa_hashes::Hash::from(EXPECTED_INPUT_BLOCK_HASH))
                    .then_some(kaspa_hashes::Hash::from(EXPECTED_OUTPUT_ROOT_HASH))
            }
        }

        let input_hash = kaspa_hashes::Hash::from(EXPECTED_INPUT_BLOCK_HASH);
        let output_hash = kaspa_hashes::Hash::from(EXPECTED_OUTPUT_ROOT_HASH);

        // Redeem: op_chainblock_seq_commit downcast add_hash(expected_output) downcast op_equal
        // Needs 1 Hash from sig: the block hash
        let typed = TypedScriptBuilder::new().op_chainblock_seq_commit().downcast().add_hash(&output_hash).downcast().op_equal();

        let redeem = typed.redeem_script().to_vec();
        let script_pub_key = pay_to_script_hash_script(&redeem);

        // Build sig: provide block hash
        let sig = typed.into_sig_builder().add_hash(input_hash).build();

        let tx = Transaction::new(
            1,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::default(), index: 0 },
                signature_script: sig,
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![],
            0,
            Default::default(),
            0,
            vec![],
        );
        let utxo = UtxoEntry::new(1000, script_pub_key, 0, false, None);
        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();

        let mut vm = TxScriptEngine::from_transaction_input(
            &populated_tx,
            &populated_tx.tx.inputs[0],
            0,
            &utxo,
            EngineCtx::new(&sig_cache).with_reused(&reused_values).with_seq_commit_accessor(&MockSeqCommitAccessor),
            EngineFlags { covenants_enabled: true },
        );
        vm.execute().expect("seq commit with correct hash should succeed");
    }

    #[test]
    fn test_generic_stack_ops() {
        // op_dup / op_drop on Groth16Tag (previously missing)
        let typed_groth16 = TypedScriptBuilder::new().add_groth16_tag().op_dup().op_drop().op_drop().op_true();

        let mut manual_groth16 = ScriptBuilder::new();
        manual_groth16
            .add_data(&[ZkTag::Groth16 as u8])
            .unwrap()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap();
        assert_eq!(typed_groth16.redeem_script(), manual_groth16.script());

        // op_dup / op_drop on R0SuccinctTag (previously missing)
        let typed_r0 = TypedScriptBuilder::new().add_r0_succinct_tag().op_dup().op_drop().op_drop().op_true();

        let mut manual_r0 = ScriptBuilder::new();
        manual_r0
            .add_data(&[ZkTag::R0Succinct as u8])
            .unwrap()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap();
        assert_eq!(typed_r0.redeem_script(), manual_r0.script());

        // op_swap on mixed types (Num<Hash<S>>) without downcast
        let hash = kaspa_hashes::Hash::from([0xAB; 32]);
        let typed_swap = TypedScriptBuilder::new()
            .add_hash(&hash)
            .add_i64(42)
            .op_swap() // Num<Hash<()>> → Hash<Num<()>>
            .op_drop() // Hash<Num<()>> → Num<()>
            .op_drop()
            .op_true();

        let mut manual_swap = ScriptBuilder::new();
        manual_swap
            .add_data(&hash.as_bytes())
            .unwrap()
            .add_i64(42)
            .unwrap()
            .add_op(OpSwap)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap();
        assert_eq!(typed_swap.redeem_script(), manual_swap.script());

        // op_rot on mixed types (Num<Hash<Data<S>>>) without downcast
        let typed_rot = TypedScriptBuilder::new()
            .add_data(&[1, 2, 3])
            .add_hash(&hash)
            .add_i64(7)
            .op_rot() // Num<Hash<Data<()>>> → Data<Num<Hash<()>>>
            .op_drop() // Data<Num<Hash<()>>> → Num<Hash<()>>
            .op_drop() // Num<Hash<()>> → Hash<()>
            .op_drop()
            .op_true();

        let mut manual_rot = ScriptBuilder::new();
        manual_rot
            .add_data(&[1, 2, 3])
            .unwrap()
            .add_data(&hash.as_bytes())
            .unwrap()
            .add_i64(7)
            .unwrap()
            .add_op(OpRot)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap();
        assert_eq!(typed_rot.redeem_script(), manual_rot.script());
    }

    #[test]
    fn test_hash_to_journal_digest_cast() {
        // op_sha256 followed by as_r0_succinct_journal_digest should emit no extra opcodes
        let typed = TypedScriptBuilder::new()
            .add_data(&[1, 2, 3])
            .op_sha256()
            .into_r0_succinct_journal_digest()
            .downcast()
            .add_data(&[0xAA; 32])
            .op_equal();

        let mut manual = ScriptBuilder::new();
        manual.add_data(&[1, 2, 3]).unwrap().add_op(OpSHA256).unwrap().add_data(&[0xAA; 32]).unwrap().add_op(OpEqual).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_r0_succinct_generic_stack_ops_on_semantic_types() {
        // op_dup / op_drop on R0SuccinctSeal
        let typed_seal = TypedScriptBuilder::new().add_r0_succinct_seal_bytes(&[0u8; 4]).op_dup().op_drop().op_drop().op_true();

        let mut manual_seal = ScriptBuilder::new();
        manual_seal
            .add_data(&[0u8; 4])
            .unwrap()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap();
        assert_eq!(typed_seal.redeem_script(), manual_seal.script());

        // op_dup / op_drop on G16Vk
        let typed_vk = TypedScriptBuilder::new().add_g16_vk(&[0xAA; 16]).op_dup().op_drop().op_drop().op_true();

        let mut manual_vk = ScriptBuilder::new();
        manual_vk
            .add_data(&[0xAA; 16])
            .unwrap()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap();
        assert_eq!(typed_vk.redeem_script(), manual_vk.script());
    }
}

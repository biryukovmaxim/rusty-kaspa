use std::marker::PhantomData;

use ark_serialize::CanonicalSerialize;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::zk_precompiles::fields::Fr;
pub use kaspa_txscript::zk_precompiles::risc0::rcpt::HashFnId as R0SuccinctHashFnId;
use kaspa_txscript::zk_precompiles::tags::ZkTag;

use crate::markers::*;

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
    pub(crate) builder: ScriptBuilder,
    pub(crate) _phantom: PhantomData<(Stack, Missing)>,
}

/// Builder for the signature script half. `Missing` tracks how many inputs
/// still need to be provided before `build()` becomes available.
pub struct ScriptSignatureBuilder<Missing> {
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) buf: Vec<u8>,
    pub(crate) _phantom: PhantomData<Missing>,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    /// Emit a raw opcode and transmute the phantom types.
    pub(crate) fn emit_op<S2, M2>(mut self, opcode: u8) -> TypedScriptBuilder<S2, M2> {
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

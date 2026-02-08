use std::marker::PhantomData;

use ark_serialize::CanonicalSerialize;
use kaspa_consensus_core::hashing::sighash_type::SigHashType;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::zk_precompiles::fields::Fr;
pub use kaspa_txscript::zk_precompiles::risc0::rcpt::HashFnId as R0SuccinctHashFnId;
use kaspa_txscript::zk_precompiles::tags::ZkTag;

use crate::markers::*;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A script builder that tracks the stack state (`Stack`), missing signature
/// inputs (`Missing`), and alt stack state (`AltStack`) at the type level.
///
/// - `Stack`: encodes what is currently on the stack.
///   `()` = empty, `Num<()>` = one number, `Num<Num<()>>` = two numbers, etc.
/// - `Missing`: encodes inputs that must be provided in the signature script.
///   `()` = nothing missing, `Num<()>` = need one number, etc.
/// - `AltStack`: encodes what is currently on the alt stack.
///   `()` = empty. Uses the same nested marker encoding as `Stack`.
pub struct TypedScriptBuilder<Stack, Missing, AltStack = ()> {
    pub(crate) builder: ScriptBuilder,
    pub(crate) _phantom: PhantomData<(Stack, Missing, AltStack)>,
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

impl<S, M, A> TypedScriptBuilder<S, M, A> {
    /// Emit a raw opcode and transmute the phantom types (preserving alt stack).
    pub(crate) fn emit_op<S2, M2>(mut self, opcode: u8) -> TypedScriptBuilder<S2, M2, A> {
        self.builder.add_op(opcode).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Emit a raw opcode and transmute all three phantom types (including alt stack).
    pub(crate) fn emit_op_alt<S2, M2, A2>(mut self, opcode: u8) -> TypedScriptBuilder<S2, M2, A2> {
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

impl<S, M, A> TypedScriptBuilder<S, M, A> {
    /// Push a number literal onto the stack.
    pub fn add_i64(mut self, val: i64) -> TypedScriptBuilder<Num<S>, M, A> {
        self.builder.add_i64(val).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push raw data bytes onto the stack.
    pub fn add_data(mut self, data: &[u8]) -> TypedScriptBuilder<Data<S>, M, A> {
        self.builder.add_data(data).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a hash value onto the stack.
    pub fn add_hash(mut self, hash: &kaspa_hashes::Hash) -> TypedScriptBuilder<Hash<S>, M, A> {
        self.builder.add_data(hash.as_ref()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a BN254 field element onto the stack.
    pub fn add_bn254_fr(mut self, fr: &Fr) -> TypedScriptBuilder<Bn254Fr<S>, M, A> {
        let mut bytes = Vec::new();
        fr.field().serialize_uncompressed(&mut bytes).expect("Fr serialization failed");
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a Groth16 ZK proof tag byte onto the stack.
    pub fn add_groth16_tag(mut self) -> TypedScriptBuilder<Groth16Tag<S>, M, A> {
        self.builder.add_data(&[ZkTag::Groth16 as u8]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 succinct ZK proof tag byte onto the stack.
    pub fn add_r0_succinct_tag(mut self) -> TypedScriptBuilder<R0SuccinctTag<S>, M, A> {
        self.builder.add_data(&[ZkTag::R0Succinct as u8]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    // -- RISC0 Succinct semantic pushers --

    /// Push a RISC0 succinct seal from `u32` words (each serialized as 4 LE bytes).
    pub fn add_r0_succinct_seal(mut self, seal_words: &[u32]) -> TypedScriptBuilder<R0SuccinctSeal<S>, M, A> {
        let bytes: Vec<u8> = seal_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 succinct claim digest (exactly 32 bytes).
    pub fn add_r0_succinct_claim(mut self, claim: &[u8; 32]) -> TypedScriptBuilder<R0SuccinctClaim<S>, M, A> {
        self.builder.add_data(claim.as_slice()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 hash-function identifier from the `R0SuccinctHashFnId` enum.
    pub fn add_r0_succinct_hashfn(mut self, id: R0SuccinctHashFnId) -> TypedScriptBuilder<R0SuccinctHashFn<S>, M, A> {
        self.builder.add_data(&[u8::from(id)]).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 Merkle-tree control index from a `u32` (serialized as 4 LE bytes).
    pub fn add_r0_succinct_control_index(mut self, index: u32) -> TypedScriptBuilder<R0SuccinctControlIndex<S>, M, A> {
        self.builder.add_data(&index.to_le_bytes()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push RISC0 control digests (concatenated 32-byte digests; length must be a multiple of 32).
    pub fn add_r0_succinct_control_digests(mut self, digests: &[u8]) -> TypedScriptBuilder<R0SuccinctControlDigests<S>, M, A> {
        assert_eq!(digests.len() % 32, 0, "control digests length must be a multiple of 32, got {}", digests.len());
        self.builder.add_data(digests).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 journal digest (exactly 32 bytes).
    pub fn add_r0_succinct_journal_digest(mut self, digest: &[u8; 32]) -> TypedScriptBuilder<R0SuccinctJournalDigest<S>, M, A> {
        self.builder.add_data(digest.as_slice()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a RISC0 image ID (exactly 32 bytes).
    pub fn add_r0_succinct_image_id(mut self, image_id: &[u8; 32]) -> TypedScriptBuilder<R0SuccinctImageId<S>, M, A> {
        self.builder.add_data(image_id.as_slice()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    // -- Signature semantic pushers --

    /// Push a Schnorr signature onto the stack (64-byte signature + 1-byte sighash type).
    pub fn add_schnorr_sig(
        mut self,
        sig: &secp256k1::schnorr::Signature,
        sighash: SigHashType,
    ) -> TypedScriptBuilder<SchnorrSig<S>, M, A> {
        let mut bytes = [0u8; 65];
        let (sig_slice, h) = bytes.split_at_mut(64);
        sig_slice.copy_from_slice(sig.as_ref());
        h[0] = sighash.to_u8();
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push an x-only public key onto the stack (32 bytes, used with Schnorr).
    pub fn add_xonly_pubkey(mut self, pubkey: &[u8; 32]) -> TypedScriptBuilder<XOnlyPubkey<S>, M, A> {
        self.builder.add_data(pubkey.as_slice()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push an ECDSA signature onto the stack (64-byte signature + 1-byte sighash type).
    pub fn add_ecdsa_sig(mut self, sig: &secp256k1::ecdsa::Signature, sighash: SigHashType) -> TypedScriptBuilder<EcdsaSig<S>, M, A> {
        let mut bytes = [0u8; 65];
        let (sig_slice, h) = bytes.split_at_mut(64);
        sig_slice.copy_from_slice(&sig.serialize_compact());
        h[0] = sighash.to_u8();
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a compressed ECDSA public key onto the stack (33 bytes).
    pub fn add_ecdsa_pubkey(mut self, pubkey: &[u8; 33]) -> TypedScriptBuilder<EcdsaPubkey<S>, M, A> {
        self.builder.add_data(pubkey.as_slice()).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    // -- Groth16 semantic pushers --

    /// Push a Groth16 verification key onto the stack (serialized compressed).
    pub fn add_g16_vk(mut self, vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> TypedScriptBuilder<G16Vk<S>, M, A> {
        let mut bytes = Vec::new();
        vk.serialize_compressed(&mut bytes).expect("VK serialization failed");
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Push a Groth16 proof onto the stack (serialized compressed).
    pub fn add_g16_proof(mut self, proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> TypedScriptBuilder<G16Proof<S>, M, A> {
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).expect("Proof serialization failed");
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Downcast: safe type erasure — every stack element is bytes at runtime.
// No opcode is emitted.
// ---------------------------------------------------------------------------

impl<Top: StackEntry, M, A> TypedScriptBuilder<Top, M, A> {
    /// Safe type erasure — every stack element is bytes at runtime. No opcode is emitted.
    pub fn downcast(self) -> TypedScriptBuilder<Data<Top::Rest>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Upcast: unsafe reinterpretation from Data to typed markers.
// No opcode is emitted. If the data doesn't match the target type at runtime,
// the script will fail.
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Data<S>, M, A> {
    /// WARNING: No runtime validation. If the data cannot be deserialized as the
    /// target type, the script will fail at execution time. Prefer operations that
    /// naturally produce typed results, and use downcast when passing typed values
    /// to data-level operations.
    pub fn unsafe_interpret_as_num(self) -> TypedScriptBuilder<Num<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_bool(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_hash(self) -> TypedScriptBuilder<Hash<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_bn254_fr(self) -> TypedScriptBuilder<Bn254Fr<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_seal(self) -> TypedScriptBuilder<R0SuccinctSeal<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_claim(self) -> TypedScriptBuilder<R0SuccinctClaim<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_hashfn(self) -> TypedScriptBuilder<R0SuccinctHashFn<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_control_index(self) -> TypedScriptBuilder<R0SuccinctControlIndex<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_control_digests(self) -> TypedScriptBuilder<R0SuccinctControlDigests<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_journal_digest(self) -> TypedScriptBuilder<R0SuccinctJournalDigest<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_image_id(self) -> TypedScriptBuilder<R0SuccinctImageId<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_g16_vk(self) -> TypedScriptBuilder<G16Vk<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_g16_proof(self) -> TypedScriptBuilder<G16Proof<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_schnorr_sig(self) -> TypedScriptBuilder<SchnorrSig<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_xonly_pubkey(self) -> TypedScriptBuilder<XOnlyPubkey<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_ecdsa_sig(self) -> TypedScriptBuilder<EcdsaSig<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_ecdsa_pubkey(self) -> TypedScriptBuilder<EcdsaPubkey<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_groth16_tag(self) -> TypedScriptBuilder<Groth16Tag<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// WARNING: No runtime validation. See `unsafe_interpret_as_num`.
    pub fn unsafe_interpret_as_r0_succinct_tag(self) -> TypedScriptBuilder<R0SuccinctTag<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Semantic casts: Hash → R0Succinct types (zero-cost, no opcode)
// A 32-byte hash on the stack can be reinterpreted as a journal digest,
// image ID, or claim without emitting any opcodes.
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Hash<S>, M, A> {
    /// Reinterpret an on-stack SHA-256 hash as a RISC0 journal digest. No opcode emitted.
    pub fn into_r0_succinct_journal_digest(self) -> TypedScriptBuilder<R0SuccinctJournalDigest<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Reinterpret an on-stack SHA-256 hash as a RISC0 image ID. No opcode emitted.
    pub fn into_r0_succinct_image_id(self) -> TypedScriptBuilder<R0SuccinctImageId<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Reinterpret an on-stack SHA-256 hash as a RISC0 claim digest. No opcode emitted.
    pub fn into_r0_succinct_claim(self) -> TypedScriptBuilder<R0SuccinctClaim<S>, M, A> {
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

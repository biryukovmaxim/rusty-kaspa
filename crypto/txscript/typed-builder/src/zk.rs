use kaspa_txscript::opcodes::codes::*;

use crate::builder::TypedScriptBuilder;
use crate::markers::*;
use crate::ops::{FixedNumInputs, FixedNumResult};

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
    type AltStack;
    fn risc0_succinct_verify(self) -> TypedScriptBuilder<Bool<Self::Rest>, Self::Missing, Self::AltStack>;
}

impl<S, M, A> R0SuccinctVerify
    for TypedScriptBuilder<
        R0SuccinctTag<
            R0SuccinctImageId<
                R0SuccinctJournalDigest<
                    R0SuccinctControlDigests<R0SuccinctControlIndex<R0SuccinctHashFn<R0SuccinctClaim<R0SuccinctSeal<S>>>>>,
                >,
            >,
        >,
        M,
        A,
    >
{
    type Rest = S;
    type Missing = M;
    type AltStack = A;
    fn risc0_succinct_verify(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpZkPrecompile)
    }
}

// ---------------------------------------------------------------------------
// ZK Precompile: Groth16 verify (trait-based)
// ---------------------------------------------------------------------------

#[diagnostic::on_unimplemented(
    message = "the stack is not ready for `groth16_verify()`",
    label = "expected stack (top→bottom): Groth16Tag, G16Vk, G16Proof, then Num(n)+Bn254Fr... or FixedNum<N>",
    note = "Two paths:\n  1. .add_bn254_fr()...add_i64(n).add_g16_proof().add_g16_vk().add_groth16_tag()\n  2. .add_bn254_fr()...add_g16_fixed_num::<N>().add_g16_proof().add_g16_vk().add_groth16_tag()"
)]
pub trait G16Verify {
    type Missing;
    type AltStack;
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, Self::Missing, Self::AltStack>;
}

impl<S, M, A> G16Verify for TypedScriptBuilder<Groth16Tag<G16Vk<G16Proof<Num<Bn254Fr<S>>>>>, M, A> {
    type Missing = M;
    type AltStack = A;
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, M, A> {
        self.emit_op(OpZkPrecompile)
    }
}

impl<const N: usize, S, M, A> G16Verify for TypedScriptBuilder<Groth16Tag<G16Vk<G16Proof<FixedNum<N, Bn254Fr<()>, S>>>>, M, A> {
    type Missing = M;
    type AltStack = A;
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, M, A> {
        self.emit_op(OpZkPrecompile)
    }
}

// ---------------------------------------------------------------------------
// ZK Precompile: inherent bridge methods
// These convert E0599 (method not found) into E0277 (trait bound not satisfied)
// so that #[diagnostic::on_unimplemented] messages actually appear.
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<S, M, A> {
    /// Verifies a RISC0 succinct ZK proof.
    ///
    /// The stack (top→bottom) must be:
    /// `R0SuccinctTag`, `R0SuccinctImageId`, `R0SuccinctJournalDigest`,
    /// `R0SuccinctControlDigests`, `R0SuccinctControlIndex`, `R0SuccinctHashFn`,
    /// `R0SuccinctClaim`, `R0SuccinctSeal`.
    pub fn risc0_succinct_verify(
        self,
    ) -> TypedScriptBuilder<
        Bool<<Self as R0SuccinctVerify>::Rest>,
        <Self as R0SuccinctVerify>::Missing,
        <Self as R0SuccinctVerify>::AltStack,
    >
    where
        Self: R0SuccinctVerify,
    {
        R0SuccinctVerify::risc0_succinct_verify(self)
    }

    /// Backward-compatible alias for [`add_fixed_num::<N, Bn254Fr<()>>()`].
    ///
    /// Pushes the input count N and transitions the stack to `FixedNum<N, Bn254Fr, Rest>`.
    /// If fewer than N `Bn254Fr` elements are on the stack, the shortfall is added
    /// to the missing-inputs type for the signature builder.
    pub fn add_g16_fixed_num<const N: usize>(
        self,
    ) -> FixedNumResult<N, Bn254Fr<()>, S, M, A>
    where
        Self: FixedNumInputs<N, Bn254Fr<()>>,
    {
        self.add_fixed_num::<N, Bn254Fr<()>>()
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
    pub fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, <Self as G16Verify>::Missing, <Self as G16Verify>::AltStack>
    where
        Self: G16Verify,
    {
        G16Verify::groth16_verify(self)
    }
}

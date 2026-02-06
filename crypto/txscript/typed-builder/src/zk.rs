use std::marker::PhantomData;

use kaspa_txscript::opcodes::codes::*;

use crate::builder::TypedScriptBuilder;
use crate::markers::sealed;
use crate::markers::*;

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
// ZK Precompile: FixedNum input counting (trait + macro)
// ---------------------------------------------------------------------------

#[diagnostic::on_unimplemented(
    message = "cannot call `add_g16_fixed_num::<{N}>()` on this stack",
    label = "expected 0..N Bn254Fr elements on the stack",
    note = "push Bn254Fr elements with .add_bn254_fr(), then call .add_g16_fixed_num::<N>()\nAny shortfall is added to missing inputs for the signature builder."
)]
pub trait G16FixedNumInputs<const N: usize> {
    type Rest;
    type NewMissing;
}

macro_rules! impl_g16_fixed_num {
    // Entry point: N as literal, N underscore tokens for counting
    ($N:literal; $($tokens:tt)*) => {
        impl_g16_fixed_num!(@step $N; stack=[]; missing=[$($tokens)*]);
    };

    // All tokens shifted from missing to stack → emit final (K=N) impl
    (@step $N:literal; stack=[$($s:tt)*]; missing=[]) => {
        impl_g16_fixed_num!(@emit $N; [$($s)*]; []);
    };

    // Emit impl for current K, then shift one token from missing to stack
    (@step $N:literal; stack=[$($s:tt)*]; missing=[_ $($m:tt)*]) => {
        impl_g16_fixed_num!(@emit $N; [$($s)*]; [_ $($m)*]);
        impl_g16_fixed_num!(@step $N; stack=[$($s)* _]; missing=[$($m)*]);
    };

    // Emit a single impl
    (@emit $N:literal; [$($s:tt)*]; [$($m:tt)*]) => {
        impl<S: sealed::NotBn254Fr, M> G16FixedNumInputs<$N>
            for TypedScriptBuilder<impl_g16_fixed_num!(@wrap [$($s)*] S), M>
        {
            type Rest = S;
            type NewMissing = impl_g16_fixed_num!(@wrap [$($m)*] M);
        }
    };

    // Helper: wrap $inner in K layers of Bn254Fr<...>
    (@wrap [] $inner:ty) => { $inner };
    (@wrap [_ $($rest:tt)*] $inner:ty) => {
        Bn254Fr<impl_g16_fixed_num!(@wrap [$($rest)*] $inner)>
    };
}

impl_g16_fixed_num!(1; _);
impl_g16_fixed_num!(2; _ _);
impl_g16_fixed_num!(3; _ _ _);
impl_g16_fixed_num!(4; _ _ _ _);
impl_g16_fixed_num!(5; _ _ _ _ _);
impl_g16_fixed_num!(6; _ _ _ _ _ _);
impl_g16_fixed_num!(7; _ _ _ _ _ _ _);
impl_g16_fixed_num!(8; _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(9; _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(10; _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(11; _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(12; _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(13; _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(14; _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(15; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(16; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(17; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(18; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(19; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(20; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(21; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(22; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(23; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(24; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(25; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(26; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(27; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(28; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(29; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(30; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(31; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_g16_fixed_num!(32; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);

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
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, Self::Missing>;
}

impl<S, M> G16Verify for TypedScriptBuilder<Groth16Tag<G16Vk<G16Proof<Num<Bn254Fr<S>>>>>, M> {
    type Missing = M;
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, M> {
        self.emit_op(OpZkPrecompile)
    }
}

impl<const N: usize, S, M> G16Verify for TypedScriptBuilder<Groth16Tag<G16Vk<G16Proof<FixedNum<N, Bn254Fr<()>, S>>>>, M> {
    type Missing = M;
    fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, M> {
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

    /// Pushes the input count N and transitions the stack to `FixedNum<N, Bn254Fr, Rest>`.
    ///
    /// If fewer than N `Bn254Fr` elements are on the stack, the shortfall is added
    /// to the missing-inputs type for the signature builder.
    ///
    /// ```compile_fail
    /// use kaspa_txscript_typed_builder::TypedScriptBuilder;
    /// // N=0 has no impls (starts at 1) — should not compile
    /// let _ = TypedScriptBuilder::new()
    ///     .add_g16_fixed_num::<0>();
    /// ```
    pub fn add_g16_fixed_num<const N: usize>(
        mut self,
    ) -> TypedScriptBuilder<FixedNum<N, Bn254Fr<()>, <Self as G16FixedNumInputs<N>>::Rest>, <Self as G16FixedNumInputs<N>>::NewMissing>
    where
        Self: G16FixedNumInputs<N>,
    {
        self.builder.add_i64(N as i64).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
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
    pub fn groth16_verify(self) -> TypedScriptBuilder<Bool<()>, <Self as G16Verify>::Missing>
    where
        Self: G16Verify,
    {
        G16Verify::groth16_verify(self)
    }
}

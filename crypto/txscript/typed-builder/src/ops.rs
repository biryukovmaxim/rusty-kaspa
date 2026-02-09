use std::marker::PhantomData;

use kaspa_txscript::opcodes::codes::*;

use crate::builder::TypedScriptBuilder;
use crate::markers::sealed;
use crate::markers::*;

// ===========================================================================
// Operations
// ===========================================================================

// ---------------------------------------------------------------------------
// Arithmetic: Binary Num×Num → Num (full stack: 2+ nums)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Num<Num<S>>, M, A> {
    pub fn op_add(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpAdd)
    }
    pub fn op_sub(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpSub)
    }
    pub fn op_mul(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpMul)
    }
    pub fn op_div(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpDiv)
    }
    pub fn op_mod(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpMod)
    }
    pub fn op_min(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpMin)
    }
    pub fn op_max(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpMax)
    }

    // Binary Num×Num → Bool
    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpNumEqual)
    }
    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpLessThan)
    }
    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpGreaterThan)
    }
    pub fn op_less_than_or_equal(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpLessThanOrEqual)
    }
    pub fn op_greater_than_or_equal(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpGreaterThanOrEqual)
    }
    pub fn op_num_not_equal(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpNumNotEqual)
    }
    pub fn op_bool_and(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpBoolAnd)
    }
    pub fn op_bool_or(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpBoolOr)
    }

    // Verify Num×Num → removes both
    pub fn op_num_equal_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpNumEqualVerify)
    }

    // Conversion: Num(size) × Num(value) → Data
    pub fn op_num2bin(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpNum2Bin)
    }
}

// ---------------------------------------------------------------------------
// Arithmetic: Binary Num×Num (partial: 1 on stack)
// ---------------------------------------------------------------------------

impl<M: AddToMissing, A> TypedScriptBuilder<Num<()>, M, A> {
    pub fn op_add(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpAdd)
    }
    pub fn op_sub(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpSub)
    }
    pub fn op_mul(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpMul)
    }
    pub fn op_div(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpDiv)
    }
    pub fn op_mod(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpMod)
    }
    pub fn op_min(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpMin)
    }
    pub fn op_max(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpMax)
    }

    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpNumEqual)
    }
    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpLessThan)
    }
    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpGreaterThan)
    }
    pub fn op_less_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpLessThanOrEqual)
    }
    pub fn op_greater_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpGreaterThanOrEqual)
    }
    pub fn op_num_not_equal(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpNumNotEqual)
    }
    pub fn op_bool_and(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpBoolAnd)
    }
    pub fn op_bool_or(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpBoolOr)
    }
}

// ---------------------------------------------------------------------------
// Arithmetic: Binary Num×Num (empty stack: need 2 from sig)
// ---------------------------------------------------------------------------

impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A>
where
    M::WithNum: AddToMissing,
    M::WithData: AddToMissing,
{
    // Binary (need 2 from sig)
    pub fn op_add(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpAdd)
    }
    pub fn op_sub(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpSub)
    }
    pub fn op_mul(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpMul)
    }
    pub fn op_div(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpDiv)
    }
    pub fn op_mod(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpMod)
    }
    pub fn op_min(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpMin)
    }
    pub fn op_max(self) -> TypedScriptBuilder<Num<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpMax)
    }

    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpNumEqual)
    }
    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpLessThan)
    }
    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpGreaterThan)
    }
    pub fn op_less_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpLessThanOrEqual)
    }
    pub fn op_greater_than_or_equal(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpGreaterThanOrEqual)
    }
    pub fn op_num_not_equal(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpNumNotEqual)
    }
    pub fn op_bool_and(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpBoolAnd)
    }
    pub fn op_bool_or(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpBoolOr)
    }

    // Unary (need 1 from sig)
    pub fn op_1_add(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(Op1Add)
    }
    pub fn op_1_sub(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(Op1Sub)
    }
    pub fn op_negate(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpNegate)
    }
    pub fn op_abs(self) -> TypedScriptBuilder<Num<()>, M::WithNum, A> {
        self.emit_op(OpAbs)
    }
    pub fn op_not(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpNot)
    }
    pub fn op_0_not_equal(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(Op0NotEqual)
    }

    // Data binary (need 2 from sig)
    pub fn op_cat(self) -> TypedScriptBuilder<Data<()>, <M::WithData as AddToMissing>::WithData, A> {
        self.emit_op(OpCat)
    }
    pub fn op_and(self) -> TypedScriptBuilder<Data<()>, <M::WithData as AddToMissing>::WithData, A> {
        self.emit_op(OpAnd)
    }
    pub fn op_or(self) -> TypedScriptBuilder<Data<()>, <M::WithData as AddToMissing>::WithData, A> {
        self.emit_op(OpOr)
    }
    pub fn op_xor(self) -> TypedScriptBuilder<Data<()>, <M::WithData as AddToMissing>::WithData, A> {
        self.emit_op(OpXor)
    }
    pub fn op_equal(self) -> TypedScriptBuilder<Bool<()>, <M::WithData as AddToMissing>::WithData, A> {
        self.emit_op(OpEqual)
    }

    // Data unary (need 1 from sig)
    pub fn op_invert(self) -> TypedScriptBuilder<Data<()>, M::WithData, A> {
        self.emit_op(OpInvert)
    }
    pub fn op_size(self) -> TypedScriptBuilder<Num<Data<()>>, M::WithData, A> {
        self.emit_op(OpSize)
    }
    pub fn op_sha256(self) -> TypedScriptBuilder<Hash<()>, M::WithData, A> {
        self.emit_op(OpSHA256)
    }
    pub fn op_blake2b(self) -> TypedScriptBuilder<Hash<()>, M::WithData, A> {
        self.emit_op(OpBlake2b)
    }
    pub fn op_bin2num(self) -> TypedScriptBuilder<Num<()>, M::WithData, A> {
        self.emit_op(OpBin2Num)
    }

    // Blake2b with key (need 2 from sig)
    pub fn op_blake2b_with_key(self) -> TypedScriptBuilder<Hash<()>, <M::WithData as AddToMissing>::WithData, A> {
        self.emit_op(OpBlake2bWithKey)
    }

    // SeqCommit (need 1 Hash from sig)
    pub fn op_chainblock_seq_commit(self) -> TypedScriptBuilder<Hash<()>, M::WithHash, A> {
        self.emit_op(OpChainblockSeqCommit)
    }
}

// ---------------------------------------------------------------------------
// Unary ops: Num<S> (1+ nums on stack)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Num<S>, M, A> {
    pub fn op_1_add(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(Op1Add)
    }
    pub fn op_1_sub(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(Op1Sub)
    }
    pub fn op_negate(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpNegate)
    }
    pub fn op_abs(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpAbs)
    }
    pub fn op_not(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpNot)
    }
    pub fn op_0_not_equal(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(Op0NotEqual)
    }
}

// ---------------------------------------------------------------------------
// Ternary: op_within  Num×Num×Num → Bool
// ---------------------------------------------------------------------------

// Full stack: 3+ nums
impl<S, M, A> TypedScriptBuilder<Num<Num<Num<S>>>, M, A> {
    pub fn op_within(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpWithin)
    }
}

// Partial: 2 on stack
impl<M: AddToMissing, A> TypedScriptBuilder<Num<Num<()>>, M, A> {
    pub fn op_within(self) -> TypedScriptBuilder<Bool<()>, M::WithNum, A> {
        self.emit_op(OpWithin)
    }
}

// Partial: 1 on stack
impl<M: AddToMissing, A> TypedScriptBuilder<Num<()>, M, A>
where
    M::WithNum: AddToMissing,
{
    pub fn op_within(self) -> TypedScriptBuilder<Bool<()>, <M::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpWithin)
    }
}

// Empty stack: 3 from sig
impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A>
where
    M::WithNum: AddToMissing,
    <M::WithNum as AddToMissing>::WithNum: AddToMissing,
{
    pub fn op_within(self) -> TypedScriptBuilder<Bool<()>, <<M::WithNum as AddToMissing>::WithNum as AddToMissing>::WithNum, A> {
        self.emit_op(OpWithin)
    }
}

// ---------------------------------------------------------------------------
// Data operations: Data<Data<S>> (binary)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Data<Data<S>>, M, A> {
    pub fn op_cat(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpCat)
    }
    pub fn op_and(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpAnd)
    }
    pub fn op_or(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpOr)
    }
    pub fn op_xor(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpXor)
    }
    pub fn op_equal(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpEqual)
    }

    // Verify Data×Data → removes both
    pub fn op_equal_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpEqualVerify)
    }

    // Blake2b with key (pops key, then data)
    pub fn op_blake2b_with_key(self) -> TypedScriptBuilder<Hash<S>, M, A> {
        self.emit_op(OpBlake2bWithKey)
    }
}

// Partial: 1 Data on stack (need 1 more from sig)
impl<M: AddToMissing, A> TypedScriptBuilder<Data<()>, M, A> {
    pub fn op_cat(self) -> TypedScriptBuilder<Data<()>, M::WithData, A> {
        self.emit_op(OpCat)
    }
    pub fn op_and(self) -> TypedScriptBuilder<Data<()>, M::WithData, A> {
        self.emit_op(OpAnd)
    }
    pub fn op_or(self) -> TypedScriptBuilder<Data<()>, M::WithData, A> {
        self.emit_op(OpOr)
    }
    pub fn op_xor(self) -> TypedScriptBuilder<Data<()>, M::WithData, A> {
        self.emit_op(OpXor)
    }
    pub fn op_equal(self) -> TypedScriptBuilder<Bool<()>, M::WithData, A> {
        self.emit_op(OpEqual)
    }
    pub fn op_blake2b_with_key(self) -> TypedScriptBuilder<Hash<()>, M::WithData, A> {
        self.emit_op(OpBlake2bWithKey)
    }
}

// ---------------------------------------------------------------------------
// Signature verification: Schnorr (OpCheckSig, OpCheckSigVerify)
// ---------------------------------------------------------------------------

// Full stack: pubkey + sig both on stack
impl<S, M, A> TypedScriptBuilder<XOnlyPubkey<SchnorrSig<S>>, M, A> {
    pub fn op_check_sig(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpCheckSig)
    }
    pub fn op_check_sig_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpCheckSigVerify)
    }
}

// Partial: pubkey on stack, sig from Missing
impl<M: AddToMissing, A> TypedScriptBuilder<XOnlyPubkey<()>, M, A> {
    pub fn op_check_sig(self) -> TypedScriptBuilder<Bool<()>, M::WithSchnorrSig, A> {
        self.emit_op(OpCheckSig)
    }
    pub fn op_check_sig_verify(self) -> TypedScriptBuilder<(), M::WithSchnorrSig, A> {
        self.emit_op(OpCheckSigVerify)
    }
}

// Empty: both pubkey and sig from Missing
impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A>
where
    M::WithSchnorrSig: AddToMissing,
{
    pub fn op_check_sig(self) -> TypedScriptBuilder<Bool<()>, <M::WithSchnorrSig as AddToMissing>::WithXOnlyPubkey, A> {
        self.emit_op(OpCheckSig)
    }
    pub fn op_check_sig_verify(self) -> TypedScriptBuilder<(), <M::WithSchnorrSig as AddToMissing>::WithXOnlyPubkey, A> {
        self.emit_op(OpCheckSigVerify)
    }
}

// ---------------------------------------------------------------------------
// Signature verification: ECDSA (OpCheckSigECDSA)
// ---------------------------------------------------------------------------

// Full stack: pubkey + sig both on stack
impl<S, M, A> TypedScriptBuilder<EcdsaPubkey<EcdsaSig<S>>, M, A> {
    pub fn op_check_sig_ecdsa(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpCheckSigECDSA)
    }
}

// Partial: pubkey on stack, sig from Missing
impl<M: AddToMissing, A> TypedScriptBuilder<EcdsaPubkey<()>, M, A> {
    pub fn op_check_sig_ecdsa(self) -> TypedScriptBuilder<Bool<()>, M::WithEcdsaSig, A> {
        self.emit_op(OpCheckSigECDSA)
    }
}

// Empty: both pubkey and sig from Missing
impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A>
where
    M::WithEcdsaSig: AddToMissing,
{
    pub fn op_check_sig_ecdsa(self) -> TypedScriptBuilder<Bool<()>, <M::WithEcdsaSig as AddToMissing>::WithEcdsaPubkey, A> {
        self.emit_op(OpCheckSigECDSA)
    }
}

// ---------------------------------------------------------------------------
// Data operations: Data<S> (unary)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Data<S>, M, A> {
    pub fn op_invert(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpInvert)
    }

    /// Pushes the size of the top data element without popping it.
    pub fn op_size(self) -> TypedScriptBuilder<Num<Data<S>>, M, A> {
        self.emit_op(OpSize)
    }

    pub fn op_sha256(self) -> TypedScriptBuilder<Hash<S>, M, A> {
        self.emit_op(OpSHA256)
    }
    pub fn op_blake2b(self) -> TypedScriptBuilder<Hash<S>, M, A> {
        self.emit_op(OpBlake2b)
    }
    pub fn op_bin2num(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpBin2Num)
    }

    // Lock time operations
    pub fn op_check_lock_time_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpCheckLockTimeVerify)
    }
    pub fn op_check_sequence_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpCheckSequenceVerify)
    }
}

// ---------------------------------------------------------------------------
// OpSubstr: Num(end) × Num(start) × Data → Data
// ---------------------------------------------------------------------------

// Full: Num<Num<Data<S>>>
impl<S, M, A> TypedScriptBuilder<Num<Num<Data<S>>>, M, A> {
    pub fn op_substr(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpSubstr)
    }
}

// Partial: 2 on stack (Num<Num<()>>) — need Data from sig
impl<M: AddToMissing, A> TypedScriptBuilder<Num<Num<()>>, M, A> {
    pub fn op_substr(self) -> TypedScriptBuilder<Data<()>, M::WithData, A> {
        self.emit_op(OpSubstr)
    }
}

// Partial: 1 on stack (Num<()>) — need Num+Data from sig
impl<M: AddToMissing, A> TypedScriptBuilder<Num<()>, M, A>
where
    M::WithNum: AddToMissing,
{
    pub fn op_substr(self) -> TypedScriptBuilder<Data<()>, <M::WithNum as AddToMissing>::WithData, A> {
        self.emit_op(OpSubstr)
    }
}

// Empty stack — need all 3: Data<Num<Num<M>>> (Data deepest, Nums on top)
impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A>
where
    M::WithNum: AddToMissing,
    <M::WithNum as AddToMissing>::WithNum: AddToMissing,
{
    pub fn op_substr(self) -> TypedScriptBuilder<Data<()>, <<M::WithNum as AddToMissing>::WithNum as AddToMissing>::WithData, A> {
        self.emit_op(OpSubstr)
    }
}

// ---------------------------------------------------------------------------
// Stack manipulation: Dup & Drop (generic via StackEntry)
// ---------------------------------------------------------------------------

impl<Top: StackEntry, M, A> TypedScriptBuilder<Top, M, A> {
    pub fn op_dup(self) -> TypedScriptBuilder<Top::Wrap<Top>, M, A> {
        self.emit_op(OpDup)
    }
    pub fn op_drop(self) -> TypedScriptBuilder<Top::Rest, M, A> {
        self.emit_op(OpDrop)
    }
}

// ---------------------------------------------------------------------------
// Stack manipulation: multi-element ops (generic via StackEntry)
// ---------------------------------------------------------------------------

// 2-element ops: top two elements can be any marker types
#[allow(clippy::type_complexity)]
impl<Top, M, A> TypedScriptBuilder<Top, M, A>
where
    Top: StackEntry,
    Top::Rest: StackEntry,
{
    /// Swap the top two elements. `[A, B, rest]` → `[B, A, rest]`
    pub fn op_swap(self) -> TypedScriptBuilder<<Top::Rest as StackEntry>::Wrap<Top::Wrap<<Top::Rest as StackEntry>::Rest>>, M, A> {
        self.emit_op(OpSwap)
    }

    /// Remove the second-to-top element. `[A, B, rest]` → `[A, rest]`
    pub fn op_nip(self) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Rest>, M, A> {
        self.emit_op(OpNip)
    }

    /// Copy the second-to-top element to the top. `[A, B, rest]` → `[B, A, B, rest]`
    pub fn op_over(self) -> TypedScriptBuilder<<Top::Rest as StackEntry>::Wrap<Top>, M, A> {
        self.emit_op(OpOver)
    }

    /// Copy the top element below the second-to-top. `[A, B, rest]` → `[A, B, A, rest]`
    pub fn op_tuck(
        self,
    ) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Wrap<Top::Wrap<<Top::Rest as StackEntry>::Rest>>>, M, A> {
        self.emit_op(OpTuck)
    }

    /// Drop the top two elements. `[A, B, rest]` → `[rest]`
    pub fn op_2_drop(self) -> TypedScriptBuilder<<Top::Rest as StackEntry>::Rest, M, A> {
        self.emit_op(Op2Drop)
    }

    /// Duplicate the top two elements. `[A, B, rest]` → `[A, B, A, B, rest]`
    pub fn op_2_dup(self) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Wrap<Top>>, M, A> {
        self.emit_op(Op2Dup)
    }
}

// 3-element ops: top three elements can be any marker types
#[allow(clippy::type_complexity)]
impl<Top, M, A> TypedScriptBuilder<Top, M, A>
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
        A,
    > {
        self.emit_op(OpRot)
    }

    /// Duplicate the top three elements. `[A, B, C, rest]` → `[A, B, C, A, B, C, rest]`
    pub fn op_3_dup(
        self,
    ) -> TypedScriptBuilder<Top::Wrap<<Top::Rest as StackEntry>::Wrap<<<Top::Rest as StackEntry>::Rest as StackEntry>::Wrap<Top>>>, M, A>
    {
        self.emit_op(Op3Dup)
    }
}

// ---------------------------------------------------------------------------
// 4-element ops: op_2_over, op_2_swap
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
impl<Top, M, A> TypedScriptBuilder<Top, M, A>
where
    Top: StackEntry,
    Top::Rest: StackEntry,
    <Top::Rest as StackEntry>::Rest: StackEntry,
    <<Top::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    // Type aliases for readability:
    // Top = A, Top::Rest = B<...>, etc.
    // Stack: [A, B, C, D, rest]
    // A = Top
    // B = Top::Rest  (StackEntry, ::Rest = C<D<rest>>)
    // C = <Top::Rest as StackEntry>::Rest  (StackEntry, ::Rest = D<rest>)
    // D = <<Top::Rest as StackEntry>::Rest as StackEntry>::Rest  (StackEntry, ::Rest = rest)
    // rest = <<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest

    /// Copy 3rd+4th elements to top. `[A, B, C, D, rest]` → `[C, D, A, B, C, D, rest]`
    pub fn op_2_over(
        self,
    ) -> TypedScriptBuilder<
        <<Top::Rest as StackEntry>::Rest as StackEntry>::Wrap<
            <<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<Top>,
        >,
        M,
        A,
    > {
        self.emit_op(Op2Over)
    }

    /// Swap top pair with next pair. `[A, B, C, D, rest]` → `[C, D, A, B, rest]`
    pub fn op_2_swap(
        self,
    ) -> TypedScriptBuilder<
        <<Top::Rest as StackEntry>::Rest as StackEntry>::Wrap<
            <<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                Top::Wrap<
                    <Top::Rest as StackEntry>::Wrap<<<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest>,
                >,
            >,
        >,
        M,
        A,
    > {
        self.emit_op(Op2Swap)
    }
}

// ---------------------------------------------------------------------------
// 6-element ops: op_2_rot
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
impl<Top, M, A> TypedScriptBuilder<Top, M, A>
where
    Top: StackEntry,
    Top::Rest: StackEntry,
    <Top::Rest as StackEntry>::Rest: StackEntry,
    <<Top::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    // Stack: [A, B, C, D, E, F, rest]
    // E = <D as StackEntry>::Rest where D = <<<...>::Rest as StackEntry>::Rest
    // F = <E as StackEntry>::Rest
    // rest = <F as StackEntry>::Rest
    // Result: [E, F, A, B, C, D, rest] — bottom pair rotated to top

    /// Rotate bottom pair to top. `[A, B, C, D, E, F, rest]` → `[E, F, A, B, C, D, rest]`
    pub fn op_2_rot(
        self,
    ) -> TypedScriptBuilder<
        <<<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
            <<<<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                Top::Wrap<
                    <Top::Rest as StackEntry>::Wrap<
                        <
                            <Top::Rest as StackEntry>::Rest as StackEntry
                        >::Wrap<
                            <<
                                <Top::Rest as StackEntry>::Rest as StackEntry
                            >::Rest as StackEntry>::Wrap<
                                <<<<<Top::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest
                            >
                        >
                    >
                >
            >
        >,
        M,
        A,
    >{
        self.emit_op(Op2Rot)
    }
}

// ---------------------------------------------------------------------------
// Alt stack operations: OpToAltStack, OpFromAltStack
// ---------------------------------------------------------------------------

// Push top of main stack onto alt stack
impl<Top: StackEntry, M, A> TypedScriptBuilder<Top, M, A> {
    pub fn op_to_alt_stack(self) -> TypedScriptBuilder<Top::Rest, M, Top::Wrap<A>> {
        self.emit_op_alt(OpToAltStack)
    }
}

// Pop from alt stack back to main stack
impl<ATop: StackEntry, S, M> TypedScriptBuilder<S, M, ATop> {
    pub fn op_from_alt_stack(self) -> TypedScriptBuilder<ATop::Wrap<S>, M, ATop::Rest> {
        self.emit_op_alt(OpFromAltStack)
    }
}

// ---------------------------------------------------------------------------
// OpDepth (blanket)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<S, M, A> {
    /// Push the current stack depth as a number.
    pub fn op_depth(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(OpDepth)
    }
}

// ---------------------------------------------------------------------------
// Verify: Bool<S> → S
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Bool<S>, M, A> {
    /// Pops the top Bool; errors if false at runtime.
    pub fn op_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpVerify)
    }
}

// ---------------------------------------------------------------------------
// Constants (blanket)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<S, M, A> {
    pub fn op_true(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpTrue)
    }
    pub fn op_false(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpFalse)
    }
    pub fn op_1_negate(self) -> TypedScriptBuilder<Num<S>, M, A> {
        self.emit_op(Op1Negate)
    }

    /// Push Op2..Op16 onto the stack. Panics if n is not in 2..=16.
    pub fn op_n(self, n: u8) -> TypedScriptBuilder<Num<S>, M, A> {
        assert!((2..=16).contains(&n), "op_n requires n in 2..=16, got {n}");
        // Op2 = 0x52, Op3 = 0x53, ..., Op16 = 0x60
        let opcode = 0x50 + n;
        self.emit_op(opcode)
    }

    pub fn op_nop(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpNop)
    }
    pub fn op_return(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpReturn)
    }
}

// ---------------------------------------------------------------------------
// OpPick (0x79) and OpRoll (0x7a) — runtime-indexed stack access
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Num<S>, M, A> {
    /// Copies the stack item at runtime `index` (0 = top of remaining stack) to
    /// the top.  The result is typed as [`Data`] because the element type at an
    /// arbitrary runtime index cannot be verified statically.
    ///
    /// For **compile-time-known** positions prefer the typed equivalents that
    /// preserve the real element type:
    /// [`op_dup()`] (index 0), [`op_over()`] (index 1).
    pub fn op_pick(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpPick)
    }

    /// Moves the stack item at runtime `index` to the top, removing it from its
    /// original position.  Typed as [`Data`] for the same reason as [`op_pick`].
    ///
    /// **Note:** one element is removed from the interior of `S`, but this
    /// removal is not reflected in the type — the rest-of-stack type `S` is
    /// kept unchanged.  This makes `op_roll` *lossy* at the type level.
    ///
    /// For **compile-time-known** positions prefer the typed equivalents that
    /// preserve the real element type:
    /// [`op_swap()`] (index 1), [`op_rot()`] (index 2).
    pub fn op_roll(self) -> TypedScriptBuilder<Data<S>, M, A> {
        self.emit_op(OpRoll)
    }
}

// ---------------------------------------------------------------------------
// Compile-time indexed pick: PickAt<N>
// ---------------------------------------------------------------------------

/// Compile-time pick at fixed depth N. Copies the element at depth N to the
/// top of the stack, preserving the element's real type.
///
/// Available for depths 0–5. For larger or runtime indices, use
/// [`op_pick()`](TypedScriptBuilder::op_pick) which returns [`Data`].
#[diagnostic::on_unimplemented(
    message = "cannot pick at compile-time depth {N} from this stack",
    label = "the stack does not have enough elements for pick({N})",
    note = "push more elements, use a smaller depth, use the runtime `op_pick()`,\nor use `op_pick_at_missing::<N, T>()` on an empty stack"
)]
pub trait PickAt<const N: usize> {
    type ResultStack;
}

// Depth 0: copy top (≡ op_dup)
impl<S: StackEntry, M, A> PickAt<0> for TypedScriptBuilder<S, M, A> {
    type ResultStack = S::Wrap<S>;
}

// Depth 1: copy second (≡ op_over)
impl<S, M, A> PickAt<1> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
{
    type ResultStack = <S::Rest as StackEntry>::Wrap<S>;
}

// Depth 2
impl<S, M, A> PickAt<2> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<S::Rest as StackEntry>::Rest as StackEntry>::Wrap<S>;
}

// Depth 3
impl<S, M, A> PickAt<3> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
    <<S::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<S>;
}

// Depth 4
impl<S, M, A> PickAt<4> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
    <<S::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<S>;
}

// Depth 5
#[allow(clippy::type_complexity)]
impl<S, M, A> PickAt<5> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
    <<S::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack =
        <<<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<S>;
}

// ---------------------------------------------------------------------------
// Compile-time indexed roll: RollAt<N>
// ---------------------------------------------------------------------------

/// Compile-time roll at fixed depth N. Moves the element at depth N to the
/// top of the stack, removing it from its original position and preserving
/// its real type.
///
/// Available for depths 0–5. For larger or runtime indices, use
/// [`op_roll()`](TypedScriptBuilder::op_roll) which returns [`Data`].
#[diagnostic::on_unimplemented(
    message = "cannot roll at compile-time depth {N} from this stack",
    label = "the stack does not have enough elements for roll({N})",
    note = "push more elements, use a smaller depth, use the runtime `op_roll()`,\nor use `op_roll_at_missing::<N, T>()` on an empty stack"
)]
pub trait RollAt<const N: usize> {
    type ResultStack;
}

// Depth 0: identity (no-op)
impl<S: StackEntry, M, A> RollAt<0> for TypedScriptBuilder<S, M, A> {
    type ResultStack = S;
}

// Depth 1: swap (≡ op_swap)
// [A, B, rest] → [B, A, rest]
impl<S, M, A> RollAt<1> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
{
    type ResultStack = <S::Rest as StackEntry>::Wrap<S::Wrap<<S::Rest as StackEntry>::Rest>>;
}

// Depth 2: rot (≡ op_rot)
// [A, B, C, rest] → [C, A, B, rest]
#[allow(clippy::type_complexity)]
impl<S, M, A> RollAt<2> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<S::Rest as StackEntry>::Rest as StackEntry>::Wrap<
        S::Wrap<<S::Rest as StackEntry>::Wrap<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest>>,
    >;
}

// Depth 3
// [A, B, C, D, rest] → [D, A, B, C, rest]
#[allow(clippy::type_complexity)]
impl<S, M, A> RollAt<3> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
    <<S::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
        S::Wrap<
            <S::Rest as StackEntry>::Wrap<
                <<S::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest,
                >,
            >,
        >,
    >;
}

// Depth 4
// [A, B, C, D, E, rest] → [E, A, B, C, D, rest]
#[allow(clippy::type_complexity)]
impl<S, M, A> RollAt<4> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
    <<S::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
        S::Wrap<
            <S::Rest as StackEntry>::Wrap<
                <<S::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                        <<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest,
                    >,
                >,
            >,
        >,
    >;
}

// Depth 5
// [A, B, C, D, E, F, rest] → [F, A, B, C, D, E, rest]
#[allow(clippy::type_complexity)]
impl<S, M, A> RollAt<5> for TypedScriptBuilder<S, M, A>
where
    S: StackEntry,
    S::Rest: StackEntry,
    <S::Rest as StackEntry>::Rest: StackEntry,
    <<S::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
    <<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest: StackEntry,
{
    type ResultStack = <<<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
        S::Wrap<
            <S::Rest as StackEntry>::Wrap<
                <<S::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                    <<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                        <<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Wrap<
                            <<<<<S::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest as StackEntry>::Rest,
                        >,
                    >,
                >,
            >,
        >,
    >;
}

// ---------------------------------------------------------------------------
// Compile-time pick/roll methods (on-stack)
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
impl<S, M, A> TypedScriptBuilder<S, M, A> {
    /// Copy the element at compile-time depth N to the top of the stack.
    /// Preserves the element's real type. Pushes N and emits `OpPick`.
    ///
    /// Equivalent to `op_dup` (N=0), `op_over` (N=1), etc., but works
    /// for arbitrary depths up to 5.
    ///
    /// For runtime (dynamic) indices, use [`op_pick()`](Self::op_pick)
    /// which returns [`Data`].
    pub fn op_pick_at<const N: usize>(mut self) -> TypedScriptBuilder<<Self as PickAt<N>>::ResultStack, M, A>
    where
        Self: PickAt<N>,
    {
        self.builder.add_i64(N as i64).expect("script size limit exceeded");
        self.builder.add_op(OpPick).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Move the element at compile-time depth N to the top of the stack,
    /// removing it from its original position. Preserves the element's real
    /// type. Pushes N and emits `OpRoll`.
    ///
    /// Equivalent to identity (N=0), `op_swap` (N=1), `op_rot` (N=2), etc.
    ///
    /// For runtime (dynamic) indices, use [`op_roll()`](Self::op_roll)
    /// which returns [`Data`].
    pub fn op_roll_at<const N: usize>(mut self) -> TypedScriptBuilder<<Self as RollAt<N>>::ResultStack, M, A>
    where
        Self: RollAt<N>,
    {
        self.builder.add_i64(N as i64).expect("script size limit exceeded");
        self.builder.add_op(OpRoll).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Beyond-stack pick/roll (empty typed stack — element from sig script)
// ---------------------------------------------------------------------------

impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A> {
    /// Pick from beyond the typed stack at compile-time depth N.
    /// The caller specifies the element type `T` (e.g., `Num<()>`, `Data<()>`).
    /// One element of type T is added to Missing for the sig builder.
    ///
    /// Pushes N and emits `OpPick`.
    pub fn op_pick_at_missing<const N: usize, T: IntoMissing>(mut self) -> TypedScriptBuilder<T::Wrap<()>, T::AddTo<M>, A> {
        self.builder.add_i64(N as i64).expect("script size limit exceeded");
        self.builder.add_op(OpPick).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Roll from beyond the typed stack at compile-time depth N.
    /// The caller specifies the element type `T` (e.g., `Num<()>`, `Data<()>`).
    /// One element of type T is added to Missing for the sig builder.
    ///
    /// Pushes N and emits `OpRoll`.
    pub fn op_roll_at_missing<const N: usize, T: IntoMissing>(mut self) -> TypedScriptBuilder<T::Wrap<()>, T::AddTo<M>, A> {
        self.builder.add_i64(N as i64).expect("script size limit exceeded");
        self.builder.add_op(OpRoll).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// FixedNumInputs — generalized compile-time element counting
// ---------------------------------------------------------------------------

/// Trait for consuming 0..N elements of type `T` from the stack and
/// transitioning to `FixedNum<N, T, Rest>`.  Any shortfall is added to
/// the Missing type for the signature builder.
#[diagnostic::on_unimplemented(
    message = "cannot call `add_fixed_num::<{N}, _>()` on this stack",
    label = "expected 0..N elements of the requested type on the stack",
    note = "push elements with the appropriate add method, then call .add_fixed_num::<N, T>()\nAny shortfall is added to missing inputs for the signature builder."
)]
pub trait FixedNumInputs<const N: usize, T> {
    type Rest;
    type NewMissing;
}

/// Type alias for the return type of `add_fixed_num` and its convenience wrappers.
pub type FixedNumResult<const N: usize, T, S, M, A> = TypedScriptBuilder<
    FixedNum<N, T, <TypedScriptBuilder<S, M, A> as FixedNumInputs<N, T>>::Rest>,
    <TypedScriptBuilder<S, M, A> as FixedNumInputs<N, T>>::NewMissing,
    A,
>;

macro_rules! impl_fixed_num {
    // Entry point: T marker, NotT trait, N literal, N underscore tokens
    ($T:ident, $NotT:ident, $N:literal; $($tokens:tt)*) => {
        impl_fixed_num!(@step $T, $NotT, $N; stack=[]; missing=[$($tokens)*]);
    };

    // All tokens shifted from missing to stack → emit final (K=N) impl
    (@step $T:ident, $NotT:ident, $N:literal; stack=[$($s:tt)*]; missing=[]) => {
        impl_fixed_num!(@emit $T, $NotT, $N; [$($s)*]; []);
    };

    // Emit impl for current K, then shift one token from missing to stack
    (@step $T:ident, $NotT:ident, $N:literal; stack=[$($s:tt)*]; missing=[_ $($m:tt)*]) => {
        impl_fixed_num!(@emit $T, $NotT, $N; [$($s)*]; [_ $($m)*]);
        impl_fixed_num!(@step $T, $NotT, $N; stack=[$($s)* _]; missing=[$($m)*]);
    };

    // Emit a single impl
    (@emit $T:ident, $NotT:ident, $N:literal; [$($s:tt)*]; [$($m:tt)*]) => {
        impl<S: sealed::$NotT, M, A> FixedNumInputs<$N, $T<()>>
            for TypedScriptBuilder<impl_fixed_num!(@wrap $T, [$($s)*] S), M, A>
        {
            type Rest = S;
            type NewMissing = impl_fixed_num!(@wrap $T, [$($m)*] M);
        }
    };

    // Helper: wrap $inner in K layers of $T<...>
    (@wrap $T:ident, [] $inner:ty) => { $inner };
    (@wrap $T:ident, [_ $($rest:tt)*] $inner:ty) => {
        $T<impl_fixed_num!(@wrap $T, [$($rest)*] $inner)>
    };
}

// Bn254Fr: N=0..32 (ZK field elements — N=0 is valid for circuits with no public inputs)
impl_fixed_num!(Bn254Fr, NotBn254Fr, 0;);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 1; _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 2; _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 3; _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 4; _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 5; _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 6; _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 7; _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 8; _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 9; _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 10; _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 11; _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 12; _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 13; _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 14; _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 15; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 16; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 17; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 18; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 19; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 20; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 21; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 22; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 23; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 24; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 25; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 26; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 27; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 28; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 29; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 30; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 31; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(Bn254Fr, NotBn254Fr, 32; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);

// SchnorrSig: N=1..20 (multisig)
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 1; _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 2; _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 3; _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 4; _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 5; _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 6; _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 7; _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 8; _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 9; _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 10; _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 11; _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 12; _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 13; _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 14; _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 15; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 16; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 17; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 18; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 19; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(SchnorrSig, NotSchnorrSig, 20; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);

// XOnlyPubkey: N=1..20 (multisig)
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 1; _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 2; _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 3; _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 4; _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 5; _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 6; _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 7; _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 8; _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 9; _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 10; _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 11; _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 12; _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 13; _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 14; _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 15; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 16; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 17; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 18; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 19; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(XOnlyPubkey, NotXOnlyPubkey, 20; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);

// EcdsaSig: N=1..20 (multisig)
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 1; _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 2; _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 3; _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 4; _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 5; _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 6; _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 7; _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 8; _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 9; _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 10; _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 11; _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 12; _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 13; _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 14; _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 15; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 16; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 17; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 18; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 19; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaSig, NotEcdsaSig, 20; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);

// EcdsaPubkey: N=1..20 (multisig)
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 1; _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 2; _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 3; _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 4; _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 5; _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 6; _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 7; _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 8; _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 9; _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 10; _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 11; _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 12; _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 13; _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 14; _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 15; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 16; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 17; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 18; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 19; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);
impl_fixed_num!(EcdsaPubkey, NotEcdsaPubkey, 20; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _);

/// Derived from `kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG`.
const MAX_MULTISIG_KEYS: i64 = kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG as i64;

// ---------------------------------------------------------------------------
// FixedNum push methods
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<S, M, A> {
    /// Push the input count N and transition the stack to `FixedNum<N, T, Rest>`.
    ///
    /// If fewer than N elements of type `T` are on the stack, the shortfall is
    /// added to the missing-inputs type for the signature builder.
    ///
    /// Requires turbofish for `T`: `.add_fixed_num::<3, SchnorrSig<()>>()`.
    pub fn add_fixed_num<const N: usize, T>(mut self) -> FixedNumResult<N, T, S, M, A>
    where
        Self: FixedNumInputs<N, T>,
    {
        self.builder.add_i64(N as i64).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }

    /// Convenience: push a Schnorr signature count.
    /// Compile-time error if N exceeds `MAX_PUB_KEYS_PER_MUTLTISIG` (20).
    pub fn add_fixed_num_schnorr_sigs<const N: usize>(self) -> FixedNumResult<N, SchnorrSig<()>, S, M, A>
    where
        Self: FixedNumInputs<N, SchnorrSig<()>>,
    {
        const { assert!(N as i64 <= MAX_MULTISIG_KEYS) };
        self.add_fixed_num::<N, SchnorrSig<()>>()
    }

    /// Convenience: push an x-only public key count.
    /// Compile-time error if N exceeds `MAX_PUB_KEYS_PER_MUTLTISIG` (20).
    pub fn add_fixed_num_xonly_pubkeys<const N: usize>(self) -> FixedNumResult<N, XOnlyPubkey<()>, S, M, A>
    where
        Self: FixedNumInputs<N, XOnlyPubkey<()>>,
    {
        const { assert!(N as i64 <= MAX_MULTISIG_KEYS) };
        self.add_fixed_num::<N, XOnlyPubkey<()>>()
    }

    /// Convenience: push an ECDSA signature count.
    /// Compile-time error if N exceeds `MAX_PUB_KEYS_PER_MUTLTISIG` (20).
    pub fn add_fixed_num_ecdsa_sigs<const N: usize>(self) -> FixedNumResult<N, EcdsaSig<()>, S, M, A>
    where
        Self: FixedNumInputs<N, EcdsaSig<()>>,
    {
        const { assert!(N as i64 <= MAX_MULTISIG_KEYS) };
        self.add_fixed_num::<N, EcdsaSig<()>>()
    }

    /// Convenience: push an ECDSA public key count.
    /// Compile-time error if N exceeds `MAX_PUB_KEYS_PER_MUTLTISIG` (20).
    pub fn add_fixed_num_ecdsa_pubkeys<const N: usize>(self) -> FixedNumResult<N, EcdsaPubkey<()>, S, M, A>
    where
        Self: FixedNumInputs<N, EcdsaPubkey<()>>,
    {
        const { assert!(N as i64 <= MAX_MULTISIG_KEYS) };
        self.add_fixed_num::<N, EcdsaPubkey<()>>()
    }
}

// ---------------------------------------------------------------------------
// Multisig: Schnorr (OpCheckMultiSig 0xae, OpCheckMultiSigVerify 0xaf)
// ---------------------------------------------------------------------------

impl<const NK: usize, const NS: usize, S, M, A>
    TypedScriptBuilder<FixedNum<NK, XOnlyPubkey<()>, FixedNum<NS, SchnorrSig<()>, S>>, M, A>
{
    pub fn op_check_multi_sig(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpCheckMultiSig)
    }
    pub fn op_check_multi_sig_verify(self) -> TypedScriptBuilder<S, M, A> {
        self.emit_op(OpCheckMultiSigVerify)
    }
}

// ---------------------------------------------------------------------------
// Multisig: ECDSA (OpCheckMultiSigECDSA 0xa9)
// ---------------------------------------------------------------------------

impl<const NK: usize, const NS: usize, S, M, A>
    TypedScriptBuilder<FixedNum<NK, EcdsaPubkey<()>, FixedNum<NS, EcdsaSig<()>, S>>, M, A>
{
    pub fn op_check_multi_sig_ecdsa(self) -> TypedScriptBuilder<Bool<S>, M, A> {
        self.emit_op(OpCheckMultiSigECDSA)
    }
}

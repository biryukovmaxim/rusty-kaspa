use kaspa_txscript::opcodes::codes::*;

use crate::builder::TypedScriptBuilder;
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

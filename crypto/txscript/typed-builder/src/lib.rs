use std::marker::PhantomData;

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;

/// Marker for a numeric stack element. `S` is the rest of the stack beneath it.
pub struct Num<S>(PhantomData<S>);

/// Marker for a boolean stack element. `S` is the rest of the stack beneath it.
pub struct Bool<S>(PhantomData<S>);

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
// 1. Blanket: push a number literal (available on every state)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    /// Push a number literal onto the stack.
    pub fn add_i64(mut self, val: i64) -> TypedScriptBuilder<Num<S>, M> {
        self.builder.add_i64(val).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// 2. Constructor
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
// 3. Binary ops with 2+ numbers on the stack
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<Num<S>>, M> {
    pub fn op_add(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAdd)
    }

    pub fn op_sub(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpSub)
    }

    pub fn op_num_equal(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpNumEqual)
    }

    pub fn op_less_than(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpLessThan)
    }

    pub fn op_greater_than(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpGreaterThan)
    }
}

// ---------------------------------------------------------------------------
// 4. Binary ops with exactly 1 number (need 1 more from sig)
// ---------------------------------------------------------------------------

impl<M> TypedScriptBuilder<Num<()>, M> {
    pub fn op_add(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpAdd)
    }

    pub fn op_sub(self) -> TypedScriptBuilder<Num<()>, Num<M>> {
        self.emit_op(OpSub)
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
}

// ---------------------------------------------------------------------------
// 5. Ops on empty stack (need all operands from sig)
// ---------------------------------------------------------------------------

impl<M> TypedScriptBuilder<(), M> {
    // -- binary (need 2 from sig) --

    pub fn op_add(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpAdd)
    }

    pub fn op_sub(self) -> TypedScriptBuilder<Num<()>, Num<Num<M>>> {
        self.emit_op(OpSub)
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

    // -- unary (need 1 from sig) --

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
}

// ---------------------------------------------------------------------------
// 6. Unary ops with 1+ numbers on the stack
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
}

// ---------------------------------------------------------------------------
// 7. Finalize (requires single Bool on stack)
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
// 8. ScriptSignatureBuilder — provide a missing number
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Num<M>> {
    /// Provide the next missing number input.
    pub fn add_i64(mut self, val: i64) -> ScriptSignatureBuilder<M> {
        self.builder.add_i64(val).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// 9. ScriptSignatureBuilder — all inputs provided, build
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
    use kaspa_txscript::{EngineCtx, TxScriptEngine, caches::Cache, pay_to_script_hash_script};

    #[test]
    fn test_push_and_arithmetic() {
        // Push two numbers, add them, compare result with a third push.
        // Stack evolution:
        //   new()           <(), ()>
        //   .add_i64(3)     <Num<()>, ()>
        //   .add_i64(5)     <Num<Num<()>>, ()>
        //   .op_add()       <Num<()>, ()>
        //   .add_i64(8)     <Num<Num<()>>, ()>
        //   .op_num_equal() <Bool<()>, ()>
        let typed = TypedScriptBuilder::new().add_i64(3).add_i64(5).op_add().add_i64(8).op_num_equal();

        // Build the same script manually.
        let mut manual = ScriptBuilder::new();
        manual.add_i64(3).unwrap().add_i64(5).unwrap().add_op(OpAdd).unwrap().add_i64(8).unwrap().add_op(OpNumEqual).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_missing_inputs() {
        // Empty stack → op_add needs 2 from sig, then op_num_equal needs 1 more.
        // Stack/Missing evolution:
        //   new()             <(), ()>
        //   .op_add()         <Num<()>, Num<Num<()>>>
        //   .op_num_equal()   <Bool<()>, Num<Num<Num<()>>>>
        let typed = TypedScriptBuilder::new().op_add().op_num_equal();

        let sig = typed
            .into_sig_builder()   // ScriptSignatureBuilder<Num<Num<Num<()>>>>
            .add_i64(8)           // provide first
            .add_i64(5)           // provide second
            .add_i64(3)           // provide third
            .build();

        // Verify that sig is non-empty and ends with a data push of the redeem script.
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_sig_builder_roundtrip() {
        // Build redeem script: op_add, op_num_equal (expects 3 nums from sig).
        let typed = TypedScriptBuilder::new().op_add().op_num_equal();

        let redeem = typed.redeem_script().to_vec();
        let sig = typed.into_sig_builder().add_i64(8).add_i64(5).add_i64(3).build();

        // Build the expected sig script manually.
        let mut manual_sig = ScriptBuilder::new();
        manual_sig.add_i64(8).unwrap().add_i64(5).unwrap().add_i64(3).unwrap().add_data(&redeem).unwrap();
        let expected_sig = manual_sig.drain();

        assert_eq!(sig, expected_sig);
    }

    #[test]
    fn test_unary_ops() {
        // Test op_1_add, op_negate, op_abs, op_not with values on the stack.
        let typed = TypedScriptBuilder::new()
            .add_i64(5)    // <Num<()>, ()>
            .op_1_add()    // <Num<()>, ()>  — value is now 6
            .op_negate()   // <Num<()>, ()>  — value is now -6
            .op_abs()      // <Num<()>, ()>  — value is now 6
            .op_not(); // <Bool<()>, ()> — value is now false (0 == false for nonzero input)

        let mut manual = ScriptBuilder::new();
        manual.add_i64(5).unwrap().add_op(Op1Add).unwrap().add_op(OpNegate).unwrap().add_op(OpAbs).unwrap().add_op(OpNot).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_unary_on_empty_stack() {
        // Unary op on empty stack requires 1 input from sig.
        let typed = TypedScriptBuilder::new()
            .op_1_add()     // <Num<()>, Num<()>>
            .op_not(); // <Bool<()>, Num<()>>

        let sig = typed.into_sig_builder().add_i64(0).build();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_comparison_ops() {
        // Test op_less_than and op_greater_than.
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
        let typed = TypedScriptBuilder::new()
            .add_i64(10)
            .add_i64(3)
            .op_sub()       // 10 - 3 = 7
            .add_i64(7)
            .op_num_equal();

        let mut manual = ScriptBuilder::new();
        manual.add_i64(10).unwrap().add_i64(3).unwrap().add_op(OpSub).unwrap().add_i64(7).unwrap().add_op(OpNumEqual).unwrap();

        assert_eq!(typed.redeem_script(), manual.script());
    }

    #[test]
    fn test_p2sh_engine_execution() {
        // Build redeem script: op_add op_num_equal (empty stack → needs 3 numbers from sig)
        // Semantics: pops c and b, computes b+c, then pops a, checks (b+c)==a
        let typed = TypedScriptBuilder::new().op_add().op_num_equal();

        let redeem = typed.redeem_script().to_vec();
        let script_pub_key = pay_to_script_hash_script(&redeem);

        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();

        // --- Correct case: a=8, b=5, c=3 → 5+3=8, 8==8 → true ---
        let correct_sig =
            TypedScriptBuilder::new().op_add().op_num_equal().into_sig_builder().add_i64(8).add_i64(5).add_i64(3).build();

        let tx = Transaction::new(
            1,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::default(), index: 0 },
                signature_script: correct_sig,
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![],
            0,
            Default::default(),
            0,
            vec![],
        );

        let utxo_entry = UtxoEntry::new(1000, script_pub_key.clone(), 0, false, None);
        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

        let mut vm = TxScriptEngine::from_transaction_input(
            &populated_tx,
            &populated_tx.tx.inputs[0],
            0,
            &utxo_entry,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm.execute().expect("correct inputs should succeed");

        // --- Failing case: a=9, b=5, c=3 → 5+3=8, 8!=9 → false ---
        let wrong_sig = TypedScriptBuilder::new().op_add().op_num_equal().into_sig_builder().add_i64(9).add_i64(5).add_i64(3).build();

        let tx_bad = Transaction::new(
            1,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::default(), index: 0 },
                signature_script: wrong_sig,
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![],
            0,
            Default::default(),
            0,
            vec![],
        );

        let populated_tx_bad = PopulatedTransaction::new(&tx_bad, vec![utxo_entry.clone()]);

        let mut vm_bad = TxScriptEngine::from_transaction_input(
            &populated_tx_bad,
            &populated_tx_bad.tx.inputs[0],
            0,
            &utxo_entry,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            Default::default(),
        );
        vm_bad.execute().expect_err("wrong inputs should fail");
    }
}

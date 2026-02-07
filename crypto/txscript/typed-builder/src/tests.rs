use super::*;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, UtxoEntry};
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

    let sig = typed.into_sig_builder().add_i64(3).add_i64(5).add_i64(8).build();

    assert!(!sig.is_empty());
}

#[test]
fn test_sig_builder_roundtrip() {
    let typed = TypedScriptBuilder::new().op_add().op_num_equal();

    let redeem = typed.redeem_script().to_vec();
    let sig = typed.into_sig_builder().add_i64(3).add_i64(5).add_i64(8).build();

    // With the reverse-words algorithm, the final byte order is:
    // push(8), push(5), push(3), push(redeem_script)
    // (reversed from call order so first-provided ends up on top of stack)
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
    manual_nip.add_data(&[1]).unwrap().add_data(&[2]).unwrap().add_op(OpNip).unwrap().add_data(&[2]).unwrap().add_op(OpEqual).unwrap();
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
    manual_verify.add_i64(1).unwrap().add_i64(1).unwrap().add_op(OpNumEqual).unwrap().add_op(OpDup).unwrap().add_op(OpVerify).unwrap();
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

    // Correct case: 3+5=8 → 8==8 → true (args in chronological order)
    let correct_sig = TypedScriptBuilder::new().op_add().op_num_equal().into_sig_builder().add_i64(3).add_i64(5).add_i64(8).build();

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

    // Failing case: 3+5≠9
    let wrong_sig = TypedScriptBuilder::new().op_add().op_num_equal().into_sig_builder().add_i64(3).add_i64(5).add_i64(9).build();

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

    // Correct: [4,5,6] ++ [1,2,3] → but on stack cat expects bottom||top = [1,2,3,4,5,6]
    // Args in chronological order: first-provided [4,5,6] ends up on top (second arg to cat),
    // second-provided [1,2,3] ends up below (first arg to cat).
    // cat([1,2,3], [4,5,6]) = [1,2,3,4,5,6]
    let correct_sig = typed.into_sig_builder().add_data(&[4, 5, 6]).add_data(&[1, 2, 3]).build();

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

// -----------------------------------------------------------------------
// FixedNum tests
// -----------------------------------------------------------------------

#[test]
fn test_zk_groth16_fixed_num() {
    use kaspa_txscript::hex;
    use kaspa_txscript::zk_precompiles::tests::helpers::{build_groth_script, execute_zk_script};

    let unprepared_compressed_vk = hex::decode("e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e1933033e7fea1f40604eaacf699d4be9aacc577054a0db22d9129a1728ff85a01a1c3af829b62bf4914c0bcf2c81a4bd577190eff5f194ee9bac95faefd53cb0030600000000000000e43bdc655d0f9d730535554d9caa611ddd152c081a06a932a8e1d5dc259aac123f42a188f683d869873ccc4c119442e57b056e03e2fa92f2028c97bc20b9078747c30f85444697fdf436e348711c011115963f855197243e4b39e6cbe236ca8ba7f2042e11f9255afbb6c6e2c3accb88e401f2aac21c097c92b3fbdb99f98a9b0dcd6c075ada6ed0ddfece1d4a2d005f61a7d5df0b75c18a5b2374d64e495fab93d4c4b1200394d5253cce2f25a59b862ee8e4cd43686603faa09d5d0d3c1c8f").unwrap();
    let groth16_proof_bytes = hex::decode("570253c0c483a1b16460118e63c155f3684e784ae7d97e8fc3f544128b37fe15075eab5ac31150c8a44253d8525971241bbd7227fcefbae2db4ae71675c56a2e0eb9235136b15ab72f16e707832f3d6ae5b0ba7cca53ae17cb52b3201919eb9d908c16297abd90aa7e00267bc21a9a78116e717d4d76edd44e21cca17e3d592d").unwrap();
    let input0 = hex::decode("a54dc85ac99f851c92d7c96d7318af4100000000000000000000000000000000").unwrap();
    let input1 = hex::decode("dbe7c0194edfcc37eb4d422a998c1f5600000000000000000000000000000000").unwrap();
    let input2 = hex::decode("a95ac0b37bfedcd8136e6c1143086bf500000000000000000000000000000000").unwrap();
    let input3 = hex::decode("d223ffcb21c6ffcb7c8f60392ca49dde00000000000000000000000000000000").unwrap();
    let input4 = hex::decode("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404").unwrap();

    // All 5 inputs on stack, using add_g16_fixed_num::<5>() instead of add_i64(5)
    let typed = TypedScriptBuilder::new()
        .add_bn254_fr(&Fr::try_from(input4.as_slice()).unwrap())
        .add_bn254_fr(&Fr::try_from(input3.as_slice()).unwrap())
        .add_bn254_fr(&Fr::try_from(input2.as_slice()).unwrap())
        .add_bn254_fr(&Fr::try_from(input1.as_slice()).unwrap())
        .add_bn254_fr(&Fr::try_from(input0.as_slice()).unwrap())
        .add_g16_fixed_num::<5>()
        .add_g16_proof(&groth16_proof_bytes)
        .add_g16_vk(&unprepared_compressed_vk)
        .add_groth16_tag()
        .groth16_verify();

    // The emitted script bytes are identical (both push i64(5))
    let manual = build_groth_script();
    assert_eq!(typed.redeem_script(), manual.as_slice());

    // Execute
    let sig_cache = Cache::new(0);
    let reused_values = SigHashReusedValuesUnsync::new();
    execute_zk_script(typed.redeem_script(), &sig_cache, &reused_values).unwrap();
}

#[test]
fn test_zk_groth16_fixed_num_partial() {
    use kaspa_txscript::hex;

    let unprepared_compressed_vk = hex::decode("e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e1933033e7fea1f40604eaacf699d4be9aacc577054a0db22d9129a1728ff85a01a1c3af829b62bf4914c0bcf2c81a4bd577190eff5f194ee9bac95faefd53cb0030600000000000000e43bdc655d0f9d730535554d9caa611ddd152c081a06a932a8e1d5dc259aac123f42a188f683d869873ccc4c119442e57b056e03e2fa92f2028c97bc20b9078747c30f85444697fdf436e348711c011115963f855197243e4b39e6cbe236ca8ba7f2042e11f9255afbb6c6e2c3accb88e401f2aac21c097c92b3fbdb99f98a9b0dcd6c075ada6ed0ddfece1d4a2d005f61a7d5df0b75c18a5b2374d64e495fab93d4c4b1200394d5253cce2f25a59b862ee8e4cd43686603faa09d5d0d3c1c8f").unwrap();
    let groth16_proof_bytes = hex::decode("570253c0c483a1b16460118e63c155f3684e784ae7d97e8fc3f544128b37fe15075eab5ac31150c8a44253d8525971241bbd7227fcefbae2db4ae71675c56a2e0eb9235136b15ab72f16e707832f3d6ae5b0ba7cca53ae17cb52b3201919eb9d908c16297abd90aa7e00267bc21a9a78116e717d4d76edd44e21cca17e3d592d").unwrap();
    let input0 = hex::decode("a54dc85ac99f851c92d7c96d7318af4100000000000000000000000000000000").unwrap();
    let input1 = hex::decode("dbe7c0194edfcc37eb4d422a998c1f5600000000000000000000000000000000").unwrap();
    let input2 = hex::decode("a95ac0b37bfedcd8136e6c1143086bf500000000000000000000000000000000").unwrap();
    let input3 = hex::decode("d223ffcb21c6ffcb7c8f60392ca49dde00000000000000000000000000000000").unwrap();
    let input4 = hex::decode("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404").unwrap();

    // Push 3 of 5 Bn254Fr on stack, the remaining 2 go to Missing
    let typed = TypedScriptBuilder::new()
        .add_bn254_fr(&Fr::try_from(input4.as_slice()).unwrap())
        .add_bn254_fr(&Fr::try_from(input3.as_slice()).unwrap())
        .add_bn254_fr(&Fr::try_from(input2.as_slice()).unwrap())
        .add_g16_fixed_num::<5>()
        .add_g16_proof(&groth16_proof_bytes)
        .add_g16_vk(&unprepared_compressed_vk)
        .add_groth16_tag()
        .groth16_verify();

    let redeem = typed.redeem_script().to_vec();

    // Use the sig builder to provide the missing 2 Bn254Fr elements (chronological order)
    let sig = typed
        .into_sig_builder()
        .add_bn254_fr(Fr::try_from(input0.as_slice()).unwrap())
        .add_bn254_fr(Fr::try_from(input1.as_slice()).unwrap())
        .build();

    // Verify that the sig is non-empty and contains the redeem script at the end
    assert!(!sig.is_empty());
    assert!(sig.len() > redeem.len());

    // Build the same script using the old Num path with all 5 on the redeem stack for comparison
    let full_redeem = TypedScriptBuilder::new()
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

    // The partial redeem is shorter (missing 2 Bn254Fr inputs which are in the sig)
    assert!(redeem.len() < full_redeem.redeem_script().len());

    // The partial redeem should be exactly 66 bytes shorter (2 * (1 push-len-byte + 32 data bytes))
    assert_eq!(full_redeem.redeem_script().len() - redeem.len(), 2 * 33);
}

#[test]
fn test_fixed_num_stack_and_math_ops() {
    let fr = Fr::try_from([0u8; 32].as_slice()).unwrap();

    // op_drop on FixedNum
    let typed_drop = TypedScriptBuilder::new().add_bn254_fr(&fr).add_g16_fixed_num::<1>().op_drop().op_true();

    let mut manual_drop = ScriptBuilder::new();
    manual_drop.add_data(&[0u8; 32]).unwrap().add_i64(1).unwrap().add_op(OpDrop).unwrap().add_op(OpTrue).unwrap();
    assert_eq!(typed_drop.redeem_script(), manual_drop.script());

    // op_dup on FixedNum
    let typed_dup = TypedScriptBuilder::new().add_bn254_fr(&fr).add_g16_fixed_num::<1>().op_dup().op_drop().op_drop().op_true();

    let mut manual_dup = ScriptBuilder::new();
    manual_dup
        .add_data(&[0u8; 32])
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap();
    assert_eq!(typed_dup.redeem_script(), manual_dup.script());

    // op_swap: Num on top of FixedNum
    let typed_swap = TypedScriptBuilder::new()
        .add_bn254_fr(&fr)
        .add_g16_fixed_num::<1>()
        .add_i64(42)
        .op_swap()
        .op_drop()
        .add_i64(42)
        .op_num_equal();

    let mut manual_swap = ScriptBuilder::new();
    manual_swap
        .add_data(&[0u8; 32])
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_i64(42)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_i64(42)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap();
    assert_eq!(typed_swap.redeem_script(), manual_swap.script());

    // arithmetic on top of FixedNum
    let typed_add = TypedScriptBuilder::new()
        .add_bn254_fr(&fr)
        .add_g16_fixed_num::<1>()
        .add_i64(3)
        .add_i64(5)
        .op_add()
        .op_swap()
        .op_drop()
        .add_i64(8)
        .op_num_equal();

    let mut manual_add = ScriptBuilder::new();
    manual_add
        .add_data(&[0u8; 32])
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_i64(5)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap();
    assert_eq!(typed_add.redeem_script(), manual_add.script());

    // op_depth on FixedNum stack
    let typed_depth =
        TypedScriptBuilder::new().add_bn254_fr(&fr).add_g16_fixed_num::<1>().op_depth().op_swap().op_drop().add_i64(1).op_num_equal();

    let mut manual_depth = ScriptBuilder::new();
    manual_depth
        .add_data(&[0u8; 32])
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpDepth)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap();
    assert_eq!(typed_depth.redeem_script(), manual_depth.script());

    // constants (op_true, op_1_negate) on FixedNum stack
    let typed_const = TypedScriptBuilder::new().add_bn254_fr(&fr).add_g16_fixed_num::<1>().op_true().op_verify().op_drop().op_true();

    let mut manual_const = ScriptBuilder::new();
    manual_const
        .add_data(&[0u8; 32])
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap();
    assert_eq!(typed_const.redeem_script(), manual_const.script());
}

// -----------------------------------------------------------------------
// Conditional (op_if / op_else / op_endif) tests
// -----------------------------------------------------------------------

#[test]
fn test_if_else_dynamic_bool() {
    // Dynamic Bool on stack: both branches produce same types.
    // Script: push(3) push(5) op_less_than op_if { push(1) } op_else { push(0) } op_endif push(1) op_num_equal
    let typed = TypedScriptBuilder::new()
        .add_i64(3)
        .add_i64(5)
        .op_less_than()
        .op_if(|b| b.add_i64(1), |b| b.add_i64(0))
        .add_i64(1)
        .op_num_equal();

    let mut manual = ScriptBuilder::new();
    manual
        .add_i64(3)
        .unwrap()
        .add_i64(5)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());
}

#[test]
fn test_if_else_missing_bool() {
    // Missing Bool: condition comes from sig script.
    // Redeem: op_if { op_add op_verify op_true } op_else { op_equal } op_endif
    // True branch needs 2 Nums + 1 Num (for verify result), false needs 2 Data.
    // Actually let's keep it simple: both branches end with Bool<()>.
    let typed = TypedScriptBuilder::new().op_if(
        // true branch: add two nums and compare
        |b| b.op_add().add_i64(8).op_num_equal(),
        // false branch: compare two data
        |b| b.op_equal(),
    );

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpIf)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());

    // Sig builder: choose true branch, provide 2 Nums (for op_add)
    let redeem = typed.redeem_script().to_vec();
    let sig_true = typed.into_sig_builder().choose_true().add_i64(3).add_i64(5).build();
    assert!(!sig_true.is_empty());
    assert!(sig_true.len() > redeem.len());
}

#[test]
fn test_if_else_missing_bool_choose_false() {
    // Same as above but choose false branch.
    let typed = TypedScriptBuilder::new().op_if(|b| b.op_add().add_i64(8).op_num_equal(), |b| b.op_equal());

    // Sig builder: choose false branch, provide 2 Data
    let sig_false = typed.into_sig_builder().choose_false().add_data(&[1, 2, 3]).add_data(&[1, 2, 3]).build();
    assert!(!sig_false.is_empty());
}

#[test]
fn test_if_only_dynamic() {
    // Dynamic Bool, stack-neutral body.
    // Script: push(true) op_if { push(1) op_drop } op_endif op_true
    let typed = TypedScriptBuilder::new().op_true().op_if_only(|b| b.add_i64(1).op_drop()).op_true();

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());
}

#[test]
fn test_if_only_missing() {
    // Missing Bool, body changes Missing but returns to empty stack.
    // Body: op_equal op_verify — compares two data, verifies result, returns to ().
    // Missing for body: Data<Data<()>>.
    // Result: Or<Data<Data<()>>, ()> — true needs 2 data, false needs nothing.
    let typed = TypedScriptBuilder::new().op_if_only(|b| b.op_equal().op_verify()).op_true(); // push true to end with Bool<()>

    let mut manual = ScriptBuilder::new();
    manual.add_op(OpIf).unwrap().add_op(OpEqual).unwrap().add_op(OpVerify).unwrap().add_op(OpEndIf).unwrap().add_op(OpTrue).unwrap();

    assert_eq!(typed.redeem_script(), manual.script());

    // choose_true: true branch needs 2 Data
    let sig_true = typed.into_sig_builder().choose_true().add_data(&[1, 2]).add_data(&[1, 2]).build();
    assert!(!sig_true.is_empty());
}

#[test]
fn test_if_fixed_true() {
    // Known true: dead branch has arbitrary bytes.
    let typed = TypedScriptBuilder::new().op_true().op_if_true(
        |b| b.add_i64(42).add_i64(42).op_num_equal(),
        |sb| {
            sb.add_data(&[0xDE, 0xAD]).unwrap();
        },
    );

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_i64(42)
        .unwrap()
        .add_i64(42)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_data(&[0xDE, 0xAD])
        .unwrap()
        .add_op(OpEndIf)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());
}

#[test]
fn test_if_fixed_false_dead() {
    // Known false: data embedding in dead branch.
    let typed = TypedScriptBuilder::new().op_false().op_if_false(
        |sb| {
            sb.add_data(&[0xCA, 0xFE]).unwrap();
        },
        |b| b.add_i64(1).add_i64(1).op_num_equal(),
    );

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpFalse)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_data(&[0xCA, 0xFE])
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());
}

#[test]
fn test_if_dead() {
    // op_if_dead: entire block is dead code for data embedding.
    let typed = TypedScriptBuilder::new()
        .op_false()
        .op_if_dead(|sb| {
            sb.add_data(b"hello world").unwrap();
        })
        .op_true();

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpFalse)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_data(b"hello world")
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());
}

#[test]
fn test_nested_if_missing() {
    // Nested missing ifs: Or<Or<A, B>, C>.
    // Outer if: true branch has inner if, false branch does something else.
    let typed = TypedScriptBuilder::new().op_if(
        // true branch: another missing if
        |b| {
            b.op_if(
                |b2| b2.add_i64(1).add_i64(1).op_num_equal(), // inner true
                |b2| b2.add_i64(2).add_i64(2).op_num_equal(), // inner false
            )
        },
        // false branch
        |b| b.add_i64(3).add_i64(3).op_num_equal(),
    );

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpIf)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());

    // Sig: choose outer-true, inner-true
    let sig = typed.into_sig_builder().choose_true().choose_true().build();
    assert!(!sig.is_empty());
}

#[test]
fn test_if_with_ops_after_endif() {
    // Missing if, then ops after endif that add to Missing.
    // These should distribute into Or branches.
    let typed = TypedScriptBuilder::new()
        .op_if(
            |b| b.op_true(),           // true branch: needs nothing extra, Missing = ()
            |b| b.op_true(),           // false branch: same
        )
        .op_verify()                   // pops Bool -> ()
        .op_add()                      // empty stack: needs 2 Nums
        .add_i64(5)
        .op_num_equal(); // needs comparison with 5

    let mut manual = ScriptBuilder::new();
    manual
        .add_op(OpIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(5)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap();

    assert_eq!(typed.redeem_script(), manual.script());

    // The missing type is Or<Num<Num<()>>, Num<Num<()>>>
    // Since both branches had M=(), the ops after distribute identically.
    // choose_true + provide 2 nums
    let sig = typed.into_sig_builder().choose_true().add_i64(2).add_i64(3).build();
    assert!(!sig.is_empty());
}

#[test]
fn test_p2sh_if_else_owner() {
    // P2SH execution: owner branch (kip-10 pattern).
    // Redeem: op_if { op_add push(8) op_num_equal } op_else { push(42) push(42) op_num_equal } op_endif
    // Owner (true): provides OpTrue + 3 + 5 + 8
    let typed =
        TypedScriptBuilder::new().op_if(|b| b.op_add().add_i64(8).op_num_equal(), |b| b.add_i64(42).add_i64(42).op_num_equal());

    let redeem = typed.redeem_script().to_vec();

    // Owner sig: choose true, provide 2 nums (for op_add; 8 is in the redeem script)
    let sig = typed.into_sig_builder().choose_true().add_i64(3).add_i64(5).build();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();

    let (tx, utxo) = make_p2sh_tx(&redeem, sig);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &populated_tx.tx.inputs[0],
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        Default::default(),
    );
    vm.execute().expect("owner branch should succeed");
}

#[test]
fn test_p2sh_if_else_borrower() {
    // P2SH execution: borrower branch (kip-10 pattern).
    // Same redeem script, but choose false branch.
    let typed =
        TypedScriptBuilder::new().op_if(|b| b.op_add().add_i64(8).op_num_equal(), |b| b.add_i64(42).add_i64(42).op_num_equal());

    let redeem = typed.redeem_script().to_vec();

    // Borrower sig: choose false (no additional inputs needed — both 42s are in redeem)
    let sig = typed.into_sig_builder().choose_false().build();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();

    let (tx, utxo) = make_p2sh_tx(&redeem, sig);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &populated_tx.tx.inputs[0],
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        Default::default(),
    );
    vm.execute().expect("borrower branch should succeed");
}

#[test]
fn test_p2sh_if_else_dynamic_both_branches() {
    // P2SH with dynamic Bool: both branches produce same Missing.
    // Redeem: push(data1) push(data2) op_equal op_if { push(1) } op_else { push(0) } push(1) op_num_equal
    let typed = TypedScriptBuilder::new()
        .add_data(&[0xAA])
        .add_data(&[0xAA])
        .op_equal()
        .op_if(|b| b.add_i64(1), |b| b.add_i64(0))
        .add_i64(1)
        .op_num_equal();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();

    let redeem = typed.redeem_script().to_vec();
    let sig = typed.into_sig_builder().build();

    let (tx, utxo) = make_p2sh_tx(&redeem, sig);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &populated_tx.tx.inputs[0],
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        Default::default(),
    );
    vm.execute().expect("dynamic if-else should succeed");
}

#[test]
fn test_p2sh_if_fixed_true() {
    // P2SH with fixed true: dead branch present but not executed.
    let typed = TypedScriptBuilder::new().op_true().op_if_true(
        |b| b.add_i64(1).add_i64(1).op_num_equal(),
        |sb| {
            sb.add_op(OpReturn).unwrap();
        }, // dead: would fail if executed
    );

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();

    let redeem = typed.redeem_script().to_vec();
    let sig = typed.into_sig_builder().build();

    let (tx, utxo) = make_p2sh_tx(&redeem, sig);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &populated_tx.tx.inputs[0],
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        Default::default(),
    );
    vm.execute().expect("fixed true branch should succeed");
}

#[test]
fn test_p2sh_if_fixed_false() {
    // P2SH with fixed false: dead true branch, active false branch.
    let typed = TypedScriptBuilder::new().op_false().op_if_false(
        |sb| {
            sb.add_op(OpReturn).unwrap();
        }, // dead: would fail if executed
        |b| b.add_i64(1).add_i64(1).op_num_equal(),
    );

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();

    let redeem = typed.redeem_script().to_vec();
    let sig = typed.into_sig_builder().build();

    let (tx, utxo) = make_p2sh_tx(&redeem, sig);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &populated_tx.tx.inputs[0],
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        Default::default(),
    );
    vm.execute().expect("fixed false branch should succeed");
}

// Compile-fail doc tests are on the public methods in conditionals.rs and sig_builder.rs.

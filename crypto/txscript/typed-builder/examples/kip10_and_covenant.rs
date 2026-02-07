//! KIP-10 threshold and simple covenant examples built with `TypedScriptBuilder`.
//!
//! Run with:
//!   cargo run -p kaspa-txscript-typed-builder --example kip10_and_covenant

use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{
        MutableTransaction, PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry, VerifiableTransaction,
    },
};
use kaspa_txscript::{
    EngineCtx, TxScriptEngine, caches::Cache, opcodes::codes::*, pay_to_script_hash_script, script_builder::ScriptBuilder,
};
use kaspa_txscript_errors::TxScriptError::EvalFalse;
use kaspa_txscript_typed_builder::TypedScriptBuilder;
use rand::thread_rng;
use secp256k1::{self, Keypair};

fn main() {
    kip10_threshold();
    simple_covenant();
    println!("\nAll examples passed!");
}

// =========================================================================
// KIP-10 standard threshold scenario
// =========================================================================
//
// Script logic:
//   OpIf
//     <owner_pubkey> OpCheckSig            -- owner spends with signature
//   OpElse
//     input.spk == output.spk              -- must send back to same P2SH
//     output_amount - threshold >= input    -- must add at least `threshold`
//   OpEndIf
//
// The Bool for OpIf comes from the sig script:
//   Owner:    [signature] [OpTrue]  [redeem_script]
//   Borrower:             [OpFalse] [redeem_script]
//
// With TypedScriptBuilder the condition is modeled as a missing Bool,
// producing `Or<SchnorrSig<()>, ()>` in the Missing type:
//   - Owner path:    Missing = SchnorrSig<()>  (the Schnorr signature)
//   - Borrower path: Missing = ()              (nothing needed)

fn kip10_threshold() {
    println!("\n=== KIP-10 Threshold (typed builder) ===");

    let owner = Keypair::new(secp256k1::SECP256K1, &mut thread_rng());
    let owner_pubkey = owner.x_only_public_key().0.serialize();
    let threshold: i64 = 100;

    // Helper: build the typed script (callable multiple times since into_sig_builder consumes self)
    let build_typed = || {
        TypedScriptBuilder::new().op_if(
            // Owner branch: push pubkey, check signature
            // Adds SchnorrSig<()> to Missing (the signature)
            |b| b.add_xonly_pubkey(&owner_pubkey).op_check_sig(),
            // Borrower branch: pure introspection, no sig items needed
            // Missing stays ()
            |b| {
                b.op_tx_input_index()
                    .op_tx_input_spk() // input SPK
                    .op_tx_input_index()
                    .op_tx_output_spk() // output SPK (same index)
                    .op_equal_verify() // verify SPK match
                    .op_tx_input_index()
                    .op_tx_output_amount() // output amount
                    .add_i64(threshold) // threshold
                    .op_sub() // output_amount - threshold
                    .op_tx_input_index()
                    .op_tx_input_amount() // input amount
                    .op_greater_than_or_equal() // (output - threshold) >= input
            },
        )
        // Result type: TypedScriptBuilder<Bool<()>, Or<SchnorrSig<()>, ()>>
    };

    // ── Extract and verify redeem script ─────────────────────────────
    let typed = build_typed();
    let redeem_script = typed.redeem_script().to_vec();

    let raw_script = ScriptBuilder::new()
        .add_op(OpIf)
        .unwrap()
        .add_data(&owner_pubkey)
        .unwrap()
        .add_op(OpCheckSig)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_ops(&[OpTxInputIndex, OpTxInputSpk, OpTxInputIndex, OpTxOutputSpk, OpEqualVerify, OpTxInputIndex, OpTxOutputAmount])
        .unwrap()
        .add_i64(threshold)
        .unwrap()
        .add_ops(&[OpSub, OpTxInputIndex, OpTxInputAmount, OpGreaterThanOrEqual])
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .drain();

    assert_eq!(redeem_script, raw_script, "typed builder must produce identical bytes");
    println!("[KIP-10] Redeem scripts match ({} bytes)", redeem_script.len());

    // ── Transaction setup ────────────────────────────────────────────
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let spk = pay_to_script_hash_script(&redeem_script);
    let input_value: u64 = 1_000_000_000;

    let output = TransactionOutput { value: input_value + threshold as u64, script_public_key: spk.clone(), covenant: None };
    let utxo_entry = UtxoEntry::new(input_value, spk, 0, false, None);
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint {
            transaction_id: TransactionId::from_bytes([
                0xc9, 0x97, 0xa5, 0xe5, 0x6e, 0x10, 0x42, 0x02, 0xfa, 0x20, 0x9c, 0x6a, 0x85, 0x2d, 0xd9, 0x06, 0x60, 0xa2, 0x0b,
                0x2d, 0x9c, 0x35, 0x24, 0x23, 0xed, 0xce, 0x25, 0x85, 0x7f, 0xcd, 0x37, 0x04,
            ]),
            index: 0,
        },
        signature_script: ScriptBuilder::new().add_data(&redeem_script).unwrap().drain(),
        sequence: 4294967295,
        sig_op_count: 1,
    };

    let mut tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);

    // ── Owner branch ─────────────────────────────────────────────────
    {
        println!("[KIP-10] Testing owner branch...");
        let mut mtx = MutableTransaction::with_entries(tx.clone(), vec![utxo_entry.clone()]);
        let sig_hash = calc_schnorr_signature_hash(&mtx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();

        let sig = owner.sign_schnorr(msg);

        // Typed sig builder: choose_true → provide the signature + sighash type
        let sig_script = build_typed().into_sig_builder().choose_true().add_schnorr_sig(&sig, SIG_HASH_ALL).build();

        // Verify against manually built sig script
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(sig.as_ref().as_slice());
        signature_bytes.push(SIG_HASH_ALL.to_u8());
        let raw_sig = {
            let mut b = ScriptBuilder::new();
            b.add_data(&signature_bytes).unwrap().add_op(OpTrue).unwrap().add_data(&redeem_script).unwrap();
            b.drain()
        };
        assert_eq!(sig_script, raw_sig, "owner sig scripts must match");

        mtx.tx.inputs[0].signature_script = sig_script;
        let vtx = mtx.as_verifiable();
        let mut vm = TxScriptEngine::from_transaction_input(&vtx, &vtx.inputs()[0], 0, &utxo_entry, ctx, Default::default());
        assert_eq!(vm.execute(), Ok(()));
        println!("[KIP-10] Owner branch: OK");
    }

    // ── Borrower branch ──────────────────────────────────────────────
    {
        println!("[KIP-10] Testing borrower branch...");
        // Typed sig builder: choose_false → nothing else needed
        let sig_script = build_typed().into_sig_builder().choose_false().build();

        let raw_sig = ScriptBuilder::new().add_op(OpFalse).unwrap().add_data(&redeem_script).unwrap().drain();
        assert_eq!(sig_script, raw_sig, "borrower sig scripts must match");

        tx.inputs[0].signature_script = sig_script;
        let ptx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let mut vm = TxScriptEngine::from_transaction_input(&ptx, &ptx.tx.inputs[0], 0, &utxo_entry, ctx, Default::default());
        assert_eq!(vm.execute(), Ok(()));
        println!("[KIP-10] Borrower branch: OK");
    }

    // ── Borrower branch: threshold not met ───────────────────────────
    {
        println!("[KIP-10] Testing borrower branch (threshold not met)...");
        tx.outputs[0].value -= 1;
        let ptx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let mut vm = TxScriptEngine::from_transaction_input(&ptx, &ptx.tx.inputs[0], 0, &utxo_entry, ctx, Default::default());
        assert_eq!(vm.execute(), Err(EvalFalse));
        println!("[KIP-10] Threshold not met: correctly rejected");
    }

    println!("[KIP-10] All checks passed!");
}

// =========================================================================
// Simple self-referential covenant
// =========================================================================
//
// Script logic (no conditionals, pure introspection):
//   input.spk == output[0].spk     -- funds must return to the same script
//   output_count == 1               -- exactly one output
//   output[0].amount >= input.amount -- no value extraction
//
// Missing = () — the sig script provides only the redeem script push.

fn simple_covenant() {
    println!("\n=== Simple Covenant (typed builder) ===");

    let typed = TypedScriptBuilder::new()
        // Verify: input SPK == output[0] SPK
        .op_tx_input_index()
        .op_tx_input_spk()
        .add_i64(0)
        .op_tx_output_spk()
        .op_equal_verify()
        // Verify: exactly one output
        .op_tx_output_count()
        .add_i64(1)
        .op_num_equal()
        .op_verify()
        // Verify: output[0] amount >= input amount
        .add_i64(0)
        .op_tx_output_amount()
        .op_tx_input_index()
        .op_tx_input_amount()
        .op_greater_than_or_equal();
    // Result type: TypedScriptBuilder<Bool<()>, ()>

    let redeem_script = typed.redeem_script().to_vec();

    // Verify byte equivalence
    let raw_script = ScriptBuilder::new()
        .add_ops(&[OpTxInputIndex, OpTxInputSpk])
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_op(OpTxOutputSpk)
        .unwrap()
        .add_op(OpEqualVerify)
        .unwrap()
        .add_op(OpTxOutputCount)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_ops(&[OpNumEqual, OpVerify])
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_ops(&[OpTxOutputAmount, OpTxInputIndex, OpTxInputAmount, OpGreaterThanOrEqual])
        .unwrap()
        .drain();

    assert_eq!(redeem_script, raw_script, "covenant scripts must match");
    println!("[COVENANT] Redeem scripts match ({} bytes)", redeem_script.len());

    // Missing = () → sig script is just the redeem script data push
    let sig_script = typed.into_sig_builder().build();

    // ── Transaction setup ────────────────────────────────────────────
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let spk = pay_to_script_hash_script(&redeem_script);
    let input_value: u64 = 1_000_000_000;

    // ── Valid spend: same SPK, single output, amount preserved ───────
    {
        println!("[COVENANT] Testing valid spend...");
        let output = TransactionOutput { value: input_value, script_public_key: spk.clone(), covenant: None };
        let utxo_entry = UtxoEntry::new(input_value, spk.clone(), 0, false, None);
        let input = TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_bytes([
                    0xc9, 0x97, 0xa5, 0xe5, 0x6e, 0x10, 0x42, 0x02, 0xfa, 0x20, 0x9c, 0x6a, 0x85, 0x2d, 0xd9, 0x06, 0x60, 0xa2, 0x0b,
                    0x2d, 0x9c, 0x35, 0x24, 0x23, 0xed, 0xce, 0x25, 0x85, 0x7f, 0xcd, 0x37, 0x04,
                ]),
                index: 0,
            },
            signature_script: sig_script.clone(),
            sequence: 4294967295,
            sig_op_count: 0,
        };

        let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
        let ptx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let mut vm = TxScriptEngine::from_transaction_input(&ptx, &ptx.tx.inputs[0], 0, &utxo_entry, ctx, Default::default());
        assert_eq!(vm.execute(), Ok(()));
        println!("[COVENANT] Valid spend: OK");
    }

    // ── Invalid: output amount less than input ───────────────────────
    {
        println!("[COVENANT] Testing invalid spend (reduced amount)...");
        let output = TransactionOutput { value: input_value - 1, script_public_key: spk.clone(), covenant: None };
        let utxo_entry = UtxoEntry::new(input_value, spk.clone(), 0, false, None);
        let input = TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0xAA; 32]), index: 0 },
            signature_script: sig_script.clone(),
            sequence: 4294967295,
            sig_op_count: 0,
        };

        let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
        let ptx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let mut vm = TxScriptEngine::from_transaction_input(&ptx, &ptx.tx.inputs[0], 0, &utxo_entry, ctx, Default::default());
        assert_eq!(vm.execute(), Err(EvalFalse));
        println!("[COVENANT] Reduced amount: correctly rejected");
    }

    // ── Invalid: wrong output SPK ────────────────────────────────────
    {
        println!("[COVENANT] Testing invalid spend (wrong SPK)...");
        let wrong_spk = pay_to_script_hash_script(&[0xDE, 0xAD]);
        let output = TransactionOutput { value: input_value, script_public_key: wrong_spk, covenant: None };
        let utxo_entry = UtxoEntry::new(input_value, spk.clone(), 0, false, None);
        let input = TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0xBB; 32]), index: 0 },
            signature_script: sig_script.clone(),
            sequence: 4294967295,
            sig_op_count: 0,
        };

        let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
        let ptx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let mut vm = TxScriptEngine::from_transaction_input(&ptx, &ptx.tx.inputs[0], 0, &utxo_entry, ctx, Default::default());
        assert!(vm.execute().is_err());
        println!("[COVENANT] Wrong SPK: correctly rejected");
    }

    println!("[COVENANT] All checks passed!");
}

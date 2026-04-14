use std::num::NonZeroUsize;
use std::time::Instant;

use kaspa_consensus_core::constants::SOMPI_PER_KASPA;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey};
use kaspa_hashes::Hash;
use kaspa_txscript::{pay_to_script_hash_script, script_builder::ScriptBuilder, zk_precompiles::tags::ZkTag};
use risc0_zkvm::{default_prover, sha::Digestible, ExecutorEnv, Prover, ProverOpts, SuccinctReceipt};
use zk_covenant_common::{hashfn_str_to_id, seal_to_compressed_proof};
use zk_covenant_rollup_core::permission_tree::PermissionTree;
use zk_covenant_rollup_core::{pay_to_pubkey_spk, perm_empty_leaf_hash, PublicInput};
use zk_covenant_rollup_host::{
    bridge::{build_delegate_entry_script, build_permission_redeem_converged, build_permission_sig_script},
    mock_chain::{self, build_initial_smt, build_mock_chain, from_bytes, AccountName},
    redeem, tx,
};
use zk_covenant_rollup_methods::{ZK_COVENANT_ROLLUP_GUEST_ELF, ZK_COVENANT_ROLLUP_GUEST_ID};

fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env()).init();

    println!("=== ZK Rollup Covenant Demo (Account-Based, Lane-based Seq Commit) ===");

    // Build initial state
    let initial_smt = build_initial_smt();
    let prev_state_hash = initial_smt.root();

    let prev_lane_tip_hash = Hash::default();
    let prev_lane_tip = from_bytes(prev_lane_tip_hash.as_bytes());

    println!("\nInitial state hash: {}", faster_hex::hex_string(bytemuck::bytes_of(&prev_state_hash)));
    println!("Initial lane_tip: {}", prev_lane_tip_hash);

    // Build mock chain with transfers
    let chain = build_mock_chain(prev_lane_tip_hash, &[0xFF; 32]);
    let new_state_hash = chain.final_state_root;
    let new_lane_tip = chain.final_lane_tip;
    let new_seq_commit = from_bytes(chain.final_seq_commit.as_bytes());

    println!("\nFinal state hash: {}", faster_hex::hex_string(bytemuck::bytes_of(&new_state_hash)));
    println!("Final lane_tip: {}", faster_hex::hex_string(bytemuck::bytes_of(&new_lane_tip)));
    println!("Final seq_commit: {}", chain.final_seq_commit);

    let covenant_id = from_bytes([0xFF; 32]);
    let public_input = PublicInput { prev_state_hash, prev_lane_tip, covenant_id };
    let program_id: [u8; 32] = bytemuck::cast(ZK_COVENANT_ROLLUP_GUEST_ID);

    // Build executor env closure
    let build_env = || {
        let mut binding = ExecutorEnv::builder();
        let builder =
            binding.write_slice(core::slice::from_ref(&public_input)).write_slice(&(chain.block_txs.len() as u32).to_le_bytes());

        for (i, txs) in chain.block_txs.iter().enumerate() {
            builder.write_slice(&(txs.len() as u32).to_le_bytes());
            if !txs.is_empty() {
                builder.write_slice(bytemuck::cast_slice::<u32, u8>(&chain.block_context_hashes[i]));
                for tx in txs {
                    tx.write_to_env(builder);
                }
            }
        }

        // Write commitment witness (Pod) + SMT proof (length-prefixed bytes)
        builder.write_slice(bytemuck::bytes_of(&chain.commitment_witness));
        zk_covenant_rollup_host::mock_tx::write_bytes(builder, &chain.smt_proof_bytes);

        // Write permission redeem script length if exits occurred
        if let Some(len) = chain.perm_redeem_script_len {
            builder.write_slice(&(len as u32).to_le_bytes());
        }

        builder.build().unwrap()
    };

    let prover = default_prover();

    // === STARK (Succinct) Proof ===
    println!("\n=== Proving with RISC0 (Succinct/STARK) ===");
    let now = Instant::now();
    let succinct_info = prover.prove_with_opts(build_env(), ZK_COVENANT_ROLLUP_GUEST_ELF, &ProverOpts::succinct()).unwrap();
    println!("Succinct proving took {} ms", now.elapsed().as_millis());

    let succinct_receipt = succinct_info.receipt;
    verify_journal(
        &succinct_receipt.journal.bytes,
        &public_input,
        &new_state_hash,
        &new_lane_tip,
        &new_seq_commit,
        chain.permission_spk_hash.as_ref(),
    );
    succinct_receipt.verify(ZK_COVENANT_ROLLUP_GUEST_ID).unwrap();
    println!("Succinct proof verified!");

    // On-chain verification for STARK
    let block_prove_to = *chain.block_hashes.last().unwrap();
    if let Ok(receipt_inner) = succinct_receipt.inner.succinct() {
        println!("\n=== On-chain STARK verification ===");
        verify_onchain_succinct(
            receipt_inner,
            &public_input,
            &new_state_hash,
            &new_lane_tip,
            &new_seq_commit,
            block_prove_to,
            &chain,
            &program_id,
        );
        println!("STARK on-chain verification passed!");
    } else {
        println!("Skipping STARK on-chain verification (dev mode)");
    }

    // === Groth16 Proof ===
    println!("\n=== Proving with RISC0 (Groth16) ===");
    let now = Instant::now();
    let groth16_info = prover.prove_with_opts(build_env(), ZK_COVENANT_ROLLUP_GUEST_ELF, &ProverOpts::groth16()).unwrap();
    println!("Groth16 proving took {} ms", now.elapsed().as_millis());

    let groth16_receipt = groth16_info.receipt;
    verify_journal(
        &groth16_receipt.journal.bytes,
        &public_input,
        &new_state_hash,
        &new_lane_tip,
        &new_seq_commit,
        chain.permission_spk_hash.as_ref(),
    );
    groth16_receipt.verify(ZK_COVENANT_ROLLUP_GUEST_ID).unwrap();
    println!("Groth16 proof verified!");

    // On-chain verification for Groth16
    if let Ok(groth16_inner) = groth16_receipt.inner.groth16() {
        println!("\n=== On-chain Groth16 verification ===");
        let compressed_proof = seal_to_compressed_proof(&groth16_inner.seal);

        verify_onchain_groth16(
            &compressed_proof,
            &public_input,
            &new_state_hash,
            &new_lane_tip,
            &new_seq_commit,
            block_prove_to,
            &chain,
            &program_id,
        );
        println!("Groth16 on-chain verification passed!");
    } else {
        println!("Skipping Groth16 on-chain verification (dev mode)");
    }

    // === Permission Withdrawal Demo ===
    // After proof submission, the permission UTXO exists on-chain.
    // Demonstrate claiming one exit leaf (Eve's 100-token withdrawal).
    if let Some(ref perm_redeem) = chain.permission_redeem {
        println!("\n=== Permission Withdrawal Demo ===");

        // The mock chain creates 2 exits: Eve(100), Dave(200)
        let eve_dest_spk = pay_to_pubkey_spk(&AccountName::Eve.pubkey_bytes());
        let dave_dest_spk = pay_to_pubkey_spk(&AccountName::Dave.pubkey_bytes());
        let exit_leaves: Vec<(Vec<u8>, u64)> = vec![(eve_dest_spk.to_vec(), 100), (dave_dest_spk.to_vec(), 200)];

        // Build permission tree and prove leaf 0 (Eve's exit)
        let tree = PermissionTree::from_leaves(exit_leaves);
        let leaf_idx = 0;
        let (spk, amount) = tree.get_leaf(leaf_idx).unwrap();
        let spk = spk.to_vec();
        let deduct = amount; // full deduct
        let proof = tree.prove(leaf_idx);

        println!("  Withdrawing leaf {}: {} sompi to Eve's address", leaf_idx, deduct);

        // Build the permission sig_script
        let perm_sig_script = build_permission_sig_script(&spk, amount, deduct, &proof, perm_redeem);

        // Build delegate entry script for gathering delegate UTXOs
        let delegate_script = build_delegate_entry_script(&[0xFF; 32]);
        let delegate_spk = pay_to_script_hash_script(&delegate_script);
        let delegate_sig_script = ScriptBuilder::new().add_data(&delegate_script).unwrap().drain();

        // Build the withdrawal transaction
        let perm_input_spk = pay_to_script_hash_script(perm_redeem);
        let withdrawal_spk = ScriptPublicKey::new(0, spk.clone().into());

        // Continuation output: compute new root from merkle proof (preserves tree depth)
        // Eve's leaf is fully consumed → replace with empty leaf hash
        let new_leaf_hash = perm_empty_leaf_hash();
        let new_root = proof.compute_new_root(&new_leaf_hash);
        let new_unclaimed = (tree.len() - 1) as u64; // one leaf fully consumed
        let max_inputs = NonZeroUsize::new(zk_covenant_rollup_core::MAX_DELEGATE_INPUTS).unwrap();
        let new_redeem = build_permission_redeem_converged(&new_root, new_unclaimed, tree.depth(), max_inputs);
        let continuation_spk = pay_to_script_hash_script(&new_redeem);

        let covenant_id = Hash::from_bytes([0xFF; 32]);

        // Build using make_multi_input_mock_transaction for proper UTXO setup
        let (mut withdraw_tx, withdraw_utxos) = tx::make_multi_input_mock_transaction(
            vec![(0, perm_input_spk, Some(covenant_id)), (deduct, delegate_spk.clone(), None)],
            vec![
                (deduct, withdrawal_spk, None),
                (SOMPI_PER_KASPA, continuation_spk, Some(CovenantBinding { authorizing_input: 0, covenant_id })),
            ],
        );

        withdraw_tx.inputs[0].signature_script = perm_sig_script;
        withdraw_tx.inputs[1].signature_script = delegate_sig_script;

        // Verify permission input (input 0)
        tx::verify_tx_input(&withdraw_tx, &withdraw_utxos, 0, &chain.accessor);
        println!("  Permission input verified!");

        // Verify delegate input (input 1)
        tx::verify_tx_input(&withdraw_tx, &withdraw_utxos, 1, &chain.accessor);
        println!("  Delegate input verified!");

        println!("  Withdrawal transaction built and verified successfully!");
    }

    println!("\n=== All verifications passed! ===");
}

fn verify_journal(
    journal: &[u8],
    public_input: &PublicInput,
    new_state_hash: &[u32; 8],
    new_lane_tip: &[u32; 8],
    new_seq_commit: &[u32; 8],
    permission_spk_hash: Option<&[u8; 32]>,
) {
    // Journal layout:
    //   Base (192 bytes = 48 words):
    //     prev_state(32) | prev_lane_tip(32) | new_state(32) | new_lane_tip(32) | new_seq_commit(32) | covenant_id(32)
    //   With permission (+32 bytes):
    //     ... base ... | permission_spk_hash(32)
    let mut off = 0;
    assert_eq!(&journal[off..off + 32], bytemuck::bytes_of(&public_input.prev_state_hash), "prev_state_hash mismatch");
    off += 32;
    assert_eq!(&journal[off..off + 32], bytemuck::bytes_of(&public_input.prev_lane_tip), "prev_lane_tip mismatch");
    off += 32;
    assert_eq!(&journal[off..off + 32], bytemuck::bytes_of(new_state_hash), "new_state_hash mismatch");
    off += 32;
    assert_eq!(&journal[off..off + 32], bytemuck::bytes_of(new_lane_tip), "new_lane_tip mismatch");
    off += 32;
    assert_eq!(&journal[off..off + 32], bytemuck::bytes_of(new_seq_commit), "new_seq_commit mismatch");
    off += 32;
    assert_eq!(&journal[off..off + 32], bytemuck::bytes_of(&public_input.covenant_id), "covenant_id mismatch");
    off += 32;
    if let Some(perm_hash) = permission_spk_hash {
        assert_eq!(&journal[off..off + 32], perm_hash, "permission_spk_hash mismatch");
        off += 32;
    }
    assert_eq!(journal.len(), off, "journal length mismatch");
}

fn verify_onchain_succinct(
    receipt: &SuccinctReceipt<risc0_zkvm::ReceiptClaim>,
    public_input: &PublicInput,
    new_state_hash: &[u32; 8],
    new_lane_tip: &[u32; 8],
    _new_seq_commit: &[u32; 8],
    block_prove_to: Hash,
    chain: &mock_chain::MockChain,
    program_id: &[u8; 32],
) {
    let zk_tag = ZkTag::R0Succinct;
    let mut computed_len = 75;
    loop {
        let script =
            redeem::build_redeem_script(public_input.prev_state_hash, public_input.prev_lane_tip, computed_len, program_id, &zk_tag);
        let new_len = script.len() as i64;
        if new_len == computed_len {
            break;
        }
        computed_len = new_len;
    }

    let input_redeem =
        redeem::build_redeem_script(public_input.prev_state_hash, public_input.prev_lane_tip, computed_len, program_id, &zk_tag);
    let output_redeem = redeem::build_redeem_script(*new_state_hash, *new_lane_tip, computed_len, program_id, &zk_tag);

    // Build transaction (1 or 2 outputs depending on permission exits)
    let (mut tx, utxo) = if let Some(ref perm_redeem) = chain.permission_redeem {
        let perm_spk = pay_to_script_hash_script(perm_redeem);
        tx::make_mock_transaction_with_permission(
            0,
            pay_to_script_hash_script(&input_redeem),
            pay_to_script_hash_script(&output_redeem),
            perm_spk,
        )
    } else {
        tx::make_mock_transaction(0, pay_to_script_hash_script(&input_redeem), pay_to_script_hash_script(&output_redeem))
    };

    // Build sig_script: push proof components, then redeem script (P2SH).
    // Stack layout (bottom to top):
    //   [seal, claim, hashfn, control_index, control_digests,
    //    new_lane_tip, new_state_hash, block_prove_to, redeem]
    let seal_bytes: Vec<u8> = receipt.seal.iter().flat_map(|w| w.to_le_bytes()).collect();
    let claim_bytes: Vec<u8> = receipt.claim.digest().as_bytes().to_vec();
    let hashfn_byte: Vec<u8> = vec![hashfn_str_to_id(&receipt.hashfn).expect("invalid hashfn")];
    let control_index_bytes: Vec<u8> = receipt.control_inclusion_proof.index.to_le_bytes().to_vec();
    let control_digests_bytes: Vec<u8> = receipt.control_inclusion_proof.digests.iter().flat_map(|d| d.as_bytes()).copied().collect();
    tx.inputs[0].signature_script = ScriptBuilder::new()
        .add_data(&seal_bytes)
        .unwrap()
        .add_data(&claim_bytes)
        .unwrap()
        .add_data(&hashfn_byte)
        .unwrap()
        .add_data(&control_index_bytes)
        .unwrap()
        .add_data(&control_digests_bytes)
        .unwrap()
        .add_data(bytemuck::bytes_of(new_lane_tip))
        .unwrap()
        .add_data(bytemuck::bytes_of(new_state_hash))
        .unwrap()
        .add_data(block_prove_to.as_bytes().as_slice())
        .unwrap()
        .add_data(&input_redeem)
        .unwrap()
        .drain();

    tx::verify_tx(&mut tx, &utxo, &chain.accessor);
}

fn verify_onchain_groth16(
    proof_bytes: &[u8],
    public_input: &PublicInput,
    new_state_hash: &[u32; 8],
    new_lane_tip: &[u32; 8],
    _new_seq_commit: &[u32; 8],
    block_prove_to: Hash,
    chain: &mock_chain::MockChain,
    program_id: &[u8; 32],
) {
    let zk_tag = ZkTag::Groth16;
    let mut computed_len = 75;
    loop {
        let script =
            redeem::build_redeem_script(public_input.prev_state_hash, public_input.prev_lane_tip, computed_len, program_id, &zk_tag);
        let new_len = script.len() as i64;
        if new_len == computed_len {
            break;
        }
        computed_len = new_len;
    }

    let input_redeem =
        redeem::build_redeem_script(public_input.prev_state_hash, public_input.prev_lane_tip, computed_len, program_id, &zk_tag);
    let output_redeem = redeem::build_redeem_script(*new_state_hash, *new_lane_tip, computed_len, program_id, &zk_tag);

    // Build transaction (1 or 2 outputs depending on permission exits)
    let (mut tx, utxo) = if let Some(ref perm_redeem) = chain.permission_redeem {
        let perm_spk = pay_to_script_hash_script(perm_redeem);
        tx::make_mock_transaction_with_permission(
            0,
            pay_to_script_hash_script(&input_redeem),
            pay_to_script_hash_script(&output_redeem),
            perm_spk,
        )
    } else {
        tx::make_mock_transaction(0, pay_to_script_hash_script(&input_redeem), pay_to_script_hash_script(&output_redeem))
    };

    // Build sig_script: push proof, then redeem script (P2SH).
    // Stack layout (bottom to top):
    //   [proof, new_lane_tip, new_state_hash, block_prove_to, redeem]
    tx.inputs[0].signature_script = ScriptBuilder::new()
        .add_data(proof_bytes)
        .unwrap()
        .add_data(bytemuck::bytes_of(new_lane_tip))
        .unwrap()
        .add_data(bytemuck::bytes_of(new_state_hash))
        .unwrap()
        .add_data(block_prove_to.as_bytes().as_slice())
        .unwrap()
        .add_data(&input_redeem)
        .unwrap()
        .drain();

    tx::verify_tx(&mut tx, &utxo, &chain.accessor);
}

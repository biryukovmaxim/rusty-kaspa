#![no_std]
#![no_main]

extern crate alloc;

mod auth;
mod block;
mod input;
mod journal;
mod state;
mod tx;
mod witness;

use risc0_zkvm::guest::env;
use zk_covenant_rollup_core::{
    MAX_DELEGATE_INPUTS, ROLLUP_LANE_KEY, build_permission_redeem_bytes, bytes_to_words, p2sh::blake2b_script_hash, pad_to_depth,
    permission_tree::StreamingPermTreeBuilder, required_depth,
    seq_commit::compute_seq_commit_for_lane,
};

risc0_zkvm::guest::entry!(main);

// ANCHOR: guest_main
pub fn main() {
    let mut stdin = env::stdin();

    let public_input = input::read_public_input(&mut stdin);
    let mut state_root = public_input.prev_state_hash;

    // ── Phase 1: compute lane tip across all blocks ──────────────
    let chain_len = input::read_u32(&mut stdin);
    let mut lane_tip = public_input.prev_lane_tip;
    let mut perm_builder = StreamingPermTreeBuilder::new();

    for _ in 0..chain_len {
        lane_tip = block::process_block(
            &mut stdin,
            &mut state_root,
            &public_input.covenant_id,
            &mut perm_builder,
            &ROLLUP_LANE_KEY,
            &lane_tip,
        );
    }

    // ── Phase 2: derive seq_commit from lane tip + witness ───────
    //   smt_leaf → proof.compute_root → lanes_root → state_root → seq_commit
    let witness = input::read_commitment_witness(&mut stdin);
    let smt_proof_bytes = input::read_aligned_bytes(&mut stdin);
    let seq_commit = compute_seq_commit_for_lane(&ROLLUP_LANE_KEY, &lane_tip, &witness, smt_proof_bytes.as_bytes());

    // ── Phase 3: build permission output if exits occurred ───────
    let perm_count = perm_builder.leaf_count();
    let permission_spk_hash = if perm_count > 0 {
        let perm_redeem_script_len = input::read_u32(&mut stdin) as i64;

        let depth = required_depth(perm_count as usize);
        let perm_root = pad_to_depth(perm_builder.finalize(), perm_count, depth);

        let perm_redeem =
            build_permission_redeem_bytes(&perm_root, perm_count as u64, depth, perm_redeem_script_len, MAX_DELEGATE_INPUTS);
        assert_eq!(perm_redeem.len() as i64, perm_redeem_script_len, "permission redeem script length mismatch");

        let script_hash = blake2b_script_hash(&perm_redeem);
        Some(bytes_to_words(script_hash))
    } else {
        None
    };

    // Output both lane_tip (new UTXO state) and seq_commit (block header verification)
    journal::write_output(&public_input, &state_root, &lane_tip, &seq_commit, permission_spk_hash.as_ref());
}
// ANCHOR_END: guest_main

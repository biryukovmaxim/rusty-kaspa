use risc0_zkvm::serde::WordRead;
use zk_covenant_rollup_core::{
    AlignedBytes,
    action::{Action, EntryAction, ExitAction, TransferAction},
    bytes_to_words_ref, perm_leaf_hash,
    permission_tree::StreamingPermTreeBuilder,
    prev_tx::parse_first_input_outpoint,
    seq_commit::{ActivityDigestBuilder, activity_leaf, from_hash, lane_tip_next, seq_commit_tx_digest, to_hash},
};

use crate::{auth, input, state, tx, witness::EntryWitness, witness::PrevTxV1WitnessData};

// ANCHOR: process_block
/// Process all transactions in a block for our lane.  Returns the
/// **new lane tip** (unchanged if the block has no lane transactions).
///
/// Input format per block:
///   `tx_count(u32) [context_hash([u32;8]) tx_data...]`
///
/// If `tx_count == 0` the lane was not active in this block — no context
/// hash is read and `prev_tip` is returned as-is.  This matches consensus
/// (`resolve_lane_updates` only touches lanes that have activity).
///
/// When `tx_count > 0`, every transaction contributes an activity leaf
/// via `seq_commit_tx_digest(tx_id, version)`.  Only V1 transactions
/// are inspected for rollup actions; V0 and V2+ are committed to the
/// digest but otherwise skipped.
pub fn process_block(
    stdin: &mut impl WordRead,
    state_root: &mut [u32; 8],
    covenant_id: &[u32; 8],
    perm_builder: &mut StreamingPermTreeBuilder,
    lane_key: &[u32; 8],
    prev_tip: &[u32; 8],
) -> [u32; 8] {
    let tx_count = input::read_u32(stdin);

    if tx_count == 0 {
        // Lane not active in this block — tip unchanged.
        return *prev_tip;
    }

    // Context hash only present when the lane is active.
    let context_hash = input::read_hash(stdin);

    let mut activity_builder = ActivityDigestBuilder::new();
    for merge_idx in 0..tx_count {
        let (tx_id, version) = process_transaction(stdin, state_root, covenant_id, perm_builder);
        let tx_digest = seq_commit_tx_digest(&tx_id, version);
        activity_builder.add_leaf(to_hash(&activity_leaf(&tx_digest, merge_idx)));
    }

    let activity_digest = from_hash(activity_builder.finalize());
    lane_tip_next(prev_tip, lane_key, &activity_digest, &context_hash)
}
// ANCHOR_END: process_block

/// Process a single transaction.  Returns `(tx_id, version)`.
///
/// - **V1**: full payload + rest_preimage via [`tx::read_v1_tx_data`].
///   If the payload contains a valid action the guest updates account state.
/// - **V0 / V2+**: host sends only the pre-computed tx_id hash via
///   [`tx::read_non_v1_tx`].  No action processing — these transactions
///   still contribute to the activity digest so the lane tip is correct.
fn process_transaction(
    stdin: &mut impl WordRead,
    state_root: &mut [u32; 8],
    covenant_id: &[u32; 8],
    perm_builder: &mut StreamingPermTreeBuilder,
) -> ([u32; 8], u16) {
    let version = input::read_u32(stdin) as u16;

    if version != 1 {
        // V0 / V2+: host sends just the tx_id hash — no action processing.
        return (tx::read_non_v1_tx(stdin), version);
    }

    // V1: full tx data — may contain an action.
    let tx_data = tx::read_v1_tx_data(stdin);

    // Guest determines if this is an action based on cryptographic data
    // If it's a valid action, host MUST provide witness data
    if let Some(action) = tx_data.action {
        process_action(stdin, state_root, action, &tx_data.rest_preimage, covenant_id, perm_builder);
    }

    (tx_data.tx_id, version)
}

// ANCHOR: process_action
/// Process a validated action transaction.
///
/// Called only when the payload parsed as a valid action (correct header
/// version, known operation, valid data).  The host must provide the
/// corresponding witness data.
///
/// The `rest_preimage` of the current transaction is used to:
/// - Extract the first input outpoint (for transfer/exit source auth).
/// - Parse the output at index 0 (for entry deposit amount).
fn process_action(
    stdin: &mut impl WordRead,
    state_root: &mut [u32; 8],
    action: Action,
    rest_preimage: &AlignedBytes,
    covenant_id: &[u32; 8],
    perm_builder: &mut StreamingPermTreeBuilder,
) {
    match action {
        Action::Transfer(transfer) => process_transfer(stdin, state_root, transfer, rest_preimage),
        Action::Entry(entry) => process_entry(stdin, state_root, entry, rest_preimage, covenant_id),
        Action::Exit(exit) => process_exit(stdin, state_root, exit, rest_preimage, perm_builder),
    }
}
// ANCHOR_END: process_action

// ANCHOR: process_transfer
/// Process a transfer action with conditional witness reading.
///
/// 1. Always reads the source `AccountWitness`.
/// 2. Checks balance — if insufficient (or empty leaf), returns immediately.
/// 3. Only reads auth (`PrevTxV1Witness`) and dest `AccountWitness` when
///    balance is sufficient.
fn process_transfer(stdin: &mut impl WordRead, state_root: &mut [u32; 8], transfer: TransferAction, rest_preimage: &AlignedBytes) {
    // 1. Read source witness
    let source_witness = input::read_account_witness(stdin);
    let intermediate_root = match state::verify_and_debit_source(&transfer.source, &source_witness, transfer.amount, state_root) {
        Some(root) => root,
        None => return, // Insufficient balance — no auth/dest to read
    };

    // 2. Read auth (host only writes when balance sufficient)
    let (prev_tx_id, output_index) =
        parse_first_input_outpoint(rest_preimage.as_bytes()).expect("action tx must have at least one input");
    let first_input_prev_tx_id = bytes_to_words_ref(&prev_tx_id);
    let prev_tx = PrevTxV1WitnessData::read_from_stdin(stdin, output_index);
    if auth::verify_source(&transfer.source, &prev_tx, &first_input_prev_tx_id).is_none() {
        return;
    }

    // 3. Read dest and update state
    let dest_witness = input::read_account_witness(stdin);
    if let Some(final_root) = state::verify_and_update_dest(&transfer.destination, &dest_witness, transfer.amount, &intermediate_root)
    {
        *state_root = final_root;
    }
}
// ANCHOR_END: process_transfer

// ANCHOR: process_entry
/// Process an entry (deposit) action.
///
/// Credits the destination account with the deposit amount extracted from
/// the transaction's first output.  Verifies the output SPK is the
/// delegate/entry P2SH for this covenant.
///
/// Rejects transactions whose input 0 has a permission-script suffix
/// (prevents delegate-change outputs from being counted as deposits).
fn process_entry(
    stdin: &mut impl WordRead,
    state_root: &mut [u32; 8],
    entry: EntryAction,
    rest_preimage: &AlignedBytes,
    covenant_id: &[u32; 8],
) {
    let witness = EntryWitness::read_from_stdin(stdin);

    // rest_preimage is already verified (guest computed rest_digest from it in read_v1_tx_data).

    // Reject if input 0 is a permission script. This prevents delegate change
    // outputs (from withdrawal transactions) from being counted as new deposits.
    if zk_covenant_rollup_core::prev_tx::input0_has_permission_suffix(rest_preimage.as_bytes()) {
        return;
    }

    // Parse the first output (index 0) to extract the deposit value.
    // Deposit output is always at index 0. tx_version=1 because entry txs are always V1.
    let output = match zk_covenant_rollup_core::prev_tx::parse_output_at_index(rest_preimage.as_bytes(), 0, 1) {
        Some(o) => o,
        None => return,
    };

    // Verify the output SPK is P2SH of the delegate/entry script for this covenant.
    if !zk_covenant_rollup_core::p2sh::verify_entry_output_spk(&output.spk, covenant_id) {
        return;
    }

    let amount = output.value;
    if amount == 0 {
        return; // Zero-value deposit — skip
    }

    // Credit the destination account
    if let Some(new_root) = state::process_entry(&entry, &witness.dest, amount, state_root) {
        *state_root = new_root;
    }
}
// ANCHOR_END: process_entry

// ANCHOR: process_exit
/// Process an exit (withdrawal) action with conditional witness reading.
///
/// 1. Always reads the source `AccountWitness`.
/// 2. Checks balance — if insufficient, returns immediately.
/// 3. Only reads auth (`PrevTxV1Witness`) when balance is sufficient.
/// 4. Updates state and adds a permission leaf for on-chain withdrawal.
fn process_exit(
    stdin: &mut impl WordRead,
    state_root: &mut [u32; 8],
    exit: ExitAction,
    rest_preimage: &AlignedBytes,
    perm_builder: &mut StreamingPermTreeBuilder,
) {
    // 1. Read source witness
    let source_witness = input::read_account_witness(stdin);
    let intermediate_root = match state::verify_and_debit_source(&exit.source, &source_witness, exit.amount, state_root) {
        Some(root) => root,
        None => return, // Insufficient balance — no auth to read
    };

    // 2. Read auth (host only writes when balance sufficient)
    let (prev_tx_id, output_index) =
        parse_first_input_outpoint(rest_preimage.as_bytes()).expect("action tx must have at least one input");
    let first_input_prev_tx_id = bytes_to_words_ref(&prev_tx_id);
    let prev_tx = PrevTxV1WitnessData::read_from_stdin(stdin, output_index);
    if auth::verify_source(&exit.source, &prev_tx, &first_input_prev_tx_id).is_none() {
        return;
    }

    // 3. Update state and add permission leaf
    *state_root = intermediate_root;
    perm_builder.add_leaf(perm_leaf_hash(exit.destination_spk_bytes(), exit.amount));
}
// ANCHOR_END: process_exit

use alloc::vec;
use risc0_zkvm::serde::WordRead;
use zk_covenant_rollup_core::{
    AlignedBytes,
    action::{Action, ActionHeader, EntryAction, ExitAction, OP_ENTRY, OP_EXIT, OP_TRANSFER, TransferAction},
    payload_digest_bytes, rest_digest_bytes, tx_id_v1,
};

use crate::input;

/// Read a non-V1 transaction — host sends just the pre-computed tx_id hash.
///
/// Used for V0 and V2+ transactions in the lane.  These still contribute
/// to the activity digest via `activity_leaf(tx_id, version, merge_idx)`,
/// but no action processing occurs.
pub fn read_non_v1_tx(stdin: &mut impl WordRead) -> [u32; 8] {
    input::read_hash(stdin)
}

// ANCHOR: v1_tx_data
/// V1 transaction data after reading from stdin.
pub struct V1TxData {
    /// Transaction ID computed as `tx_id_v1(payload_digest, rest_digest)`.
    pub tx_id: [u32; 8],
    /// Parsed action, if the payload contains a valid one.
    pub action: Option<Action>,
    /// Full rest_preimage — guest computes `rest_digest` from it (never trusts
    /// a host-provided digest).  Used by action processing to verify inputs
    /// and extract outputs.
    pub rest_preimage: AlignedBytes,
}
// ANCHOR_END: v1_tx_data

// ANCHOR: read_v1_tx_data
/// Read a **V1** transaction and compute its `tx_id`.
///
/// The caller (`block::process_transaction`) already read the version word
/// and dispatches here only for `version == 1`.
///
/// **Payload handling:**
/// - Host sends `payload_byte_len` (u32), then `ceil(len/4)` words (padded).
/// - Guest computes `payload_digest` from actual bytes (trimmed to `payload_byte_len`).
/// - Action is parsed only when the payload is 4-byte aligned.
///
/// **Rest preimage:**
/// - Host sends the full rest_preimage (length-prefixed).
/// - Guest computes `rest_digest = hash(rest_preimage)`.
/// - Stored for action processing (input verification, output parsing).
///
/// **Action detection** is purely payload-based — no tx_id prefix check.
/// All rollup-lane V1 transactions are potential actions; the payload
/// content (header version + known opcode + valid data) determines whether
/// an action is present.
pub fn read_v1_tx_data(stdin: &mut impl WordRead) -> V1TxData {
    // Read payload length in BYTES
    let payload_byte_len = input::read_u32(stdin) as usize;

    // Calculate words needed (round up to word boundary)
    let payload_word_len = payload_byte_len.div_ceil(4);

    // Read as words (guaranteed 4-byte aligned)
    let mut payload_words = vec![0u32; payload_word_len];
    stdin.read_words(&mut payload_words).unwrap();

    // View as bytes for payload_digest
    let payload_bytes: &[u8] = bytemuck::cast_slice(&payload_words);
    let payload_bytes = &payload_bytes[..payload_byte_len]; // trim padding

    // Read rest_preimage (length-prefixed) and compute rest_digest
    let rest_preimage = input::read_aligned_bytes(stdin);
    let rest_digest = rest_digest_bytes(rest_preimage.as_bytes());

    // Compute tx_id = H(payload_digest || rest_digest)
    let pd = payload_digest_bytes(payload_bytes);
    let tx_id = tx_id_v1(&pd, &rest_digest);

    // Only parse action if payload is 4-byte aligned (required for our action format)
    let action = if payload_byte_len.is_multiple_of(4) {
        parse_action(&payload_words)
    } else {
        None // Unaligned payload — not a valid action format
    };

    // All lane txs are potential actions — filter only by payload validity
    let valid_action = action.filter(|a| a.is_valid());

    V1TxData { tx_id, action: valid_action, rest_preimage }
}
// ANCHOR_END: read_v1_tx_data

// ANCHOR: parse_action
/// Parse an action from payload words.
///
/// Returns `None` if the header version is invalid, the operation code
/// is unknown, or the payload is too short for the operation's data.
fn parse_action(payload: &[u32]) -> Option<Action> {
    let (header_words, rest) = payload.split_first_chunk::<{ ActionHeader::WORDS }>()?;
    let header = ActionHeader::from_words_ref(header_words);

    if !header.is_valid_version() {
        return None;
    }

    match header.operation {
        OP_TRANSFER => {
            let transfer_words = rest.first_chunk()?;
            let transfer = TransferAction::from_words(*transfer_words);
            Some(Action::Transfer(transfer))
        }
        OP_ENTRY => {
            let entry_words = rest.first_chunk()?;
            let entry = EntryAction::from_words(*entry_words);
            Some(Action::Entry(entry))
        }
        OP_EXIT => {
            let exit_words = rest.first_chunk()?;
            let exit = ExitAction::from_words(*exit_words);
            Some(Action::Exit(exit))
        }
        _ => None, // Unknown operation — not an action
    }
}
// ANCHOR_END: parse_action

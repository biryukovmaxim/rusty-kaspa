use risc0_zkvm::{guest::env, serde::WordWrite};
use zk_covenant_rollup_core::PublicInput;

// ANCHOR: write_output
/// Write the proof output to the journal.
///
/// Journal layout:
///   Base (192 bytes = 48 words):
///     prev_state_hash(32) | prev_lane_tip(32) | new_state(32) | new_lane_tip(32) | new_seq_commit(32) | covenant_id(32)
///   With permission (+32 bytes = 56 words):
///     ... base ... | permission_spk_hash(32)
#[inline]
pub fn write_output(
    public_input: &PublicInput,
    final_state_root: &[u32; 8],
    new_lane_tip: &[u32; 8],
    new_seq_commit: &[u32; 8],
    permission_spk_hash: Option<&[u32; 8]>,
) {
    let mut journal = env::journal();

    journal.write_words(&public_input.prev_state_hash).unwrap();
    journal.write_words(&public_input.prev_lane_tip).unwrap();

    journal.write_words(final_state_root).unwrap();
    journal.write_words(new_lane_tip).unwrap();
    journal.write_words(new_seq_commit).unwrap();

    journal.write_words(&public_input.covenant_id).unwrap();

    if let Some(hash_words) = permission_spk_hash {
        journal.write_words(hash_words).unwrap();
    }
}
// ANCHOR_END: write_output

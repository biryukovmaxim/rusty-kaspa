//! Lane-based seq-commit functions for the rollup guest.
//!
//! Thin `[u32; 8]` wrappers around [`kaspa_seq_commit`] hashing functions.

use kaspa_hashes::{Hash, SeqCommitActiveNode};
use kaspa_smt::proof::OwnedSmtProof;

pub use kaspa_seq_commit::hashing::ActivityDigestBuilder;
pub use kaspa_seq_commit::types::LaneId;

// ── Conversion helpers ───────────────────────────────────────────────

#[inline]
pub fn to_hash(words: &[u32; 8]) -> Hash {
    Hash::from_bytes(bytemuck::cast(*words))
}

#[inline]
pub fn from_hash(h: Hash) -> [u32; 8] {
    bytemuck::cast(h.as_bytes())
}

// ── Hash functions ([u32;8] interface) ───────────────────────────────

/// `H_activity_leaf(tx_id || le_u16(version) || le_u32(merge_idx))`
#[inline]
pub fn activity_leaf(tx_id: &[u32; 8], version: u16, merge_idx: u32) -> [u32; 8] {
    from_hash(kaspa_seq_commit::hashing::activity_leaf(&to_hash(tx_id), version, merge_idx))
}

/// `H_lane_key(lane_id)`
#[inline]
pub fn lane_key(lane_id: &LaneId) -> [u32; 8] {
    from_hash(kaspa_seq_commit::hashing::lane_key(lane_id))
}

/// `H_lane_tip(parent_ref || lane_key || activity_digest || context_hash)`
#[inline]
pub fn lane_tip_next(parent_ref: &[u32; 8], lane_key: &[u32; 8], activity_digest: &[u32; 8], context_hash: &[u32; 8]) -> [u32; 8] {
    from_hash(kaspa_seq_commit::hashing::lane_tip_next(&kaspa_seq_commit::types::LaneTipInput {
        parent_ref: &to_hash(parent_ref),
        lane_key: &to_hash(lane_key),
        activity_digest: &to_hash(activity_digest),
        context_hash: &to_hash(context_hash),
    }))
}

/// `H_active_leaf(lane_tip || le_u64(blue_score))`
///
/// `lane_tip` already commits to `lane_key` via `H_lane_tip`, and the SMT
/// key path commits to `lane_key` as well, so including `lane_key` here
/// would be redundant.
#[inline]
pub fn smt_leaf_hash(lane_tip: &[u32; 8], blue_score: u64) -> [u32; 8] {
    from_hash(kaspa_seq_commit::hashing::smt_leaf_hash(&kaspa_seq_commit::types::SmtLeafInput {
        lane_tip: &to_hash(lane_tip),
        blue_score,
    }))
}

/// `H_seq(lanes_root, payload_and_ctx_digest)`
#[inline]
pub fn seq_state_root(lanes_root: &[u32; 8], payload_and_ctx_digest: &[u32; 8]) -> [u32; 8] {
    from_hash(kaspa_seq_commit::hashing::seq_state_root(&kaspa_seq_commit::types::SeqState {
        lanes_root: &to_hash(lanes_root),
        payload_and_ctx_digest: &to_hash(payload_and_ctx_digest),
    }))
}

/// `H_seq(parent_seq_commit, state_root)`
#[inline]
pub fn seq_commit(parent_seq_commit: &[u32; 8], state_root: &[u32; 8]) -> [u32; 8] {
    from_hash(kaspa_seq_commit::hashing::seq_commit(&kaspa_seq_commit::types::SeqCommitInput {
        parent_seq_commit: &to_hash(parent_seq_commit),
        state_root: &to_hash(state_root),
    }))
}

// ── Commitment witness ───────────────────────────────────────────────

/// Fixed-size header the host provides so the guest can derive `seq_commit`
/// from the lane tip.  Laid out as plain POD — host writes it as one slice,
/// guest reads it with a single `read_words`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct CommitmentWitness {
    pub payload_and_ctx_digest: [u32; 8],
    pub parent_seq_commit: [u32; 8],
    pub blue_score: u64,
}

/// Derive `seq_commit` from a lane tip + SMT proof + witness header.
///
/// Mirrors `compute_seq_commit_for_lane` from the `prove_lane_activity` test:
///   `smt_leaf → proof.compute_root → lanes_root → state_root → seq_commit`.
pub fn compute_seq_commit_for_lane(
    lane_key: &[u32; 8],
    lane_tip: &[u32; 8],
    witness: &CommitmentWitness,
    smt_proof_bytes: &[u8],
) -> [u32; 8] {
    let proof = OwnedSmtProof::from_bytes(smt_proof_bytes).expect("invalid SMT proof");
    let leaf = to_hash(&smt_leaf_hash(lane_tip, witness.blue_score));
    let lanes_root = proof.compute_root::<SeqCommitActiveNode>(&to_hash(lane_key), Some(leaf)).expect("SMT proof compute_root failed");
    let sr = seq_state_root(&from_hash(lanes_root), &witness.payload_and_ctx_digest);
    seq_commit(&witness.parent_seq_commit, &sr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precomputed_lane_key_matches() {
        assert_eq!(lane_key(&crate::ROLLUP_SUBNETWORK_ID), crate::ROLLUP_LANE_KEY);
    }

    #[test]
    fn roundtrip_conversion() {
        let original = [0xDEADBEEFu32, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(from_hash(to_hash(&original)), original);
    }
}

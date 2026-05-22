//! IBD SMT verification: metadata check.
//!
//! Proof verification with branch caching uses [`SmtProof::compute_root_with_visitor`]
//! from `kaspa-smt` with `&mut ProofBranchCache` as the visitor.

use crate::hashing::{mergeset_context_hash, payload_and_context_digest, seq_state_root};
use crate::types::{MergesetContext, SeqState};
use kaspa_hashes::{Hash, HasherBase, SeqCommitMerkleBranch};

/// Metadata sent before lane entries, verified against the pruning point header.
#[derive(Clone, Copy, Debug)]
pub struct SmtMetadata<'a> {
    pub lanes_root: &'a Hash,
    pub payload_and_ctx_digest: &'a Hash,
    /// Lets the verifier reconstruct `payload_and_ctx_digest` from
    /// `mergeset_context_hash(ctx)` and authenticate the claimed
    /// `finality_anchor` (carried inside `ctx`) against the header's AIMR.
    pub payload_root: &'a Hash,
    pub parent_seq_commit: &'a Hash,
}

/// Error during SMT import verification.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SmtVerifyError {
    #[error("seq_commit mismatch: expected {expected}, computed {computed}")]
    SeqCommitMismatch { expected: Hash, computed: Hash },

    #[error("parent_seq_commit mismatch: expected {expected}, got {got}")]
    ParentSeqCommitMismatch { expected: Hash, got: Hash },

    #[error("payload_and_ctx_digest mismatch: expected {expected}, computed {computed}")]
    PayloadAndCtxDigestMismatch { expected: Hash, computed: Hash },

    #[error("proof verification failed for lane at index {index}")]
    ProofFailed { index: usize },

    #[error("tree root mismatch: expected {expected}, computed {computed}")]
    RootMismatch { expected: Hash, computed: Hash },

    #[error("proof error: {0}")]
    ProofError(#[from] kaspa_smt::proof::SmtProofError),
}

/// Verify that the metadata is consistent with the header's
/// `accepted_id_merkle_root` (= seq_commit).
///
/// Beyond the AIMR + parent linkage check, this also rebuilds
/// `payload_and_ctx_digest` from `mergeset_context_hash(ctx)` and
/// `metadata.payload_root` to authenticate `ctx.finality_anchor`. Callers
/// reconstruct `ctx` from header data (timestamp from the PP's selected
/// parent, daa_score / blue_score from the PP header) plus the claimed
/// anchor from the wire.
pub fn verify_smt_metadata(
    metadata: &SmtMetadata<'_>,
    ctx: &MergesetContext,
    expected_seq_commit: Hash,
    expected_parent_seq_commit: Hash,
) -> Result<(), SmtVerifyError> {
    if *metadata.parent_seq_commit != expected_parent_seq_commit {
        return Err(SmtVerifyError::ParentSeqCommitMismatch {
            expected: expected_parent_seq_commit,
            got: *metadata.parent_seq_commit,
        });
    }

    let context_hash = mergeset_context_hash(ctx);
    let computed_pd = payload_and_context_digest(&context_hash, metadata.payload_root);
    if computed_pd != *metadata.payload_and_ctx_digest {
        return Err(SmtVerifyError::PayloadAndCtxDigestMismatch { expected: *metadata.payload_and_ctx_digest, computed: computed_pd });
    }

    let state_root =
        seq_state_root(&SeqState { lanes_root: metadata.lanes_root, payload_and_ctx_digest: metadata.payload_and_ctx_digest });

    let computed = {
        let mut h = SeqCommitMerkleBranch::new();
        h.update(metadata.parent_seq_commit).update(state_root);
        h.finalize()
    };

    if computed != expected_seq_commit {
        return Err(SmtVerifyError::SeqCommitMismatch { expected: expected_seq_commit, computed });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::hashing::{lane_key, payload_and_context_digest, smt_leaf_hash};
    use crate::types::{LaneId, SmtLeafInput};
    use kaspa_hashes::{SeqCommitActiveNode, ZERO_HASH};
    use kaspa_smt::proof::ProofBranchCache;
    use kaspa_smt::tree::SparseMerkleTree;

    type Smt = SparseMerkleTree<SeqCommitActiveNode>;

    fn lid(b: u8) -> LaneId {
        let mut id = [0u8; 20];
        id[0] = b;
        id
    }

    fn tip(b: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        Hash::from_bytes(bytes)
    }

    fn lh(_lane_id: &LaneId, lane_tip: &Hash, blue_score: u64) -> Hash {
        smt_leaf_hash(&SmtLeafInput { lane_tip, blue_score })
    }

    fn build_ref(entries: &[(LaneId, Hash, u64)]) -> (Hash, Smt) {
        let mut tree = Smt::new();
        for (id, t, bs) in entries {
            tree.insert(lane_key(id), lh(id, t, *bs));
        }
        (tree.root(), tree)
    }

    fn sample_ctx() -> MergesetContext {
        MergesetContext { timestamp: 1_700_000_000, daa_score: 1234, blue_score: 250, finality_anchor: Hash::from_bytes([7; 32]) }
    }

    #[test]
    fn metadata_correct() {
        let lr = Hash::from_bytes([1; 32]);
        let pr = Hash::from_bytes([3; 32]);
        let ps = Hash::from_bytes([4; 32]);
        let ctx = sample_ctx();

        let ch = mergeset_context_hash(&ctx);
        let pd = payload_and_context_digest(&ch, &pr);
        let sr = seq_state_root(&SeqState { lanes_root: &lr, payload_and_ctx_digest: &pd });
        let sc = {
            let mut h = SeqCommitMerkleBranch::new();
            h.update(ps).update(sr);
            h.finalize()
        };

        let md = SmtMetadata { lanes_root: &lr, payload_and_ctx_digest: &pd, payload_root: &pr, parent_seq_commit: &ps };
        assert!(verify_smt_metadata(&md, &ctx, sc, ps).is_ok());
    }

    #[test]
    fn metadata_wrong_parent() {
        let lr = Hash::from_bytes([1; 32]);
        let pd = Hash::from_bytes([2; 32]);
        let pr = Hash::from_bytes([3; 32]);
        let ps = Hash::from_bytes([4; 32]);
        let md = SmtMetadata { lanes_root: &lr, payload_and_ctx_digest: &pd, payload_root: &pr, parent_seq_commit: &ps };
        assert!(matches!(
            verify_smt_metadata(&md, &sample_ctx(), ZERO_HASH, Hash::from_bytes([99; 32])),
            Err(SmtVerifyError::ParentSeqCommitMismatch { .. })
        ));
    }

    #[test]
    fn metadata_wrong_commit() {
        let lr = Hash::from_bytes([1; 32]);
        let pr = Hash::from_bytes([3; 32]);
        let ps = Hash::from_bytes([4; 32]);
        let ctx = sample_ctx();
        let ch = mergeset_context_hash(&ctx);
        let pd = payload_and_context_digest(&ch, &pr);
        let md = SmtMetadata { lanes_root: &lr, payload_and_ctx_digest: &pd, payload_root: &pr, parent_seq_commit: &ps };
        assert!(matches!(
            verify_smt_metadata(&md, &ctx, Hash::from_bytes([99; 32]), ps),
            Err(SmtVerifyError::SeqCommitMismatch { .. })
        ));
    }

    #[test]
    fn metadata_wrong_anchor_detected_via_payload_digest() {
        let lr = Hash::from_bytes([1; 32]);
        let pr = Hash::from_bytes([3; 32]);
        let ps = Hash::from_bytes([4; 32]);
        let ctx = sample_ctx();
        let ch = mergeset_context_hash(&ctx);
        let pd = payload_and_context_digest(&ch, &pr);
        let sr = seq_state_root(&SeqState { lanes_root: &lr, payload_and_ctx_digest: &pd });
        let sc = {
            let mut h = SeqCommitMerkleBranch::new();
            h.update(ps).update(sr);
            h.finalize()
        };
        let mut bad_ctx = ctx;
        bad_ctx.finality_anchor = Hash::from_bytes([0xAB; 32]);
        let md = SmtMetadata { lanes_root: &lr, payload_and_ctx_digest: &pd, payload_root: &pr, parent_seq_commit: &ps };
        assert!(matches!(verify_smt_metadata(&md, &bad_ctx, sc, ps), Err(SmtVerifyError::PayloadAndCtxDigestMismatch { .. })));
    }

    #[test]
    fn proof_verify_with_branch_cache() {
        let (root, tree) = build_ref(&[(lid(1), tip(10), 100)]);
        let lk = lane_key(&lid(1));
        let leaf = lh(&lid(1), &tip(10), 100);
        let proof = tree.prove(&lk).unwrap();

        let mut branches = ProofBranchCache::new();
        let ok = proof.as_proof().verify_cached::<SeqCommitActiveNode>(&lk, Some(leaf), root, &mut branches).unwrap();
        assert!(ok);
        assert!(branches.len() <= proof.non_empty_count());
    }

    #[test]
    fn proof_wrong_leaf_with_cache() {
        let (root, tree) = build_ref(&[(lid(1), tip(10), 100)]);
        let lk = lane_key(&lid(1));
        let proof = tree.prove(&lk).unwrap();

        let mut branches = ProofBranchCache::new();
        let ok =
            proof.as_proof().verify_cached::<SeqCommitActiveNode>(&lk, Some(Hash::from_bytes([99; 32])), root, &mut branches).unwrap();
        assert!(!ok);
    }

    #[test]
    fn proof_short_circuit_via_shared_branches() {
        let entries = [(lid(1), tip(10), 100), (lid(2), tip(20), 200)];
        let (root, tree) = build_ref(&entries);

        let mut branches = ProofBranchCache::new();

        let lk0 = lane_key(&lid(1));
        let proof0 = tree.prove(&lk0).unwrap();
        assert!(
            proof0
                .as_proof()
                .verify_cached::<SeqCommitActiveNode>(&lk0, Some(lh(&lid(1), &tip(10), 100)), root, &mut branches)
                .unwrap()
        );
        let after_first = branches.len();

        let lk1 = lane_key(&lid(2));
        let proof1 = tree.prove(&lk1).unwrap();
        assert!(
            proof1
                .as_proof()
                .verify_cached::<SeqCommitActiveNode>(&lk1, Some(lh(&lid(2), &tip(20), 200)), root, &mut branches)
                .unwrap()
        );
        assert!(branches.len() >= after_first);
        assert!(branches.len() < 512);
    }
}

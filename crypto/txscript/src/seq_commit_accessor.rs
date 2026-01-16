use kaspa_hashes::Hash;

pub trait SeqCommitAccessor: Sync {
    fn is_selected_block(&self, block_hash: Hash) -> Option<bool>;
    fn seq_commitment_within_depth(&self, block_hash: Hash) -> Option<Hash>;
}

use crate::caches::Cache;
use crate::covenants::{CovenantsContext, EMPTY_COV_CONTEXT};
use crate::{SeqCommitAccessor, SigCacheKey};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValues;

pub struct EngineContext<'a, Reused: SigHashReusedValues> {
    pub(crate) reused_values: &'a Reused,
    pub(crate) sig_cache: &'a Cache<SigCacheKey, bool>,
    pub(crate) covenants_ctx: &'a CovenantsContext,
    pub(crate) seq_commit_accessor: Option<&'a dyn SeqCommitAccessor>,
}

impl<'a, Reused: SigHashReusedValues> EngineContext<'a, Reused> {
    pub fn new(reused_values: &'a Reused, sig_cache: &'a Cache<SigCacheKey, bool>) -> Self {
        Self { reused_values, sig_cache, covenants_ctx: &EMPTY_COV_CONTEXT, seq_commit_accessor: None }
    }

    pub fn with_covenants_ctx(mut self, covenants_ctx: &'a CovenantsContext) -> Self {
        self.covenants_ctx = covenants_ctx;
        self
    }

    pub fn with_seq_commit_accessor(mut self, seq_commit_accessor: &'a dyn SeqCommitAccessor) -> Self {
        self.seq_commit_accessor = Some(seq_commit_accessor);
        self
    }

    pub fn with_seq_commit_accessor_opt(mut self, seq_commit_accessor: Option<&'a dyn SeqCommitAccessor>) -> Self {
        self.seq_commit_accessor = seq_commit_accessor;
        self
    }
}

impl<'a, Reused: SigHashReusedValues> Clone for EngineContext<'a, Reused> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Reused: SigHashReusedValues> Copy for EngineContext<'a, Reused> {}

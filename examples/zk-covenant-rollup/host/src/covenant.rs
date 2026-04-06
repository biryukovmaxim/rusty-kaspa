use kaspa_txscript::opcodes::codes::{
    OpAdd, OpBlake2b, OpCat, OpChainblockSeqCommit, OpCovOutputCount, OpData32, OpDrop, OpDup, OpElse, OpEndIf, OpEqual,
    OpEqualVerify, OpFromAltStack, OpIf, OpInputCovenantId, OpNumEqual, OpNumEqualVerify, OpSHA256, OpSwap, OpToAltStack,
    OpTxInputIndex, OpTxInputScriptSigLen, OpTxInputScriptSigSubstr, OpTxOutputSpk, OpTxOutputSpkSubstr,
};
use kaspa_txscript::script_builder::ScriptBuilder;

/// Redeem script prefix size in bytes.
///
/// Layout (66 bytes total):
/// - 1 byte:  `OpData32`
/// - 32 bytes: `prev_lane_tip`
/// - 1 byte:  `OpData32`
/// - 32 bytes: `prev_state_hash`
pub const REDEEM_PREFIX_LEN: i64 = 66;

/// Rollup covenant methods.
///
/// ## Sig script push order (bottom → top)
///
/// ```text
/// [...proof_data..., new_lane_tip, new_state_hash, block_prove_to, redeem]
/// ```
///
/// ## Stack after prefix pushes + stash
///
/// ```text
/// Stack: [..., new_lane_tip, new_state_hash, block_prove_to]
/// Alt:   [prev_state_hash, prev_lane_tip]
/// ```
pub trait RollupCovenant {
    type Error;

    /// Stash prefix-pushed prev values to alt stack.
    ///
    /// Expects: [..., new_lane_tip, new_state_hash, block_prove_to, prev_lane_tip, prev_state_hash]
    /// Leaves:  [..., new_lane_tip, new_state_hash, block_prove_to], alt:[prev_state, prev_lane_tip]
    fn stash_prev_values(&mut self) -> Result<&mut Self, Self::Error>;

    /// Derive new_seq_commit from block_prove_to via OpChainblockSeqCommit.
    ///
    /// Expects: [..., new_lane_tip, new_state_hash, block_prove_to]
    /// Leaves:  [..., new_lane_tip, new_state_hash, new_seq_commit]
    fn obtain_new_seq_commitment(&mut self) -> Result<&mut Self, Self::Error>;

    /// Build the 66-byte prefix for the output UTXO's redeem script.
    /// Stashes new_seq_commit, new_state, new_lane_tip to alt stack for journal.
    ///
    /// Expects: [..., new_lane_tip, new_state_hash, new_seq_commit],
    ///          alt:[prev_state, prev_lane_tip]
    /// Leaves:  [..., 66-byte prefix],
    ///          alt:[prev_state, prev_lane_tip, new_seq_commit, new_state, new_lane_tip]
    fn build_next_redeem_prefix_rollup(&mut self) -> Result<&mut Self, Self::Error>;

    /// Expects: [..., prefix]
    /// Leaves:  [..., new_redeem_script]
    fn extract_redeem_suffix_and_concat(&mut self, redeem_script_len: i64) -> Result<&mut Self, Self::Error>;

    /// Build journal preimage from alt stack values + covenant_id, then SHA256.
    ///
    /// Journal: prev_state(32) || prev_lane_tip(32) || new_state(32)
    ///          || new_lane_tip(32) || new_seq_commit(32) || covenant_id(32)
    ///          [optional: || perm_script_hash(32)]
    ///
    /// Expects: [...], alt:[prev_state, prev_lane_tip, new_seq_commit, new_state, new_lane_tip]
    /// Leaves:  [..., journal_hash]
    fn build_and_hash_journal(&mut self) -> Result<&mut Self, Self::Error>;

    fn verify_outputs_and_append_perm_hash(&mut self) -> Result<&mut Self, Self::Error>;
}

impl RollupCovenant for ScriptBuilder {
    type Error = kaspa_txscript::script_builder::ScriptBuilderError;

    fn stash_prev_values(&mut self) -> Result<&mut Self, Self::Error> {
        // Stack: [..., block_prove_to, prev_lane_tip, prev_state_hash]
        self.add_op(OpToAltStack)?; // → alt:[prev_state]
        self.add_op(OpToAltStack) // → alt:[prev_state, prev_lane_tip]
    }

    fn obtain_new_seq_commitment(&mut self) -> Result<&mut Self, Self::Error> {
        // Stack: [..., new_lane_tip, new_state_hash, block_prove_to]
        self.add_op(OpChainblockSeqCommit)
        // Stack: [..., new_lane_tip, new_state_hash, new_seq_commit]
    }

    fn build_next_redeem_prefix_rollup(&mut self) -> Result<&mut Self, Self::Error> {
        // Stack: [..., new_lane_tip, new_state_hash, new_seq_commit]
        // Goal:  build prefix = OpData32||new_lane_tip||OpData32||new_state_hash
        //        and stash new_seq_commit, new_state, new_lane_tip for journal

        // Stash new_seq_commit
        self.add_op(OpToAltStack)?;
        // Stack: [..., new_lane_tip, new_state_hash], alt:[..., new_seq_commit]

        // Dup + stash new_state_hash, then build (OpData32||new_state_hash)
        self.add_op(OpDup)?;
        self.add_op(OpToAltStack)?;
        // Stack: [..., new_lane_tip, new_state_hash], alt:[..., new_seq_commit, new_state]
        self.add_data(&[OpData32])?;
        self.add_op(OpSwap)?;
        self.add_op(OpCat)?;
        // Stack: [..., new_lane_tip, (OpData32||new_state_hash)]

        self.add_op(OpSwap)?;
        // Stack: [..., (OpData32||new_state_hash), new_lane_tip]

        // Dup + stash new_lane_tip, then build (OpData32||new_lane_tip)
        self.add_op(OpDup)?;
        self.add_op(OpToAltStack)?;
        // Stack: [..., (OpData32||new_state), new_lane_tip], alt:[..., new_seq, new_state, new_lane_tip]
        self.add_data(&[OpData32])?;
        self.add_op(OpSwap)?;
        self.add_op(OpCat)?;
        // Stack: [..., (OpData32||new_state), (OpData32||new_lane_tip)]

        self.add_op(OpSwap)?;
        self.add_op(OpCat)
        // Stack: [..., (OpData32||new_lane_tip||OpData32||new_state)] = 66-byte prefix
    }

    fn extract_redeem_suffix_and_concat(&mut self, redeem_script_len: i64) -> Result<&mut Self, Self::Error> {
        self.add_op(OpTxInputIndex)?;
        self.add_op(OpTxInputIndex)?;
        self.add_op(OpTxInputScriptSigLen)?;
        self.add_i64(-redeem_script_len + REDEEM_PREFIX_LEN)?;
        self.add_op(OpAdd)?;
        self.add_op(OpTxInputIndex)?;
        self.add_op(OpTxInputScriptSigLen)?;
        self.add_op(OpTxInputScriptSigSubstr)?;
        self.add_op(OpCat)
    }

    fn build_and_hash_journal(&mut self) -> Result<&mut Self, Self::Error> {
        // Alt stack (top→bottom): [new_lane_tip, new_state, new_seq_commit, prev_lane_tip, prev_state]
        //
        // Journal (192 or 224 bytes):
        //   prev_state(32) || prev_lane_tip(32) || new_state(32) || new_lane_tip(32)
        //   || new_seq_commit(32) || covenant_id(32)
        //   [optional: || perm_script_hash(32)]

        // Pop new values: new_lane_tip, new_state, new_seq_commit
        self.add_op(OpFromAltStack)?; // new_lane_tip
        self.add_op(OpFromAltStack)?; // new_state
        self.add_op(OpFromAltStack)?; // new_seq_commit

        // Build (new_state||new_lane_tip||new_seq_commit) = 96 bytes
        // Stack: [..., new_lane_tip, new_state, new_seq_commit]
        self.add_op(OpSwap)?;
        // Stack: [..., new_lane_tip, new_seq_commit, new_state]
        // We need: new_state || new_lane_tip || new_seq_commit
        // Rotate: bring new_lane_tip to position
        // Stack has: [..., new_lane_tip, new_seq_commit, new_state]
        // OpRot would be: a b c → b c a
        // But we don't have OpRot imported... let me use alt stack

        // Stash new_state temporarily
        self.add_op(OpToAltStack)?;
        // Stack: [..., new_lane_tip, new_seq_commit], alt:[..., new_state]
        self.add_op(OpSwap)?;
        // Stack: [..., new_seq_commit, new_lane_tip]
        self.add_op(OpFromAltStack)?;
        // Stack: [..., new_seq_commit, new_lane_tip, new_state]
        self.add_op(OpSwap)?;
        // Stack: [..., new_seq_commit, new_state, new_lane_tip]
        self.add_op(OpCat)?;
        // Stack: [..., new_seq_commit, (new_state||new_lane_tip)]
        self.add_op(OpSwap)?;
        self.add_op(OpCat)?;
        // Stack: [..., (new_state||new_lane_tip||new_seq_commit)] = 96B

        // Pop prev values
        self.add_op(OpFromAltStack)?; // prev_lane_tip
        self.add_op(OpFromAltStack)?; // prev_state
        self.add_op(OpSwap)?;
        self.add_op(OpCat)?;
        // Stack: [..., 96B_new, (prev_state||prev_lane_tip)] = 64B
        self.add_op(OpSwap)?;
        self.add_op(OpCat)?;
        // Stack: [..., (prev_state||prev_lane_tip||new_state||new_lane_tip||new_seq_commit)] = 160B

        // Append covenant_id → 192B base
        self.add_op(OpTxInputIndex)?;
        self.add_op(OpInputCovenantId)?;
        self.add_op(OpCat)?;

        // Verify outputs + optionally append perm hash, then SHA256
        self.verify_outputs_and_append_perm_hash()?;
        self.add_op(OpSHA256)
    }

    fn verify_outputs_and_append_perm_hash(&mut self) -> Result<&mut Self, Self::Error> {
        self.add_op(OpTxInputIndex)?;
        self.add_op(OpInputCovenantId)?;
        self.add_op(OpCovOutputCount)?;
        self.add_op(OpDup)?;
        self.add_i64(2)?;
        self.add_op(OpNumEqual)?;
        self.add_op(OpIf)?;
        // count == 2
        self.add_op(OpDrop)?;
        self.add_i64(1)?;
        self.add_i64(4)?;
        self.add_i64(36)?;
        self.add_op(OpTxOutputSpkSubstr)?;
        self.add_op(OpDup)?;
        self.add_data(&[0x00, 0x00, OpBlake2b, OpData32])?;
        self.add_op(OpSwap)?;
        self.add_op(OpCat)?;
        self.add_data(&[OpEqual])?;
        self.add_op(OpCat)?;
        self.add_i64(1)?;
        self.add_op(OpTxOutputSpk)?;
        self.add_op(OpEqualVerify)?;
        self.add_op(OpCat)?;
        self.add_op(OpElse)?;
        // count == 1
        self.add_i64(1)?;
        self.add_op(OpNumEqualVerify)?;
        self.add_op(OpEndIf)
    }
}

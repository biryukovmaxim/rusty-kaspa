use kaspa_txscript::opcodes::codes::*;

use crate::builder::TypedScriptBuilder;
use crate::markers::*;

// ---------------------------------------------------------------------------
// Transaction introspection: zero-input pushers (blanket)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<S, M> {
    pub fn op_tx_input_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputCount)
    }
    pub fn op_tx_output_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxOutputCount)
    }
    pub fn op_tx_version(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxVersion)
    }
    pub fn op_tx_lock_time(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxLockTime)
    }
    pub fn op_tx_gas(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxGas)
    }
    pub fn op_tx_input_index(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputIndex)
    }
    pub fn op_tx_payload_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxPayloadLen)
    }
    pub fn op_tx_subnet_id(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxSubnetId)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: index-consuming (on Num<S>)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    // → Num<S>
    pub fn op_tx_input_amount(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputAmount)
    }
    pub fn op_tx_output_amount(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxOutputAmount)
    }
    pub fn op_outpoint_index(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpOutpointIndex)
    }
    pub fn op_tx_input_spk_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputSpkLen)
    }
    pub fn op_tx_output_spk_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxOutputSpkLen)
    }
    pub fn op_tx_input_script_sig_len(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpTxInputScriptSigLen)
    }

    // → Data<S>
    pub fn op_tx_input_spk(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputSpk)
    }
    pub fn op_tx_output_spk(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxOutputSpk)
    }
    pub fn op_tx_input_seq(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputSeq)
    }

    // → Hash<S>
    pub fn op_outpoint_tx_id(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpOutpointTxId)
    }

    // → Bool<S>
    pub fn op_tx_input_is_coinbase(self) -> TypedScriptBuilder<Bool<S>, M> {
        self.emit_op(OpTxInputIsCoinbase)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: substr from tx (on Num<Num<S>>)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<Num<S>>, M> {
    pub fn op_tx_payload_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxPayloadSubstr)
    }
}

// ---------------------------------------------------------------------------
// Transaction introspection: substr with index (on Num<Num<Num<S>>>)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<Num<Num<S>>>, M> {
    pub fn op_tx_input_script_sig_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputScriptSigSubstr)
    }
    pub fn op_tx_input_spk_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxInputSpkSubstr)
    }
    pub fn op_tx_output_spk_substr(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpTxOutputSpkSubstr)
    }
}

// ---------------------------------------------------------------------------
// Covenant operations
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    pub fn op_auth_output_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAuthOutputCount)
    }
}

impl<S, M> TypedScriptBuilder<Num<Num<S>>, M> {
    pub fn op_auth_output_idx(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpAuthOutputIdx)
    }
}

impl<S, M> TypedScriptBuilder<Num<S>, M> {
    /// Output is polymorphic (Hash or false at runtime), typed as Data.
    pub fn op_input_covenant_id(self) -> TypedScriptBuilder<Data<S>, M> {
        self.emit_op(OpInputCovenantId)
    }
}

impl<S, M> TypedScriptBuilder<Hash<S>, M> {
    pub fn op_cov_input_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovInputCount)
    }
    pub fn op_cov_out_count(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovOutCount)
    }
}

impl<S, M> TypedScriptBuilder<Num<Hash<S>>, M> {
    pub fn op_cov_input_idx(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovInputIdx)
    }
    pub fn op_cov_output_idx(self) -> TypedScriptBuilder<Num<S>, M> {
        self.emit_op(OpCovOutputIdx)
    }
}

// ---------------------------------------------------------------------------
// SeqCommit
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Hash<S>, M> {
    /// Pops block hash, pushes commitment hash.
    pub fn op_chainblock_seq_commit(self) -> TypedScriptBuilder<Hash<S>, M> {
        self.emit_op(OpChainblockSeqCommit)
    }
}

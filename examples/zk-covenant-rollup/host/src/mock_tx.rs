use kaspa_consensus_core::{
    hashing::tx::{payload_digest, transaction_v1_rest_preimage},
    subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE},
    tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput},
};
use zk_covenant_rollup_core::{
    action::{ActionHeader, EntryAction, ExitAction, TransferAction, OP_ENTRY, OP_EXIT, OP_TRANSFER},
    bytes_to_words_ref,
    prev_tx::PrevTxV1Witness,
    state::AccountWitness,
    AlignedBytes, ROLLUP_SUBNETWORK_ID,
};

/// The rollup's subnetwork ID as a consensus SubnetworkId type.
fn rollup_subnet() -> SubnetworkId {
    SubnetworkId::from_bytes(ROLLUP_SUBNETWORK_ID)
}

/// Transfer payload with header (for computing tx_id)
#[derive(Clone, Copy, Debug)]
pub struct TransferPayload {
    pub header: ActionHeader,
    pub transfer: TransferAction,
}

impl TransferPayload {
    /// Create a new transfer payload
    pub fn new(source: [u32; 8], destination: [u32; 8], amount: u64, nonce: u32) -> Self {
        Self { header: ActionHeader::new(OP_TRANSFER, nonce), transfer: TransferAction::new(source, destination, amount) }
    }

    /// Get as words for hashing
    pub fn as_words(&self) -> Vec<u32> {
        let mut words = Vec::with_capacity(ActionHeader::WORDS + TransferAction::WORDS);
        words.extend_from_slice(self.header.as_words());
        words.extend_from_slice(self.transfer.as_words());
        words
    }

    /// Get as bytes for payload field
    pub fn as_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice(&self.as_words()).to_vec()
    }
}

/// Entry (deposit) payload with header (for computing tx_id)
#[derive(Clone, Copy, Debug)]
pub struct EntryPayload {
    pub header: ActionHeader,
    pub entry: EntryAction,
}

impl EntryPayload {
    /// Create a new entry payload
    pub fn new(destination: [u32; 8], nonce: u32) -> Self {
        Self { header: ActionHeader::new(OP_ENTRY, nonce), entry: EntryAction::new(destination) }
    }

    /// Get as words for hashing
    pub fn as_words(&self) -> Vec<u32> {
        let mut words = Vec::with_capacity(ActionHeader::WORDS + EntryAction::WORDS);
        words.extend_from_slice(self.header.as_words());
        words.extend_from_slice(self.entry.as_words());
        words
    }

    /// Get as bytes for payload field
    pub fn as_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice(&self.as_words()).to_vec()
    }
}

/// Exit (withdrawal) payload with header (for computing tx_id)
#[derive(Clone, Debug)]
pub struct ExitPayload {
    pub header: ActionHeader,
    pub exit: ExitAction,
}

impl ExitPayload {
    /// Create a new exit payload
    pub fn new(source: [u32; 8], destination_spk: &[u8], amount: u64, nonce: u32) -> Self {
        Self { header: ActionHeader::new(OP_EXIT, nonce), exit: ExitAction::new(source, destination_spk, amount) }
    }

    /// Get as words for hashing
    pub fn as_words(&self) -> Vec<u32> {
        let mut words = Vec::with_capacity(ActionHeader::WORDS + ExitAction::WORDS);
        words.extend_from_slice(self.header.as_words());
        words.extend_from_slice(self.exit.as_words());
        words
    }

    /// Get as bytes for payload field
    pub fn as_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice(&self.as_words()).to_vec()
    }
}

/// Witness data for transfer actions.
///
/// Always includes `source` (for the balance check).
/// `rest` is `Some` only when the source balance is sufficient —
/// the guest reads auth + dest conditionally.
#[derive(Clone, Debug)]
pub struct TransferWitnessData {
    /// Source account witness (always provided)
    pub source: AccountWitness,
    /// Auth + dest witness (only when balance sufficient)
    pub rest: Option<TransferWitnessRest>,
}

/// Auth + destination witness for a transfer (written only when balance is sufficient).
#[derive(Clone, Debug)]
pub struct TransferWitnessRest {
    /// Destination account witness
    pub dest: AccountWitness,
    /// Previous transaction (the UTXO being spent)
    pub prev_tx: Transaction,
    /// Output index in the previous transaction
    pub prev_output_index: u32,
}

/// Witness data for entry (deposit) actions.
/// Deposit amount is always taken from output index 0.
/// rest_preimage is no longer needed here — it comes from V1TxData.
#[derive(Clone, Debug)]
pub struct EntryWitnessData {
    /// Destination account witness
    pub dest: AccountWitness,
}

/// Witness data for exit (withdrawal) actions.
///
/// Always includes `source` (for the balance check).
/// `rest` is `Some` only when the source balance is sufficient —
/// the guest reads auth conditionally.
#[derive(Clone, Debug)]
pub struct ExitWitnessData {
    /// Source account witness (always provided)
    pub source: AccountWitness,
    /// Auth witness (only when balance sufficient)
    pub rest: Option<ExitWitnessRest>,
}

/// Auth witness for an exit (written only when balance is sufficient).
#[derive(Clone, Debug)]
pub struct ExitWitnessRest {
    /// Previous transaction (the UTXO being spent, proves source ownership)
    pub prev_tx: Transaction,
    /// Output index in the previous transaction
    pub prev_output_index: u32,
}

/// Witness data for action transactions (discriminated by action type)
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ActionWitness {
    Transfer(Box<TransferWitnessData>),
    Entry(EntryWitnessData),
    Exit(Box<ExitWitnessData>),
}

/// Transaction wrapper that combines a real Kaspa Transaction with ZK witness data
#[derive(Clone, Debug)]
pub struct ZkTransaction {
    /// The real Kaspa transaction
    pub tx: Transaction,
    /// Optional witness data for action transactions
    pub witness: Option<ActionWitness>,
}

impl ZkTransaction {
    /// Create a new ZkTransaction
    pub fn new(tx: Transaction, witness: Option<ActionWitness>) -> Self {
        Self { tx, witness }
    }

    /// Get the transaction version
    pub fn version(&self) -> u16 {
        self.tx.version
    }

    /// Get the transaction ID as [u32; 8]
    pub fn tx_id(&self) -> [u32; 8] {
        bytes_to_words_ref(&self.tx.id().as_bytes())
    }

    /// Write to executor env in the format expected by guest
    pub fn write_to_env(&self, builder: &mut risc0_zkvm::ExecutorEnvBuilder<'_>) {
        builder.write_slice(&(self.version() as u32).to_le_bytes());

        if self.tx.version == 0 {
            // V0: just write tx_id
            let tx_id = self.tx_id();
            builder.write_slice(bytemuck::cast_slice::<_, u8>(&tx_id));
            return;
        }

        // V1+: write payload, rest_preimage, and witness data
        {
            // V1: write payload, rest_preimage (length-prefixed), and witness data if action tx
            let payload_bytes = &self.tx.payload;
            builder.write_slice(&(payload_bytes.len() as u32).to_le_bytes());
            if !payload_bytes.is_empty() {
                // Pad to word boundary
                let padded_len = payload_bytes.len().div_ceil(4) * 4;
                let mut padded = vec![0u8; padded_len];
                padded[..payload_bytes.len()].copy_from_slice(payload_bytes);
                builder.write_slice(&padded);
            }

            // Write full rest_preimage (length-prefixed) — guest computes rest_digest from it
            let rest_preimage = transaction_v1_rest_preimage(&self.tx);
            write_bytes(builder, &rest_preimage);

            // All lane txs are potential actions — check payload to determine if witness needed
            {
                let payload_words: Vec<u32> =
                    payload_bytes.chunks_exact(4).map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap())).collect();

                match &self.witness {
                    Some(ActionWitness::Transfer(w)) if is_valid_transfer_payload(&payload_words) => {
                        // Always write source witness
                        builder.write_slice(w.source.as_bytes());
                        // Conditionally write auth + dest (only when balance sufficient)
                        if let Some(rest) = &w.rest {
                            let prev_tx_witness = create_prev_tx_v1_witness(&rest.prev_tx, rest.prev_output_index);
                            write_prev_tx_v1_witness(builder, &prev_tx_witness);
                            builder.write_slice(rest.dest.as_bytes());
                        }
                    }
                    Some(ActionWitness::Entry(w)) if is_valid_entry_payload(&payload_words) => {
                        // Write entry witness: dest account only
                        // (rest_preimage is already sent above for all V1 txs)
                        builder.write_slice(w.dest.as_bytes());
                    }
                    Some(ActionWitness::Exit(w)) if is_valid_exit_payload(&payload_words) => {
                        // Always write source witness
                        builder.write_slice(w.source.as_bytes());
                        // Conditionally write auth (only when balance sufficient)
                        if let Some(rest) = &w.rest {
                            let prev_tx_witness = create_prev_tx_v1_witness(&rest.prev_tx, rest.prev_output_index);
                            write_prev_tx_v1_witness(builder, &prev_tx_witness);
                        }
                    }
                    _ => {
                        // Panic only if this is a *known* action type — the host must always
                        // supply a witness for Transfer/Entry/Exit.  A tx with an unrecognised
                        // opcode simply gets no witness written (guest skips it).
                        let action_type = if is_valid_transfer_payload(&payload_words) {
                            Some("Transfer")
                        } else if is_valid_entry_payload(&payload_words) {
                            Some("Entry")
                        } else if is_valid_exit_payload(&payload_words) {
                            Some("Exit")
                        } else {
                            None
                        };
                        if let Some(action_type) = action_type {
                            let tx_hash = self.tx.id();
                            let prev_info = self.tx.inputs.first().map_or_else(
                                || "no inputs".to_string(),
                                |inp| {
                                    format!(
                                        "needs prev_tx={} output_idx={}",
                                        inp.previous_outpoint.transaction_id, inp.previous_outpoint.index
                                    )
                                },
                            );
                            let witness_desc = match &self.witness {
                                None => "witness=None (prev_tx not found in DB)",
                                Some(ActionWitness::Transfer(_)) => "wrong type: have Transfer",
                                Some(ActionWitness::Entry(_)) => "wrong type: have Entry",
                                Some(ActionWitness::Exit(_)) => "wrong type: have Exit",
                            };
                            panic!("host has no witness for {} action tx {} | {} | {}", action_type, tx_hash, prev_info, witness_desc);
                        }
                        // Unknown opcode — write nothing; guest will skip.
                    }
                }
            }
        }
    }
}

/// Check if payload words represent a valid transfer payload
fn is_valid_transfer_payload(payload_words: &[u32]) -> bool {
    if payload_words.len() < ActionHeader::WORDS + TransferAction::WORDS {
        return false;
    }
    let header = ActionHeader::from_words_ref(payload_words[..ActionHeader::WORDS].try_into().unwrap());
    if !header.is_valid_version() || header.operation != OP_TRANSFER {
        return false;
    }
    let transfer = TransferAction::from_words(payload_words[ActionHeader::WORDS..][..TransferAction::WORDS].try_into().unwrap());
    transfer.is_valid()
}

/// Check if payload words represent a valid entry payload
fn is_valid_entry_payload(payload_words: &[u32]) -> bool {
    if payload_words.len() < ActionHeader::WORDS + EntryAction::WORDS {
        return false;
    }
    let header = ActionHeader::from_words_ref(payload_words[..ActionHeader::WORDS].try_into().unwrap());
    if !header.is_valid_version() || header.operation != OP_ENTRY {
        return false;
    }
    let entry = EntryAction::from_words(payload_words[ActionHeader::WORDS..][..EntryAction::WORDS].try_into().unwrap());
    entry.is_valid()
}

/// Create a PrevTxV1Witness from a real Transaction
fn create_prev_tx_v1_witness(prev_tx: &Transaction, output_index: u32) -> PrevTxV1Witness {
    assert!(prev_tx.version >= 1, "PrevTxV1Witness requires V1+ transaction");

    let rest_preimage = transaction_v1_rest_preimage(prev_tx);
    let pd = payload_digest(&prev_tx.payload);
    let payload_digest_words = bytes_to_words_ref(&pd.as_bytes());

    PrevTxV1Witness::new(output_index, AlignedBytes::from_bytes(&rest_preimage), payload_digest_words)
}

/// Write PrevTxV1Witness to executor env.
///
/// Does NOT write prev_tx_id or output_index — the guest derives those from
/// the current action tx's first input outpoint (committed in rest_preimage).
fn write_prev_tx_v1_witness(builder: &mut risc0_zkvm::ExecutorEnvBuilder<'_>, witness: &PrevTxV1Witness) {
    // Write rest_preimage with length prefix
    write_bytes(builder, witness.rest_preimage.as_bytes());

    // Write payload_digest (fixed 32 bytes, no length prefix needed)
    builder.write_slice(bytemuck::cast_slice::<_, u8>(&witness.payload_digest));
}

/// Write length-prefixed bytes to executor env (u64 len + word-padded data).
pub fn write_bytes(builder: &mut risc0_zkvm::ExecutorEnvBuilder<'_>, data: &[u8]) {
    // Write length as u64
    builder.write_slice(&(data.len() as u64).to_le_bytes());

    if !data.is_empty() {
        // Pad to word boundary
        let padded_len = data.len().div_ceil(4) * 4;
        let mut padded = vec![0u8; padded_len];
        padded[..data.len()].copy_from_slice(data);
        builder.write_slice(&padded);
    }
}

/// Check if payload words represent a valid exit payload
fn is_valid_exit_payload(payload_words: &[u32]) -> bool {
    if payload_words.len() < ActionHeader::WORDS + ExitAction::WORDS {
        return false;
    }
    let header = ActionHeader::from_words_ref(payload_words[..ActionHeader::WORDS].try_into().unwrap());
    if !header.is_valid_version() || header.operation != OP_EXIT {
        return false;
    }
    let exit = ExitAction::from_words(payload_words[ActionHeader::WORDS..][..ExitAction::WORDS].try_into().unwrap());
    exit.is_valid()
}

/// Create a V1 exit (withdrawal) action transaction with witness data.
pub fn create_exit_tx(
    source: [u32; 8],
    destination_spk: &[u8],
    amount: u64,
    outputs: Vec<TransactionOutput>,
    source_witness: AccountWitness,
    prev_tx: Transaction,
    prev_output_index: u32,
) -> ZkTransaction {
    let input =
        TransactionInput::new_with_compute_budget(TransactionOutpoint::new(prev_tx.id(), prev_output_index), vec![], 0, 0);

    let payload = ExitPayload::new(source, destination_spk, amount, 0);

    let tx = Transaction::new(1, vec![input], outputs, 0, rollup_subnet(), 0, payload.as_bytes());

    ZkTransaction::new(
        tx,
        Some(ActionWitness::Exit(Box::new(ExitWitnessData {
            source: source_witness,
            rest: Some(ExitWitnessRest { prev_tx, prev_output_index }),
        }))),
    )
}

/// Create a V1 exit action transaction where the source has insufficient balance.
/// The witness has `rest: None` — the guest reads source, sees insufficient balance, and skips.
pub fn create_exit_tx_insufficient(
    source: [u32; 8],
    destination_spk: &[u8],
    amount: u64,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    source_witness: AccountWitness,
) -> ZkTransaction {
    let payload = ExitPayload::new(source, destination_spk, amount, 0);

    let tx = Transaction::new(1, inputs, outputs, 0, rollup_subnet(), 0, payload.as_bytes());

    ZkTransaction::new(tx, Some(ActionWitness::Exit(Box::new(ExitWitnessData { source: source_witness, rest: None }))))
}

/// Create a "previous transaction" for use as UTXO source.
/// This creates a V1 transaction with a single output containing the given SPK.
pub fn create_prev_tx(output_value: u64, output_spk: ScriptPublicKey) -> Transaction {
    Transaction::new(
        1,
        vec![], // No inputs needed for prev tx in testing
        vec![TransactionOutput::new(output_value, output_spk)],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![], // Empty payload for prev tx
    )
}

/// Create a V1 transfer action transaction with witness data
pub fn create_transfer_tx(
    source: [u32; 8],
    destination: [u32; 8],
    amount: u64,
    outputs: Vec<TransactionOutput>,
    source_witness: AccountWitness,
    dest_witness: AccountWitness,
    prev_tx: Transaction,
    prev_output_index: u32,
) -> ZkTransaction {
    let input =
        TransactionInput::new_with_compute_budget(TransactionOutpoint::new(prev_tx.id(), prev_output_index), vec![], 0, 0);

    // Find nonce that makes tx_id an action (with the correct input)
    let payload = TransferPayload::new(source, destination, amount, 0);

    // Create the actual transaction
    let tx = Transaction::new(1, vec![input], outputs, 0, rollup_subnet(), 0, payload.as_bytes());

    ZkTransaction::new(
        tx,
        Some(ActionWitness::Transfer(Box::new(TransferWitnessData {
            source: source_witness,
            rest: Some(TransferWitnessRest { dest: dest_witness, prev_tx, prev_output_index }),
        }))),
    )
}

/// Create a V1 entry (deposit) action transaction with witness data.
/// The deposit amount is always taken from output index 0.
pub fn create_entry_tx(destination: [u32; 8], outputs: Vec<TransactionOutput>, dest_witness: AccountWitness) -> ZkTransaction {
    // Entry txs don't need a specific prev tx input for authorization
    let payload = EntryPayload::new(destination, 0);

    // Create the actual transaction
    let tx = Transaction::new(1, vec![], outputs, 0, rollup_subnet(), 0, payload.as_bytes());

    ZkTransaction::new(tx, Some(ActionWitness::Entry(EntryWitnessData { dest: dest_witness })))
}

/// Create a V1 transaction that is NOT an action (tx_id doesn't start with action prefix).
/// This tests that the guest correctly ignores non-action V1 transactions.
pub fn create_v1_non_action_tx() -> ZkTransaction {
    // Create a simple V1 tx with arbitrary payload that won't have action prefix
    // Using empty payload ensures it won't be detected as action
    let tx = Transaction::new(
        1,
        vec![],
        vec![TransactionOutput::new(100, ScriptPublicKey::new(0, vec![0u8; 34].into()))],
        0,
        rollup_subnet(),
        0,
        vec![], // Empty payload - not an action
    );

    ZkTransaction::new(tx, None)
}

/// Create a V1 transaction with UNKNOWN operation code.
/// Tests that the guest correctly ignores unknown action types.
pub fn create_unknown_action_tx() -> ZkTransaction {
    const UNKNOWN_OP: u16 = 0xFFFF;

    let outputs = vec![TransactionOutput::new(100, ScriptPublicKey::new(0, vec![0u8; 34].into()))];
    let header = ActionHeader { version: zk_covenant_rollup_core::action::ACTION_VERSION, operation: UNKNOWN_OP, nonce: 0 };
    let payload_bytes: Vec<u8> = bytemuck::cast_slice(header.as_words()).to_vec();
    let tx = Transaction::new(1, vec![], outputs, 0, rollup_subnet(), 0, payload_bytes);
    ZkTransaction::new(tx, None)
}

/// A transaction that is **not** part of any rollup lane.
/// Uses `SUBNETWORK_ID_NATIVE` and a varying `lock_time` so each call yields
/// a distinct tx_id. The mock chain inserts these alongside rollup txs to
/// exercise sparse `merge_idx` values (host filters by subnetwork before
/// sending lane txs to the guest).
pub fn create_unrelated_tx(nonce: u64) -> ZkTransaction {
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(kaspa_hashes::Hash::from_u64_word(nonce), 0),
            vec![],
            0,
            0,
        )],
        vec![TransactionOutput::new(1, ScriptPublicKey::new(0, vec![0u8; 34].into()))],
        nonce,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    ZkTransaction::new(tx, None)
}

/// Return the indices of transactions that belong to the rollup lane
/// (filtered by subnetwork id). The caller uses these as the real `merge_idx`
/// values passed to the guest — non-lane txs never enter the zkVM, but their
/// positions in the full block tx list are preserved by the surviving indices.
pub fn rollup_lane_indices(txs: &[ZkTransaction]) -> Vec<u32> {
    let rollup = rollup_subnet();
    txs.iter().enumerate().filter_map(|(i, t)| (t.tx.subnetwork_id == rollup).then_some(i as u32)).collect()
}

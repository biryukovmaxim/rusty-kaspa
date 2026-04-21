use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
use kaspa_hashes::Hash;
use kaspa_rpc_core::GetVirtualChainFromBlockV2Response;
use kaspa_seq_commit::hashing::mergeset_context_hash;
use kaspa_seq_commit::types::MergesetContext;
use std::sync::Arc;
use zk_covenant_rollup_core::permission_tree::required_depth;
use zk_covenant_rollup_core::seq_commit::{from_hash, CommitmentWitness};
use zk_covenant_rollup_core::PublicInput;
use zk_covenant_rollup_core::{
    action::{ActionHeader, EntryAction, ExitAction, TransferAction, OP_ENTRY, OP_EXIT, OP_TRANSFER},
    extract_pubkey_from_spk, is_p2pk_spk, perm_leaf_hash,
    permission_tree::StreamingPermTreeBuilder,
    smt::Smt,
    state::{AccountWitness, StateRoot},
};
use zk_covenant_rollup_host::mock_chain::from_bytes;
use zk_covenant_rollup_host::mock_tx::{
    rollup_lane_indices, ActionWitness, EntryWitnessData, ExitWitnessData, ExitWitnessRest, TransferWitnessData, TransferWitnessRest,
    ZkTransaction,
};
use zk_covenant_rollup_host::prove::ProveInput;

use crate::db::RollupDb;

/// State saved before a proof attempt so it can be restored if the proof fails.
struct RollbackState {
    accumulated_block_txs: Vec<Vec<ZkTransaction>>,
    accumulated_block_lane_indices: Vec<Vec<u32>>,
    accumulated_block_context_hashes: Vec<[u32; 8]>,
    accumulated_exit_data: Vec<(Vec<u8>, u64)>,
    prev_proved_state_root: StateRoot,
    prev_proved_lane_tip: Hash,
    prev_processed_block_timestamp: u64,
}

/// Host-side witness for the final block of a proving window.
///
/// Populated out-of-band via [`RollupProver::set_lane_proof`] by calling the
/// `get_seq_commit_lane_proof` RPC. Without it the prover cannot build a
/// complete [`ProveInput`], so [`RollupProver::take_prove_snapshot`] will
/// return `None`.
#[derive(Clone, Debug)]
pub struct LaneProofWitness {
    pub witness: CommitmentWitness,
    pub smt_proof_bytes: Vec<u8>,
}

/// Tracks L2 state and processes chain data for proving.
pub struct RollupProver {
    /// Sparse Merkle Tree holding account balances.
    pub smt: Smt,
    /// Current state root ([u32; 8]).
    pub state_root: StateRoot,
    /// Current sequence commitment (Hash).
    pub lane_tip: Hash,
    /// Covenant ID as [u32; 8] (for host crate compatibility).
    pub covenant_id: [u32; 8],
    /// Covenant ID as bytes.
    pub covenant_id_bytes: [u8; 32],
    /// Hash of the last block we have processed.
    pub last_processed_block: Hash,
    /// Permission tree builder for exits — mirrors accumulated_perm_builder within a window.
    /// Shown in UI as "Exit leaves"; reset together with accumulated_perm_builder on snapshot.
    pub perm_builder: StreamingPermTreeBuilder,
    /// Persistent tx store: transactions whose outputs pay to known L2 accounts.
    /// Keyed by tx hash so process_transfer/process_exit can retrieve the actual prev_tx.
    /// Temporary — will be removed when lane_tip commits spk+amount of UTXO input.
    db: Arc<RollupDb>,
    /// All ZkTransactions from the last processing run (grouped by block).
    pub last_block_txs: Vec<Vec<ZkTransaction>>,

    // ── Proving accumulator ──
    // These track ALL data since the last proof, so we can snapshot and prove.
    /// State root at the start of the current proving window.
    pub prev_proved_state_root: StateRoot,
    /// Sequence commitment at the start of the current proving window.
    pub prev_proved_lane_tip: Hash,
    /// All block txs accumulated since the last proof.
    pub accumulated_block_txs: Vec<Vec<ZkTransaction>>,
    /// Per-block rollup-lane `merge_idx` values (positions of lane txs inside
    /// each block's `accumulated_block_txs[i]`).
    pub accumulated_block_lane_indices: Vec<Vec<u32>>,
    /// Per-block `mergeset_context_hash` (`H_mergeset_context(ts, daa, blue)`)
    /// computed from block headers in `process_chain_response`.
    pub accumulated_block_context_hashes: Vec<[u32; 8]>,
    /// Permission tree builder for the current proving window (for exits).
    pub accumulated_perm_builder: StreamingPermTreeBuilder,
    /// (spk_bytes, amount) for each exit in the current proving window.
    pub accumulated_exit_data: Vec<(Vec<u8>, u64)>,
    /// Timestamp of the most recently processed chain block — used as
    /// `selected_parent_timestamp` for the next block's context hash
    /// (per `kaspa_seq_commit::hashing::seq_commit_timestamp`).
    pub last_processed_block_timestamp: u64,

    /// Host witness for the LAST block of the current proving window.
    /// Set by the RPC layer via [`set_lane_proof`] before calling
    /// [`take_prove_snapshot`].
    pub pending_lane_proof: Option<LaneProofWitness>,

    /// Snapshot saved before the last proof attempt; used to roll back on failure.
    pending_rollback: Option<RollbackState>,
}

/// Data returned by `take_prove_snapshot`, combining the prove input
/// with the permission redeem script (if exits occurred in this batch).
pub struct ProveSnapshot {
    pub input: ProveInput,
    /// Full permission redeem script bytes (only when exits occurred).
    pub perm_redeem_script: Option<Vec<u8>>,
    /// (spk_bytes, amount) for each exit in the proving window (empty if none).
    pub perm_exit_data: Vec<(Vec<u8>, u64)>,
}

/// Reason [`RollupProver::take_prove_snapshot`] returned `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProveSnapshotSkipReason {
    /// No blocks have accumulated since the last proof.
    NoAccumulatedBlocks,
    /// Blocks accumulated but the lane proof witness hasn't been fetched yet.
    /// Call [`RollupProver::set_lane_proof`] after `get_seq_commit_lane_proof`.
    MissingLaneProof,
}

/// Result of processing a VCC v2 response.
pub struct ProcessResult {
    pub blocks_processed: usize,
    pub txs_processed: usize,
    pub actions_found: usize,
    pub new_state_root: StateRoot,
    pub new_lane_tip: Hash,
}

impl RollupProver {
    pub fn new(
        covenant_id: Hash,
        initial_state_root: StateRoot,
        initial_lane_tip: Hash,
        starting_block: Hash,
        starting_block_timestamp: u64,
        db: Arc<RollupDb>,
    ) -> Self {
        let covenant_id_words = from_bytes(covenant_id.as_bytes());
        Self {
            smt: Smt::new(),
            state_root: initial_state_root,
            lane_tip: initial_lane_tip,
            covenant_id: covenant_id_words,
            covenant_id_bytes: covenant_id.as_bytes(),
            last_processed_block: starting_block,
            perm_builder: StreamingPermTreeBuilder::new(),
            db,
            last_block_txs: Vec::new(),
            prev_proved_state_root: initial_state_root,
            prev_proved_lane_tip: initial_lane_tip,
            accumulated_block_txs: Vec::new(),
            accumulated_block_lane_indices: Vec::new(),
            accumulated_block_context_hashes: Vec::new(),
            accumulated_perm_builder: StreamingPermTreeBuilder::new(),
            accumulated_exit_data: Vec::new(),
            last_processed_block_timestamp: starting_block_timestamp,
            pending_lane_proof: None,
            pending_rollback: None,
        }
    }

    /// Set the host-side lane-proof witness obtained from the
    /// `get_seq_commit_lane_proof` RPC for the hash stored in
    /// [`Self::last_processed_block`]. Must be called before
    /// [`Self::take_prove_snapshot`].
    pub fn set_lane_proof(&mut self, witness: CommitmentWitness, smt_proof_bytes: Vec<u8>) {
        self.pending_lane_proof = Some(LaneProofWitness { witness, smt_proof_bytes });
    }

    /// Clear the pending lane-proof witness. Should be called when the
    /// accumulator grows past the block the witness was fetched for.
    pub fn clear_lane_proof(&mut self) {
        self.pending_lane_proof = None;
    }

    /// Number of blocks accumulated since the last proof.
    pub fn accumulated_blocks(&self) -> usize {
        self.accumulated_block_txs.len()
    }

    /// Take a snapshot of the accumulated data for proving, then reset the
    /// accumulator so new chain data can continue flowing in.
    ///
    /// The previous accumulator state is saved internally. Call `commit_prove_window()`
    /// after a successful proof, or `rollback_prove_window()` after a failure, to restore it.
    ///
    /// Returns `None` if there are no blocks to prove.
    pub fn take_prove_snapshot(&mut self) -> Option<ProveSnapshot> {
        self.try_take_prove_snapshot().ok()
    }

    /// Like [`take_prove_snapshot`] but returns the specific skip reason on failure.
    pub fn try_take_prove_snapshot(&mut self) -> Result<ProveSnapshot, ProveSnapshotSkipReason> {
        if self.accumulated_block_txs.is_empty() {
            return Err(ProveSnapshotSkipReason::NoAccumulatedBlocks);
        }
        let lane_proof = self.pending_lane_proof.take().ok_or(ProveSnapshotSkipReason::MissingLaneProof)?;

        // Save rollback state before consuming anything.
        self.pending_rollback = Some(RollbackState {
            accumulated_block_txs: self.accumulated_block_txs.clone(),
            accumulated_block_lane_indices: self.accumulated_block_lane_indices.clone(),
            accumulated_block_context_hashes: self.accumulated_block_context_hashes.clone(),
            accumulated_exit_data: self.accumulated_exit_data.clone(),
            prev_proved_state_root: self.prev_proved_state_root,
            prev_proved_lane_tip: self.prev_proved_lane_tip,
            prev_processed_block_timestamp: self.last_processed_block_timestamp,
        });

        let public_input = PublicInput {
            prev_state_hash: self.prev_proved_state_root,
            prev_lane_tip: from_bytes(self.prev_proved_lane_tip.as_bytes()),
            covenant_id: self.covenant_id,
        };

        let block_txs = std::mem::take(&mut self.accumulated_block_txs);
        let block_lane_indices = std::mem::take(&mut self.accumulated_block_lane_indices);
        let block_context_hashes = std::mem::take(&mut self.accumulated_block_context_hashes);

        // Take the accumulated perm builder (replace with fresh one)
        let old_perm_builder = std::mem::replace(&mut self.accumulated_perm_builder, StreamingPermTreeBuilder::new());
        let perm_count = old_perm_builder.leaf_count();
        let (perm_redeem_script_len, perm_redeem_script) = if perm_count > 0 {
            let perm_root = old_perm_builder.finalize();
            let depth = required_depth(perm_count as usize);
            let padded_root = zk_covenant_rollup_core::permission_tree::pad_to_depth(perm_root, perm_count, depth);
            let redeem = zk_covenant_rollup_core::permission_script::build_permission_redeem_bytes_converged(
                &padded_root,
                perm_count as u64,
                depth,
                zk_covenant_rollup_core::MAX_DELEGATE_INPUTS,
            );
            let len = Some(redeem.len() as i64);
            (len, Some(redeem))
        } else {
            (None, None)
        };

        // Take exit data for this proving window
        let perm_exit_data = std::mem::take(&mut self.accumulated_exit_data);

        // Reset per-window perm_builder (shown in UI) so its count stays in sync.
        self.perm_builder = StreamingPermTreeBuilder::new();

        // Advance the proving window start to current state
        self.prev_proved_state_root = self.state_root;
        self.prev_proved_lane_tip = self.lane_tip;

        Ok(ProveSnapshot {
            input: ProveInput {
                public_input,
                block_txs,
                block_lane_indices,
                block_context_hashes,
                commitment_witness: lane_proof.witness,
                smt_proof_bytes: lane_proof.smt_proof_bytes,
                perm_redeem_script_len,
            },
            perm_redeem_script,
            perm_exit_data,
        })
    }

    /// Call after a successful proof. Drops the saved rollback state.
    pub fn commit_prove_window(&mut self) {
        self.pending_rollback = None;
    }

    /// Call after a failed proof. Restores accumulated blocks, exit data, and perm trees
    /// to what they were before `take_prove_snapshot()`, so the window can be retried.
    pub fn rollback_prove_window(&mut self) {
        let rb = match self.pending_rollback.take() {
            Some(rb) => rb,
            None => return,
        };
        self.accumulated_block_txs = rb.accumulated_block_txs;
        self.accumulated_block_lane_indices = rb.accumulated_block_lane_indices;
        self.accumulated_block_context_hashes = rb.accumulated_block_context_hashes;
        self.accumulated_exit_data = rb.accumulated_exit_data.clone();
        self.prev_proved_state_root = rb.prev_proved_state_root;
        self.prev_proved_lane_tip = rb.prev_proved_lane_tip;
        self.last_processed_block_timestamp = rb.prev_processed_block_timestamp;
        // Invalidate any pending lane-proof witness — it covered the post-rollback window.
        self.pending_lane_proof = None;

        // Reconstruct both perm builders from the saved exit data.
        let mut acc = StreamingPermTreeBuilder::new();
        let mut per_window = StreamingPermTreeBuilder::new();
        for (spk_bytes, amount) in &rb.accumulated_exit_data {
            let leaf = perm_leaf_hash(spk_bytes, *amount);
            acc.add_leaf(leaf);
            per_window.add_leaf(leaf);
        }
        self.accumulated_perm_builder = acc;
        self.perm_builder = per_window;
    }

    /// Process a VCC v2 response, converting RPC transactions to ZkTransactions
    /// and updating the L2 state (SMT + lane_tip).
    pub fn process_chain_response(&mut self, response: &GetVirtualChainFromBlockV2Response) -> ProcessResult {
        let mut blocks_processed = 0;
        let mut txs_processed = 0;
        let mut actions_found = 0;

        self.last_block_txs.clear();

        for (block_idx, block) in response.chain_block_accepted_transactions.iter().enumerate() {
            let mut zk_txs = Vec::new();

            for rpc_tx in &block.accepted_transactions {
                // Try to convert the optional RPC transaction to a consensus Transaction
                let tx = match rpc_optional_to_transaction(rpc_tx) {
                    Some(tx) => tx,
                    None => continue,
                };

                let version = tx.version;

                // All rollup lane txs are V1 and potential actions (payload-based detection)
                let witness = if version == 1 {
                    actions_found += 1;
                    self.build_action_witness(&tx)
                } else {
                    None
                };

                // Scan outputs: persist txs that pay to known L2 accounts so they can later
                // be retrieved as auth witnesses for transfer/exit actions.
                let cov_hash = Hash::from_bytes(self.covenant_id_bytes);
                let has_matching_output = tx.outputs.iter().any(|out| {
                    let spk = out.script_public_key.script();
                    if !is_p2pk_spk(spk) {
                        return false;
                    }
                    if let Some(pk_words) = extract_pubkey_from_spk(spk) {
                        self.smt.get(&pk_words).is_some()
                    } else {
                        false
                    }
                });
                if has_matching_output {
                    let tx_hash = tx.id();
                    if let Err(e) = self.db.put_prev_tx(cov_hash, tx_hash, &tx) {
                        // Non-fatal: log and continue; proof will fail later if this tx is needed
                        eprintln!("[prover] failed to persist prev_tx {tx_hash}: {e}");
                    }
                }

                zk_txs.push(ZkTransaction { tx, witness });
                txs_processed += 1;
            }

            // Read lane_tip from block header (no need to compute — OpSeqCommit reads it on-chain)
            if let Some(air) = block.chain_block_header.accepted_id_merkle_root {
                self.lane_tip = air;
            }

            // Update last processed block hash
            if block_idx < response.added_chain_block_hashes.len() {
                self.last_processed_block = response.added_chain_block_hashes[block_idx];
            }

            // Per-block context hash: `H_mergeset_context(ts, daa, blue)`.
            // Timestamp is the selected parent's per `seq_commit_timestamp` — i.e. the
            // timestamp of the block we just finished processing (or
            // `last_processed_block_timestamp` for the first block of a sync batch).
            let daa_score = block.chain_block_header.daa_score.unwrap_or(0);
            let blue_score = block.chain_block_header.blue_score.unwrap_or(0);
            let ctx = MergesetContext { timestamp: self.last_processed_block_timestamp, daa_score, blue_score };
            let ctx_hash_words = from_hash(mergeset_context_hash(&ctx));

            // Lane indices: positions of rollup-lane txs in zk_txs.
            let lane_indices = rollup_lane_indices(&zk_txs);

            // Advance timestamp pointer for the next block's context hash.
            if let Some(ts) = block.chain_block_header.timestamp {
                self.last_processed_block_timestamp = ts;
            }

            // Also accumulate for proving (clone into the proving window)
            self.accumulated_block_txs.push(zk_txs.clone());
            self.accumulated_block_lane_indices.push(lane_indices);
            self.accumulated_block_context_hashes.push(ctx_hash_words);
            self.last_block_txs.push(zk_txs);
            blocks_processed += 1;
        }

        self.state_root = self.smt.root();

        ProcessResult { blocks_processed, txs_processed, actions_found, new_state_root: self.state_root, new_lane_tip: self.lane_tip }
    }

    /// Build an ActionWitness for an action transaction and apply the state transition.
    fn build_action_witness(&mut self, tx: &Transaction) -> Option<ActionWitness> {
        let payload = &tx.payload;
        if payload.len() < 4 {
            return None;
        }

        let payload_words: Vec<u32> = payload.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();

        if payload_words.len() < ActionHeader::WORDS {
            return None;
        }

        let header = ActionHeader::from_words_ref(payload_words[..ActionHeader::WORDS].try_into().unwrap());
        if !header.is_valid_version() {
            return None;
        }

        match header.operation {
            OP_TRANSFER => self.process_transfer(&payload_words, tx),
            OP_ENTRY => self.process_entry(&payload_words, tx),
            OP_EXIT => self.process_exit(&payload_words, tx),
            _ => None,
        }
    }

    fn process_transfer(&mut self, payload_words: &[u32], tx: &Transaction) -> Option<ActionWitness> {
        if payload_words.len() < ActionHeader::WORDS + TransferAction::WORDS {
            return None;
        }

        let action = TransferAction::from_words(payload_words[ActionHeader::WORDS..][..TransferAction::WORDS].try_into().unwrap());
        if !action.is_valid() {
            return None;
        }

        let source_pk = action.source;
        let dest_pk = action.destination;
        let amount = action.amount;

        // Always build source witness (works for both existing and unknown accounts)
        let source_balance = self.smt.get(&source_pk).unwrap_or(0);
        let source_proof = self.smt.prove(&source_pk);
        let source_exists = self.smt.get(&source_pk).is_some();
        let source_witness = if source_exists {
            AccountWitness::new(source_pk, source_balance, source_proof)
        } else {
            AccountWitness::new([0u32; 8], 0, source_proof)
        };

        // If balance insufficient, provide source-only witness (guest reads source, skips rest)
        if source_balance < amount {
            return Some(ActionWitness::Transfer(Box::new(TransferWitnessData { source: source_witness, rest: None })));
        }

        // Balance sufficient — need auth + dest.
        // Look up the actual prev_tx BEFORE modifying any state.
        let first_input = tx.inputs.first().expect("action tx must have at least one input");
        let prev_tx_id = first_input.previous_outpoint.transaction_id;
        let prev_output_index = first_input.previous_outpoint.index;
        let cov_hash = Hash::from_bytes(self.covenant_id_bytes);
        // TODO(covpp-mainnet): prev_tx lookup will be replaced by txindex or by a
        // lane_tip change that commits spk+amount per input. With the 2-byte
        // prefix (~1/65536 collision) and the SMT balance check above, a collision tx
        // reaching this point is extremely unlikely — panicking is acceptable for now.
        let prev_tx = self
            .db
            .get_prev_tx(cov_hash, prev_tx_id)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("prev_tx {} not found in DB for transfer action (source={:?})", prev_tx_id, source_pk));

        // Update source balance (intermediate state)
        let new_source_balance = source_balance - amount;
        self.smt.upsert(source_pk, new_source_balance);

        // Build dest witness from intermediate state
        let dest_balance = self.smt.get(&dest_pk).unwrap_or(0);
        let dest_proof = self.smt.prove(&dest_pk);
        let dest_exists = self.smt.get(&dest_pk).is_some();
        let dest_witness = if dest_exists {
            AccountWitness::new(dest_pk, dest_balance, dest_proof)
        } else {
            AccountWitness::new([0u32; 8], 0, dest_proof)
        };

        // Update dest balance
        let new_dest_balance = dest_balance + amount;
        self.smt.upsert(dest_pk, new_dest_balance);

        Some(ActionWitness::Transfer(Box::new(TransferWitnessData {
            source: source_witness,
            rest: Some(TransferWitnessRest { dest: dest_witness, prev_tx, prev_output_index }),
        })))
    }

    fn process_entry(&mut self, payload_words: &[u32], tx: &Transaction) -> Option<ActionWitness> {
        if payload_words.len() < ActionHeader::WORDS + EntryAction::WORDS {
            return None;
        }

        let action = EntryAction::from_words(payload_words[ActionHeader::WORDS..][..EntryAction::WORDS].try_into().unwrap());

        let dest_pk = action.destination;

        // Get deposit amount from first output value
        let deposit_amount = tx.outputs.first().map(|o| o.value).unwrap_or(0);
        if deposit_amount == 0 {
            return None;
        }

        // Build dest witness
        let dest_exists = self.smt.get(&dest_pk).is_some();
        let dest_balance = self.smt.get(&dest_pk).unwrap_or(0);
        let dest_proof = self.smt.prove(&dest_pk);
        let dest_witness = if dest_exists {
            AccountWitness::new(dest_pk, dest_balance, dest_proof)
        } else {
            AccountWitness::new([0u32; 8], 0, dest_proof)
        };

        // Update dest balance
        let new_balance = dest_balance + deposit_amount;
        self.smt.upsert(dest_pk, new_balance);

        Some(ActionWitness::Entry(EntryWitnessData { dest: dest_witness }))
    }

    fn process_exit(&mut self, payload_words: &[u32], tx: &Transaction) -> Option<ActionWitness> {
        if payload_words.len() < ActionHeader::WORDS + ExitAction::WORDS {
            return None;
        }

        let action = ExitAction::from_words(payload_words[ActionHeader::WORDS..][..ExitAction::WORDS].try_into().unwrap());

        let source_pk = action.source;
        let exit_amount = action.amount;

        // Always build source witness (works for both existing and unknown accounts)
        let source_balance = self.smt.get(&source_pk).unwrap_or(0);
        let source_proof = self.smt.prove(&source_pk);
        let source_exists = self.smt.get(&source_pk).is_some();
        let source_witness = if source_exists {
            AccountWitness::new(source_pk, source_balance, source_proof)
        } else {
            AccountWitness::new([0u32; 8], 0, source_proof)
        };

        // If balance insufficient, provide source-only witness (guest reads source, skips rest)
        if source_balance < exit_amount {
            return Some(ActionWitness::Exit(Box::new(ExitWitnessData { source: source_witness, rest: None })));
        }

        // Balance sufficient — need auth.
        // Look up the actual prev_tx BEFORE modifying any state.
        let first_input = tx.inputs.first().expect("action tx must have at least one input");
        let prev_tx_id = first_input.previous_outpoint.transaction_id;
        let prev_output_index = first_input.previous_outpoint.index;
        let cov_hash = Hash::from_bytes(self.covenant_id_bytes);
        // TODO(covpp-mainnet): prev_tx lookup will be replaced by txindex or by a
        // lane_tip change that commits spk+amount per input. With the 2-byte
        // prefix (~1/65536 collision) and the SMT balance check above, a collision tx
        // reaching this point is extremely unlikely — panicking is acceptable for now.
        let prev_tx = self
            .db
            .get_prev_tx(cov_hash, prev_tx_id)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("prev_tx {} not found in DB for exit action (source={:?})", prev_tx_id, source_pk));

        // Update source balance
        let new_balance = source_balance - exit_amount;
        self.smt.upsert(source_pk, new_balance);

        // Add to permission tree — use action.destination_spk_bytes() which infers
        // the correct SPK length (34 for Schnorr P2PK, 35 for ECDSA/P2SH), matching
        // the guest's perm_leaf_hash(exit.destination_spk_bytes(), exit.amount).
        let dest_spk = action.destination_spk_bytes();
        let leaf = perm_leaf_hash(dest_spk, exit_amount);
        self.perm_builder.add_leaf(leaf);
        self.accumulated_perm_builder.add_leaf(leaf);
        self.accumulated_exit_data.push((dest_spk.to_vec(), exit_amount));

        Some(ActionWitness::Exit(Box::new(ExitWitnessData {
            source: source_witness,
            rest: Some(ExitWitnessRest { prev_tx, prev_output_index }),
        })))
    }
}

/// Convert an RpcOptionalTransaction (from VCCv2 with High verbosity) to a consensus Transaction.
fn rpc_optional_to_transaction(rpc: &kaspa_rpc_core::RpcOptionalTransaction) -> Option<Transaction> {
    let version = rpc.version?;
    let lock_time = rpc.lock_time.unwrap_or(0);
    let subnetwork_id = rpc.subnetwork_id.unwrap_or(SUBNETWORK_ID_NATIVE);
    let gas = rpc.gas.unwrap_or(0);
    let payload = rpc.payload.clone().unwrap_or_default();

    let inputs: Vec<TransactionInput> = rpc
        .inputs
        .iter()
        .filter_map(|inp| {
            let outpoint = inp.previous_outpoint.as_ref()?;
            let tx_id = outpoint.transaction_id?;
            let index = outpoint.index?;
            let previous_outpoint = TransactionOutpoint::new(tx_id, index);
            let signature_script = inp.signature_script.clone().unwrap_or_default();
            let sequence = inp.sequence.unwrap_or(0);
            Some(if kaspa_consensus_core::tx::TxInputMass::version_expects_compute_budget_field(version) {
                TransactionInput::new_with_compute_budget(
                    previous_outpoint,
                    signature_script,
                    sequence,
                    inp.compute_budget.unwrap_or(0),
                )
            } else {
                TransactionInput::new(previous_outpoint, signature_script, sequence, inp.sig_op_count.unwrap_or(0))
            })
        })
        .collect();

    let outputs: Vec<TransactionOutput> = rpc
        .outputs
        .iter()
        .filter_map(|out| {
            let value = out.value?;
            let spk = out.script_public_key.clone()?;
            // V1+ tx_id hash includes `covenant.is_some()` as a boolean; omitting covenant
            // would produce a wrong tx_id for any output that carries a covenant binding.
            let covenant = out.covenant.as_ref().and_then(|n| n.0).map(|c| c.0);
            Some(TransactionOutput::with_covenant(value, spk, covenant))
        })
        .collect();

    Some(Transaction::new(version, inputs, outputs, lock_time, subnetwork_id, gas, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use zk_covenant_rollup_core::state::empty_tree_root;

    fn test_prover(tmp: &TempDir) -> RollupProver {
        let db = Arc::new(RollupDb::open(tmp.path()).expect("open rollup db"));
        RollupProver::new(
            Hash::from_bytes([1; 32]),
            empty_tree_root(),
            Hash::from_bytes([2; 32]),
            Hash::from_bytes([3; 32]),
            1_700_000_000,
            db,
        )
    }

    fn mk_witness() -> CommitmentWitness {
        CommitmentWitness { payload_and_ctx_digest: [0x11; 8], parent_seq_commit: [0x22; 8], blue_score: 42 }
    }

    #[test]
    fn take_snapshot_returns_none_when_empty() {
        let tmp = TempDir::new().unwrap();
        let mut prover = test_prover(&tmp);
        assert!(matches!(prover.try_take_prove_snapshot(), Err(ProveSnapshotSkipReason::NoAccumulatedBlocks)));
    }

    #[test]
    fn take_snapshot_reports_missing_lane_proof() {
        let tmp = TempDir::new().unwrap();
        let mut prover = test_prover(&tmp);
        // Simulate a synced block window without the RPC lane proof yet.
        prover.accumulated_block_txs.push(Vec::new());
        prover.accumulated_block_lane_indices.push(Vec::new());
        prover.accumulated_block_context_hashes.push([0; 8]);
        assert!(matches!(prover.try_take_prove_snapshot(), Err(ProveSnapshotSkipReason::MissingLaneProof)));
    }

    #[test]
    fn set_lane_proof_enables_snapshot_and_is_consumed() {
        let tmp = TempDir::new().unwrap();
        let mut prover = test_prover(&tmp);
        prover.accumulated_block_txs.push(Vec::new());
        prover.accumulated_block_lane_indices.push(Vec::new());
        prover.accumulated_block_context_hashes.push([0xCC; 8]);

        prover.set_lane_proof(mk_witness(), vec![0xAA, 0xBB]);
        let snap = prover.try_take_prove_snapshot().expect("snapshot should succeed");

        assert_eq!(snap.input.block_lane_indices.len(), 1);
        assert_eq!(snap.input.block_context_hashes, vec![[0xCC; 8]]);
        assert_eq!(snap.input.commitment_witness.blue_score, 42);
        assert_eq!(snap.input.smt_proof_bytes, vec![0xAA, 0xBB]);

        // Witness is single-use: after being folded into the snapshot it must be cleared,
        // otherwise a second prove window would reuse a stale witness.
        assert!(prover.pending_lane_proof.is_none());
        // And the accumulators are drained.
        assert!(prover.accumulated_block_txs.is_empty());
        assert!(prover.accumulated_block_lane_indices.is_empty());
        assert!(prover.accumulated_block_context_hashes.is_empty());
    }

    #[test]
    fn rollback_restores_accumulators_and_drops_witness() {
        let tmp = TempDir::new().unwrap();
        let mut prover = test_prover(&tmp);
        prover.accumulated_block_txs.push(Vec::new());
        prover.accumulated_block_lane_indices.push(vec![0, 1]);
        prover.accumulated_block_context_hashes.push([0xDE; 8]);
        prover.set_lane_proof(mk_witness(), vec![0x42]);
        let _snap = prover.try_take_prove_snapshot().unwrap();

        prover.rollback_prove_window();

        assert_eq!(prover.accumulated_block_lane_indices, vec![vec![0u32, 1]]);
        assert_eq!(prover.accumulated_block_context_hashes, vec![[0xDE; 8]]);
        assert!(prover.pending_lane_proof.is_none(), "rollback must clear stale witness");
    }
}

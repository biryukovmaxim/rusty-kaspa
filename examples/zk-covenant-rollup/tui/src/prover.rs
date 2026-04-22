use kaspa_consensus_core::subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE};
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
use kaspa_hashes::Hash;
use kaspa_rpc_core::{GetVirtualChainFromBlockV2Response, RpcOptionalTransaction};
use kaspa_seq_commit::hashing::{activity_leaf, mergeset_context_hash, seq_commit_timestamp};
use kaspa_seq_commit::types::MergesetContext;
use std::sync::Arc;
use zk_covenant_rollup_core::permission_tree::required_depth;
use zk_covenant_rollup_core::seq_commit::{from_hash, lane_tip_next, to_hash, ActivityDigestBuilder, CommitmentWitness};
use zk_covenant_rollup_core::{
    action::{ActionHeader, EntryAction, ExitAction, TransferAction, OP_ENTRY, OP_EXIT, OP_TRANSFER},
    extract_pubkey_from_spk, is_p2pk_spk, perm_leaf_hash,
    permission_tree::StreamingPermTreeBuilder,
    smt::Smt,
    state::{AccountWitness, StateRoot},
    PublicInput, ROLLUP_LANE_KEY, ROLLUP_SUBNETWORK_ID,
};
use zk_covenant_rollup_host::mock_chain::from_bytes;
use zk_covenant_rollup_host::mock_tx::{
    ActionWitness, EntryWitnessData, ExitWitnessData, ExitWitnessRest, TransferWitnessData, TransferWitnessRest, ZkTransaction,
};
use zk_covenant_rollup_host::prove::ProveInput;

use crate::db::RollupDb;

/// A single block on the selected chain that accepted at least one of our
/// rollup-lane transactions. Produced by a `find_our_activity`-style scan
/// (see `cli_demo.rs`) and fed to [`RollupProver::apply_block_activity`].
///
/// `lane_txs[i].1` is the **global** `merge_idx` of that tx in the block's
/// full `AcceptedTxList` — its position among all accepted txs of the
/// block's mergeset, *not* just among rollup-lane txs.
#[derive(Clone, Debug)]
pub struct BlockActivity {
    pub block_hash: Hash,
    /// Timestamp of the block's selected parent. Passed through
    /// `seq_commit_timestamp` when building the context hash, per KIP-21.
    pub selected_parent_timestamp: u64,
    pub daa_score: u64,
    pub blue_score: u64,
    /// `(tx, global_merge_idx)` for each of our rollup-lane txs in this block,
    /// in ascending `merge_idx` order.
    pub lane_txs: Vec<(Transaction, u32)>,
}

/// State saved before a proof attempt so it can be restored if the proof fails.
struct RollbackState {
    accumulated_block_lane_txs: Vec<Vec<ZkTransaction>>,
    accumulated_block_lane_merge_idxs: Vec<Vec<u32>>,
    accumulated_block_context_hashes: Vec<[u32; 8]>,
    accumulated_exit_data: Vec<(Vec<u8>, u64)>,
    prev_proved_state_root: StateRoot,
    prev_proved_lane_tip: Hash,
    lane_tip: Hash,
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
    /// Current lane tip, advanced via `lane_tip_next` on each applied
    /// activity block (KIP-21).
    pub lane_tip: Hash,
    /// Covenant ID as [u32; 8] (for host crate compatibility).
    pub covenant_id: [u32; 8],
    /// Covenant ID as bytes.
    pub covenant_id_bytes: [u8; 32],
    /// Hash of the last activity block we applied.
    pub last_processed_block: Hash,
    /// Permission tree builder for exits — mirrors accumulated_perm_builder within a window.
    /// Shown in UI as "Exit leaves"; reset together with accumulated_perm_builder on snapshot.
    pub perm_builder: StreamingPermTreeBuilder,
    /// Persistent tx store: transactions whose outputs pay to known L2 accounts.
    /// Keyed by tx hash so process_transfer/process_exit can retrieve the actual prev_tx.
    /// Temporary — will be removed when lane_tip commits spk+amount of UTXO input.
    db: Arc<RollupDb>,
    /// Lane-only `ZkTransaction`s from the most recently applied batch
    /// (grouped by activity block). Used by the TUI for display and by
    /// `cli_demo` for its tx-persist pass.
    pub last_block_txs: Vec<Vec<ZkTransaction>>,

    // ── Proving accumulator ──
    // These track all activity blocks applied since the last proof.
    /// State root at the start of the current proving window.
    pub prev_proved_state_root: StateRoot,
    /// Lane tip at the start of the current proving window.
    pub prev_proved_lane_tip: Hash,
    /// Lane-only txs for each applied activity block, ordered by
    /// global `merge_idx`.
    pub accumulated_block_lane_txs: Vec<Vec<ZkTransaction>>,
    /// Global `merge_idx` of each lane tx, parallel to
    /// `accumulated_block_lane_txs`. Used as the `merge_idx` fed to
    /// `activity_leaf` on the guest side (KIP-21).
    pub accumulated_block_lane_merge_idxs: Vec<Vec<u32>>,
    /// Per-block `mergeset_context_hash(seq_commit_timestamp(parent_ts),
    /// daa, blue)` for each applied activity block.
    pub accumulated_block_context_hashes: Vec<[u32; 8]>,
    /// Permission tree builder for the current proving window (for exits).
    pub accumulated_perm_builder: StreamingPermTreeBuilder,
    /// (spk_bytes, amount) for each exit in the current proving window.
    pub accumulated_exit_data: Vec<(Vec<u8>, u64)>,

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

/// Outcome of applying one activity block.
#[derive(Clone, Copy, Debug)]
pub struct ApplyResult {
    pub lane_tx_count: usize,
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
            accumulated_block_lane_txs: Vec::new(),
            accumulated_block_lane_merge_idxs: Vec::new(),
            accumulated_block_context_hashes: Vec::new(),
            accumulated_perm_builder: StreamingPermTreeBuilder::new(),
            accumulated_exit_data: Vec::new(),
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

    /// Number of activity blocks accumulated since the last proof.
    pub fn accumulated_blocks(&self) -> usize {
        self.accumulated_block_lane_txs.len()
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
        if self.accumulated_block_lane_txs.is_empty() {
            return Err(ProveSnapshotSkipReason::NoAccumulatedBlocks);
        }
        let lane_proof = self.pending_lane_proof.take().ok_or(ProveSnapshotSkipReason::MissingLaneProof)?;

        // Save rollback state before consuming anything.
        self.pending_rollback = Some(RollbackState {
            accumulated_block_lane_txs: self.accumulated_block_lane_txs.clone(),
            accumulated_block_lane_merge_idxs: self.accumulated_block_lane_merge_idxs.clone(),
            accumulated_block_context_hashes: self.accumulated_block_context_hashes.clone(),
            accumulated_exit_data: self.accumulated_exit_data.clone(),
            prev_proved_state_root: self.prev_proved_state_root,
            prev_proved_lane_tip: self.prev_proved_lane_tip,
            lane_tip: self.lane_tip,
        });

        let public_input = PublicInput {
            prev_state_hash: self.prev_proved_state_root,
            prev_lane_tip: from_bytes(self.prev_proved_lane_tip.as_bytes()),
            covenant_id: self.covenant_id,
        };

        let block_lane_txs = std::mem::take(&mut self.accumulated_block_lane_txs);
        let block_lane_merge_idxs = std::mem::take(&mut self.accumulated_block_lane_merge_idxs);
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
                block_lane_txs,
                block_lane_merge_idxs,
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
        self.accumulated_block_lane_txs = rb.accumulated_block_lane_txs;
        self.accumulated_block_lane_merge_idxs = rb.accumulated_block_lane_merge_idxs;
        self.accumulated_block_context_hashes = rb.accumulated_block_context_hashes;
        self.accumulated_exit_data = rb.accumulated_exit_data.clone();
        self.prev_proved_state_root = rb.prev_proved_state_root;
        self.prev_proved_lane_tip = rb.prev_proved_lane_tip;
        self.lane_tip = rb.lane_tip;
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

    /// Apply one activity block per KIP-21:
    ///
    /// 1. Build `ActionWitness`es for each of our lane txs and update L2 state
    ///    (SMT balances).
    /// 2. Feed each lane tx's `activity_leaf(tx_id, version, merge_idx)` to an
    ///    [`ActivityDigestBuilder`], **using the supplied global `merge_idx`**.
    /// 3. Compute `mergeset_context_hash(seq_commit_timestamp(parent_ts), daa,
    ///    blue)` for this block.
    /// 4. Advance `lane_tip` via `lane_tip_next(prev_tip, ROLLUP_LANE_KEY,
    ///    activity_digest, context_hash)`.
    /// 5. Accumulate the lane txs, merge_idxs, and context hash into the
    ///    proving window so `take_prove_snapshot` can assemble a `ProveInput`.
    pub fn apply_block_activity(&mut self, block: &BlockActivity) -> ApplyResult {
        self.last_block_txs.clear();

        let mut lane_zk_txs: Vec<ZkTransaction> = Vec::with_capacity(block.lane_txs.len());
        let mut merge_idxs: Vec<u32> = Vec::with_capacity(block.lane_txs.len());
        let mut activity_builder = ActivityDigestBuilder::new();
        let mut actions_found = 0usize;

        for (tx, merge_idx) in &block.lane_txs {
            let witness = if tx.version == 1 {
                actions_found += 1;
                self.build_action_witness(tx)
            } else {
                None
            };

            // Persist AFTER building the witness: `process_entry` just inserted
            // the destination account into the SMT, so an entry's P2PK change
            // output now passes the "known L2 account" check and the entry tx
            // is kept around for the next action's `prev_tx` lookup.
            self.persist_prev_tx_if_relevant(tx);

            activity_builder.add_leaf(activity_leaf(&tx.id(), tx.version, *merge_idx));
            lane_zk_txs.push(ZkTransaction { tx: tx.clone(), witness });
            merge_idxs.push(*merge_idx);
        }

        // Context hash: always needed when the lane has activity in this block.
        let ctx_hash = mergeset_context_hash(&MergesetContext {
            timestamp: seq_commit_timestamp(block.selected_parent_timestamp),
            daa_score: block.daa_score,
            blue_score: block.blue_score,
        });
        let ctx_words = from_hash(ctx_hash);

        // Activity digest as [u32; 8] for lane_tip_next.
        let activity_digest = from_hash(activity_builder.finalize());

        // Advance lane_tip.
        let prev_tip_words = from_bytes(self.lane_tip.as_bytes());
        let new_tip_words = lane_tip_next(&prev_tip_words, &ROLLUP_LANE_KEY, &activity_digest, &ctx_words);
        self.lane_tip = to_hash(&new_tip_words);

        // Update L2 state root.
        self.state_root = self.smt.root();
        self.last_processed_block = block.block_hash;

        // Accumulate for the proving window.
        self.accumulated_block_lane_txs.push(lane_zk_txs.clone());
        self.accumulated_block_lane_merge_idxs.push(merge_idxs);
        self.accumulated_block_context_hashes.push(ctx_words);
        self.last_block_txs.push(lane_zk_txs.clone());

        ApplyResult {
            lane_tx_count: lane_zk_txs.len(),
            actions_found,
            new_state_root: self.state_root,
            new_lane_tip: self.lane_tip,
        }
    }

    /// Streaming compat path for the TUI: walk a VCC v2 response, find blocks
    /// that accepted at least one tx on the rollup subnetwork, and apply
    /// each as one KIP-21 activity block. Non-activity blocks are used only
    /// to advance `selected_parent_timestamp` for subsequent context-hash
    /// computation.
    ///
    /// Returns the number of activity blocks applied and the number of
    /// rollup-lane actions found (transfer/entry/exit) across them.
    pub fn process_vcc_rollup_lane(
        &mut self,
        response: &GetVirtualChainFromBlockV2Response,
        selected_parent_timestamp: &mut u64,
    ) -> (usize, usize) {
        let mut activity_blocks = 0usize;
        let mut actions = 0usize;

        let rollup_subnet = SubnetworkId::from_bytes(ROLLUP_SUBNETWORK_ID);

        for (i, rpc_block) in response.chain_block_accepted_transactions.iter().enumerate() {
            let block_hash = match response.added_chain_block_hashes.get(i).copied() {
                Some(h) => h,
                None => continue,
            };
            let header = &rpc_block.chain_block_header;

            let mut lane_txs: Vec<(Transaction, u32)> = Vec::new();
            for (merge_idx, rpc_tx) in rpc_block.accepted_transactions.iter().enumerate() {
                if rpc_tx.subnetwork_id != Some(rollup_subnet) {
                    continue;
                }
                if let Some(tx) = rpc_optional_to_transaction(rpc_tx) {
                    lane_txs.push((tx, merge_idx as u32));
                }
            }

            if !lane_txs.is_empty() {
                let block = BlockActivity {
                    block_hash,
                    selected_parent_timestamp: *selected_parent_timestamp,
                    daa_score: header.daa_score.unwrap_or(0),
                    blue_score: header.blue_score.unwrap_or(0),
                    lane_txs,
                };
                let result = self.apply_block_activity(&block);
                activity_blocks += 1;
                actions += result.actions_found;
            }

            if let Some(ts) = header.timestamp {
                *selected_parent_timestamp = ts;
            }
        }

        (activity_blocks, actions)
    }

    /// If the tx pays to a known L2 account, persist it so later transfer/exit
    /// actions can retrieve it as their `prev_tx`.
    fn persist_prev_tx_if_relevant(&self, tx: &Transaction) {
        let has_matching_output = tx.outputs.iter().any(|out| {
            let spk = out.script_public_key.script();
            if !is_p2pk_spk(spk) {
                return false;
            }
            extract_pubkey_from_spk(spk).is_some_and(|pk_words| self.smt.get(&pk_words).is_some())
        });
        if !has_matching_output {
            return;
        }
        let cov_hash = Hash::from_bytes(self.covenant_id_bytes);
        let tx_hash = tx.id();
        if let Err(e) = self.db.put_prev_tx(cov_hash, tx_hash, tx) {
            eprintln!("[prover] failed to persist prev_tx {tx_hash}: {e}");
        }
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

/// Convert an RpcOptionalTransaction (from VCC v2 with Full verbosity) into a
/// consensus [`Transaction`]. Returns `None` if required fields are missing.
pub fn rpc_optional_to_transaction(rpc: &RpcOptionalTransaction) -> Option<Transaction> {
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
        RollupProver::new(Hash::from_bytes([1; 32]), empty_tree_root(), Hash::from_bytes([2; 32]), Hash::from_bytes([3; 32]), db)
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
        // Simulate an applied activity block without the RPC lane proof yet.
        prover.accumulated_block_lane_txs.push(Vec::new());
        prover.accumulated_block_lane_merge_idxs.push(Vec::new());
        prover.accumulated_block_context_hashes.push([0; 8]);
        assert!(matches!(prover.try_take_prove_snapshot(), Err(ProveSnapshotSkipReason::MissingLaneProof)));
    }

    #[test]
    fn set_lane_proof_enables_snapshot_and_is_consumed() {
        let tmp = TempDir::new().unwrap();
        let mut prover = test_prover(&tmp);
        prover.accumulated_block_lane_txs.push(Vec::new());
        prover.accumulated_block_lane_merge_idxs.push(Vec::new());
        prover.accumulated_block_context_hashes.push([0xCC; 8]);

        prover.set_lane_proof(mk_witness(), vec![0xAA, 0xBB]);
        let snap = prover.try_take_prove_snapshot().expect("snapshot should succeed");

        assert_eq!(snap.input.block_lane_merge_idxs.len(), 1);
        assert_eq!(snap.input.block_context_hashes, vec![[0xCC; 8]]);
        assert_eq!(snap.input.commitment_witness.blue_score, 42);
        assert_eq!(snap.input.smt_proof_bytes, vec![0xAA, 0xBB]);

        // Witness is single-use: after being folded into the snapshot it must be cleared,
        // otherwise a second prove window would reuse a stale witness.
        assert!(prover.pending_lane_proof.is_none());
        // And the accumulators are drained.
        assert!(prover.accumulated_block_lane_txs.is_empty());
        assert!(prover.accumulated_block_lane_merge_idxs.is_empty());
        assert!(prover.accumulated_block_context_hashes.is_empty());
    }

    #[test]
    fn rollback_restores_accumulators_and_drops_witness() {
        let tmp = TempDir::new().unwrap();
        let mut prover = test_prover(&tmp);
        prover.accumulated_block_lane_txs.push(Vec::new());
        prover.accumulated_block_lane_merge_idxs.push(vec![0, 1]);
        prover.accumulated_block_context_hashes.push([0xDE; 8]);
        prover.set_lane_proof(mk_witness(), vec![0x42]);
        let _snap = prover.try_take_prove_snapshot().unwrap();

        prover.rollback_prove_window();

        assert_eq!(prover.accumulated_block_lane_merge_idxs, vec![vec![0u32, 1]]);
        assert_eq!(prover.accumulated_block_context_hashes, vec![[0xDE; 8]]);
        assert!(prover.pending_lane_proof.is_none(), "rollback must clear stale witness");
    }
}

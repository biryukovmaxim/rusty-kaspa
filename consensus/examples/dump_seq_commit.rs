//! Diagnostic: recompute `seq_commit` for a block against an existing kaspad
//! consensus RocksDB snapshot, and dump every input and intermediate value so
//! two DB snapshots can be diffed line-by-line.
//!
//! Designed for the case where the syncee disqualified a block with
//! `BadAcceptedIDMerkleRoot`. If the block has committed `acceptance_data` in
//! the DB, that's used. Otherwise the example re-runs UTXO validation against
//! the parent's UTXO view (taken from `virtual_stores.utxo_set` reversed by
//! `virtual_state.utxo_diff`) so we can reproduce *exactly* the syncee's
//! computation that produced the wrong commit.
//!
//! Two snapshots will diverge somewhere in:
//!   - the accepted-tx set (per-merged-block list of accepted tx ids),
//!   - the per-lane existing-tip lookups (lane_version store contents),
//!   - the branch-walk reads inside `compute_root_update` (branch_version
//!     store contents at the visited (depth, node_key) addresses).
//! All three are dumped explicitly.
//!
//! The DB must NOT be opened by another process. RocksDB takes a file lock —
//! close kaspad first. The example does not write through the public store
//! APIs, but `ConnBuilder::default()` opens read-write so RocksDB may replay
//! WAL / append to LOG; logical state is unchanged.
//!
//! Usage:
//!   cargo run --release --example dump_seq_commit -p kaspa-consensus -- \
//!     --db /path/to/datadir/consensus/consensus-NNN \
//!     --block <64-hex-hash> \
//!     [--network devnet|testnet|mainnet|simnet]   (default: devnet)

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use parking_lot::RwLock;

use kaspa_consensus::model::services::reachability::{MTReachabilityService, ReachabilityService};
use kaspa_consensus::model::services::seq_commit_accessor::SeqCommitAccessor;
use kaspa_consensus::model::stores::acceptance_data::{AcceptanceDataStoreReader, DbAcceptanceDataStore};
use kaspa_consensus::model::stores::block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore};
use kaspa_consensus::model::stores::ghostdag::{DbGhostdagStore, GhostdagStoreReader};
use kaspa_consensus::model::stores::headers::{DbHeadersStore, HeaderStoreReader};
use kaspa_consensus::model::stores::reachability::DbReachabilityStore;
use kaspa_consensus::model::stores::smt_metadata::DbSmtMetadataStore;
use kaspa_consensus::model::stores::utxo_set::DbUtxoSetStore;
use kaspa_consensus::model::stores::virtual_state::{DbVirtualStateStore, LkgVirtualState, VirtualStateStoreReader};
use kaspa_consensus::processes::transaction_validator::TransactionValidator;
use kaspa_consensus::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags;
use kaspa_consensus_core::acceptance_data::{AcceptanceData, AcceptedTxEntry, MergesetBlockAcceptanceData};
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, Params, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::tx::{PopulatedTransaction, VerifiableTransaction};
use kaspa_consensus_core::utxo::utxo_view::{UtxoView, UtxoViewComposition};
use kaspa_database::prelude::{CachePolicy, ConnBuilder, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::{Hash, ZERO_HASH};
use kaspa_seq_commit::hashing::{
    activity_digest_lane, activity_leaf, lane_key, lane_tip_next, mergeset_context_hash, miner_payload_leaf, miner_payload_root,
    payload_and_context_digest, seq_commit, seq_commit_timestamp, seq_state_root,
};
use kaspa_seq_commit::types::{LaneTipInput, MergesetContext, MinerPayloadLeafInput, SeqCommitInput, SeqState};
use kaspa_smt::store::{BranchKey, Node, SmtStore};
use kaspa_smt::tree::compute_root_update;
use kaspa_smt_store::processor::{SmtReadBounds, SmtStores};
use kaspa_txscript::caches::TxScriptCacheCounters;

const SECTION: &str = "============================================================";
const SUB: &str = "------------------------------------------------------------";

#[derive(Debug)]
struct Args {
    db: PathBuf,
    block: Hash,
    params: &'static Params,
    branch_keys: Vec<(u8, Hash)>,
    lane_keys: Vec<Hash>,
}

fn parse_args() -> Args {
    let mut db: Option<PathBuf> = None;
    let mut block: Option<String> = None;
    let mut network: String = String::from("devnet");
    let mut branch_keys: Vec<(u8, Hash)> = Vec::new();
    let mut lane_keys: Vec<Hash> = Vec::new();

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--db" => {
                db = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
            }
            "--block" => {
                block = Some(argv[i + 1].clone());
                i += 2;
            }
            "--network" | "-n" => {
                network = argv[i + 1].clone();
                i += 2;
            }
            "--branch" => {
                // Format: <depth>:<64-hex-node_key>. Repeat to dump multiple keys.
                let raw = &argv[i + 1];
                let (d, k) = raw.split_once(':').expect("--branch expects <depth>:<hex32>");
                let depth: u8 = d.parse().expect("branch depth must be u8");
                let node_key = Hash::from_str(k).expect("branch node_key must be 64-char hex");
                branch_keys.push((depth, node_key));
                i += 2;
            }
            "--lane" => {
                lane_keys.push(Hash::from_str(&argv[i + 1]).expect("--lane must be 64-char hex"));
                i += 2;
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: dump_seq_commit --db <path> --block <hex> \\\n           [--network devnet|testnet|mainnet|simnet] \\\n           [--branch <depth>:<hex32> ...] [--lane <hex32> ...]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }

    let db = db.expect("--db is required");
    let block_hex = block.expect("--block is required");
    let block = Hash::from_str(&block_hex).expect("--block must be a 64-char hex hash");
    let params: &'static Params = match network.as_str() {
        "devnet" => &DEVNET_PARAMS,
        "testnet" => &TESTNET_PARAMS,
        "mainnet" => &MAINNET_PARAMS,
        "simnet" => &SIMNET_PARAMS,
        other => {
            eprintln!("Unknown network: {other}");
            std::process::exit(2);
        }
    };
    Args { db, block, params, branch_keys, lane_keys }
}

fn main() {
    let args = parse_args();
    let f = args.params.finality_depth();
    println!("{SECTION}");
    println!("dump_seq_commit");
    println!("  db                = {}", args.db.display());
    println!("  block             = {}", args.block);
    println!("  network           = {} (finality_depth={})", args.params.net, f);
    println!("{SECTION}\n");

    let db = ConnBuilder::default()
        .with_db_path(args.db.clone())
        .with_files_limit(512)
        .build()
        .expect("failed to open DB (is kaspad running on this datadir?)");

    let cp = || CachePolicy::Empty;

    let headers_store = Arc::new(DbHeadersStore::new(db.clone(), cp(), cp()));
    let ghostdag_store = Arc::new(DbGhostdagStore::new(db.clone(), 0, cp(), cp()));
    let block_transactions_store = Arc::new(DbBlockTransactionsStore::new(db.clone(), cp()));
    let acceptance_data_store = Arc::new(DbAcceptanceDataStore::new(db.clone(), cp()));
    let smt_metadata_store = Arc::new(DbSmtMetadataStore::new(db.clone(), cp()));
    let smt_stores = Arc::new(SmtStores::new(db.clone(), 16, 16));
    let virtual_state_store = DbVirtualStateStore::new(db.clone(), LkgVirtualState::default());
    let virtual_utxo_set = DbUtxoSetStore::new(db.clone(), cp(), DatabaseStorePrefixes::VirtualUtxoset.into());
    let reachability_store = Arc::new(RwLock::new(DbReachabilityStore::new(db.clone(), cp(), cp())));
    let reachability_service = MTReachabilityService::new(reachability_store);

    // ---- Block + parent ----
    let header = headers_store.get_header(args.block).unwrap_or_else(|e| panic!("header for {} not found: {e}", args.block));
    let ghostdag = ghostdag_store.get_data(args.block).expect("ghostdag data missing for block");
    let selected_parent = ghostdag.selected_parent;
    let parent_header = headers_store.get_header(selected_parent).expect("parent header missing");

    let current_bs = ghostdag.blue_score;
    let parent_bs = parent_header.blue_score;
    let current_active_min = current_bs.saturating_sub(f);

    println!("[block]");
    println!("  hash                       = {}", header.hash);
    println!("  blue_score                 = {current_bs}");
    println!("  daa_score                  = {}", header.daa_score);
    println!("  timestamp                  = {}", header.timestamp);
    println!("  blue_work                  = {:#x}", header.blue_work);
    println!("  hash_merkle_root           = {}", header.hash_merkle_root);
    println!("  accepted_id_merkle_root    = {}  <-- header-committed seq_commit", header.accepted_id_merkle_root);
    println!("  utxo_commitment            = {}", header.utxo_commitment);
    println!();
    println!("[selected_parent]");
    println!("  hash                       = {}", selected_parent);
    println!("  blue_score                 = {parent_bs}");
    println!("  timestamp                  = {}", parent_header.timestamp);
    println!("  accepted_id_merkle_root    = {}  <-- parent_seq_commit input", parent_header.accepted_id_merkle_root);
    println!();

    let parent_seq_commit = parent_header.accepted_id_merkle_root;
    let context_hash = mergeset_context_hash(&MergesetContext {
        timestamp: seq_commit_timestamp(parent_header.timestamp),
        daa_score: header.daa_score,
        blue_score: current_bs,
    });
    println!("[mergeset_context]");
    println!("  seq_commit_timestamp(parent.ts) = {}", seq_commit_timestamp(parent_header.timestamp));
    println!("  context_hash               = {context_hash}");
    println!();

    let merged: Vec<Hash> = std::iter::once(selected_parent)
        .chain(ghostdag.consensus_ordered_mergeset_without_selected_parent(&*ghostdag_store))
        .collect();
    println!("[mergeset]  ({} blocks: selected_parent + {} merged)", merged.len(), merged.len() - 1);
    for (i, mh) in merged.iter().enumerate() {
        let role = if i == 0 { "selected_parent" } else { "merged_blue/red" };
        let mhdr = headers_store.get_header(*mh).expect("merged header missing");
        println!("  [{i:>3}] {role:>16}  hash={mh}  blue_score={}", mhdr.blue_score);
    }
    println!();

    // ---- Acceptance: stored, or re-validate against virtual ----
    let acceptance: AcceptanceData = match acceptance_data_store.get(args.block) {
        Ok(a) => {
            println!("[acceptance_data] STORED — using committed acceptance from DB");
            (*a).clone()
        }
        Err(StoreError::KeyNotFound(_)) => {
            println!("[acceptance_data] MISSING — re-validating against virtual state");
            recompute_acceptance(
                args.params,
                &virtual_state_store,
                &virtual_utxo_set,
                &block_transactions_store,
                &headers_store,
                &reachability_service,
                &header,
                header.daa_score, // pov_daa_score = current block's daa
                selected_parent,
                &merged,
            )
        }
        Err(e) => panic!("acceptance_data_store error: {e}"),
    };
    println!("  mergeset entries          = {}", acceptance.len());
    let total_accepted: usize = acceptance.iter().map(|a| a.accepted_transactions.len()).sum();
    println!("  total accepted txs        = {}", total_accepted);
    println!();

    println!("[accepted_per_merged_block]");
    for ba in acceptance.iter() {
        println!("  block={} accepted_count={}", ba.block_hash, ba.accepted_transactions.len());
        for tx in ba.accepted_transactions.iter() {
            println!("    tx_id={} idx_within_block={}", tx.transaction_id, tx.index_within_block);
        }
    }
    println!();

    // ---- collect_mergeset_seq_data ----
    let mut lane_activities: BTreeMap<[u8; 20], Vec<Hash>> = BTreeMap::new();
    let mut miner_payload_leaves: Vec<Hash> = Vec::new();
    let mut global_merge_idx: u32 = 0;
    for ba in acceptance.iter() {
        let mh = ba.block_hash;
        let mhdr = headers_store.get_header(mh).expect("merged header missing");
        let block_txs = block_transactions_store.get(mh).expect("merged block txs missing");
        let coinbase_payload = &block_txs[0].payload;
        miner_payload_leaves.push(miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &mh,
            blue_work_be_bytes: &mhdr.blue_work.to_be_bytes(),
            payload: coinbase_payload,
        }));
        for at in ba.accepted_transactions.iter() {
            let tx = &block_txs[at.index_within_block as usize];
            let lane_id: [u8; 20] = *tx.subnetwork_id.as_bytes();
            let al = activity_leaf(&at.transaction_id, tx.version, global_merge_idx);
            lane_activities.entry(lane_id).or_default().push(al);
            global_merge_idx += 1;
        }
    }

    let payload_root = miner_payload_root(miner_payload_leaves.clone().into_iter());
    let pd = payload_and_context_digest(&context_hash, &payload_root);
    println!("[payload]");
    println!("  miner_payload_leaves      = {}", miner_payload_leaves.len());
    println!("  payload_root              = {payload_root}");
    println!("  payload_and_ctx_digest    = {pd}");
    println!();

    // ---- parent_smt_metadata: canonical (parent_bs, 0) ----
    let canonical_for_sp = |bh: Hash| is_smt_canonical(&reachability_service, bh, selected_parent);
    let active_lanes_count = smt_metadata_store.get(selected_parent).map(|m| m.active_lanes_count).unwrap_or(0);
    let parent_lanes_root = smt_stores.get_lanes_root(SmtReadBounds::new(parent_bs, 0), |bh| canonical_for_sp(bh));
    println!("[parent_smt_metadata]");
    println!("  active_lanes_count        = {active_lanes_count}");
    println!("  parent_lanes_root         = {parent_lanes_root}");
    println!();

    // ---- resolve_lane_updates: canonical bounds = (current_bs, current_bs - F) ----
    let lane_bounds = SmtReadBounds::for_pov(current_bs, f);
    println!("[lane_updates]  bounds=(target={}, min={})", lane_bounds.target_blue_score, lane_bounds.min_blue_score);
    println!("  Per-lane: lane_id, activity_digest, existing tip (or None), parent_ref, new_tip, is_new.");
    println!();

    struct ResolvedUpdate {
        lane_key: Hash,
        new_tip: Hash,
        is_new: bool,
    }
    let mut updates: Vec<ResolvedUpdate> = Vec::with_capacity(lane_activities.len());

    for (lane_id, activity_leaves) in &lane_activities {
        let lk = lane_key(lane_id);
        let ad = activity_digest_lane(activity_leaves.iter().copied());
        let existing = smt_stores.get_lane(lk, lane_bounds, |bh| canonical_for_sp(bh));
        let is_new = existing.is_none();
        let (existing_str, parent_ref) = match &existing {
            Some(v) => (format!("blue_score={} block_hash={} tip={}", v.blue_score(), v.block_hash(), v.data()), *v.data()),
            None => ("None".to_string(), parent_seq_commit),
        };
        let new_tip =
            lane_tip_next(&LaneTipInput { parent_ref: &parent_ref, lane_key: &lk, activity_digest: &ad, context_hash: &context_hash });
        println!("  lane_id={}", hex(lane_id));
        println!("    lane_key             = {lk}");
        println!("    activity_digest      = {ad}");
        println!("    activity_leaves.len  = {}", activity_leaves.len());
        println!("    existing             = {existing_str}");
        println!("    parent_ref           = {parent_ref}");
        println!("    new_tip              = {new_tip}");
        println!("    is_new               = {is_new}");
        updates.push(ResolvedUpdate { lane_key: lk, new_tip, is_new });
    }
    println!();

    // ---- expire_stale_lanes ----
    let parent_active_min = parent_bs.saturating_sub(f);
    let expired_range = if current_active_min > parent_active_min { Some(parent_active_min..=current_active_min - 1) } else { None };
    println!("[expire_stale_lanes]");
    let mut expired: Vec<Hash> = Vec::new();
    if let Some(r) = expired_range {
        println!("  scan score-index in [{}, {}]", r.start(), r.end());
        let mut seen: std::collections::BTreeSet<Hash> = std::collections::BTreeSet::new();
        for entry in smt_stores.score_index.get_leaf_updates(r) {
            let entry = entry.expect("score_index iter error");
            if !canonical_for_sp(entry.block_hash()) {
                continue;
            }
            for lk in entry.data().iter() {
                if !seen.insert(*lk) {
                    continue;
                }
                if smt_stores.get_lane(*lk, lane_bounds, |bh| canonical_for_sp(bh)).is_none() {
                    expired.push(*lk);
                }
            }
        }
    } else {
        println!("  no scan band");
    }
    println!("  expired_count             = {}", expired.len());
    println!();

    // ---- build_seq_commit, with branch-read logging ----
    println!("[build_seq_commit]  bounds=(target={}, min={})", lane_bounds.target_blue_score, lane_bounds.min_blue_score);

    // Build the leaf updates that compute_root_update consumes.
    use kaspa_hashes::SeqCommitActiveNode;
    use kaspa_seq_commit::hashing::smt_leaf_hash;
    use kaspa_seq_commit::types::SmtLeafInput;
    let mut leaf_map: BTreeMap<Hash, Hash> = BTreeMap::new();
    // Expirations first; updates overwrite expirations on the same lane_key.
    for lk in &expired {
        // BlockLaneChanges encodes expirations as ZERO_HASH leaves
        // (see SmtProcessor's to_leaf_updates).
        leaf_map.insert(*lk, ZERO_HASH);
    }
    for u in &updates {
        let leaf = smt_leaf_hash(&SmtLeafInput { lane_tip: &u.new_tip, blue_score: current_bs });
        leaf_map.insert(u.lane_key, leaf);
    }

    let logging_reader = LoggingSmtReader {
        stores: &smt_stores,
        bounds: lane_bounds,
        is_canonical: &canonical_for_sp,
        reads: RefCell::new(Vec::new()),
    };

    let (lanes_root, node_changes) = if leaf_map.is_empty() {
        println!("  no leaf updates — short-circuit; lanes_root = parent_lanes_root");
        (parent_lanes_root, kaspa_smt::tree::SmtNodeChanges::new())
    } else {
        let leaves = kaspa_smt::store::SortedLeafUpdates::from_sorted_map(&leaf_map, |_k, v| *v);
        compute_root_update::<SeqCommitActiveNode, _>(&logging_reader, parent_lanes_root, leaves).expect("compute_root_update failed")
    };
    let new_lane_count = updates.iter().filter(|u| u.is_new).count() as u64;
    let expired_count = expired.len() as u64;
    let active_lanes_after = (active_lanes_count + new_lane_count).saturating_sub(expired_count);
    let state_root = seq_state_root(&SeqState { lanes_root: &lanes_root, payload_and_ctx_digest: &pd });
    let commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &state_root });

    println!("  parent_lanes_root         = {parent_lanes_root}");
    println!("  expired_count             = {expired_count}");
    println!("  new_lane_count            = {new_lane_count}");
    println!("  active_lanes_count after  = {active_lanes_after}");
    println!("  lanes_root                = {lanes_root}");
    println!("  state_root                = {state_root}");
    println!("  seq_commit                = {commit}");
    if commit == header.accepted_id_merkle_root {
        println!("  *** MATCHES header.accepted_id_merkle_root ***");
    } else {
        println!("  !!! does NOT match header.accepted_id_merkle_root ({}) !!!", header.accepted_id_merkle_root);
    }
    println!();

    // ---- Branch reads dump (sorted by depth, node_key — comparable across DBs) ----
    let mut reads = logging_reader.reads.into_inner();
    reads.sort_by(|a, b| (a.0.depth, a.0.node_key).cmp(&(b.0.depth, b.0.node_key)));
    println!("[branch_reads]  {} branch entries read by compute_root_update", reads.len());
    println!("  Sorted by (depth asc, node_key asc) so two DBs can be diffed line-by-line.");
    println!("  Format: depth=NN node_key=<hex32> -> <Internal hash | Collapsed (lane_key, leaf_hash) | None>");
    for (key, value) in &reads {
        let v = match value {
            Some(Node::Internal(h)) => format!("Internal({h})"),
            Some(Node::Collapsed(cl)) => format!("Collapsed(lane_key={}, leaf_hash={})", cl.lane_key, cl.leaf_hash),
            None => "None".to_string(),
        };
        println!("  depth={:>3} node_key={} -> {v}", key.depth, key.node_key);
    }
    println!();

    println!("[node_changes]  {} branch entries written by compute_root_update", node_changes.len());
    let mut writes: Vec<(BranchKey, Option<Node>)> = node_changes.iter().map(|(k, v)| (*k, *v)).collect();
    writes.sort_by(|a, b| (a.0.depth, a.0.node_key).cmp(&(b.0.depth, b.0.node_key)));
    for (key, value) in &writes {
        let v = match value {
            Some(Node::Internal(h)) => format!("Internal({h})"),
            Some(Node::Collapsed(cl)) => format!("Collapsed(lane_key={}, leaf_hash={})", cl.lane_key, cl.leaf_hash),
            None => "Deleted".to_string(),
        };
        println!("  depth={:>3} node_key={} -> {v}", key.depth, key.node_key);
    }
    println!();

    // ---- History dumpers (--branch / --lane) ----
    if !args.branch_keys.is_empty() {
        println!("[branch_history]  {} key(s) requested", args.branch_keys.len());
        for (depth, node_key) in &args.branch_keys {
            println!();
            println!("  depth={depth} node_key={node_key}");
            println!("    All versions (newest blue_score first), full history (no canonicality filter):");
            let mut count = 0usize;
            for entry in smt_stores.branch_version.get_at(*depth, *node_key, u64::MAX, 0) {
                let entry = entry.expect("branch_version iter error");
                let bh = entry.block_hash();
                let bs = entry.blue_score();
                let canon = canonical_for_sp(bh);
                let v = match *entry.data() {
                    Some(Node::Internal(h)) => format!("Internal({h})"),
                    Some(Node::Collapsed(cl)) => {
                        format!("Collapsed(lane_key={}, leaf_hash={})", cl.lane_key, cl.leaf_hash)
                    }
                    None => "Tombstone".to_string(),
                };
                let canon_tag = if canon { "canonical" } else { "non-canonical" };
                let zero_tag = if bh == ZERO_HASH { " [ZERO_HASH=IBD-import]" } else { "" };
                println!("      blue_score={bs:>10} block_hash={bh} [{canon_tag}]{zero_tag} -> {v}");
                count += 1;
            }
            if count == 0 {
                println!("      (no versions found)");
            }
        }
        println!();
    }

    if !args.lane_keys.is_empty() {
        println!("[lane_history]  {} lane(s) requested", args.lane_keys.len());
        for lk in &args.lane_keys {
            println!();
            println!("  lane_key={lk}");
            println!("    All versions (newest blue_score first), full history (no canonicality filter):");
            let mut count = 0usize;
            for entry in smt_stores.lane_version.get_at(*lk, u64::MAX, 0) {
                let entry = entry.expect("lane_version iter error");
                let bh = entry.block_hash();
                let bs = entry.blue_score();
                let canon = canonical_for_sp(bh);
                let tip = entry.data();
                let canon_tag = if canon { "canonical" } else { "non-canonical" };
                let zero_tag = if bh == ZERO_HASH { " [ZERO_HASH=IBD-import]" } else { "" };
                println!("      blue_score={bs:>10} block_hash={bh} [{canon_tag}]{zero_tag} -> tip={tip}");
                count += 1;
            }
            if count == 0 {
                println!("      (no versions found)");
            }
        }
        println!();
    }

    println!("{SECTION}");
    println!("Done.");
    println!("{SECTION}");
}

/// SmtStore wrapper that records every (BranchKey, value) it answers.
/// Used to capture the exact branch_version reads `compute_root_update` makes.
struct LoggingSmtReader<'a, F: Fn(Hash) -> bool> {
    stores: &'a SmtStores,
    bounds: SmtReadBounds,
    is_canonical: &'a F,
    reads: RefCell<Vec<(BranchKey, Option<Node>)>>,
}

impl<F: Fn(Hash) -> bool> SmtStore for LoggingSmtReader<'_, F> {
    type Error = StoreError;
    fn get_node(&self, key: &BranchKey) -> Result<Option<Node>, StoreError> {
        let entity = kaspa_smt_store::cache::BranchEntity { depth: key.depth, node_key: key.node_key };
        let result = self.stores.get_node(entity, self.bounds, |bh| (self.is_canonical)(bh)).and_then(|v| *v.data());
        self.reads.borrow_mut().push((*key, result));
        Ok(result)
    }
}

/// Mirrors `VirtualStateProcessor::is_smt_canonical`.
fn is_smt_canonical<R: ReachabilityService>(svc: &R, bh: Hash, selected_parent: Hash) -> bool {
    bh == ZERO_HASH || matches!(svc.try_is_chain_ancestor_of(bh, selected_parent), Ok(true))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Recompute `acceptance_data` from scratch by re-running tx validation against
/// the parent's UTXO view.
///
/// **Assumption:** `virtual_state.ghostdag_data.selected_parent == selected_parent`.
/// In other words, the parent of the block under inspection IS the current
/// selected tip. That holds on a syncee that disqualified `block` (the chain
/// stays at the parent). On a node that already accepted `block`, this won't
/// hold and the function panics — but in that case `acceptance_data_store` has
/// the committed acceptance and the caller takes the stored path.
fn recompute_acceptance(
    params: &Params,
    virtual_state_store: &DbVirtualStateStore,
    virtual_utxo_set: &DbUtxoSetStore,
    block_transactions_store: &DbBlockTransactionsStore,
    headers_store: &Arc<DbHeadersStore>,
    reachability_service: &MTReachabilityService<DbReachabilityStore>,
    header: &kaspa_consensus_core::header::Header,
    pov_daa_score: u64,
    selected_parent: Hash,
    merged: &[Hash],
) -> AcceptanceData {
    let virtual_state = virtual_state_store.get().expect("virtual state missing");
    if virtual_state.ghostdag_data.selected_parent != selected_parent {
        eprintln!(
            "ERROR: virtual.selected_parent={} != block.selected_parent={}.\n\
             Cannot reconstruct parent UTXO view without walking diffs.\n\
             Run this on a DB where the block was disqualified (its parent is the chain tip),\n\
             or on a DB where it was accepted (acceptance_data is then read from store directly).",
            virtual_state.ghostdag_data.selected_parent, selected_parent
        );
        std::process::exit(3);
    }

    // SP UTXO view = virtual UTXO + reversed virtual.utxo_diff
    let sp_view = virtual_utxo_set.compose(virtual_state.utxo_diff.as_reversed());

    // Build TransactionValidator from network params.
    let mass_calculator =
        MassCalculator::new(params.mass_per_tx_byte, params.mass_per_script_pub_key_byte, params.storage_mass_parameter);
    let counters = Arc::new(TxScriptCacheCounters::default());
    let tv = TransactionValidator::new(
        params.max_tx_inputs,
        params.max_tx_outputs,
        params.max_signature_script_len,
        params.max_script_public_key_len,
        params.coinbase_payload_script_public_key_max_len,
        params.coinbase_maturity(),
        params.ghostdag_k(),
        counters,
        mass_calculator,
        params.covenants_activation,
        params.mass_per_sig_op,
    );
    let seq_commit_accessor = if params.covenants_activation.is_active(header.daa_score) {
        Some(SeqCommitAccessor::new(
            selected_parent,
            reachability_service,
            headers_store,
            params.covenants_activation,
            params.finality_depth(),
        ))
    } else {
        None
    };

    // Mirror `calculate_utxo_state`:
    //   for each merged block (selected_parent first):
    //     composed_view = sp_view + running mergeset_diff   (rebuilt once per block)
    //     validate all non-coinbase txs against composed_view (parallel in real code,
    //       sequential here — order of independent txs doesn't matter)
    //     bulk-apply accepted txs to mergeset_diff with pov_daa_score
    //   selected_parent's coinbase is added explicitly with new_coinbase semantics
    //   selected_parent's other txs use SkipScriptChecks (already verified by SP)
    use kaspa_consensus_core::tx::ValidatedTransaction;
    use kaspa_consensus_core::utxo::utxo_diff::UtxoDiff;

    let mut diff = UtxoDiff::default();
    let mut out: AcceptanceData = Vec::with_capacity(merged.len());
    let mut total_accepted = 0usize;
    let mut total_seen = 0usize;
    let mut total_rejected: BTreeMap<String, usize> = BTreeMap::new();

    for (i, mh) in merged.iter().enumerate() {
        let mhdr = headers_store.get_header(*mh).expect("merged header missing");
        let block_txs = block_transactions_store.get(*mh).expect("merged txs missing");
        let is_selected_parent = i == 0;
        let validation_flags = if is_selected_parent { TxValidationFlags::SkipScriptChecks } else { TxValidationFlags::Full };

        // 1) Validate every non-coinbase tx of this block against the composed view
        //    that does NOT include any of this block's own outputs.
        let mut accepted_in_block: Vec<(usize, ValidatedTransaction<'_>)> = Vec::new();
        let composed = (&sp_view).compose(&diff);
        for (idx, tx) in block_txs.iter().enumerate().skip(1) {
            total_seen += 1;
            let mut entries = Vec::with_capacity(tx.inputs.len());
            let mut missing = false;
            for input in tx.inputs.iter() {
                if let Some(e) = composed.get(&input.previous_outpoint) {
                    entries.push(e);
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                *total_rejected.entry("MissingTxOutpoints".into()).or_insert(0) += 1;
                continue;
            }
            let populated = PopulatedTransaction::new(tx, entries);
            match tv.validate_populated_transaction_and_get_fee(
                &populated,
                pov_daa_score,
                mhdr.daa_score,
                validation_flags,
                None,
                seq_commit_accessor.as_ref().map(|v| v as _),
            ) {
                Ok(fee) => {
                    accepted_in_block.push((idx, ValidatedTransaction::new(populated, fee)));
                    total_accepted += 1;
                }
                Err(e) => {
                    *total_rejected.entry(classify_err(&e)).or_insert(0) += 1;
                }
            }
        }
        drop(composed);

        // 2) Build acceptance entries; for selected_parent prepend the coinbase.
        let mut accepted: Vec<AcceptedTxEntry> = Vec::new();
        if is_selected_parent {
            let coinbase = &block_txs[0];
            let coinbase_id = kaspa_consensus_core::hashing::tx::id(coinbase);
            accepted.push(AcceptedTxEntry { transaction_id: coinbase_id, index_within_block: 0 });
            // Add SP coinbase to running diff exactly like calculate_utxo_state does
            // (`ValidatedTransaction::new_coinbase` + add_transaction(pov_daa_score)).
            let validated_cb = ValidatedTransaction::new_coinbase(coinbase);
            diff.add_transaction(&validated_cb, pov_daa_score).expect("coinbase add");
        }
        for (idx, vtx) in &accepted_in_block {
            accepted.push(AcceptedTxEntry { transaction_id: vtx.id(), index_within_block: *idx as u32 });
        }

        // 3) Apply accepted-tx diffs to the running view AFTER all validations,
        //    using pov_daa_score so output maturity matches real consensus.
        for (_, vtx) in &accepted_in_block {
            diff.add_transaction(vtx, pov_daa_score).expect("add_transaction");
        }

        out.push(MergesetBlockAcceptanceData { block_hash: *mh, accepted_transactions: accepted });
    }

    println!("{SUB}");
    println!("Re-validation summary:");
    println!("  txs seen (excl. coinbase)   = {total_seen}");
    println!("  txs accepted                = {total_accepted}");
    println!("  txs rejected                = {}", total_seen - total_accepted);
    if !total_rejected.is_empty() {
        let mut entries: Vec<(&String, &usize)> = total_rejected.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1));
        println!("  rejection breakdown:");
        for (k, v) in entries {
            println!("    {k:<40} {v:>6}");
        }
    }
    println!("{SUB}\n");

    out
}

/// Map any error to a short stable label by stripping the variant name from its
/// `Debug` rendering. Avoids hard-coding the exact `TxRuleError` variant set.
fn classify_err<E: std::fmt::Debug>(e: &E) -> String {
    let s = format!("{e:?}");
    s.split(|c: char| c == '(' || c == ' ' || c == '{').next().unwrap_or("Unknown").to_string()
}

//! Diagnostic: dump the full breakdown of `recompute_seq_commit` for a given block
//! against an existing kaspad consensus RocksDB snapshot.
//!
//! Reproduces every intermediate value `verify_expected_utxo_state ->
//! recompute_seq_commit -> {collect_mergeset_seq_data, resolve_lane_updates,
//! get_parent_smt_metadata, build_seq_commit}` would compute, with side-by-side
//! probes against three SMT read-bound variants per lookup so the divergence
//! point is visible at a glance.
//!
//! The DB must NOT be opened by another process (kaspad). RocksDB takes a file
//! lock — close kaspad first. The example does not write to the DB but uses the
//! standard read-write open path (RocksDB rejects concurrent rw opens).
//!
//! Usage (either form):
//!   # Auto-resolve the active consensus DB from kaspad's datadir layout
//!   # ({datadir}/meta + {datadir}/consensus/consensus-NNN):
//!   cargo run --release --example dump_seq_commit -p kaspa-consensus -- \
//!     --datadir /path/to/datadir \
//!     --block <64-hex-hash> \
//!     --finality-depth 432000
//!
//!   # Or pass the inner consensus DB path directly:
//!   cargo run --release --example dump_seq_commit -p kaspa-consensus -- \
//!     --db /path/to/datadir/consensus/consensus-002 \
//!     --block <64-hex-hash> \
//!     --finality-depth 432000
//!
//! `--finality-depth` should match the network's `params.finality_depth()`.
//! Devnet default = 432000, testnet-11 = 86400 — check
//! `consensus/core/src/config/params.rs` for the value of the network you're
//! investigating.
//!
//! Output:
//!   - Header / parent header / context hash / mergeset listing.
//!   - If acceptance data exists for the block (it is committed only for blocks
//!     that passed UTXO validation), the full per-lane and per-bound breakdown
//!     plus the recomputed `seq_commit`. Compare against
//!     `header.accepted_id_merkle_root`.
//!   - If acceptance data is missing (the block was disqualified), only the
//!     header/mergeset surface and the `parent_lanes_root` probes are printed.
//!     In that case run the same example on the working DB to get the full
//!     dump and diff manually, or on the last-passing chain block on the
//!     failing DB to see whether the SMT state is already drifted there.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use parking_lot::RwLock;

use kaspa_consensus::model::services::reachability::{MTReachabilityService, ReachabilityService};
use kaspa_consensus::model::stores::acceptance_data::{AcceptanceDataStoreReader, DbAcceptanceDataStore};
use kaspa_consensus::model::stores::block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore};
use kaspa_consensus::model::stores::ghostdag::{DbGhostdagStore, GhostdagStoreReader};
use kaspa_consensus::model::stores::headers::{DbHeadersStore, HeaderStoreReader};
use kaspa_consensus::model::stores::reachability::DbReachabilityStore;
use kaspa_consensus::model::stores::smt_metadata::DbSmtMetadataStore;
use kaspa_database::prelude::{CachePolicy, ConnBuilder, StoreError};
use kaspa_hashes::{Hash, SeqCommitActiveNode, ZERO_HASH};
use kaspa_seq_commit::hashing::{
    activity_digest_lane, activity_leaf, lane_key, lane_tip_next, mergeset_context_hash,
    miner_payload_leaf, miner_payload_root, payload_and_context_digest, seq_commit, seq_commit_timestamp,
    seq_state_root,
};
use kaspa_seq_commit::types::{
    LaneTipInput, MergesetContext, MinerPayloadLeafInput, SeqCommitInput, SeqState,
};
use kaspa_smt::SmtHasher;
use kaspa_smt_store::processor::{SmtProcessor, SmtReadBounds, SmtStores};

const SECTION: &str = "============================================================";
const SUB: &str = "------------------------------------------------------------";

#[derive(Debug)]
struct Args {
    db: PathBuf,
    block: Hash,
    finality_depth: u64,
}

fn parse_args() -> Args {
    let mut db: Option<PathBuf> = None;
    let mut block: Option<String> = None;
    let mut finality_depth: Option<u64> = None;

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
            "--finality-depth" | "-F" => {
                finality_depth = Some(argv[i + 1].parse().expect("finality-depth must be u64"));
                i += 2;
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: dump_seq_commit --db <path> --block <hex> --finality-depth <u64>"
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
    let finality_depth = finality_depth.expect("--finality-depth is required");
    let block = Hash::from_str(&block_hex).expect("--block must be a 64-char hex hash");

    Args { db, block, finality_depth }
}

fn main() {
    let args = parse_args();
    println!("{SECTION}");
    println!("dump_seq_commit");
    println!("  db                = {}", args.db.display());
    println!("  block             = {}", args.block);
    println!("  finality_depth F  = {}", args.finality_depth);
    println!("{SECTION}\n");

    // Open the DB. ConnBuilder defaults to read-write open; if kaspad is running
    // on the same dir RocksDB will refuse the lock.
    let db = ConnBuilder::default()
        .with_db_path(args.db.clone())
        .with_files_limit(512)
        .build()
        .expect("failed to open DB (is kaspad running on this datadir?)");

    // Minimal cache everywhere — examples shouldn't keep gigabytes resident.
    let cp = || CachePolicy::Empty;

    let headers_store = Arc::new(DbHeadersStore::new(db.clone(), cp(), cp()));
    let ghostdag_store = Arc::new(DbGhostdagStore::new(db.clone(), 0, cp(), cp()));
    let block_transactions_store = Arc::new(DbBlockTransactionsStore::new(db.clone(), cp()));
    let acceptance_data_store = Arc::new(DbAcceptanceDataStore::new(db.clone(), cp()));
    let smt_metadata_store = Arc::new(DbSmtMetadataStore::new(db.clone(), cp()));
    let smt_stores = Arc::new(SmtStores::new(db.clone(), 16, 16));
    let reachability_store = Arc::new(RwLock::new(DbReachabilityStore::new(db.clone(), cp(), cp())));
    let reachability_service = MTReachabilityService::new(reachability_store);

    let header = match headers_store.get_header(args.block) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: header for {} not found: {e}", args.block);
            std::process::exit(1);
        }
    };
    let ghostdag = ghostdag_store
        .get_data(args.block)
        .expect("ghostdag data missing for block");
    let selected_parent = ghostdag.selected_parent;
    let parent_header = headers_store
        .get_header(selected_parent)
        .expect("parent header missing");

    let current_bs = ghostdag.blue_score;
    let parent_bs = parent_header.blue_score;
    let f = args.finality_depth;
    let current_active_min = current_bs.saturating_sub(f);
    let parent_active_min = parent_bs.saturating_sub(f);

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

    // ---- Mergeset context ----
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

    // ---- Mergeset enumeration ----
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

    // ---- Try to read acceptance data ----
    let acceptance = match acceptance_data_store.get(args.block) {
        Ok(a) => Some(a),
        Err(StoreError::KeyNotFound(_)) => None,
        Err(e) => panic!("acceptance_data_store error: {e}"),
    };

    if acceptance.is_none() {
        println!("{SUB}");
        println!("Acceptance data for {} is NOT in the DB.", args.block);
        println!("This block was disqualified before utxo state could be committed,");
        println!("so we cannot reproduce the per-lane breakdown from this DB alone.");
        println!("Falling back to the parent_lanes_root probes; for the full dump,");
        println!("run the same example on a DB where the block was committed");
        println!("(e.g., the working snapshot), or on the last-passing block before");
        println!("the cascade on this DB.");
        println!("{SUB}\n");
    }

    // ---- Parent SMT metadata: probe with three different read-bounds ----
    println!("[parent_smt_metadata]");
    let active_lanes_count = smt_metadata_store
        .get(selected_parent)
        .map(|m| m.active_lanes_count)
        .unwrap_or(0);
    println!("  active_lanes_count (DB metadata) = {active_lanes_count}");

    let canonical_for_sp = |bh: Hash| is_smt_canonical(&reachability_service, bh, selected_parent);

    let probe_root = |label: &str, bounds: SmtReadBounds| {
        let r = smt_stores.get_lanes_root(bounds, |bh| canonical_for_sp(bh));
        println!(
            "  parent_lanes_root [{label:<20}] target={:>10}  min={:>10}  -> {r}",
            bounds.target_blue_score, bounds.min_blue_score
        );
        r
    };
    let r_buggy = probe_root("buggy: (parent_bs, parent-F)", SmtReadBounds::for_pov(parent_bs, f));
    let r_canonical = probe_root("canonical: (parent_bs, 0)", SmtReadBounds::new(parent_bs, 0));
    let _r_current_pov = probe_root("current-pov:(current,curr-F)", SmtReadBounds::for_pov(current_bs, f));
    println!();

    let acceptance = match acceptance {
        Some(a) => a,
        None => {
            // Skeleton recompute without acceptance data:
            //   - payload_root depends only on the mergeset coinbase payloads
            //     and headers, which we have unconditionally.
            //   - For lanes_root we use three baselines:
            //       (1) parent_lanes_root unchanged (no lane updates, no expirations)
            //       (2) after running expire_stale_lanes only (still no updates)
            //       (3) empty SMT root (sanity reference)
            //   The resulting seq_commits bracket what the producer's value can
            //   be once the missing accepted-tx lane updates are folded in.
            println!("[skeleton recompute]  (no acceptance data — best-effort)");
            println!("  Walking the mergeset (selected_parent + ordered merged blocks) for");
            println!("  miner payload leaves only. Lane activities are unknown.");

            let mut miner_payload_leaves: Vec<Hash> = Vec::with_capacity(merged.len());
            for mh in &merged {
                let mhdr = headers_store.get_header(*mh).expect("merged header missing");
                let block_txs = block_transactions_store.get(*mh).expect("merged block txs missing");
                let coinbase_payload = &block_txs[0].payload;
                let mpl = miner_payload_leaf(MinerPayloadLeafInput {
                    block_hash: mh,
                    blue_work_be_bytes: &mhdr.blue_work.to_be_bytes(),
                    payload: coinbase_payload,
                });
                miner_payload_leaves.push(mpl);
            }
            let payload_root = miner_payload_root(miner_payload_leaves.into_iter());
            let pd = payload_and_context_digest(&context_hash, &payload_root);
            println!("  payload_root              = {payload_root}");
            println!("  payload_and_ctx_digest    = {pd}");
            println!();

            // Run expire_stale_lanes against three bound choices to see how many
            // lanes would be expired regardless of incoming updates.
            let bounds_buggy = SmtReadBounds::new(parent_bs, current_active_min);
            let bounds_canonical = SmtReadBounds::for_pov(current_bs, f);
            let expired_range = if current_active_min > parent_active_min {
                Some(parent_active_min..=current_active_min - 1)
            } else {
                None
            };
            let count_expired = |label: &str, bounds: SmtReadBounds| -> Vec<Hash> {
                let mut out = Vec::new();
                let Some(r) = expired_range.clone() else {
                    println!("  expire_stale_lanes [{label:<14}] = no scan band");
                    return out;
                };
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
                        if smt_stores.get_lane(*lk, bounds, |bh| canonical_for_sp(bh)).is_none() {
                            out.push(*lk);
                        }
                    }
                }
                println!("  expire_stale_lanes [{label:<14}] = {} lanes expire", out.len());
                out
            };
            let expired_buggy = count_expired("buggy: parent", bounds_buggy);
            let expired_canonical = count_expired("canonical: cur", bounds_canonical);
            println!();

            let compute_skeleton = |label: &str, parent_root: Hash, bounds: SmtReadBounds, expired: &[Hash]| {
                let mut proc = SmtProcessor::new(&smt_stores, current_bs, bounds, parent_root);
                for lk in expired {
                    proc.expire_lane(*lk);
                }
                let build = proc.build(|bh| canonical_for_sp(bh)).expect("smt build failed");
                let state_root = seq_state_root(&SeqState { lanes_root: &build.root, payload_and_ctx_digest: &pd });
                let commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &state_root });
                println!("[skeleton / {label}]");
                println!("  parent_lanes_root         = {parent_root}");
                println!("  bounds                    = target={} min={}", bounds.target_blue_score, bounds.min_blue_score);
                println!("  expired_count             = {}", expired.len());
                println!("  lanes_root after expire   = {}", build.root);
                println!("  state_root                = {state_root}");
                println!("  seq_commit (no updates)   = {commit}");
                if commit == header.accepted_id_merkle_root {
                    println!("  *** MATCHES header.accepted_id_merkle_root ***");
                    println!("      => zero lane updates would already produce the header's value.");
                } else {
                    println!("  != header.accepted_id_merkle_root ({})", header.accepted_id_merkle_root);
                }
                println!();
                commit
            };

            compute_skeleton("buggy: parent_root buggy + expired_buggy", r_buggy, bounds_buggy, &expired_buggy);
            compute_skeleton("canonical: parent_root canonical + expired_canonical", r_canonical, bounds_canonical, &expired_canonical);

            let empty_root = SeqCommitActiveNode::empty_root();
            let pd_empty_state_root = seq_state_root(&SeqState { lanes_root: &empty_root, payload_and_ctx_digest: &pd });
            let pd_empty_commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &pd_empty_state_root });
            println!("[skeleton / sanity: empty SMT]");
            println!("  empty_root                = {empty_root}");
            println!("  seq_commit (empty SMT)    = {pd_empty_commit}");
            if pd_empty_commit == header.accepted_id_merkle_root {
                println!("  *** matches header (the parent SMT view was empty) ***");
            }
            println!();

            println!("{SECTION}");
            println!("Done (skeleton-only).");
            println!("  - To compare with the value the syncee actually computed in the log");
            println!("    (e.g. 4305ba2e...77262d for c026adb3...), match the seq_commits above.");
            println!("  - For the FULL per-lane breakdown, run on the working DB with the same");
            println!("    --block, or on the selected_parent {} of the failing block on this DB.", selected_parent);
            println!("{SECTION}");
            return;
        }
    };
    println!("[acceptance_data]  {} mergeset entries", acceptance.len());

    // ---- collect_mergeset_seq_data ----
    let mut lane_activities: BTreeMap<[u8; 20], Vec<Hash>> = BTreeMap::new();
    let mut miner_payload_leaves: Vec<Hash> = Vec::new();
    let mut global_merge_idx: u32 = 0;

    for block_acc in acceptance.iter() {
        let merged_block = block_acc.block_hash;
        let mhdr = headers_store.get_header(merged_block).expect("merged header missing");
        let block_txs = block_transactions_store.get(merged_block).expect("merged block txs missing");

        let coinbase_payload = &block_txs[0].payload;
        let mpl = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &merged_block,
            blue_work_be_bytes: &mhdr.blue_work.to_be_bytes(),
            payload: coinbase_payload,
        });
        miner_payload_leaves.push(mpl);

        for accepted_tx in block_acc.accepted_transactions.iter() {
            let tx = &block_txs[accepted_tx.index_within_block as usize];
            let lane_id: [u8; 20] = *tx.subnetwork_id.as_bytes();
            let al = activity_leaf(&accepted_tx.transaction_id, tx.version, global_merge_idx);
            lane_activities.entry(lane_id).or_default().push(al);
            global_merge_idx += 1;
        }
    }

    println!("  total accepted txs           = {global_merge_idx}");
    println!("  miner_payload_leaves.len()  = {}", miner_payload_leaves.len());
    println!("  distinct lanes               = {}", lane_activities.len());
    println!();

    let payload_root = miner_payload_root(miner_payload_leaves.clone().into_iter());
    let pd = payload_and_context_digest(&context_hash, &payload_root);
    println!("[payload]");
    println!("  payload_root              = {payload_root}");
    println!("  payload_and_ctx_digest    = {pd}");
    println!();

    // ---- resolve_lane_updates: per-lane lookup with three bound variants ----
    println!("[lane_updates]");
    println!(
        "  Format per lane: lane_id, activity_digest, then the 'existing tip' returned by"
    );
    println!("  three different bound variants. Differences here mean the SMT seek window");
    println!("  is materially changing the result.");
    println!();

    struct ResolvedUpdate {
        lane_key: Hash,
        new_tip: Hash,
        is_new: bool,
    }

    let mut updates_buggy: Vec<ResolvedUpdate> = Vec::with_capacity(lane_activities.len());
    let mut updates_canonical: Vec<ResolvedUpdate> = Vec::with_capacity(lane_activities.len());
    let bounds_buggy = SmtReadBounds::new(parent_bs, current_active_min); // [current-F, parent]
    let bounds_canonical = SmtReadBounds::for_pov(current_bs, f); // [current-F, current]
    let bounds_full = SmtReadBounds::new(current_bs, 0); // [0, current]

    for (lane_id, activity_leaves) in &lane_activities {
        let lk = lane_key(lane_id);
        let ad = activity_digest_lane(activity_leaves.iter().copied());

        let probe = |bounds: SmtReadBounds| -> Option<(u64, Hash, Hash)> {
            smt_stores
                .get_lane(lk, bounds, |bh| canonical_for_sp(bh))
                .map(|v| (v.blue_score(), v.block_hash(), *v.data()))
        };

        let r_buggy = probe(bounds_buggy);
        let r_canonical = probe(bounds_canonical);
        let r_full = probe(bounds_full);

        println!("  lane_id={}", hex(lane_id));
        println!("    lane_key             = {lk}");
        println!("    activity_digest      = {ad}");
        println!("    activity_leaves.len  = {}", activity_leaves.len());
        let fmt = |label: &str, opt: &Option<(u64, Hash, Hash)>| match opt {
            Some((bs, bh, t)) => format!(
                "    existing [{label:<14}] = blue_score={bs} block_hash={bh} tip={t}"
            ),
            None => format!("    existing [{label:<14}] = None"),
        };
        println!("{}", fmt("buggy: parent", &r_buggy));
        println!("{}", fmt("canonical: cur", &r_canonical));
        println!("{}", fmt("full history", &r_full));

        // Build resolved-update for both buggy and canonical bound choices.
        let mk_update = |existing: Option<(u64, Hash, Hash)>| {
            let is_new = existing.is_none();
            let parent_ref = existing.map(|(_, _, t)| t).unwrap_or(parent_seq_commit);
            let new_tip = lane_tip_next(&LaneTipInput {
                parent_ref: &parent_ref,
                lane_key: &lk,
                activity_digest: &ad,
                context_hash: &context_hash,
            });
            ResolvedUpdate { lane_key: lk, new_tip, is_new }
        };
        let u_b = mk_update(r_buggy);
        let u_c = mk_update(r_canonical);
        println!(
            "    new_tip [buggy]      = {}  is_new={}",
            u_b.new_tip, u_b.is_new
        );
        println!(
            "    new_tip [canonical]  = {}  is_new={}",
            u_c.new_tip, u_c.is_new
        );
        if u_b.new_tip != u_c.new_tip {
            println!("    *** new_tip DIFFERS between buggy and canonical bounds ***");
        }
        updates_buggy.push(u_b);
        updates_canonical.push(u_c);
        println!();
    }

    // ---- expire_stale_lanes (just enumerate; report count under each bounds choice) ----
    let expired_range = if current_active_min > parent_active_min {
        Some(parent_active_min..=current_active_min - 1)
    } else {
        None
    };
    println!("[expire_stale_lanes]");
    match &expired_range {
        Some(r) => println!("  scan score-index in [{}, {}]", r.start(), r.end()),
        None => println!("  no scan (current_active_min <= parent_active_min)"),
    }
    let mut expired_buggy: Vec<Hash> = Vec::new();
    let mut expired_canonical: Vec<Hash> = Vec::new();
    if let Some(r) = expired_range {
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
                let alive_buggy = smt_stores
                    .get_lane(*lk, bounds_buggy, |bh| canonical_for_sp(bh))
                    .is_some();
                let alive_canonical = smt_stores
                    .get_lane(*lk, bounds_canonical, |bh| canonical_for_sp(bh))
                    .is_some();
                if !alive_buggy {
                    expired_buggy.push(*lk);
                }
                if !alive_canonical {
                    expired_canonical.push(*lk);
                }
                if alive_buggy != alive_canonical {
                    println!(
                        "  lane_key={lk} divergence: alive_buggy={alive_buggy} alive_canonical={alive_canonical}"
                    );
                }
            }
        }
    }
    println!("  expired_count [buggy]      = {}", expired_buggy.len());
    println!("  expired_count [canonical]  = {}", expired_canonical.len());
    println!();

    // ---- build_seq_commit: run SmtProcessor for each bounds choice ----
    let run_build = |label: &str, parent_root: Hash, bounds: SmtReadBounds, updates: &[ResolvedUpdate], expired: &[Hash]| -> (Hash, u64) {
        let mut proc = SmtProcessor::new(&smt_stores, current_bs, bounds, parent_root);
        for lk in expired {
            proc.expire_lane(*lk);
        }
        for u in updates {
            proc.update_lane(u.lane_key, u.new_tip);
        }
        let build = proc.build(|bh| canonical_for_sp(bh)).expect("smt build failed");
        let new_lane_count = updates.iter().filter(|u| u.is_new).count() as u64;
        let expired_count = expired.len() as u64;
        let active_after = active_lanes_count + new_lane_count - expired_count.min(active_lanes_count + new_lane_count);
        let state_root = seq_state_root(&SeqState { lanes_root: &build.root, payload_and_ctx_digest: &pd });
        let commit = seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &state_root });

        println!("[build_seq_commit / {label}]");
        println!("  parent_lanes_root         = {parent_root}");
        println!("  bounds                    = target={} min={}", bounds.target_blue_score, bounds.min_blue_score);
        println!("  expired_count             = {}", expired.len());
        println!("  new_lane_count            = {new_lane_count}");
        println!("  active_lanes_count after  = {active_after}");
        println!("  lanes_root                = {}", build.root);
        println!("  state_root                = {state_root}");
        println!("  seq_commit                = {commit}");
        if commit == header.accepted_id_merkle_root {
            println!("  *** MATCHES header.accepted_id_merkle_root ***");
        } else {
            println!("  !!! does NOT match header.accepted_id_merkle_root ({}) !!!", header.accepted_id_merkle_root);
        }
        println!();
        (commit, build.root.as_slice()[0] as u64) // dummy second return to stay typed
    };

    println!("{SUB}");
    println!("Recompute under each bounds choice (full pipeline):");
    println!("{SUB}\n");

    let _ = run_build("buggy: parent_root buggy + lane_buggy", r_buggy, bounds_buggy, &updates_buggy, &expired_buggy);
    let _ = run_build("canonical (current-pov)", r_canonical, bounds_canonical, &updates_canonical, &expired_canonical);
    let _ = run_build("parent_root full + lane_canonical", r_canonical, bounds_canonical, &updates_canonical, &expired_canonical);
    // Bonus: empty-leaf reference root, in case the parent_lanes_root probe returned empty
    let empty_root = SeqCommitActiveNode::empty_root();
    println!(
        "[reference] empty SMT root = {empty_root}  (returned by get_lanes_root when no in-window root entry exists)\n"
    );

    println!("{SECTION}");
    println!("Done.");
    println!("{SECTION}");
}

/// Mirrors `VirtualStateProcessor::is_smt_canonical`:
/// `bh == ZERO_HASH || bh is chain ancestor of selected_parent`. Errors from
/// reachability (e.g., pruned reachability data) are treated as non-canonical.
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

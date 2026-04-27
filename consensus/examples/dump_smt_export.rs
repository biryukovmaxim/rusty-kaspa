//! Diagnostic: walk a kaspad consensus DB's pruning-point SMT lane stream and
//! emit the same per-checkpoint rolling fingerprints that the IBD streaming
//! receiver logs (`streaming_import` in `kaspa-smt-store`).
//!
//! Compare two runs (one on the syncer DB, one against receiver logs) to
//! localize the divergent segment when the IBD root mismatches the
//! `lanes_root` advertised in `SmtMetadata`.
//!
//! - Receiver-side fingerprints come from logs of the form:
//!   `SMT import checkpoint: idx=… lane_key=… leaf_hash=… fp=… …`
//! - This tool produces the same `idx`, `lane_key`, `leaf_hash`, and `fp`
//!   strings against any kaspad consensus DB. The first segment whose
//!   fingerprint differs contains the bad lane(s).
//!
//! The DB must NOT be opened by another process. RocksDB takes a file lock —
//! close kaspad first.
//!
//! Usage:
//!   cargo run --release --example dump_smt_export -p kaspa-consensus -- \
//!     --db /path/to/datadir/consensus/consensus-NNN \
//!     [--network devnet|testnet|mainnet|simnet]   (default: devnet)

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use kaspa_consensus::model::services::reachability::{MTReachabilityService, ReachabilityService};
use kaspa_consensus::model::stores::headers::{DbHeadersStore, HeaderStoreReader};
use kaspa_consensus::model::stores::pruning::{DbPruningStore, PruningStoreReader};
use kaspa_consensus::model::stores::reachability::DbReachabilityStore;
use kaspa_consensus_core::api::SMT_PROOF_INTERVAL;
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, Params, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_database::prelude::{CachePolicy, ConnBuilder};
use kaspa_hashes::{Hash, ZERO_HASH, blake3};
use kaspa_seq_commit::hashing::smt_leaf_hash;
use kaspa_seq_commit::types::SmtLeafInput;
use kaspa_smt_store::processor::SmtStores;

const SECTION: &str = "============================================================";

#[derive(Debug)]
struct Args {
    db: PathBuf,
    params: &'static Params,
}

fn parse_args() -> Args {
    let mut db: Option<PathBuf> = None;
    let mut network: String = String::from("devnet");

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--db" => {
                db = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
            }
            "--network" | "-n" => {
                network = argv[i + 1].clone();
                i += 2;
            }
            "-h" | "--help" => {
                eprintln!("Usage: dump_smt_export --db <path> [--network devnet|testnet|mainnet|simnet]");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }

    let db = db.expect("--db is required");
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
    Args { db, params }
}

fn main() {
    let args = parse_args();
    let f = args.params.finality_depth();
    println!("{SECTION}");
    println!("dump_smt_export");
    println!("  db                = {}", args.db.display());
    println!("  network           = {} (finality_depth={f})", args.params.net);
    println!("  proof_interval    = {SMT_PROOF_INTERVAL}");
    println!("{SECTION}\n");

    let db = ConnBuilder::default()
        .with_db_path(args.db.clone())
        .with_files_limit(512)
        .build()
        .expect("failed to open DB (is kaspad running on this datadir?)");

    let cp = || CachePolicy::Empty;

    let headers_store = Arc::new(DbHeadersStore::new(db.clone(), cp(), cp()));
    let pruning_point_store = Arc::new(RwLock::new(DbPruningStore::new(db.clone())));
    let smt_stores = Arc::new(SmtStores::new(db.clone(), 16, 16));
    let reachability_store = Arc::new(RwLock::new(DbReachabilityStore::new(db.clone(), cp(), cp())));
    let reachability_service = MTReachabilityService::new(reachability_store);

    let pp = pruning_point_store.read().pruning_point().expect("pruning point not set");
    let pp_header = headers_store.get_header(pp).expect("pruning point header missing");
    let max_score = pp_header.blue_score;
    let min_score = max_score.saturating_sub(f);

    println!("[pruning_point]");
    println!("  hash              = {pp}");
    println!("  blue_score        = {max_score}");
    println!("  scan_window       = [{min_score}, {max_score}]");
    println!();

    // Mirror VirtualStateProcessor::is_smt_canonical(bh, pp): a stored entry
    // is canonical for the pruning-point view if it's the IBD ZERO_HASH
    // sentinel or a chain ancestor of pp.
    let svc = reachability_service.clone();
    let is_canonical = move |bh: Hash| -> bool { bh == ZERO_HASH || matches!(svc.try_is_chain_ancestor_of(bh, pp), Ok(true)) };

    let mut fp = blake3::Hasher::new();
    let mut idx: u64 = 0;
    let mut last_checkpoint_idx: u64 = 0;

    println!("[checkpoints]  (every SMT_PROOF_INTERVAL = {SMT_PROOF_INTERVAL} lanes)");
    println!("  Format matches `streaming_import` log lines so they can be diff'd directly.\n");

    for res in smt_stores.lane_version.iter_all_canonical_owned(None, min_score, Some(max_score), is_canonical) {
        let (lane_key, verified) = res.expect("lane iter error");
        let lane_tip = *verified.data();
        let blue_score = verified.blue_score();
        let leaf_hash = smt_leaf_hash(&SmtLeafInput { lane_tip: &lane_tip, blue_score });

        fp.update(&lane_key.as_bytes());
        fp.update(&leaf_hash.as_bytes());
        fp.update(&blue_score.to_le_bytes());

        if (idx as usize).is_multiple_of(SMT_PROOF_INTERVAL) {
            let snap = snapshot(&fp);
            println!(
                "SMT import checkpoint: idx={idx} segment=[{last_checkpoint_idx}, {idx}] \
                 lane_key={lane_key} blue_score={blue_score} leaf_hash={leaf_hash} fp={snap} proof_present=true"
            );
            last_checkpoint_idx = idx;
        }
        idx += 1;
    }

    let final_fp = snapshot(&fp);
    println!("SMT import final: lanes_imported={idx} segment=[{last_checkpoint_idx}, {idx}] fp={final_fp}");

    println!("\n{SECTION}");
    println!("Done. Total lanes seen: {idx}");
    println!("{SECTION}");
}

fn snapshot(fp: &blake3::Hasher) -> Hash {
    let mut out = [0u8; 32];
    out.copy_from_slice(fp.finalize().as_bytes());
    Hash::from_bytes(out)
}

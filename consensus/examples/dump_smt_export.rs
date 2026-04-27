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
use kaspa_consensus::model::stores::smt_metadata::DbSmtMetadataStore;
use kaspa_consensus_core::api::{ImportLane, SMT_PROOF_INTERVAL};
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, Params, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_database::create_temp_db;
use kaspa_database::prelude::{CachePolicy, ConnBuilder};
use kaspa_hashes::{Hash, SeqCommitActiveNode, ZERO_HASH, blake3};
use kaspa_seq_commit::hashing::smt_leaf_hash;
use kaspa_seq_commit::types::SmtLeafInput;
use kaspa_smt::SmtHasher;
use kaspa_smt::store::{BTreeSmtStore, LeafUpdate, Node, SortedLeafUpdates};
use kaspa_smt::tree::compute_root_update;
use kaspa_smt_store::cache::BranchEntity;
use kaspa_smt_store::processor::{SmtReadBounds, SmtStores};
use kaspa_smt_store::streaming_import::streaming_import;

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
    let smt_metadata_store = Arc::new(DbSmtMetadataStore::new(db.clone(), cp()));
    let smt_stores = Arc::new(SmtStores::new(db.clone(), 16, 16));
    let reachability_store = Arc::new(RwLock::new(DbReachabilityStore::new(db.clone(), cp(), cp())));
    let reachability_service = MTReachabilityService::new(reachability_store);

    let pp = pruning_point_store.read().pruning_point().expect("pruning point not set");
    let pp_header = headers_store.get_header(pp).expect("pruning point header missing");
    let max_score = pp_header.blue_score;
    let min_score = max_score.saturating_sub(f);
    let stored_active_lanes_count = smt_metadata_store.get(pp).map(|m| m.active_lanes_count).ok();

    println!("[pruning_point]");
    println!("  hash                 = {pp}");
    println!("  blue_score           = {max_score}");
    println!("  scan_window          = [{min_score}, {max_score}]");
    match stored_active_lanes_count {
        Some(n) => println!("  active_lanes_count   = {n}    (from smt_metadata_store at pp)"),
        None => println!("  active_lanes_count   = <missing>    (smt_metadata not stored for pp)"),
    }
    println!();

    // Mirror VirtualStateProcessor::is_smt_canonical(bh, pp): a stored entry
    // is canonical for the pruning-point view if it's the IBD ZERO_HASH
    // sentinel or a chain ancestor of pp. Cloned per-call site below so each
    // closure owns its own Arc into the reachability service.
    let make_canonical = || {
        let svc = reachability_service.clone();
        move |bh: Hash| bh == ZERO_HASH || matches!(svc.try_is_chain_ancestor_of(bh, pp), Ok(true))
    };
    let bounds = SmtReadBounds::for_pov(max_score, f);

    let mut fp = blake3::Hasher::new();
    let mut idx: u64 = 0;
    let mut last_checkpoint_idx: u64 = 0;
    // Buffer the lanes as we walk so we can re-feed them to `streaming_import`
    // below without a second iter walk. ~80 bytes per lane → tens to a few
    // hundred MB for production-scale snapshots; acceptable for an offline
    // diagnostic on the kind of host that runs kaspad.
    const CHUNK_LEN: usize = 4096;
    let mut chunks: Vec<Vec<ImportLane>> = Vec::new();
    let mut current_chunk: Vec<ImportLane> = Vec::with_capacity(CHUNK_LEN);

    println!("[checkpoints]  (every SMT_PROOF_INTERVAL = {SMT_PROOF_INTERVAL} lanes)");
    println!("  Format matches `streaming_import` log lines so they can be diff'd directly.\n");

    for res in smt_stores.lane_version.iter_all_canonical_owned(None, min_score, Some(max_score), make_canonical()) {
        let (lane_key, verified) = res.expect("lane iter error");
        let lane_tip = *verified.data();
        let blue_score = verified.blue_score();
        let leaf_hash = smt_leaf_hash(&SmtLeafInput { lane_tip: &lane_tip, blue_score });

        fp.update(&lane_key.as_bytes());
        fp.update(&leaf_hash.as_bytes());
        fp.update(&blue_score.to_le_bytes());

        // At SMT_PROOF_INTERVAL boundaries, generate a real inclusion proof
        // against the syncer's tree (root = stored_lanes_root computed
        // below). Attaching it makes `streaming_import`'s `localize_divergence`
        // useful: on mismatch it'll diff the proof's expected ancestor
        // hashes against what streaming actually wrote at the same
        // (depth, node_key) — pinning *which subtree* diverged.
        let on_checkpoint = (idx as usize).is_multiple_of(SMT_PROOF_INTERVAL);
        let proof = if on_checkpoint {
            Some(smt_stores.prove_lane(&lane_key, bounds, make_canonical()).expect("prove_lane failed"))
        } else {
            None
        };

        if on_checkpoint {
            let snap = snapshot(&fp);
            println!(
                "SMT import checkpoint: idx={idx} segment=[{last_checkpoint_idx}, {idx}] \
                 lane_key={lane_key} blue_score={blue_score} leaf_hash={leaf_hash} fp={snap} proof_present=true"
            );
            last_checkpoint_idx = idx;
        }
        idx += 1;

        current_chunk.push(ImportLane { lane_key, lane_tip, blue_score, proof });
        if current_chunk.len() == CHUNK_LEN {
            chunks.push(std::mem::replace(&mut current_chunk, Vec::with_capacity(CHUNK_LEN)));
        }
    }
    if !current_chunk.is_empty() {
        chunks.push(current_chunk);
    }

    let total_lanes = idx;
    let final_fp = snapshot(&fp);
    println!("SMT import final: lanes_imported={total_lanes} segment=[{last_checkpoint_idx}, {total_lanes}] fp={final_fp}");
    println!();

    // ---- stored_lanes_root: what the syncer would advertise in SmtMetadata ----
    //
    // Mirrors `VirtualStateProcessor::get_pruning_point_smt_metadata` exactly:
    // SmtReadBounds::for_pov(pp_blue_score, finality_depth) + the same
    // canonicality predicate. This reads the syncer's branch_version tree
    // and returns the stored root at depth=0.
    let stored_lanes_root = smt_stores.get_lanes_root(bounds, make_canonical());

    // ---- fresh_recompute_root: pure-leaf rebuild via compute_root_update ----
    //
    // Same algorithm the live processor uses for incremental block applies,
    // but applied here with an EMPTY in-memory store and `current_root =
    // empty_root` — i.e. it derives the tree purely from the iter-walk
    // leaves, ignoring any pre-existing tree on disk. This is the
    // ground-truth root for a leaf set: if both `stored` and `streamed`
    // are correct implementations, they must each equal `fresh_recompute`.
    //
    // 3-way comparison (read with `streamed` and `stored` below):
    //   fresh == streamed, fresh != stored → live-incremental wrote the
    //     wrong tree (or `branch_version` is missing/extra leaves).
    //   fresh == stored,   fresh != streamed → `streaming_import` has a
    //     bug for this leaf distribution.
    //   fresh distinct from both → leaf-set-dependent bug in one of them.
    println!("[fresh_recompute_root] running compute_root_update over an empty BTreeSmtStore ...");
    let mut leaf_updates: Vec<LeafUpdate> = Vec::with_capacity(total_lanes as usize);
    for chunk in &chunks {
        for lane in chunk {
            let leaf_hash = smt_leaf_hash(&SmtLeafInput { lane_tip: &lane.lane_tip, blue_score: lane.blue_score });
            leaf_updates.push(LeafUpdate { key: lane.lane_key, leaf_hash });
        }
    }
    let sorted = SortedLeafUpdates::from_unsorted(leaf_updates);
    let btree_store = BTreeSmtStore::new();
    let (fresh_recompute_root, _changes) =
        compute_root_update::<SeqCommitActiveNode, _>(&btree_store, SeqCommitActiveNode::empty_root(), sorted)
            .expect("compute_root_update failed");

    // ---- streamed_lanes_root: rebuild via streaming_import on a temp DB ----
    //
    // Same lane stream we just walked, fed through the streaming builder
    // with a fresh, empty DB as sink. The streaming builder walks bottom-up
    // over sorted leaves and is structurally different from
    // `compute_root_update`'s top-down recursion — agreement of the two on
    // the same leaf set is non-trivial.
    println!("[streamed_lanes_root] rebuilding via streaming_import on a temp DB ...");
    let (_lt, temp_db) = create_temp_db!(ConnBuilder::default().with_files_limit(64));
    let temp_stores = SmtStores::new(temp_db.clone(), 1, 1);
    // Pass `stored_lanes_root` as `lanes_root` so streaming_import's own
    // mismatch-detection / localization fires automatically if the rebuilt
    // root differs.
    let result =
        streaming_import(&temp_db, &temp_stores, max_score, ZERO_HASH, total_lanes, stored_lanes_root, chunks.into_iter(), 4096)
            .expect("streaming_import failed");
    let streamed_lanes_root = result.root;

    println!();
    println!("[roots]");
    println!("  stored_lanes_root        = {stored_lanes_root}    (live tree via smt_stores.get_lanes_root)");
    println!("  streamed_lanes_root      = {streamed_lanes_root}    (bottom-up streaming_import on iter walk)");
    println!("  fresh_recompute_root     = {fresh_recompute_root}    (top-down compute_root_update on empty BTreeSmtStore)");
    let stored_eq_streamed = stored_lanes_root == streamed_lanes_root;
    let stored_eq_fresh = stored_lanes_root == fresh_recompute_root;
    let streamed_eq_fresh = streamed_lanes_root == fresh_recompute_root;
    println!();
    println!("  stored == streamed       = {}", if stored_eq_streamed { "MATCH" } else { "MISMATCH" });
    println!("  stored == fresh          = {}", if stored_eq_fresh { "MATCH" } else { "MISMATCH" });
    println!("  streamed == fresh        = {}", if streamed_eq_fresh { "MATCH" } else { "MISMATCH" });
    println!();
    println!("Interpretation:");
    match (stored_eq_streamed, stored_eq_fresh, streamed_eq_fresh) {
        (true, true, true) => {
            println!("  All three agree — no divergence. If a receiver still computes a different");
            println!("  root from this peer's stream, the divergence is in the wire path or the");
            println!("  receiver's own DB writes.");
        }
        (false, false, true) => {
            println!("  streamed and fresh agree, stored disagrees → both leaf-based builders agree");
            println!("  on the iter-walk lane set, but the LIVE tree on disk doesn't reflect that");
            println!("  set. Most likely: branch_version is missing or has extra Collapsed leaves");
            println!("  vs lane_version (incremental write-path bug or expire/prune divergence).");
        }
        (false, true, false) => {
            println!("  stored and fresh agree, streamed disagrees → `streaming_import` builds a");
            println!("  different tree than `compute_root_update` for this specific leaf set. The");
            println!("  bug is in the streaming builder; capture this lane set as a regression.");
        }
        (true, false, false) => {
            println!("  stored and streamed agree, fresh disagrees → both DB-using paths agree but");
            println!("  the in-memory pure-recompute differs. This would mean `compute_root_update`");
            println!("  reads stale data from the empty BTreeSmtStore — almost certainly a tooling");
            println!("  bug here; treat with skepticism.");
        }
        (false, false, false) => {
            println!("  All three disagree — the leaf set or hashing is non-deterministic, or there");
            println!("  are multiple bugs interacting. Capture this snapshot for offline analysis.");
        }
        _ => {
            println!("  (Unexpected match pattern — review raw values above.)");
        }
    }

    // ---- Leaf-set diff: iter walk vs branch_version DFS ----
    //
    // Both streams emit `(lane_key, leaf_hash)` in strictly ascending
    // lane_key order — iter walk by RocksDB lane_version key prefix order
    // and `LeafDfs` by SMT path order, both of which equal lex order on
    // the 32-byte lane_key. We merge-step them in O(1) memory and emit
    // exact `only_in_iter` / `only_in_tree` / `value_mismatch` lane keys
    // (sample-bounded). This is what tells us *which* lanes the live tree
    // disagrees with the iter export on.
    println!();
    println!("[leaf_set_diff] iter_all_canonical_owned vs branch_version DFS");
    println!("  Streaming both sorted-by-lane_key sources and merge-stepping.");
    println!("  Sample bound: up to {DIFF_SAMPLE_LIMIT} lane_keys per category.");
    println!();

    // Re-iterate &chunks (still in scope until streaming_import consumed it
    // — careful: it was moved). We need a sorted (lane_key, leaf_hash)
    // stream from iter walk; we materialised one earlier as `leaf_updates`,
    // but that was moved into `compute_root_update`. Easiest fix: re-derive
    // from a fresh canonical iter — small marginal cost vs the DFS itself.
    let iter_for_diff = smt_stores
        .lane_version
        .iter_all_canonical_owned(None, min_score, Some(max_score), make_canonical())
        .map(|res| {
            let (lane_key, verified) = res.expect("lane iter (diff pass) error");
            let lane_tip = *verified.data();
            let blue_score = verified.blue_score();
            let leaf_hash = smt_leaf_hash(&SmtLeafInput { lane_tip: &lane_tip, blue_score });
            (lane_key, leaf_hash)
        });
    let dfs = LeafDfs::new(&smt_stores, bounds, make_canonical());
    let DiffSummary { iter_count, tree_count, only_in_iter_count, only_in_tree_count, value_mismatch_count } =
        run_diff(iter_for_diff, dfs);

    println!("  iter_count           = {iter_count}");
    println!("  tree_count           = {tree_count}");
    println!("  only_in_iter         = {only_in_iter_count}    (lane_version has but branch_version's canonical view does not)");
    println!("  only_in_tree         = {only_in_tree_count}    (branch_version has but iter_all_canonical_owned skipped)");
    println!("  value_mismatch       = {value_mismatch_count}    (same lane_key, different leaf_hash → divergent (lane_tip, blue_score))");

    println!("\n{SECTION}");
    println!("Done. Total lanes seen: {total_lanes}");
    println!("{SECTION}");
}

const DIFF_SAMPLE_LIMIT: usize = 50;

#[derive(Default)]
struct DiffSummary {
    iter_count: u64,
    tree_count: u64,
    only_in_iter_count: u64,
    only_in_tree_count: u64,
    value_mismatch_count: u64,
}

/// Merge-step two ascending `(lane_key, leaf_hash)` streams, printing a
/// bounded sample of every kind of difference and accumulating totals.
fn run_diff(
    mut iter_stream: impl Iterator<Item = (Hash, Hash)>,
    mut tree_stream: impl Iterator<Item = (Hash, Hash)>,
) -> DiffSummary {
    let mut summary = DiffSummary::default();
    let mut only_in_iter_printed = 0usize;
    let mut only_in_tree_printed = 0usize;
    let mut mismatch_printed = 0usize;

    let mut a = iter_stream.next();
    let mut b = tree_stream.next();

    loop {
        match (a, b) {
            (None, None) => break,
            (Some((ka, _va)), None) => {
                summary.iter_count += 1;
                summary.only_in_iter_count += 1;
                if only_in_iter_printed < DIFF_SAMPLE_LIMIT {
                    println!("  only_in_iter:   {ka}");
                    only_in_iter_printed += 1;
                }
                a = iter_stream.next();
            }
            (None, Some((kb, _vb))) => {
                summary.tree_count += 1;
                summary.only_in_tree_count += 1;
                if only_in_tree_printed < DIFF_SAMPLE_LIMIT {
                    println!("  only_in_tree:   {kb}");
                    only_in_tree_printed += 1;
                }
                b = tree_stream.next();
            }
            (Some((ka, va)), Some((kb, vb))) => match ka.cmp(&kb) {
                std::cmp::Ordering::Less => {
                    summary.iter_count += 1;
                    summary.only_in_iter_count += 1;
                    if only_in_iter_printed < DIFF_SAMPLE_LIMIT {
                        println!("  only_in_iter:   {ka}");
                        only_in_iter_printed += 1;
                    }
                    a = iter_stream.next();
                }
                std::cmp::Ordering::Greater => {
                    summary.tree_count += 1;
                    summary.only_in_tree_count += 1;
                    if only_in_tree_printed < DIFF_SAMPLE_LIMIT {
                        println!("  only_in_tree:   {kb}");
                        only_in_tree_printed += 1;
                    }
                    b = tree_stream.next();
                }
                std::cmp::Ordering::Equal => {
                    summary.iter_count += 1;
                    summary.tree_count += 1;
                    if va != vb {
                        summary.value_mismatch_count += 1;
                        if mismatch_printed < DIFF_SAMPLE_LIMIT {
                            println!("  value_mismatch: {ka}    iter_leaf={va} tree_leaf={vb}");
                            mismatch_printed += 1;
                        }
                    }
                    a = iter_stream.next();
                    b = tree_stream.next();
                }
            },
        }
    }

    summary
}

fn snapshot(fp: &blake3::Hasher) -> Hash {
    let mut out = [0u8; 32];
    out.copy_from_slice(fp.finalize().as_bytes());
    Hash::from_bytes(out)
}

/// In-order DFS walker over `branch_version`'s canonical view, yielding
/// `Collapsed` leaves as `(lane_key, leaf_hash)` in **strictly ascending
/// lane_key order** (SMT path order = bit-prefix order = lex order on the
/// 32-byte key). Streams in O(stack depth) memory — no full-set
/// materialisation — so we can merge-diff against the equally-sorted
/// `iter_all_canonical_owned` stream in O(1) auxiliary memory.
struct LeafDfs<'a, F: Fn(Hash) -> bool> {
    stores: &'a SmtStores,
    bounds: SmtReadBounds,
    is_canonical: F,
    /// Subtrees yet to descend into, in pop-order = visit-order.
    /// Each entry is the `(depth, key_prefix)` of an internal subtree we
    /// haven't visited; we resolve `get_node` lazily inside `next()`.
    /// Empty subtrees (`None` reads) and Collapsed terminals don't sit on
    /// the stack — Internals push their two children on encounter.
    stack: Vec<(u8, Hash)>,
}

impl<'a, F: Fn(Hash) -> bool> LeafDfs<'a, F> {
    fn new(stores: &'a SmtStores, bounds: SmtReadBounds, is_canonical: F) -> Self {
        // Start from the root: depth=0, normalized key all-zero.
        Self { stores, bounds, is_canonical, stack: vec![(0, Hash::from_bytes([0u8; 32]))] }
    }
}

impl<F: Fn(Hash) -> bool> Iterator for LeafDfs<'_, F> {
    type Item = (Hash, Hash); // (lane_key, leaf_hash)

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((depth, key_prefix)) = self.stack.pop() {
            let bk = kaspa_smt::store::BranchKey::new(depth, &key_prefix);
            let entity = BranchEntity { depth, node_key: bk.node_key };
            let node = self.stores.get_node(entity, self.bounds, |bh| (self.is_canonical)(bh)).and_then(|v| *v.data());
            match node {
                Some(Node::Internal(_)) => {
                    // Push right then left so left is visited first → in-order traversal.
                    let mut right = bk.node_key.as_bytes();
                    right[depth as usize / 8] |= 1u8 << (7 - (depth as usize % 8));
                    let right = Hash::from_bytes(right);
                    let left = bk.node_key;
                    let next_depth = depth + 1;
                    self.stack.push((next_depth, right));
                    self.stack.push((next_depth, left));
                }
                Some(Node::Collapsed(cl)) => {
                    return Some((cl.lane_key, cl.leaf_hash));
                }
                None => {
                    // Empty subtree — keep popping.
                }
            }
        }
        None
    }
}

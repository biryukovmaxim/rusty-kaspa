//! Streaming import of pruning-point SMT lanes.
//!
//! Processes sorted lanes in chunks: parallel leaf hashing via rayon,
//! then feeds to [`StreamingSmtBuilder`] with [`DbSink`] for batched DB writes.

use kaspa_smt::SmtHasher;
mod db_sink;

use std::time::Instant;

use std::collections::BTreeMap;

use kaspa_consensus_core::api::{ImportLane, SMT_PROOF_INTERVAL};
use kaspa_database::prelude::{BatchDbWriter, DB, StoreError};
use kaspa_hashes::{Hash, SeqCommitActiveNode, blake3};
use kaspa_seq_commit::hashing::smt_leaf_hash;
use kaspa_seq_commit::types::SmtLeafInput;
use kaspa_smt::proof::{OwnedSmtProof, ProofBranchCache};
use kaspa_smt::store::Node;
use kaspa_smt::streaming::{StreamError, StreamingSmtBuilder};
use log::{info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::IndexedParallelIterator;
use rocksdb::WriteBatch;

use crate::BlockHash;
use crate::keys::ScoreIndexKind;
use crate::processor::SmtStores;

use db_sink::DbSink;

pub struct StreamingImportResult {
    pub root: Hash,
    pub lanes_imported: u64,
    pub nodes_written: usize,
}

/// Rolling fingerprint over `(lane_key || leaf_hash || blue_score_le)` per lane.
///
/// Identifies the divergent segment when the streaming root mismatches: the
/// expected `lanes_root`. The receiver logs a snapshot of this hash at every
/// proof-bearing lane (every `SMT_PROOF_INTERVAL` lanes — by construction the
/// same boundaries the wire layer uses), and the standalone
/// `dump_smt_export` example reproduces the same fingerprints from a syncer
/// DB. Matching prefix → that segment is fine; first divergent fingerprint
/// → the bad lanes are between the previous checkpoint and that one.
fn fingerprint_lane(fp: &mut blake3::Hasher, lane_key: &Hash, leaf_hash: &Hash, blue_score: u64) {
    fp.update(&lane_key.as_bytes());
    fp.update(&leaf_hash.as_bytes());
    fp.update(&blue_score.to_le_bytes());
}

fn fingerprint_snapshot(fp: &blake3::Hasher) -> Hash {
    let mut out = [0u8; 32];
    out.copy_from_slice(fp.finalize().as_bytes());
    Hash::from_bytes(out)
}

/// One proof-bearing lane retained for divergence localization on root mismatch.
struct ProofAnchor {
    idx: u64,
    lane_key: Hash,
    leaf_hash: Hash,
    proof: OwnedSmtProof,
}

/// Locate the divergence between the streaming-built tree and the expected one.
///
/// Each retained proof is a Merkle path: `verify_cached` against the EXPECTED
/// `lanes_root` populates `ProofBranchCache` with the expected `Internal` hash
/// at every `(depth, node_key)` on the proof's path (depths `0..terminal.depth`).
/// We then read the actual `Internal` the streaming import wrote at each of
/// those positions in `branch_version` and report the shallowest divergence
/// per anchor.
///
/// With 6 anchors over a 6 M-lane import, the union of (depth, normalized_key)
/// divergences narrows the bad subtree — the bad lane(s) live below the
/// shallowest mismatched depth on at least one anchor's path.
fn localize_divergence(stores: &SmtStores, lanes_root: Hash, computed_root: Hash, anchors: &[ProofAnchor]) {
    warn!("=== SMT root mismatch localization (anchors={}) ===", anchors.len());
    warn!("expected_lanes_root={lanes_root}");
    warn!("computed_root      ={computed_root}");

    for anchor in anchors {
        let mut cache = ProofBranchCache::new();
        let verify_ok = anchor
            .proof
            .as_proof()
            .verify_cached::<SeqCommitActiveNode>(&anchor.lane_key, Some(anchor.leaf_hash), lanes_root, &mut cache)
            .unwrap_or(false);

        warn!(
            "anchor idx={} lane_key={} leaf_hash={} proof_path_len={} verifies_against_expected={}",
            anchor.idx,
            anchor.lane_key,
            anchor.leaf_hash,
            cache.len(),
            verify_ok,
        );

        // BTreeMap iterates by BranchKey (depth ascending, then node_key) — shallow first.
        let mut shallowest: Option<(u8, Hash)> = None;
        let mut last_match_depth: Option<u8> = None;
        let mut mismatches = 0usize;
        let mut compared = 0usize;

        for (bk, expected_hash) in cache.iter() {
            // Read the actual stored entry. IBD entries use ZERO_HASH as block_hash and
            // are written exactly once per (depth, node_key) by the streaming sink, so
            // the newest version (target=u64::MAX, min=0) is the import-written value.
            let actual_first = stores.branch_version.get_at(bk.depth, bk.node_key, u64::MAX, 0).next();
            compared += 1;
            let actual_hash: Option<Hash> = match actual_first {
                Some(Ok(fork)) => match *fork.data() {
                    Some(Node::Internal(h)) => Some(h),
                    Some(Node::Collapsed(_)) => None, // structural mismatch: expected Internal here
                    None => None,                     // tombstone
                },
                Some(Err(_)) | None => None,
            };

            if actual_hash != Some(*expected_hash) {
                mismatches += 1;
                if shallowest.is_none() {
                    shallowest = Some((bk.depth, *expected_hash));
                    let actual_str = match actual_hash {
                        Some(h) => format!("Internal({h})"),
                        None => "absent_or_collapsed".to_string(),
                    };
                    warn!(
                        "  shallowest divergence: depth={} node_key={} expected_internal={} actual={}",
                        bk.depth, bk.node_key, expected_hash, actual_str,
                    );
                }
            } else if shallowest.is_none() {
                // Track the deepest still-matching ancestor (only meaningful while no mismatch yet).
                last_match_depth = Some(bk.depth);
            }
        }

        match shallowest {
            Some((d, _)) => {
                let last_ok = last_match_depth.map(|x| x as i32).unwrap_or(-1);
                warn!(
                    "  anchor summary: matched up to depth={} ; first divergence at depth={} ; \
                     mismatches/compared={}/{} → bad lanes are within the subtree rooted at \
                     (depth={}, node_key=BranchKey::new({}, anchor.lane_key))",
                    last_ok, d, mismatches, compared, d, d,
                );
            }
            None => {
                warn!(
                    "  anchor summary: every ancestor on this lane's path matches the DB. \
                     The divergence must be off this lane's path (i.e., in a subtree this \
                     proof does not cover)."
                );
            }
        }
    }
    warn!("=== end SMT root mismatch localization ===");
}

struct ImportProgress {
    total_lanes: u64,
    lanes_processed: u64,
    last_log_time: Instant,
}

impl ImportProgress {
    fn new(total_lanes: u64) -> Self {
        Self { total_lanes, lanes_processed: 0, last_log_time: Instant::now() }
    }

    fn report(&mut self, delta: usize) {
        self.lanes_processed += delta as u64;
        let now = Instant::now();
        if now.duration_since(self.last_log_time) >= std::time::Duration::from_secs(2) {
            let pct = (self.lanes_processed as f64 / self.total_lanes as f64 * 100.0) as u32;
            info!("SMT import {} of {} ({}%)", self.lanes_processed, self.total_lanes, pct);
            self.last_log_time = now;
        }
    }

    fn report_completion(&self) {
        info!("SMT import complete ({} lanes)", self.lanes_processed);
    }
}

/// Streams pre-chunked lane batches into the tree builder.
///
/// `chunks` yields `Vec<ImportLane>` already sized by the upstream
/// wire-level chunker (see `SMT_CHUNK_SIZE` in `protocol/flows/src/ibd/streams.rs`).
/// Each incoming Vec is processed as one step — parallel leaf hashing, proof
/// verification, DB batching, and `builder.feed`. No internal re-batching or
/// accumulator.
///
/// `max_batch_entries` remains the RocksDB `WriteBatch` flush threshold for
/// lane/score-index writes; it is independent of the incoming chunk size.
pub fn streaming_import(
    db: &DB,
    stores: &SmtStores,
    pp_blue_score: u64,
    block_hash: BlockHash,
    total_count: u64,
    lanes_root: Hash,
    chunks: impl Iterator<Item = Vec<ImportLane>>,
    max_batch_entries: usize,
) -> Result<StreamingImportResult, StreamError<StoreError>> {
    if total_count == 0 {
        return Ok(StreamingImportResult { root: SeqCommitActiveNode::empty_root(), lanes_imported: 0, nodes_written: 0 });
    }

    info!(
        "SMT import starting: total_count={total_count}, expected_lanes_root={lanes_root}, pp_blue_score={pp_blue_score}, \
         proof_interval={SMT_PROOF_INTERVAL}"
    );

    // `branch_version` writes are versioned per-leaf (see `DbSink::write_node`)
    // so they age out of the read window at the same rate the live processor
    // would have produced. The sink itself doesn't need a sink-wide bs.
    let sink = DbSink::new(db, stores, block_hash, max_batch_entries);
    let mut builder = StreamingSmtBuilder::<SeqCommitActiveNode, _>::new(total_count, sink);
    let mut lane_batch = WriteBatch::default();
    let mut batch_count = 0usize;
    let mut batch_id = 0u32;
    let mut score_groups: BTreeMap<u64, Vec<Hash>> = BTreeMap::new();
    let mut lanes_imported = 0u64;
    let mut progress = ImportProgress::new(total_count);
    let mut leaf_hashes: Vec<(Hash, Hash)> = Vec::new();
    let mut fp = blake3::Hasher::new();
    let mut last_checkpoint_idx: u64 = 0;
    // Retained for divergence localization. With SMT_PROOF_INTERVAL = 1<<20
    // and 6 M lanes this is at most ~6 entries — cheap to keep.
    let mut proof_anchors: Vec<ProofAnchor> = Vec::new();

    for chunk in chunks {
        if chunk.is_empty() {
            continue;
        }

        chunk
            .par_iter()
            .map(|lane: &ImportLane| {
                let leaf_hash = smt_leaf_hash(&SmtLeafInput { lane_tip: &lane.lane_tip, blue_score: lane.blue_score });
                (lane.lane_key, leaf_hash)
            })
            .collect_into_vec(&mut leaf_hashes);

        // Verify proofs against the expected lanes_root.
        for (lane, &(lane_key, leaf_hash)) in chunk.iter().zip(leaf_hashes.iter()) {
            let Some(proof) = &lane.proof else { continue };
            let Ok(true) = proof.verify::<SeqCommitActiveNode>(&lane_key, Some(leaf_hash), lanes_root) else {
                return Err(StreamError::ProofFailed(format!("lane {lane_key}")));
            };
        }

        write_lane_versions(stores, block_hash, &chunk, &mut lane_batch, &mut batch_count)?;
        write_score_index(stores, pp_blue_score, block_hash, &chunk, &mut score_groups, &mut lane_batch, &mut batch_count, batch_id)?;

        if batch_count >= max_batch_entries {
            db.write(std::mem::take(&mut lane_batch)).map_err(|e| StreamError::Sink(StoreError::DbError(e)))?;
            batch_count = 0;
        }
        batch_id += 1;

        for (i, (lane, &(lane_key, leaf_hash))) in chunk.iter().zip(leaf_hashes.iter()).enumerate() {
            let global_idx = lanes_imported + i as u64;
            fingerprint_lane(&mut fp, &lane_key, &leaf_hash, lane.blue_score);

            // Boundaries match the wire encoder (`SmtStream` in
            // `protocol/flows/src/ibd/streams.rs`): a proof is attached at
            // lane indices that are multiples of `SMT_PROOF_INTERVAL`. We
            // log a fingerprint snapshot at each so the receiver's stream
            // can be diffed segment-by-segment against the syncer's
            // `iter_all_canonical_owned` walk (use the
            // `dump_smt_export` example to produce the matching fingerprints).
            if (global_idx as usize).is_multiple_of(SMT_PROOF_INTERVAL) {
                let snap = fingerprint_snapshot(&fp);
                info!(
                    "SMT import checkpoint: idx={global_idx} segment=[{last_checkpoint_idx}, {global_idx}] \
                     lane_key={lane_key} blue_score={} leaf_hash={leaf_hash} fp={snap} proof_present={}",
                    lane.blue_score,
                    lane.proof.is_some(),
                );
                last_checkpoint_idx = global_idx;
            }

            if let Some(proof) = &lane.proof {
                proof_anchors.push(ProofAnchor { idx: global_idx, lane_key, leaf_hash, proof: proof.clone() });
            }

            builder.feed(lane_key, leaf_hash, lane.blue_score)?;
        }
        lanes_imported += chunk.len() as u64;
        progress.report(chunk.len());
    }

    progress.report_completion();

    let final_fp = fingerprint_snapshot(&fp);
    info!("SMT import final: lanes_imported={lanes_imported} segment=[{last_checkpoint_idx}, {lanes_imported}] fp={final_fp}");

    let (root, mut sink) = builder.finish()?;
    sink.flush_batch().map_err(StreamError::Sink)?;
    flush_lane_batch(db, lane_batch, batch_count)?;

    if root == lanes_root {
        info!("SMT import root: computed={root} expected={lanes_root} MATCH");
    } else {
        warn!("SMT import root: computed={root} expected={lanes_root} MISMATCH");
        localize_divergence(stores, lanes_root, root, &proof_anchors);
    }

    Ok(StreamingImportResult { root, lanes_imported, nodes_written: sink.nodes_written() })
}

fn write_score_index(
    stores: &SmtStores,
    pp_blue_score: u64,
    block_hash: BlockHash,
    chunk: &[ImportLane],
    score_groups: &mut BTreeMap<u64, Vec<Hash>>,
    batch: &mut WriteBatch,
    batch_count: &mut usize,
    batch_id: u32,
) -> Result<(), StreamError<StoreError>> {
    // LeafUpdate: grouped by each lane's own blue_score
    score_groups.clear();
    for lane in chunk {
        score_groups.entry(lane.blue_score).or_default().push(lane.lane_key);
    }
    for (bs, keys) in score_groups.iter() {
        stores
            .score_index
            .put_batched(BatchDbWriter::new(batch), *bs, ScoreIndexKind::LeafUpdate, block_hash, keys, batch_id)
            .map_err(StreamError::Sink)?;
        *batch_count += 1;
    }

    // Structural: all lanes at the pruning point's blue_score.
    //
    // We intentionally keep these at `pp_blue_score` (not the per-lane bs).
    // `Structural` describes the structural snapshot at the pruning point —
    // distinct from the per-lane `LeafUpdate` history. After the bs-keying
    // fix to `branch_version`, prune-time delete-key derivation
    // (`processor::prune_chunk`) will emit no-op delete keys at depths
    // where no entry at `pp_blue_score` exists; RocksDB tolerates that and
    // the cost is negligible because pruning is rare. Do not "fix" this
    // to lane_bs — it would erase the structural-snapshot semantic.
    let all_keys: Vec<Hash> = chunk.iter().map(|l| l.lane_key).collect();
    stores
        .score_index
        .put_batched(BatchDbWriter::new(batch), pp_blue_score, ScoreIndexKind::Structural, block_hash, &all_keys, batch_id)
        .map_err(StreamError::Sink)?;
    *batch_count += 1;

    Ok(())
}

fn write_lane_versions(
    stores: &SmtStores,
    block_hash: BlockHash,
    chunk: &[ImportLane],
    lane_batch: &mut WriteBatch,
    lane_batch_count: &mut usize,
) -> Result<(), StreamError<StoreError>> {
    // Writes go directly to the DB lane-version store and intentionally skip
    // the in-memory lane cache. `SmtStores::get_lane` treats a cache hit as
    // authoritative (see the newest-suffix invariant in `crate::cache`), so
    // bypassing the cache is safe only because IBD SMT import runs after
    // `SmtStores::clear_all()` has emptied both the DB stores and the caches.
    // Thus there can be no stale cached lane versions disagreeing with the
    // imported DB state. After import the caches remain cold, and reads fall
    // back to DB until later incremental writes repopulate them.
    for lane in chunk {
        stores
            .lane_version
            .put(BatchDbWriter::new(lane_batch), lane.lane_key, lane.blue_score, block_hash, &lane.lane_tip)
            .map_err(StreamError::Sink)?;
    }
    // One RocksDB entry per lane — account for them as a single bump so the
    // flush threshold in `streaming_import` trips after roughly every
    // `max_batch_entries` lanes regardless of chunk size.
    *lane_batch_count += chunk.len();
    Ok(())
}

fn flush_lane_batch(db: &DB, lane_batch: WriteBatch, count: usize) -> Result<(), StreamError<StoreError>> {
    if count > 0 {
        db.write(lane_batch).map_err(|e| StreamError::Sink(StoreError::DbError(e)))?;
    }
    Ok(())
}

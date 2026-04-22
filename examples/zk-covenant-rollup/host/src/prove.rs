use std::rc::Rc;

use risc0_zkvm::{ExecutorEnv, ExternalProver, LocalProver, Prover, ProverOpts, Receipt};
use zk_covenant_rollup_core::PublicInput;
use zk_covenant_rollup_methods::ZK_COVENANT_ROLLUP_GUEST_ELF;

use crate::mock_tx::ZkTransaction;

/// Which risc0 prover backend to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverBackend {
    /// Local in-process prover. Uses CPU normally, GPU when built with `cuda` feature.
    Local,
    /// External prover via `r0vm` subprocess (IPC over Unix socket).
    Ipc,
}

impl ProverBackend {
    pub fn label(&self) -> &'static str {
        match self {
            ProverBackend::Local => {
                if cfg!(feature = "cuda") {
                    "Local (GPU)"
                } else {
                    "Local (CPU)"
                }
            }
            ProverBackend::Ipc => "IPC (r0vm)",
        }
    }

    pub fn next(self) -> Self {
        match self {
            ProverBackend::Local => ProverBackend::Ipc,
            ProverBackend::Ipc => ProverBackend::Local,
        }
    }
}

/// Which type of proof to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// STARK-based succinct proof (constant size).
    Succinct,
    /// Groth16 SNARK proof (smallest, requires Docker for proving).
    Groth16,
}

impl ProofKind {
    pub fn label(&self) -> &'static str {
        match self {
            ProofKind::Succinct => "Succinct (STARK)",
            ProofKind::Groth16 => "Groth16 (SNARK)",
        }
    }

    pub fn all() -> &'static [ProofKind] {
        &[ProofKind::Succinct, ProofKind::Groth16]
    }
}

/// All data needed to produce a ZK proof for a batch of rollup blocks.
///
/// Only blocks with rollup-lane activity appear here. `block_lane_txs[i]`
/// holds the lane txs of block `i` in global-merge-idx order;
/// `block_lane_merge_idxs[i][j]` is the global `merge_idx` of
/// `block_lane_txs[i][j]` in that block's `AcceptedTxList` — i.e. its
/// position among **all** accepted txs of the block's mergeset, not among
/// lane-only txs. Non-lane txs are never fetched nor sent to the guest.
pub struct ProveInput {
    /// Public input committed to the proof (prev state, prev seq, covenant ID).
    pub public_input: PublicInput,
    /// Only the rollup-lane txs per block, ordered by global merge_idx.
    pub block_lane_txs: Vec<Vec<ZkTransaction>>,
    /// Global `merge_idx` of each lane tx in its block's full AcceptedTxList
    /// (parallel to `block_lane_txs`).
    pub block_lane_merge_idxs: Vec<Vec<u32>>,
    /// Per-block context hashes (host precomputes `mergeset_context_hash`).
    pub block_context_hashes: Vec<[u32; 8]>,
    /// Commitment witness header (Pod).
    pub commitment_witness: zk_covenant_rollup_core::CommitmentWitness,
    /// Serialized SMT proof for the rollup lane.
    pub smt_proof_bytes: Vec<u8>,
    /// Converged permission redeem script length (only if exits occurred).
    pub perm_redeem_script_len: Option<i64>,
}

/// Successful proof output.
pub struct ProveOutput {
    /// The full receipt (contains journal + inner proof).
    pub receipt: Receipt,
    /// Proving statistics (segments, cycles).
    pub stats: risc0_zkvm::SessionStats,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u128,
}

/// Run the risc0 prover and return the proof or an error message.
///
/// This function is blocking and CPU-intensive. Call it from
/// `tokio::task::spawn_blocking` or a dedicated thread.
///
/// Panics inside the prover (e.g. OOM) are caught and returned as `Err`.
pub fn prove(input: &ProveInput, backend: ProverBackend, kind: ProofKind) -> Result<ProveOutput, String> {
    let env = build_env(input).map_err(|e| format!("Failed to build executor env: {e}"))?;
    let prover = get_prover(backend)?;

    let opts = match kind {
        ProofKind::Succinct => ProverOpts::succinct(),
        ProofKind::Groth16 => ProverOpts::groth16(),
    };

    let now = std::time::Instant::now();
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove_with_opts(env, ZK_COVENANT_ROLLUP_GUEST_ELF, &opts)));
    let elapsed_ms = now.elapsed().as_millis();

    match result {
        Ok(Ok(info)) => Ok(ProveOutput { receipt: info.receipt, stats: info.stats, elapsed_ms }),
        Ok(Err(e)) => Err(format!("Proving failed: {e}")),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            Err(format!("Prover panicked: {msg}"))
        }
    }
}

/// Compute the permission redeem script length for a set of exit leaves.
///
/// Returns `None` if `perm_count == 0` (no exits).
pub fn compute_perm_redeem_script_len(perm_root: &[u32; 8], perm_count: u32) -> Option<i64> {
    if perm_count == 0 {
        return None;
    }
    let depth = zk_covenant_rollup_core::permission_tree::required_depth(perm_count as usize);
    let padded_root = zk_covenant_rollup_core::permission_tree::pad_to_depth(*perm_root, perm_count, depth);
    let redeem = zk_covenant_rollup_core::permission_script::build_permission_redeem_bytes_converged(
        &padded_root,
        perm_count as u64,
        depth,
        zk_covenant_rollup_core::MAX_DELEGATE_INPUTS,
    );
    Some(redeem.len() as i64)
}

fn get_prover(backend: ProverBackend) -> Result<Rc<dyn Prover>, String> {
    match backend {
        ProverBackend::Local => Ok(Rc::new(LocalProver::new("local"))),
        ProverBackend::Ipc => {
            let r0vm_path = find_r0vm()?;
            Ok(Rc::new(ExternalProver::new("ipc", r0vm_path)))
        }
    }
}

fn find_r0vm() -> Result<std::path::PathBuf, String> {
    if let Ok(path) = std::env::var("RISC0_SERVER_PATH") {
        let p = std::path::PathBuf::from(&path);
        if p.is_file() {
            return Ok(p);
        }
    }
    // Fall back to bare name — OS will resolve via PATH.
    Ok(std::path::PathBuf::from("r0vm"))
}

fn build_env(input: &ProveInput) -> Result<ExecutorEnv<'_>, String> {
    let mut binding = ExecutorEnv::builder();
    let builder = binding
        .write_slice(core::slice::from_ref(&input.public_input))
        .write_slice(&(input.block_lane_txs.len() as u32).to_le_bytes());

    for (i, lane_txs) in input.block_lane_txs.iter().enumerate() {
        let lane_count = lane_txs.len() as u32;
        builder.write_slice(&lane_count.to_le_bytes());
        if lane_count > 0 {
            // Context hash only when the lane is active in this block
            builder.write_slice(bytemuck::cast_slice::<u32, u8>(&input.block_context_hashes[i]));
            for (j, tx) in lane_txs.iter().enumerate() {
                let merge_idx = input.block_lane_merge_idxs[i][j];
                builder.write_slice(&merge_idx.to_le_bytes());
                tx.write_to_env(builder);
            }
        }
    }

    // Write commitment witness as Pod (single slice) + SMT proof (length-prefixed)
    builder.write_slice(bytemuck::bytes_of(&input.commitment_witness));
    crate::mock_tx::write_bytes(builder, &input.smt_proof_bytes);

    // Write permission redeem script length if exits occurred
    if let Some(len) = input.perm_redeem_script_len {
        builder.write_slice(&(len as u32).to_le_bytes());
    }

    builder.build().map_err(|e| format!("Failed to build executor env: {e}"))
}

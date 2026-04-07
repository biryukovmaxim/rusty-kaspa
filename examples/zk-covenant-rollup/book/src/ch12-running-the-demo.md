# Running the Demo

> **Note:** The demo currently simulates the rollup at the transaction engine level — it does **not** connect to a live Kaspa network. The host builds a mock chain with mock blocks and transactions, generates real ZK proofs over them, and verifies the proofs through the actual on-chain script logic (covenant + permission scripts executed via `kaspa-txscript`). This validates the full proof pipeline and script verification end-to-end, without requiring a running node.

## Prerequisites

- Rust stable toolchain
- [RISC Zero](https://dev.risczero.com/api/zkvm/install) toolchain (`rzup`)

For CUDA-accelerated proving (optional):
- NVIDIA GPU with CUDA support
- CUDA toolkit installed

## Building and running

All commands must be run from the `host/` directory:

```bash
cd examples/zk-covenant-rollup/host
```

### CPU proving (default)

```bash
cargo run --release
```

### CUDA-accelerated proving

```bash
cargo run --release --features cuda
```

## What the demo does

1. Builds an initial empty SMT (sparse Merkle tree) state
2. Constructs a mock chain with L2 action transactions in the rollup lane (deposits, transfers, exits), using the KIP-21 lane-based seq-commit scheme
3. Generates a **STARK (succinct) proof** via RISC Zero and verifies it
4. Simulates on-chain verification of the STARK proof through the covenant script
5. Generates a **Groth16 proof** and verifies it
6. Simulates on-chain verification of the Groth16 proof through the covenant script
7. If exits occurred, verifies the permission script flow as well

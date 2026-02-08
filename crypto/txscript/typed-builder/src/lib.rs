mod builder;
mod conditionals;
mod introspection;
pub(crate) mod markers;
mod ops;
mod sig_builder;
mod zk;

#[cfg(test)]
mod tests;

pub use builder::*;
pub use markers::*;
pub use ops::{FixedNumInputs, PickAt, RollAt};
pub use zk::{G16Verify, R0SuccinctVerify};

// Re-export dependency types used in the public API.
pub use kaspa_consensus_core::hashing::sighash_type::SigHashType;
pub use secp256k1;

// Re-export opcode constants and ZK types used by tests and downstream consumers.
#[doc(hidden)]
pub use kaspa_txscript::opcodes::codes::*;
#[doc(hidden)]
pub use kaspa_txscript::zk_precompiles::fields::Fr;
#[doc(hidden)]
pub use kaspa_txscript::zk_precompiles::tags::ZkTag;

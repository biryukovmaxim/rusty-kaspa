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
pub use zk::{G16FixedNumInputs, G16Verify, R0SuccinctVerify};

// Re-export opcode constants and ZK types used by tests and downstream consumers.
#[doc(hidden)]
pub use kaspa_txscript::opcodes::codes::*;
#[doc(hidden)]
pub use kaspa_txscript::zk_precompiles::fields::Fr;
#[doc(hidden)]
pub use kaspa_txscript::zk_precompiles::tags::ZkTag;

use kaspa_txscript::opcodes::codes::{OpVerify, OpZkPrecompile};
use kaspa_txscript::script_builder::{ScriptBuilder, ScriptBuilderResult};
use kaspa_txscript::zk_precompiles::tags::ZkTag;

/// Converts a RISC0 hash function name string to its byte ID.
/// Returns None for unrecognized hash function names.
pub fn hashfn_str_to_id(s: &str) -> Option<u8> {
    match s {
        "blake2b" => Some(0),
        "poseidon2" => Some(1),
        "sha256" => Some(2),
        _ => None,
    }
}

pub trait Risc0SuccinctVerify {
    /// Verifies a RISC0 Succinct (STARK) proof.
    ///
    /// Expects on stack (bottom to top):
    ///   [claim, control_index, control_digests, seal, journal_hash, image_id, control_id, hashfn]
    ///
    /// Where:
    ///   - claim: Receipt claim digest (32 bytes)
    ///   - control_index: Merkle proof leaf index (u32 LE, 4 bytes)
    ///   - control_digests: Merkle proof path digests (N × 32 bytes)
    ///   - seal: STARK proof data (Vec<u32> as LE bytes)
    ///   - journal_hash: SHA256 hash of journal (32 bytes)
    ///   - image_id: Program ID (32 bytes)
    ///   - control_id: Recursion control ID digest (32 bytes) — added by PR #957
    ///   - hashfn: Hash function ID (1 byte: 0=Blake2b, 1=Poseidon2, 2=Sha256)
    fn verify_risc0_succinct(&mut self) -> ScriptBuilderResult<&mut ScriptBuilder>;
}

impl Risc0SuccinctVerify for ScriptBuilder {
    fn verify_risc0_succinct(&mut self) -> ScriptBuilderResult<&mut ScriptBuilder> {
        // Stack: [claim, control_index, control_digests, seal, journal_hash, image_id, control_id, hashfn]
        self.add_data(&[ZkTag::R0Succinct as u8])?; // R0Succinct tag
                                                    // Stack: [..., hashfn, 0x21]
        self.add_op(OpZkPrecompile)?;
        // Stack: [true]
        self.add_op(OpVerify)
        // Stack: []
    }
}

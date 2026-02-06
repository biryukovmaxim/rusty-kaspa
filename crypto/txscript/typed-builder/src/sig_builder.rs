use std::marker::PhantomData;

use ark_serialize::CanonicalSerialize;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::zk_precompiles::fields::Fr;

use crate::builder::{R0SuccinctHashFnId, ScriptSignatureBuilder, TypedScriptBuilder};
use crate::markers::*;

// ---------------------------------------------------------------------------
// Finalize (requires single Bool on stack)
// ---------------------------------------------------------------------------

impl<M> TypedScriptBuilder<Bool<()>, M> {
    /// Returns the redeem script bytes.
    pub fn redeem_script(&self) -> &[u8] {
        self.builder.script()
    }

    /// Consumes the builder and returns a signature builder that will collect
    /// the missing inputs described by `M`.
    pub fn into_sig_builder(mut self) -> ScriptSignatureBuilder<M> {
        let redeem_script = self.builder.drain();
        ScriptSignatureBuilder { redeem_script, builder: ScriptBuilder::new(), _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide a missing number
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Num<M>> {
    /// Provide the next missing number input.
    pub fn add_i64(mut self, val: i64) -> ScriptSignatureBuilder<M> {
        self.builder.add_i64(val).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing data
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Data<M>> {
    /// Provide the next missing data input.
    pub fn add_data(mut self, data: &[u8]) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(data).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing hash
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Hash<M>> {
    /// Provide the next missing hash input.
    pub fn add_hash(mut self, hash: kaspa_hashes::Hash) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(&hash.as_bytes()).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing Bn254Fr
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<Bn254Fr<M>> {
    /// Provide the next missing BN254 field element.
    pub fn add_bn254_fr(mut self, fr: Fr) -> ScriptSignatureBuilder<M> {
        let mut bytes = Vec::new();
        fr.field().serialize_uncompressed(&mut bytes).expect("Fr serialization failed");
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — provide missing R0Succinct / G16 semantic types
// ---------------------------------------------------------------------------

impl<M> ScriptSignatureBuilder<R0SuccinctSeal<M>> {
    pub fn add_r0_succinct_seal(mut self, seal_words: &[u32]) -> ScriptSignatureBuilder<M> {
        let bytes: Vec<u8> = seal_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.builder.add_data(&bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_seal_bytes(mut self, bytes: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(bytes.len() % 4 == 0, "seal bytes length must be a multiple of 4, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctClaim<M>> {
    pub fn add_r0_succinct_claim(mut self, claim: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(claim.len() == 32, "claim must be exactly 32 bytes, got {}", claim.len());
        self.builder.add_data(claim).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctHashFn<M>> {
    pub fn add_r0_succinct_hashfn(mut self, id: R0SuccinctHashFnId) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(&[u8::from(id)]).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_hashfn_raw(mut self, id: u8) -> ScriptSignatureBuilder<M> {
        assert!(id <= 2, "hash function id must be 0, 1, or 2, got {id}");
        self.builder.add_data(&[id]).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_hashfn_bytes(mut self, bytes: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(bytes.len() == 1, "hashfn bytes must be exactly 1 byte, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctControlIndex<M>> {
    pub fn add_r0_succinct_control_index(mut self, index: u32) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(&index.to_le_bytes()).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
    pub fn add_r0_succinct_control_index_bytes(mut self, bytes: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(bytes.len() == 4, "control index must be exactly 4 bytes, got {}", bytes.len());
        self.builder.add_data(bytes).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctControlDigests<M>> {
    pub fn add_r0_succinct_control_digests(mut self, digests: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(digests.len() % 32 == 0, "control digests length must be a multiple of 32, got {}", digests.len());
        self.builder.add_data(digests).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctJournalDigest<M>> {
    pub fn add_r0_succinct_journal_digest(mut self, digest: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(digest.len() == 32, "journal digest must be exactly 32 bytes, got {}", digest.len());
        self.builder.add_data(digest).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<R0SuccinctImageId<M>> {
    pub fn add_r0_succinct_image_id(mut self, image_id: &[u8]) -> ScriptSignatureBuilder<M> {
        assert!(image_id.len() == 32, "image ID must be exactly 32 bytes, got {}", image_id.len());
        self.builder.add_data(image_id).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<G16Vk<M>> {
    pub fn add_g16_vk(mut self, vk: &[u8]) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(vk).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

impl<M> ScriptSignatureBuilder<G16Proof<M>> {
    pub fn add_g16_proof(mut self, proof: &[u8]) -> ScriptSignatureBuilder<M> {
        self.builder.add_data(proof).expect("script size limit exceeded");
        ScriptSignatureBuilder { redeem_script: self.redeem_script, builder: self.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// ScriptSignatureBuilder — all inputs provided, build
// ---------------------------------------------------------------------------

impl ScriptSignatureBuilder<()> {
    /// All missing inputs have been provided. Appends the redeem script as a
    /// data push and returns the complete signature script bytes.
    pub fn build(mut self) -> Vec<u8> {
        self.builder.add_data(&self.redeem_script).expect("script size limit exceeded");
        self.builder.drain()
    }
}

use crate::opcodes::codes::{OpCheckLockTimeVerify, OpCheckSig, OpDup, OpElse, OpEndIf, OpEqualVerify, OpIf, OpSHA256};
use crate::script_builder::{ScriptBuilder, ScriptBuilderResult};

pub fn htlc_redeem_script(receiver_pubkey: &[u8], sender_pubkey: &[u8], hash: &[u8], locktime: u64) -> ScriptBuilderResult<Vec<u8>> {
    let mut builder = ScriptBuilder::new();
    builder
        // withdraw branch
        .add_op(OpIf)?
        .add_op(OpSHA256)?
        .add_data(hash)?
        .add_op(OpEqualVerify)?
        .add_op(OpDup)?
        .add_data(receiver_pubkey)?
        .add_op(OpEqualVerify)?
        .add_op(OpCheckSig)?
        // refund branch
        .add_op(OpElse)?
        .add_lock_time(locktime)?
        .add_op(OpCheckLockTimeVerify)?
        .add_op(OpDup)?
        .add_data(sender_pubkey)?
        .add_op(OpEqualVerify)?
        .add_op(OpCheckSig)?
        // end
        .add_op(OpEndIf)?;

    Ok(builder.drain())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caches::Cache;
    use crate::opcodes::codes::{OpFalse, OpTrue};
    use crate::{pay_to_script_hash_script, TxScriptEngine};
    use kaspa_consensus_core::{
        hashing::{
            sighash::{calc_schnorr_signature_hash, SigHashReusedValues},
            sighash_type::SIG_HASH_ALL,
        },
        subnets::SubnetworkId,
        tx::{
            MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, UtxoEntry, VerifiableTransaction,
        },
    };
    use rand::thread_rng;
    use secp256k1::KeyPair;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;

    fn kp() -> [KeyPair; 3] {
        let kp1 = KeyPair::from_seckey_slice(
            secp256k1::SECP256K1,
            hex::decode("1d99c236b1f37b3b845336e6c568ba37e9ced4769d83b7a096eec446b940d160").unwrap().as_slice(),
        )
        .unwrap();
        let kp2 = KeyPair::from_seckey_slice(
            secp256k1::SECP256K1,
            hex::decode("349ca0c824948fed8c2c568ce205e9d9be4468ef099cad76e3e5ec918954aca4").unwrap().as_slice(),
        )
        .unwrap();
        let kp3 = KeyPair::new(secp256k1::SECP256K1, &mut thread_rng());
        [kp1, kp2, kp3]
    }

    #[test]
    fn test_redeem_x86() {
        let raw = r#"{"tx":{"version":0,"inputs":[{"previousOutpoint":{"transactionId":"75b3d09f6d208e2bf1a64e2fd411a8a31cf0afae3b40a58a2ea52cc946c49b22","index":0},"signatureScript":"41a2bc1b31f191fa1a2c16dd6431f2c097c767d377beafd9d21451210f55bd7d041d9b5a5417ce20e42c58e95327e6b2e5962ad3a67b5e801e4cf6de7b761e581001203c419d39e0e944b9c9156ba2df6fae2319907a2d3a3cfb390ef3136bd6a167e506736563726574514c7063a8202bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b8876203c419d39e0e944b9c9156ba2df6fae2319907a2d3a3cfb390ef3136bd6a167e588ac6751b07620422a703f084f3ee442608bc740f6c4e71ab2a3b1644abda1f4f73e42731516ba88ac68","sequence":0,"sigOpCount":2}],"outputs":[{"value":50000000000,"scriptPublicKey":"000020422a703f084f3ee442608bc740f6c4e71ab2a3b1644abda1f4f73e42731516baac"},{"value":49899996953,"scriptPublicKey":"0000aa2090e21125133401c44fdf8fc692eca3df7463209807d20213c1221c09da2ce60c87"}],"lockTime":0,"subnetworkId":"0000000000000000000000000000000000000000","gas":0,"payload":"","id":"1cdceb1082147a7c53474af5b7ef7931678d181cb39fb4638b52bca747f0f569"},"entries":[{"amount":100000000000,"scriptPublicKey":"0000aa2090e21125133401c44fdf8fc692eca3df7463209807d20213c1221c09da2ce60c87","blockDaaScore":44,"isCoinbase":false}],"calculated_fee":null,"calculated_mass":null}"#;
        let mut_tx: MutableTransaction<Transaction> = serde_json::from_str(raw).unwrap();
        let cache = Cache::new(10_000);
        let mut reused_values = SigHashReusedValues::new();
        let entries = mut_tx.entries.first().cloned().unwrap().unwrap();

        let tx = &mut_tx.as_verifiable();
        let mut engine =
            TxScriptEngine::from_transaction_input(tx, mut_tx.tx.inputs.first().unwrap(), 0, &entries, &mut reused_values, &cache)
                .unwrap();
        assert!(engine.execute().is_ok());
    }
    #[test]
    fn test_htlc() {
        let [receiver, sender, ..] = kp();

        let mut hasher = Sha256::new();
        hasher.update(b"hello world");
        let result = hasher.finalize();
        let hash = &result[..];

        let script = htlc_redeem_script(
            receiver.x_only_public_key().0.serialize().as_slice(),
            sender.x_only_public_key().0.serialize().as_slice(),
            hash,
            1702311302000,
        )
        .unwrap();

        // Taken from: d839d29b549469d0f9a23e51febe68d4084967a6a477868b511a5a8d88c5ae06
        let prev_tx_id = TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84").unwrap();

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 2,
            }],
            vec![],
            1702311302000,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let entries = vec![UtxoEntry {
            amount: 100000000000,
            script_public_key: pay_to_script_hash_script(&script),
            block_daa_score: 52251005,
            is_coinbase: false,
        }];

        // check witdraw
        {
            let mut tx = MutableTransaction::with_entries(tx.clone(), entries.clone());
            let mut reused_values = SigHashReusedValues::new();
            let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &mut reused_values);
            let msg = secp256k1::Message::from_slice(sig_hash.as_bytes().as_slice()).unwrap();

            let sig = receiver.sign_schnorr(msg);
            let mut signature = Vec::new();
            signature.extend_from_slice(sig.as_ref().as_slice());
            signature.push(SIG_HASH_ALL.to_u8());

            let mut builder = ScriptBuilder::new();
            builder.add_data(&signature).unwrap();
            builder.add_data(receiver.x_only_public_key().0.serialize().as_slice()).unwrap();
            builder.add_data(b"hello world").unwrap();
            builder.add_op(OpTrue).unwrap();
            builder.add_data(&script).unwrap();
            {
                tx.tx.inputs[0].signature_script = builder.drain();
            }

            let tx = tx.as_verifiable();
            let (input, entry) = tx.populated_inputs().next().unwrap();

            let cache = Cache::new(10_000);
            let mut engine = TxScriptEngine::from_transaction_input(&tx, input, 0, entry, &mut reused_values, &cache).unwrap();
            assert!(engine.execute().is_ok());
        }

        // check refund
        {
            let mut tx = MutableTransaction::with_entries(tx, entries);
            let mut reused_values = SigHashReusedValues::new();
            let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &mut reused_values);
            let msg = secp256k1::Message::from_slice(sig_hash.as_bytes().as_slice()).unwrap();

            let sig = sender.sign_schnorr(msg);
            let mut signature = Vec::new();
            signature.extend_from_slice(sig.as_ref().as_slice());
            signature.push(SIG_HASH_ALL.to_u8());

            let mut builder = ScriptBuilder::new();
            builder.add_data(&signature).unwrap();
            builder.add_data(sender.x_only_public_key().0.serialize().as_slice()).unwrap();
            builder.add_op(OpFalse).unwrap();
            builder.add_data(&script).unwrap();
            {
                tx.tx.inputs[0].signature_script = builder.drain();
            }

            let tx = tx.as_verifiable();
            let (input, entry) = tx.populated_inputs().next().unwrap();

            let cache = Cache::new(10_000);
            let mut engine = TxScriptEngine::from_transaction_input(&tx, input, 0, entry, &mut reused_values, &cache).unwrap();
            assert!(engine.execute().is_ok());
        }
    }
}

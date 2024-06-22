use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus::processes::transaction_validator::transaction_validator_populated::{
    check_scripts, check_scripts_par_iter, check_scripts_par_iter_thread,
};
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::pay_to_address_script;
use rand::{thread_rng, Rng};
use secp256k1::Keypair;
use std::sync::Arc;

// You may need to add more detailed mocks depending on your actual code.
fn mock_tx(inputs_count: usize, non_uniq_signatures: usize) -> (Transaction, Vec<UtxoEntry>) {
    let reused_values = SigHashReusedValuesUnsync::new();
    let dummy_prev_out = TransactionOutpoint::new(kaspa_hashes::Hash::from_u64_word(1), 1);
    let mut tx = Transaction::new(
        0,
        vec![],
        vec![],
        0,
        SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        0,
        vec![],
    );
    let mut utxos = vec![];
    let mut kps = vec![];
    for _ in 0..inputs_count - non_uniq_signatures {
        let kp = Keypair::new(secp256k1::SECP256K1, &mut thread_rng());
        tx.inputs.push(TransactionInput { previous_outpoint: dummy_prev_out, signature_script: vec![], sequence: 0, sig_op_count: 1 });
        let address = Address::new(Prefix::Mainnet, Version::PubKey, &kp.x_only_public_key().0.serialize());
        utxos.push(UtxoEntry {
            amount: thread_rng().gen::<u32>() as u64,
            script_public_key: pay_to_address_script(&address),
            block_daa_score: 333,
            is_coinbase: false,
        });
        kps.push(kp);
    }
    for _ in 0..non_uniq_signatures {
        let kp = kps.last().unwrap();
        tx.inputs.push(TransactionInput { previous_outpoint: dummy_prev_out, signature_script: vec![], sequence: 0, sig_op_count: 1 });
        let address = Address::new(Prefix::Mainnet, Version::PubKey, &kp.x_only_public_key().0.serialize());
        utxos.push(UtxoEntry {
            amount: thread_rng().gen::<u32>() as u64,
            script_public_key: pay_to_address_script(&address),
            block_daa_score: 444,
            is_coinbase: false,
        });
    }
    for i in 0..inputs_count - non_uniq_signatures {
        let mut_tx = MutableTransaction::with_entries(&tx, utxos.clone());
        let sig_hash = calc_schnorr_signature_hash(&mut_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
        let sig: [u8; 64] = *kps[i].sign_schnorr(msg).as_ref();
        // This represents OP_DATA_65 <SIGNATURE+SIGHASH_TYPE> (since signature length is 64 bytes and SIGHASH_TYPE is one byte)
        tx.inputs[i].signature_script = std::iter::once(65u8).chain(sig).chain([SIG_HASH_ALL.to_u8()]).collect();
    }
    let length = tx.inputs.len();
    for i in (inputs_count - non_uniq_signatures)..length {
        let kp = kps.last().unwrap();
        let mut_tx = MutableTransaction::with_entries(&tx, utxos.clone());
        let sig_hash = calc_schnorr_signature_hash(&mut_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
        let sig: [u8; 64] = *kp.sign_schnorr(msg).as_ref();
        // This represents OP_DATA_65 <SIGNATURE+SIGHASH_TYPE> (since signature length is 64 bytes and SIGHASH_TYPE is one byte)
        tx.inputs[i].signature_script = std::iter::once(65u8).chain(sig).chain([SIG_HASH_ALL.to_u8()]).collect();
    }
    (tx, utxos)
}

fn benchmark_check_scripts(_: &mut Criterion) {
    let mut c = Criterion::default().with_output_color(true)
        .sample_size(100)  // Number of samples
        .measurement_time(std::time::Duration::new(10, 0))  // Increase measurement time to 10 seconds
        .warm_up_time(std::time::Duration::new(5, 0));

    for inputs_count in [100, 50, 10, 5, 2] {
        // for non_uniq_signatures in (0..inputs_count).step_by(inputs_count / 2) {
        for non_uniq_signatures in [0] {
            let (tx, utxos) = mock_tx(inputs_count, 0);
            let mut group = c.benchmark_group(format!("inputs: {inputs_count}, non uniq: {non_uniq_signatures}"));

            group.bench_function("check_scripts_par_iter", |b| {
                let tx = Arc::new(MutableTransaction::with_entries(tx.clone(), utxos.clone()));
                let cache = Cache::new(inputs_count as u64);
                b.iter(|| {
                    cache.map.clear();
                    check_scripts_par_iter(black_box(&cache), black_box(&tx)).unwrap();
                })
            });

            for i in [2, 4, 8, 16, 32, 0] {
                if inputs_count >= i {
                    group.bench_function(&format!("check_scripts_par_iter_thread, thread count {i}"), |b| {
                        let tx = Arc::new(MutableTransaction::with_entries(tx.clone(), utxos.clone()));
                        // Create a custom thread pool with the specified number of threads
                        let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
                        let cache = Cache::new(inputs_count as u64);
                        b.iter(|| {
                            cache.map.clear();
                            check_scripts_par_iter_thread(black_box(&cache), black_box(&tx), black_box(&pool)).unwrap();
                        })
                    });
                }
            }
            group.bench_function("check_scripts", |b| {
                let tx = MutableTransaction::with_entries(&tx, utxos.clone());
                let cache = Cache::new(inputs_count as u64);
                b.iter(|| {
                    cache.map.clear();
                    check_scripts(black_box(&cache), black_box(&tx.as_verifiable())).unwrap();
                })
            });
        }
    }
}

criterion_group!(benches, benchmark_check_scripts);
criterion_main!(benches);

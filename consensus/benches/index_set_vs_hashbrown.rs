use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hashbrown::HashSet;
use indexmap::IndexSet;
use kaspa_consensus_core::BlockHasher;
use kaspa_hashes::Hash;
use rand::Rng;

const SIZE: usize = 10_000;
const INPUT_LEN: usize = SIZE * 10;
#[inline]
fn brown_insert(set: &mut HashSet<Hash, BlockHasher>, value: Hash) -> Option<Hash> {
    if set.len() >= SIZE {
        let t = set.raw_table_mut();
        let i = rand::thread_rng().gen_range(0..t.buckets());
        unsafe {
            if t.is_bucket_full(i) {
                let ((hash, _), _) = t.remove(t.bucket(i));
                Some(hash)
            } else {
                None
            }
        }
    } else {
        set.insert(value);
        None
    }
}

#[inline]
fn indexed_insert(set: &mut IndexSet<Hash, BlockHasher>, value: Hash) -> Option<Hash> {
    if set.len() >= SIZE {
        let hash = set.swap_remove_index(rand::thread_rng().gen_range(0..set.len())).expect("Element must exist");
        Some(hash)
    } else {
        set.insert(value);
        None
    }
}

fn generate_random_hashes() -> Vec<Hash> {
    let mut rng = rand::thread_rng();
    (0..INPUT_LEN).map(|_| Hash::from_bytes(rng.gen())).collect()
}

fn bench_collections(c: &mut Criterion) {
    let hashes = generate_random_hashes();

    let mut group = c.benchmark_group("Collection Insertion");
    group.bench_function("HashSet", |b| {
        let mut set = HashSet::with_capacity_and_hasher(SIZE, BlockHasher::default());
        // Perform an initial insert to allocate memory before starting the benchmark
        let _ = brown_insert(&mut set, hashes[0]);
        let mut mut_max_size = 0;
        b.iter(|| {
            for hash in &hashes[1..] {
                let returned = black_box(brown_insert(&mut set, *hash));
                _ = black_box(returned);
                assert!(set.len() <= SIZE);
                mut_max_size = mut_max_size.max(set.len());
            }
        });
        assert_eq!(mut_max_size, SIZE);
    });

    group.bench_function("IndexSet", |b| {
        let mut set = IndexSet::with_capacity_and_hasher(SIZE, BlockHasher::default());
        // Perform an initial insert to allocate memory before starting the benchmark
        let _ = indexed_insert(&mut set, hashes[0]);
        let mut mut_max_size = 0;
        b.iter(|| {
            for hash in &hashes[1..] {
                let returned = black_box(indexed_insert(&mut set, *hash));
                _ = black_box(returned);
                assert!(set.len() <= SIZE);
                mut_max_size = mut_max_size.max(set.len());
            }
        });
        assert_eq!(mut_max_size, SIZE);
    });
    group.finish();
}

criterion_group!(benches, bench_collections);
criterion_main!(benches);

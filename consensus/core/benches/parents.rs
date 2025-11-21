// This benchmark compares three variants of parents compression in Rusty Kaspa:
// 1. Old: Vec<Vec<Hash>> - the original uncompressed format
// 2. Compact: CompressedParents - Vec<(u8, Vec<Hash>>) - the existing compressed format
// 3. Flat: FlatParents - Vec<Hash> + Vec<u16> offsets + Vec<u8> counts
//
// It uses *only* the existing access patterns from the codebase:
// - Full expansion to Vec<Vec<Hash>> (used in validation, ghostdag ordering, virtual processor)
// - Sequential iteration over all levels (used in ghostdag protocol, pruning proof, merge depth checks)
// - Random level access (rare, but in tests and pruning validation edge cases)

use borsh::BorshDeserialize;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kaspa_consensus_core::header::{flat_parents::FlatParents, CompressedParents};
use kaspa_hashes::Hash;
use rand::{rngs::SmallRng, Rng, SeedableRng};

// For old uncompressed, use Vec<Vec<Hash>> directly
type UncompressedParents = Vec<Vec<Hash>>;

// Generate realistic data based on Kaspa mainnet 2025: avg 300 levels, 3.8 runs, 10-50 parents/level
fn generate_expanded_parents(num_headers: usize, seed: u64) -> Vec<Vec<Vec<Hash>>> {
    let mut rng = SmallRng::seed_from_u64(seed);
    (0..num_headers)
        .map(|_| {
            let num_levels = rng.gen_range(180..=255); // Cap at 255 to avoid CompressedParents error
            let num_runs = rng.gen_range(2..15);
            let base_run_len = num_levels / num_runs;
            let mut expanded = Vec::with_capacity(num_levels);
            let mut total_levels = 0;
            for r in 0..num_runs {
                let parents_per_level = rng.gen_range(10..50);
                let level_parents: Vec<Hash> = (0..parents_per_level).map(|_| Hash::from_u64_word(rng.gen())).collect();
                let this_run_len = if r < num_runs - 1 { base_run_len } else { num_levels - total_levels };
                for _ in 0..this_run_len {
                    expanded.push(level_parents.clone());
                }
                total_levels += this_run_len;
            }
            expanded
        })
        .collect()
}

fn parents_bench(c: &mut Criterion) {
    let expanded_list = generate_expanded_parents(1000, 42); // 1000 items for batch

    let mut group = c.benchmark_group("parents_compression");
    group.sample_size(50);

    // Precompute variants
    let uncompressed: Vec<UncompressedParents> = expanded_list.clone();
    let compact: Vec<CompressedParents> = expanded_list.iter().map(|e| CompressedParents::try_from(e.clone()).unwrap()).collect();
    let flat: Vec<FlatParents> = expanded_list.iter().map(|e| FlatParents::from_expanded(e)).collect();

    // Pattern 1: Full expansion (used in validation, ghostdag ordering)
    group.bench_function("expand_uncompressed", |b| {
        b.iter_batched(
            || uncompressed.clone(),
            |data| {
                for p in data {
                    black_box(p.clone());
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("expand_compact", |b| {
        b.iter_batched(
            || compact.clone(),
            |data| {
                for p in data {
                    black_box(Vec::<Vec<Hash>>::from(p.clone()));
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("expand_flat", |b| {
        b.iter_batched(
            || flat.clone(),
            |data| {
                for p in data {
                    black_box(p.expand());
                }
            },
            BatchSize::SmallInput,
        )
    });

    // Pattern 2: Sequential iteration (used in ghostdag protocol, pruning proof, virtual processor, merge depth checks)
    // Simulate work: sum some hash bytes for all levels
    group.bench_function("iter_uncompressed", |b| {
        b.iter(|| {
            for p in &uncompressed {
                let mut sum: u64 = 0;
                for level in p {
                    for h in level {
                        sum = sum.wrapping_add(h.to_le_u64()[3]);
                    }
                }
                black_box(sum);
            }
        })
    });

    group.bench_function("iter_compact", |b| {
        b.iter(|| {
            for p in &compact {
                let mut sum: u64 = 0;
                for level in p.iter() {
                    for h in level {
                        sum = sum.wrapping_add(h.to_le_u64()[3]);
                    }
                }
                black_box(sum);
            }
        })
    });

    group.bench_function("iter_flat", |b| {
        b.iter(|| {
            for p in &flat {
                let mut sum: u64 = 0;
                for level in p.iter_levels() {
                    for h in level {
                        sum = sum.wrapping_add(h.to_le_u64()[3]);
                    }
                }
                black_box(sum);
            }
        })
    });

    // Pattern 3: Random level access (used in pruning proof validation, reachability queries, tests)
    // Generate random levels per item
    let mut rng = SmallRng::seed_from_u64(42);
    let queries: Vec<Vec<usize>> = expanded_list
        .iter()
        .map(|e| {
            (0..100).map(|_| rng.gen_range(0..e.len())).collect() // 100 random accesses per item
        })
        .collect();

    group.bench_function("random_access_uncompressed", |b| {
        b.iter(|| {
            for (i, p) in uncompressed.iter().enumerate() {
                let mut sum: u64 = 0;
                for &level in &queries[i] {
                    let parents = &p[level];
                    for h in parents {
                        sum = sum.wrapping_add(h.to_le_u64()[3]);
                    }
                }
                black_box(sum);
            }
        })
    });

    group.bench_function("random_access_compact", |b| {
        b.iter(|| {
            for (i, p) in compact.iter().enumerate() {
                let mut sum: u64 = 0;
                for &level in &queries[i] {
                    let parents = p.get(level).unwrap();
                    for h in parents {
                        sum = sum.wrapping_add(h.to_le_u64()[3]);
                    }
                }
                black_box(sum);
            }
        })
    });

    group.bench_function("random_access_flat", |b| {
        b.iter(|| {
            for (i, p) in flat.iter().enumerate() {
                let mut sum: u64 = 0;
                for &level in &queries[i] {
                    let parents = p.parents_of_level(level);
                    for h in parents {
                        sum = sum.wrapping_add(h.to_le_u64()[3]);
                    }
                }
                black_box(sum);
            }
        })
    });

    // Additional: Serialize / Deserialize (used in IBD, P2P, DB storage)
    group.bench_function("serialize_uncompressed", |b| {
        b.iter(|| {
            for p in &uncompressed {
                black_box(borsh::to_vec(p).unwrap());
            }
        })
    });

    group.bench_function("serialize_compact", |b| {
        b.iter(|| {
            for p in &compact {
                black_box(borsh::to_vec(p).unwrap());
            }
        })
    });

    group.bench_function("serialize_flat", |b| {
        b.iter(|| {
            for p in &flat {
                black_box(borsh::to_vec(p).unwrap());
            }
        })
    });

    // Precompute serialized for deserialize bench
    let uncompressed_ser: Vec<Vec<u8>> = uncompressed.iter().map(|p| borsh::to_vec(p).unwrap()).collect();
    let compact_ser: Vec<Vec<u8>> = compact.iter().map(|p| borsh::to_vec(p).unwrap()).collect();
    let flat_ser: Vec<Vec<u8>> = flat.iter().map(|p| borsh::to_vec(p).unwrap()).collect();

    group.bench_function("deserialize_uncompressed", |b| {
        b.iter(|| {
            for data in &uncompressed_ser {
                black_box(Vec::<Vec<Hash>>::try_from_slice(data).unwrap());
            }
        })
    });

    group.bench_function("deserialize_compact", |b| {
        b.iter(|| {
            for data in &compact_ser {
                black_box(CompressedParents::try_from_slice(data).unwrap());
            }
        })
    });

    group.bench_function("deserialize_flat", |b| {
        b.iter(|| {
            for data in &flat_ser {
                black_box(FlatParents::try_from_slice(data).unwrap());
            }
        })
    });
}

criterion_group!(benches, parents_bench);
criterion_main!(benches);

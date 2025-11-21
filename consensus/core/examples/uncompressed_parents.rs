use borsh::{BorshDeserialize, BorshSerialize};
use dhat;
use kaspa_hashes::Hash;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::hint::black_box;
use std::time::Instant;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// Pre-generate and serialize 1000 identical datasets outside profiler
fn prepare_serialized() -> Vec<Vec<u8>> {
    let mut rng = SmallRng::seed_from_u64(42);
    let num_levels = 200;
    let num_runs = 4;
    let base_run_len = num_levels / num_runs;
    let mut expanded: Vec<Vec<Hash>> = Vec::with_capacity(num_levels);
    let mut total_levels = 0;
    for r in 0..num_runs {
        let parents_per_level = rng.gen_range(10..30);
        let level_parents: Vec<Hash> = (0..parents_per_level).map(|_| Hash::from_u64_word(rng.gen())).collect();
        let this_run_len = if r < num_runs - 1 { base_run_len } else { num_levels - total_levels };
        for _ in 0..this_run_len {
            expanded.push(level_parents.clone());
        }
        total_levels += this_run_len;
    }
    let serialized_one = borsh::to_vec(&expanded).unwrap();
    let mut serialized_vec = Vec::with_capacity(1000);
    for _ in 0..1000 {
        serialized_vec.push(serialized_one.clone());
    }
    serialized_vec
}

fn main() {
    let serialized_vec = prepare_serialized(); // No allocations counted here

    let _profiler = dhat::Profiler::builder().file_name("uncompressed.json").build();

    let start = Instant::now();

    // Looped work: deserialize each + black_box the structure
    for i in 0..1000 {
        let uncompressed: Vec<Vec<Hash>> = Vec::<Vec<Hash>>::try_from_slice(&serialized_vec[i]).unwrap();
        black_box(&uncompressed);
    }

    let elapsed = start.elapsed().as_millis();
    println!("Uncompressed Time: {} ms", elapsed);

    let stats = dhat::HeapStats::get();
    println!("Uncompressed Stats: {:?}", stats);
}

use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash;
use std::iter;

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FlatParents {
    /// All unique parent hashes concatenated across runs (no duplicates).
    pub parents: Vec<Hash>,
    /// Start offsets into `parents` for each run (length = runs + 1, last = parents.len()).
    pub offsets: Vec<u16>,
    /// Run lengths: how many consecutive levels share the same parent slice.
    pub counts: Vec<u8>,
}

impl FlatParents {
    /// Compresses an expanded Vec<Vec<Hash>> into the flat RLE format.
    pub fn from_expanded(parents_by_level: &[Vec<Hash>]) -> Self {
        let mut parents = Vec::new();
        let mut offsets = vec![0u16];
        let mut counts = Vec::new();

        if parents_by_level.is_empty() {
            return Self { parents, offsets, counts };
        }

        let mut current = &parents_by_level[0];
        let mut count = 1u8;
        parents.extend_from_slice(current);

        for level in &parents_by_level[1..] {
            if level == current {
                count += 1;
            } else {
                offsets.push(parents.len() as u16);
                counts.push(count);
                current = level;
                count = 1;
                parents.extend_from_slice(current);
            }
        }

        offsets.push(parents.len() as u16);
        counts.push(count);

        Self { parents, offsets, counts }
    }

    /// Iterator over all levels, yielding &[Hash] slices (zero-copy, cache-friendly).
    #[inline(always)]
    pub fn iter_levels<'a>(&'a self) -> impl Iterator<Item = &'a [Hash]> + 'a {
        self.counts.iter().zip(self.offsets.windows(2)).flat_map(|(&count, window)| {
            let slice = &self.parents[window[0] as usize..window[1] as usize];
            iter::repeat(slice).take(count as usize)
        })
    }

    /// Get parents for a specific level (linear scan over runs - fast due to avg 3.8 runs).
    /// Panics if level is out of bounds (callers should check against blue_score / depth).
    pub fn parents_of_level(&self, mut level: usize) -> &[Hash] {
        for (i, &count) in self.counts.iter().enumerate() {
            if level < count as usize {
                let start = self.offsets[i] as usize;
                let end = self.offsets[i + 1] as usize;
                return &self.parents[start..end];
            }
            level -= count as usize;
        }
        panic!("Level out of bounds");
    }

    /// Expand to full Vec<Vec<Hash>> for compatibility/testing (allocates).
    pub fn expand(&self) -> Vec<Vec<Hash>> {
        self.iter_levels().map(|s| s.to_vec()).collect()
    }
}

// For integration into Header:
// In header.rs, replace `compressed_parents: CompressedParents` with `flat_parents: FlatParents`.
// Adjust Header methods like `parents_by_level` to return self.flat_parents.iter_levels().map(|s| s.to_vec()).collect() or similar.
// In serialization, use Borsh directly on FlatParents.

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};
    use kaspa_hashes::Hash;
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    // Mock the current CompressedParents for compatibility testing.
    // This is the existing implementation (Vec<(u8, Vec<Hash>)>).
    #[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
    struct OldCompressedParents(Vec<(u8, Vec<Hash>)>);

    impl OldCompressedParents {
        fn from_expanded(parents_by_level: &[Vec<Hash>]) -> Self {
            let mut runs = Vec::new();
            if parents_by_level.is_empty() {
                return Self(runs);
            }
            let mut current = parents_by_level[0].clone();
            let mut count = 1u8;
            for level in &parents_by_level[1..] {
                if level == &current {
                    count += 1;
                } else {
                    runs.push((count, current));
                    current = level.clone();
                    count = 1;
                }
            }
            runs.push((count, current));
            Self(runs)
        }

        fn expand(&self) -> Vec<Vec<Hash>> {
            let mut expanded = Vec::new();
            for &(count, ref parents) in &self.0 {
                for _ in 0..count {
                    expanded.push(parents.clone());
                }
            }
            expanded
        }
    }

    // Helper to generate realistic random parents_by_level (simulates Kaspa DAG levels).
    fn generate_random_parents_by_level(seed: u64, levels: usize, max_parents_per_level: usize) -> Vec<Vec<Hash>> {
        let mut rng = SmallRng::seed_from_u64(seed);
        (0..levels)
            .map(|_| {
                let num = rng.gen_range(0..=max_parents_per_level);
                (0..num).map(|_| Hash::from_u64_word(rng.gen())).collect()
            })
            .collect()
    }

    #[test]
    fn test_flat_parents_compression_and_expansion() {
        for seed in 0..100 {
            let expanded = generate_random_parents_by_level(seed, 200, 50);
            let flat = FlatParents::from_expanded(&expanded);
            let expanded_back = flat.expand();
            assert_eq!(expanded, expanded_back, "Expansion mismatch for seed {}", seed);
        }
    }

    #[test]
    fn test_compatibility_with_old_compressed_parents() {
        for seed in 0..100 {
            let expanded = generate_random_parents_by_level(seed, 450, 100); // Realistic max levels
            let old = OldCompressedParents::from_expanded(&expanded);
            let flat = FlatParents::from_expanded(&expanded);

            // Check expansion matches
            assert_eq!(old.expand(), expanded);
            assert_eq!(flat.expand(), expanded);

            // Check random level access matches
            for level in 0..expanded.len() {
                assert_eq!(flat.parents_of_level(level), &expanded[level][..]);
                // Simulate old access: old.expand()[level] but we already checked full expand
            }
        }
    }

    #[test]
    fn test_serialization_size_reduction() {
        for seed in 0..50 {
            let expanded = generate_random_parents_by_level(seed, 300, 80);
            let old = OldCompressedParents::from_expanded(&expanded);
            let flat = FlatParents::from_expanded(&expanded);

            let old_ser = borsh::to_vec(&old).unwrap();
            let flat_ser = borsh::to_vec(&flat).unwrap();

            assert!(
                flat_ser.len() < old_ser.len(),
                "Flat should be smaller: {} vs {} for seed {}",
                flat_ser.len(),
                old_ser.len(),
                seed
            );

            // Deserialize and check
            let flat_back = FlatParents::try_from_slice(&flat_ser).unwrap();
            assert_eq!(flat_back.expand(), expanded);
        }
    }

    #[test]
    fn test_edge_cases() {
        // Empty
        let expanded: Vec<Vec<Hash>> = vec![];
        let flat = FlatParents::from_expanded(&expanded);
        assert_eq!(flat.parents, vec![]);
        assert_eq!(flat.offsets, vec![0]);
        assert_eq!(flat.counts, Vec::<u8>::new());
        assert_eq!(flat.expand(), expanded);

        // Single level
        let expanded = vec![vec![Hash::from_u64_word(1), Hash::from_u64_word(2)]];
        let flat = FlatParents::from_expanded(&expanded);
        assert_eq!(flat.expand(), expanded);
        assert_eq!(flat.parents_of_level(0), &[Hash::from_u64_word(1), Hash::from_u64_word(2)]);

        // All identical runs
        let expanded = vec![vec![Hash::from_u64_word(1)]; 255]; // Max u8
        let flat = FlatParents::from_expanded(&expanded);
        assert_eq!(flat.counts, vec![255]);
        assert_eq!(flat.offsets, vec![0, 1]);
        assert_eq!(flat.expand(), expanded);

        // Max offsets (u16 limit)
        let mut expanded = vec![];
        for i in 0..1000 {
            expanded.push(vec![Hash::from_u64_word(i as u64)]);
        }
        let flat = FlatParents::from_expanded(&expanded);
        assert_eq!(flat.offsets.last().unwrap(), &(1000u16)); // Within u16
        assert_eq!(flat.expand(), expanded);
    }

    #[test]
    #[should_panic(expected = "Level out of bounds")]
    fn test_out_of_bounds_panic() {
        let expanded = generate_random_parents_by_level(0, 100, 20);
        let flat = FlatParents::from_expanded(&expanded);
        flat.parents_of_level(100);
    }
}

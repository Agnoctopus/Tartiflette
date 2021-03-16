//! Random utils

use std::{convert::TryInto, panic::Location};
use std::ops::Range;

use getrandom::getrandom;

/// Pseudorandom number generator (xoroshiro128+ impl)
#[derive(Copy, Clone, Debug)]
pub struct Rand {
    // Seed
    seed: [u64; 2],
}

impl Rand {
    /// Create a new `Rand` instance
    pub fn new(seed: [u64; 2]) -> Self {
        Self { seed: seed }
    }

    /// Create a new `Rand` instance with a random seed
    pub fn new_random_seed() -> Self {
        // Compute a random seed
        let mut seed: [u8; 16] = [0u8; 16];
        getrandom(&mut seed).expect("Failed to get random entropy.");

        Self {
            seed: [
                u64::from_ne_bytes(seed[0..8].try_into().unwrap()),
                u64::from_ne_bytes(seed[8..16].try_into().unwrap()),
            ],
        }
    }

    /// Intern rotation, part of the algorithm
    #[inline]
    fn rotl(x: u64, k: u32) -> u64 {
        (x << k) | (x >> (64 - k))
    }

    /// Get the next pseudo-random value
    #[inline]
    pub fn next(&mut self) -> u64 {
        let (s0, mut s1) = (self.seed[0], self.seed[1]);
        let result = s0.wrapping_add(s1);

        s1 ^= s0;
        self.seed[0] = Self::rotl(s0, 24) ^ s1 ^ (s1 << 16);
        self.seed[1] = Self::rotl(s1, 37);

        result
    }

    /// Get the next pseudo-random value inside a range
    #[inline]
    pub fn random_in(&mut self, range: Range<u64>) -> u64 {
        assert!(range.end >= range.start);

        (self.next() % (range.end - range.start + 1)) + range.start
    }

    /// Get a random bool
    #[inline]
    pub fn random_bool(&mut self) -> bool {
        self.next() % 2 == 0
    }
}

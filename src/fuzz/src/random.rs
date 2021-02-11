//! Random utils

use std::convert::TryInto;

use getrandom;
use std::ops::Range;

/// Pseudorandom number generator (xoroshiro128+ impl)
#[derive(Copy, Clone, Debug)]
pub struct Rand {
    seed: [u64; 2],
}

impl Rand {
    /// Create a new `Rand` instance
    pub fn new(seed: [u64; 2]) -> Self {
        Self { seed: seed }
    }

    /// Create a new `Rand` instance with a random seed
    pub fn new_random_seed() -> Self {
        let mut seed: [u8; 16] = [0u8; 16];
        getrandom::getrandom(&mut seed).unwrap();

        Self {
            seed: [
                u64::from_ne_bytes(seed[0..8].try_into().unwrap()),
                u64::from_ne_bytes(seed[8..16].try_into().unwrap()),
            ],
        }
    }

    #[inline]
    fn rotl(x: u64, k: u32) -> u64 {
        (x << k) | (x >> (64 - k))
    }

    #[inline]
    pub fn next(&mut self) -> u64 {
        let (s0, mut s1) = (self.seed[0], self.seed[1]);
        let result = s0 + s1;

        s1 ^= s0;
        self.seed[0] = Self::rotl(s0, 24) ^ s1 ^ (s1 << 16);
        self.seed[1] = Self::rotl(s1, 37);

        result
    }

    #[inline]
    pub fn random_in(&mut self, range: Range<u64>) -> u64 {
        assert!(!range.is_empty());

        (self.next() % (range.end - range.start + 1)) + range.start
    }

    #[inline]
    pub fn random_bool(&mut self) -> bool {
        self.next() % 2 == 0
    }
}

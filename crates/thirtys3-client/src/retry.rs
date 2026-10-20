//! The wait between repeats of a request.

use std::hash::{BuildHasher, Hasher, RandomState};
use std::time::Duration;

/// Exponential backoff with random variation: the wait for repeat `n` (from 0) is between half and all of `initial * 2^n`, at most `max`.
/// The variation keeps many clients that failed together from coming back together.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Backoff {
    pub(crate) initial: Duration,
    pub(crate) max: Duration,
}

impl Backoff {
    /// The longest the wait for this repeat can be, before the variation.
    pub(crate) fn ceiling(&self, repeat: u32) -> Duration {
        self.initial.saturating_mul(1_u32.checked_shl(repeat.min(30)).unwrap_or(u32::MAX)).min(self.max)
    }

    /// The wait for this repeat.
    pub(crate) fn delay(&self, repeat: u32) -> Duration {
        let ceiling = self.ceiling(repeat);
        // RandomState is seeded from the operating system, which is all the randomness this needs.
        let random = RandomState::new().build_hasher().finish();
        let fraction = (random >> 11) as f64 / (1_u64 << 53) as f64;
        ceiling.mul_f64(0.5 + fraction / 2.0)
    }
}

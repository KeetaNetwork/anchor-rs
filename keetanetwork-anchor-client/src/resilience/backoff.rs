//! Pure backoff scheduling and jitter.
//!
//! Neither type reads a clock, sleeps, or allocates: [`Backoff`] maps an
//! attempt number to a delay, and [`Jitter`] perturbs a delay from a
//! caller-supplied random value.

/// Default first-attempt delay.
const DEFAULT_BASE_MS: u64 = 500;

/// Default per-attempt growth factor.
const DEFAULT_FACTOR: u32 = 2;

/// Default delay ceiling.
const DEFAULT_MAX_MS: u64 = 30_000;

/// A truncated exponential backoff schedule: `base * factor^attempt`, capped at
/// `max`, with an optional retry ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Backoff {
	base_ms: u64,
	factor: u32,
	max_ms: u64,
	max_retries: Option<u32>,
}

impl Default for Backoff {
	fn default() -> Self {
		let base_ms = DEFAULT_BASE_MS;
		let factor = DEFAULT_FACTOR;
		let max_ms = DEFAULT_MAX_MS;
		let max_retries = None;

		Self { base_ms, factor, max_ms, max_retries }
	}
}

impl Backoff {
	/// The delay for a zero-based `attempt`, or [`None`] once the retry ceiling
	/// is reached.
	pub fn delay(&self, attempt: u32) -> Option<u64> {
		if self.max_retries.is_some_and(|max| attempt >= max) {
			return None;
		}

		let growth = u64::from(self.factor)
			.checked_pow(attempt)
			.unwrap_or(u64::MAX);

		let delay = self.base_ms.saturating_mul(growth).min(self.max_ms);
		Some(delay)
	}

	/// Override the first-attempt delay.
	#[must_use]
	pub const fn with_base_ms(mut self, base_ms: u64) -> Self {
		self.base_ms = base_ms;
		self
	}

	/// Override the per-attempt growth factor.
	#[must_use]
	pub const fn with_factor(mut self, factor: u32) -> Self {
		self.factor = factor;
		self
	}

	/// Override the delay ceiling.
	#[must_use]
	pub const fn with_max_ms(mut self, max_ms: u64) -> Self {
		self.max_ms = max_ms;
		self
	}

	/// Cap the number of retries; [`delay`](Self::delay) yields [`None`] at and
	/// beyond `max_retries`.
	#[must_use]
	pub const fn with_max_retries(mut self, max_retries: u32) -> Self {
		self.max_retries = Some(max_retries);
		self
	}
}

/// How a computed delay is perturbed to avoid synchronized retries.
///
/// `rand` is any value the caller supplies (so this stays dependency-free and
/// deterministic in tests); only its low bits are used.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Jitter {
	/// Use the delay verbatim.
	None,

	/// Uniform in `[0, delay]` (matches the TypeScript reference's jitter).
	#[default]
	Full,

	/// Uniform in `[delay / 2, delay]`.
	Equal,
}

impl Jitter {
	/// Perturb `delay_ms` using `rand`.
	pub fn apply(&self, delay_ms: u64, rand: u64) -> u64 {
		match self {
			Self::None => delay_ms,
			Self::Full => bounded(rand, delay_ms),
			Self::Equal => {
				let floor = delay_ms / 2;
				floor + bounded(rand, delay_ms - floor)
			}
		}
	}
}

/// A value in `[0, max]` drawn from `rand`.
fn bounded(rand: u64, max: u64) -> u64 {
	if max == 0 {
		return 0;
	}

	rand % (max + 1)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn delay_grows_exponentially_until_capped() {
		let backoff = Backoff::default()
			.with_base_ms(100)
			.with_factor(2)
			.with_max_ms(1_000);

		let delays: alloc::vec::Vec<_> = (0..6).map(|attempt| backoff.delay(attempt)).collect();
		assert_eq!(delays, [Some(100), Some(200), Some(400), Some(800), Some(1_000), Some(1_000)]);
	}

	#[test]
	fn delay_saturates_without_overflow() {
		let backoff = Backoff::default()
			.with_base_ms(u64::MAX)
			.with_max_ms(u64::MAX);
		assert_eq!(backoff.delay(64), Some(u64::MAX));
	}

	#[test]
	fn retry_ceiling_stops_the_schedule() {
		let backoff = Backoff::default().with_max_retries(2);
		assert!(backoff.delay(0).is_some());
		assert!(backoff.delay(1).is_some());
		assert_eq!(backoff.delay(2), None);
	}

	#[test]
	fn no_jitter_returns_the_delay() {
		assert_eq!(Jitter::None.apply(1_000, 12_345), 1_000);
	}

	#[test]
	fn full_jitter_stays_within_the_delay() {
		let samples = [0, 1, 999, 1_000, 1_001, u64::MAX];
		for rand in samples {
			let value = Jitter::Full.apply(1_000, rand);
			assert!(value <= 1_000);
		}
	}

	#[test]
	fn equal_jitter_stays_in_the_upper_half() {
		let samples = [0, 1, 499, 500, 501, u64::MAX];
		for rand in samples {
			let value = Jitter::Equal.apply(1_000, rand);
			assert!((500..=1_000).contains(&value));
		}
	}

	#[test]
	fn jitter_of_zero_delay_is_zero() {
		assert_eq!(Jitter::Full.apply(0, 42), 0);
		assert_eq!(Jitter::Equal.apply(0, 42), 0);
	}
}

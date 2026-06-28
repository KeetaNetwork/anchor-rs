//! A token-bucket rate limiter.
//!
//! The bucket holds up to `capacity` tokens and refills at `refill_per_sec`.
//! Tokens are tracked as integer *millitokens* (thousandths of a token) so a
//! fractional refill rate stays exact without floats: at `refill_per_sec`
//! tokens/sec the bucket gains exactly `refill_per_sec` millitokens per
//! millisecond. Time is in plain milliseconds (`*_ms`).

/// Millitokens in one whole token.
const MILLITOKENS_PER_TOKEN: u64 = 1_000;

/// A token bucket: a burst of `capacity` with a steady `refill_per_sec` rate.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
	capacity_millitokens: u64,
	refill_per_sec: u64,
	tokens_millitokens: u64,
	last_ms: u64,
}

impl TokenBucket {
	/// A bucket that starts full at `now_ms`.
	pub fn new(capacity: u32, refill_per_sec: u32, now_ms: u64) -> Self {
		let capacity_millitokens = u64::from(capacity).saturating_mul(MILLITOKENS_PER_TOKEN);
		Self {
			capacity_millitokens,
			refill_per_sec: u64::from(refill_per_sec),
			tokens_millitokens: capacity_millitokens,
			last_ms: now_ms,
		}
	}

	/// Consume one token, or report the milliseconds until one is available.
	///
	/// # Errors
	///
	/// Returns the wait in milliseconds when the bucket is empty; [`u64::MAX`]
	/// when no refill is scheduled (`refill_per_sec` of zero).
	pub fn try_take(&mut self, now_ms: u64) -> Result<(), u64> {
		self.refill(now_ms);

		if self.tokens_millitokens >= MILLITOKENS_PER_TOKEN {
			self.tokens_millitokens -= MILLITOKENS_PER_TOKEN;
			return Ok(());
		}

		let deficit = MILLITOKENS_PER_TOKEN - self.tokens_millitokens;
		if self.refill_per_sec == 0 {
			return Err(u64::MAX);
		}

		Err(deficit.div_ceil(self.refill_per_sec))
	}

	/// Whole tokens currently available, refilled to `now_ms`.
	pub fn available(&mut self, now_ms: u64) -> u32 {
		self.refill(now_ms);
		u32::try_from(self.tokens_millitokens / MILLITOKENS_PER_TOKEN).unwrap_or(u32::MAX)
	}

	fn refill(&mut self, now_ms: u64) {
		let elapsed_ms = now_ms.saturating_sub(self.last_ms);
		if elapsed_ms == 0 {
			return;
		}

		let gained_millitokens = elapsed_ms.saturating_mul(self.refill_per_sec);
		self.tokens_millitokens = self
			.tokens_millitokens
			.saturating_add(gained_millitokens)
			.min(self.capacity_millitokens);
		self.last_ms = now_ms;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_fresh_bucket_serves_its_full_burst() {
		let mut bucket = TokenBucket::new(3, 1, 0);
		assert_eq!(bucket.try_take(0), Ok(()));
		assert_eq!(bucket.try_take(0), Ok(()));
		assert_eq!(bucket.try_take(0), Ok(()));
		assert_eq!(bucket.try_take(0), Err(1_000));
	}

	#[test]
	fn refill_restores_tokens_over_time() {
		let mut bucket = TokenBucket::new(1, 2, 0);
		assert_eq!(bucket.try_take(0), Ok(()));
		assert_eq!(bucket.try_take(0), Err(500));
		assert_eq!(bucket.try_take(500), Ok(()));
	}

	#[test]
	fn refill_never_exceeds_capacity() {
		let mut bucket = TokenBucket::new(2, 100, 0);
		assert_eq!(bucket.available(10_000), 2);
	}

	#[test]
	fn a_bucket_without_refill_reports_never() {
		let mut bucket = TokenBucket::new(1, 0, 0);
		assert_eq!(bucket.try_take(0), Ok(()));
		assert_eq!(bucket.try_take(1_000_000), Err(u64::MAX));
	}
}

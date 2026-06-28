//! Retry with backoff, honoring a server `Retry-After` hint.
//!
//! [`RetryPolicy::run`] re-runs an operation while it returns a transient
//! transport error or a retryable status, sleeping per the backoff schedule
//! (or the response's `Retry-After`, whichever is longer) until the call
//! succeeds, a non-retryable result arrives, or the time budget is spent.

use alloc::boxed::Box;
use core::future::Future;

use super::backoff::{Backoff, Jitter};
use super::error::{retryable_status, transient, ResilienceError};
use super::runtime::ResilienceRuntime;
use crate::error::TransportError;
use crate::transport::HttpResponse;

/// Default ceiling on total time spent across all attempts.
const DEFAULT_MAX_TOTAL_MS: u64 = 30_000;

/// The golden-ratio constant used to season the jitter PRNG seed.
const SEED_SALT: u64 = 0x9E37_79B9_7F4A_7C15;

/// A retry schedule: a [`Backoff`], its [`Jitter`], and a total time budget.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
	backoff: Backoff,
	jitter: Jitter,
	max_total_ms: u64,
}

impl Default for RetryPolicy {
	fn default() -> Self {
		let backoff = Backoff::default();
		let jitter = Jitter::default();
		let max_total_ms = DEFAULT_MAX_TOTAL_MS;

		Self { backoff, jitter, max_total_ms }
	}
}

impl RetryPolicy {
	/// Override the backoff schedule.
	#[must_use]
	pub const fn with_backoff(mut self, backoff: Backoff) -> Self {
		self.backoff = backoff;
		self
	}

	/// Override the jitter strategy.
	#[must_use]
	pub const fn with_jitter(mut self, jitter: Jitter) -> Self {
		self.jitter = jitter;
		self
	}

	/// Override the total time budget across all attempts.
	#[must_use]
	pub const fn with_max_total_ms(mut self, max_total_ms: u64) -> Self {
		self.max_total_ms = max_total_ms;
		self
	}

	/// Run `operation` with retries.
	///
	/// Returns the first non-retryable outcome (a success, a terminal status,
	/// or a terminal transport error). When the budget is spent on transient
	/// failures, returns [`TransportError::Resilience`] wrapping
	/// [`ResilienceError::RetryExhausted`]; when it is spent on a retryable
	/// status, hands back that last response.
	pub async fn run<R, F, Fut>(&self, runtime: &R, mut operation: F) -> Result<HttpResponse, TransportError>
	where
		R: ResilienceRuntime + ?Sized,
		F: FnMut() -> Fut,
		Fut: Future<Output = Result<HttpResponse, TransportError>>,
	{
		let start = runtime.now_millis();
		let mut seed = (start ^ SEED_SALT) | 1;
		let mut attempt: u32 = 0;

		loop {
			match operation().await {
				Ok(response) => {
					if !retryable_status(response.status) {
						return Ok(response);
					}

					let hint = response
						.retry_after
						.as_ref()
						.and_then(|after| after.to_millis());
					let remaining = self.remaining_budget(start, runtime.now_millis());
					match self.next_delay(attempt, hint, remaining, &mut seed) {
						Some(delay) => runtime.sleep_ms(delay).await,
						None => return Ok(response),
					}
				}
				Err(error) => {
					if !transient(&error) {
						return Err(error);
					}

					let source = Box::new(error);
					let now = runtime.now_millis();
					let remaining = self.remaining_budget(start, now);
					match self.next_delay(attempt, None, remaining, &mut seed) {
						Some(delay) => runtime.sleep_ms(delay).await,
						None => {
							let elapsed_ms = now.saturating_sub(start);
							let exhausted =
								ResilienceError::RetryExhausted { attempts: attempt + 1, elapsed_ms, source };
							return Err(TransportError::from(exhausted));
						}
					}
				}
			}

			attempt += 1;
		}
	}

	/// The time left in the total budget after the elapsed span.
	fn remaining_budget(&self, start_ms: u64, now_ms: u64) -> u64 {
		let elapsed = now_ms.saturating_sub(start_ms);
		self.max_total_ms.saturating_sub(elapsed)
	}

	/// The next sleep: the jittered backoff (or the `Retry-After` hint, the
	/// larger of the two) clamped to `remaining_ms`, or [`None`] when no
	/// attempts or time remain.
	fn next_delay(&self, attempt: u32, hint: Option<u64>, remaining_ms: u64, seed: &mut u64) -> Option<u64> {
		if remaining_ms == 0 {
			return None;
		}

		let scheduled = self.backoff.delay(attempt)?;
		let jittered = self.jitter.apply(scheduled, next_rand(seed));
		let wanted = hint.map_or(jittered, |hint| hint.max(jittered));

		Some(wanted.min(remaining_ms))
	}
}

/// A xorshift64 step, seeding the jitter source from the monotonic clock so the
/// layer needs no `rand` dependency.
fn next_rand(state: &mut u64) -> u64 {
	let mut value = *state;
	value ^= value << 13;
	value ^= value >> 7;
	value ^= value << 17;
	*state = value;

	value
}

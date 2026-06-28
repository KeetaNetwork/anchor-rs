//! Typed failures raised when a resilience policy sheds load or spends its
//! budget, plus the classifiers that decide what is worth retrying.

use alloc::boxed::Box;

use snafu::Snafu;

use crate::error::TransportError;

/// A resilience-policy failure.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ResilienceError {
	/// The rate limiter shed the call and no refill is scheduled.
	#[snafu(display("rate limited; retry after {retry_after_ms}ms"))]
	RateLimited {
		/// Milliseconds to wait before the bucket yields a token.
		retry_after_ms: u64,
	},

	/// The retry budget was spent before the call succeeded.
	#[snafu(display("retry budget exhausted after {attempts} attempt(s) in {elapsed_ms}ms: {source}"))]
	RetryExhausted {
		/// How many attempts were made.
		attempts: u32,
		/// Total wall time spent across the attempts, in milliseconds.
		elapsed_ms: u64,
		/// The final transport failure that ended the budget.
		source: Box<TransportError>,
	},
}

impl ResilienceError {
	/// Whether the caller may retry the operation.
	pub fn retryable(&self) -> bool {
		matches!(self, Self::RateLimited { .. })
	}

	/// The HTTP status a server would surface this failure as.
	pub fn status(&self) -> u16 {
		match self {
			Self::RateLimited { .. } => 429,
			Self::RetryExhausted { .. } => 500,
		}
	}

	/// The retry-after hint in milliseconds, when one applies.
	pub fn retry_after_ms(&self) -> Option<u64> {
		match self {
			Self::RateLimited { retry_after_ms } => Some(*retry_after_ms),
			Self::RetryExhausted { .. } => None,
		}
	}
}

/// Whether a transport error is a transient fault worth retrying. A request
/// that could not be sent or got no response is transient; a malformed URL is
/// not.
pub fn transient(error: &TransportError) -> bool {
	matches!(error, TransportError::Request { .. })
}

/// Whether an HTTP status invites a retry: request timeout, too-many-requests,
/// or any server-side (5xx) failure.
pub fn retryable_status(status: u16) -> bool {
	matches!(status, 408 | 429) || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
	use alloc::boxed::Box;

	use super::*;

	#[test]
	fn rate_limited_is_retryable_with_a_hint() {
		let error = ResilienceError::RateLimited { retry_after_ms: 250 };
		assert!(error.retryable());
		assert_eq!(error.status(), 429);
		assert_eq!(error.retry_after_ms(), Some(250));
	}

	#[test]
	fn exhaustion_is_terminal() {
		let source = Box::new(TransportError::Request { reason: "boom".into() });
		let error = ResilienceError::RetryExhausted { attempts: 3, elapsed_ms: 900, source };
		assert!(!error.retryable());
		assert_eq!(error.status(), 500);
		assert_eq!(error.retry_after_ms(), None);
	}

	#[test]
	fn only_request_failures_are_transient() {
		assert!(transient(&TransportError::Request { reason: "x".into() }));
		assert!(!transient(&TransportError::InvalidUrl { reason: "x".into() }));
	}

	#[test]
	fn retryable_statuses_cover_timeout_throttle_and_server_errors() {
		let retryable = [408, 429, 500, 502, 503, 599];
		for status in retryable {
			assert!(retryable_status(status));
		}

		let terminal = [200, 301, 400, 404, 451, 600];
		for status in terminal {
			assert!(!retryable_status(status));
		}
	}
}

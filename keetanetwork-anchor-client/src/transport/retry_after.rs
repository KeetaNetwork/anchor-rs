//! The HTTP `Retry-After` value, shared by both directions.
//!
//! A client parses it from a response header to pace its retries; a server
//! emits it by rendering this type into the header value. Per [RFC 9110], the
//! value is either a non-negative number of seconds or an HTTP-date.
//!
//! [RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110#field.retry-after

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use snafu::Snafu;

const MS_PER_SECOND: u64 = 1_000;

/// A parsed `Retry-After` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryAfter {
	/// A relative delay, in seconds (`Retry-After: 120`).
	Seconds(u64),

	/// An absolute HTTP-date (`Retry-After: Wed, 21 Oct 2025 ...`).
	HttpDate(String),
}

/// The `Retry-After` value was empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Snafu)]
#[snafu(display("Retry-After value is empty"))]
pub struct EmptyRetryAfter;

impl RetryAfter {
	/// A relative `Retry-After` of `seconds`.
	pub fn seconds(seconds: u64) -> Self {
		Self::Seconds(seconds)
	}

	/// The delay in milliseconds, when expressible without a wall clock.
	///
	/// [`Self::Seconds`] resolves directly; [`Self::HttpDate`] needs the
	/// current time to resolve and yields [`None`] here, so callers fall back
	/// to their own backoff schedule.
	pub fn to_millis(&self) -> Option<u64> {
		match self {
			Self::Seconds(seconds) => Some(seconds.saturating_mul(MS_PER_SECOND)),
			Self::HttpDate(_) => None,
		}
	}
}

impl FromStr for RetryAfter {
	type Err = EmptyRetryAfter;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		let trimmed = value.trim();
		if trimmed.is_empty() {
			return Err(EmptyRetryAfter);
		}

		let parsed = trimmed
			.parse::<u64>()
			.map_or_else(|_| Self::HttpDate(trimmed.into()), Self::Seconds);
		Ok(parsed)
	}
}

impl fmt::Display for RetryAfter {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Seconds(seconds) => write!(formatter, "{seconds}"),
			Self::HttpDate(date) => formatter.write_str(date),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn numeric_value_parses_to_seconds() {
		let parsed = "120".parse::<RetryAfter>();
		assert_eq!(parsed, Ok(RetryAfter::Seconds(120)));
	}

	#[test]
	fn surrounding_whitespace_is_trimmed() {
		let parsed = "  30  ".parse::<RetryAfter>();
		assert_eq!(parsed, Ok(RetryAfter::Seconds(30)));
	}

	#[test]
	fn non_numeric_value_is_kept_as_a_date() {
		let parsed = "Wed, 21 Oct 2025 07:28:00 GMT".parse::<RetryAfter>();
		assert_eq!(parsed, Ok(RetryAfter::HttpDate("Wed, 21 Oct 2025 07:28:00 GMT".into())));
	}

	#[test]
	fn empty_value_is_rejected() {
		let parsed = "   ".parse::<RetryAfter>();
		assert_eq!(parsed, Err(EmptyRetryAfter));
	}

	#[test]
	fn seconds_resolve_to_milliseconds() {
		assert_eq!(RetryAfter::Seconds(2).to_millis(), Some(2_000));
	}

	#[test]
	fn a_date_has_no_clockless_delay() {
		assert_eq!(RetryAfter::HttpDate("x".into()).to_millis(), None);
	}

	#[test]
	fn display_renders_the_header_value() {
		use alloc::string::ToString;

		assert_eq!(RetryAfter::Seconds(45).to_string(), "45");
		assert_eq!(RetryAfter::HttpDate("Wed".into()).to_string(), "Wed");
	}
}

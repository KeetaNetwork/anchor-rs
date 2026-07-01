//! Input validation shared by the anchor binding crates.
//!
//! Each helper returns a [`CodedError`] with a stable code so invalid host
//! input is rejected identically across every FFI boundary. Parsing borrows
//! from the input where possible to stay zero-copy.

use alloc::borrow::Cow;
use alloc::format;

use crate::error::CodedError;

/// A required value was empty.
pub const EMPTY_VALUE: &str = "EMPTY_VALUE";
/// A country code was not a valid ISO 3166-1 alpha-2 code.
pub const INVALID_COUNTRY_CODE: &str = "INVALID_COUNTRY_CODE";
/// A provider identifier was empty.
pub const INVALID_PROVIDER_ID: &str = "INVALID_PROVIDER_ID";

/// Trim `value` and reject it when empty, attributing the failure to `code`.
///
/// Returns the trimmed sub-slice (borrowed from the input).
pub fn non_empty<'a>(value: &'a str, code: &str) -> Result<&'a str, CodedError> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err(CodedError::new(code, "value must not be empty"));
	}

	Ok(trimmed)
}

/// Validate and upper-case an ISO 3166-1 alpha-2 country code.
///
/// Already-uppercase input is borrowed; mixed-case input is normalized into
/// an owned string.
pub fn country_code(value: &str) -> Result<Cow<'_, str>, CodedError> {
	let trimmed = value.trim();
	let is_alpha2 = trimmed.len() == 2 && trimmed.bytes().all(|byte| byte.is_ascii_alphabetic());
	if !is_alpha2 {
		return Err(CodedError::new(INVALID_COUNTRY_CODE, format!("invalid country code: {trimmed}")));
	}

	let already_upper = trimmed.bytes().all(|byte| byte.is_ascii_uppercase());
	if already_upper {
		return Ok(Cow::Borrowed(trimmed));
	}

	Ok(Cow::Owned(trimmed.to_ascii_uppercase()))
}

/// Validate a non-empty provider identifier.
pub fn provider_id(value: &str) -> Result<&str, CodedError> {
	non_empty(value, INVALID_PROVIDER_ID)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn non_empty_trims_surrounding_whitespace() -> Result<(), CodedError> {
		let parsed = non_empty("  abc  ", EMPTY_VALUE)?;
		assert_eq!(parsed, "abc");
		Ok(())
	}

	#[test]
	fn non_empty_rejects_blank_input() {
		let error = non_empty("   ", EMPTY_VALUE).unwrap_err();
		assert_eq!(error.code, EMPTY_VALUE);
	}

	#[test]
	fn country_code_borrows_uppercase_input() -> Result<(), CodedError> {
		let parsed = country_code("US")?;
		assert!(matches!(parsed, Cow::Borrowed("US")));
		Ok(())
	}

	#[test]
	fn country_code_normalizes_lowercase_input() -> Result<(), CodedError> {
		let parsed = country_code("us")?;
		assert_eq!(parsed.as_ref(), "US");
		assert!(matches!(parsed, Cow::Owned(_)));
		Ok(())
	}

	#[test]
	fn country_code_rejects_wrong_length() {
		let error = country_code("USA").unwrap_err();
		assert_eq!(error.code, INVALID_COUNTRY_CODE);
	}

	#[test]
	fn provider_id_rejects_blank_input() {
		let error = provider_id("").unwrap_err();
		assert_eq!(error.code, INVALID_PROVIDER_ID);
	}
}

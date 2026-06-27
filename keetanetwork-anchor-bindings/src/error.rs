//! Boundary error shared by the anchor binding crates.

use alloc::string::String;

/// Code used when a core error exposes no stable code.
pub const UNKNOWN_CODE: &str = "UNKNOWN";

/// A core failure reduced to a stable code and a human-readable message.
///
/// This is the single error shape that crosses every FFI boundary, so
/// consumers in any host language branch on `code` and surface `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedError {
	/// Stable, machine-readable code consumers branch on.
	pub code: String,
	/// Human-readable description.
	pub message: String,
}

impl CodedError {
	/// A coded error from a code and message.
	pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
		Self { code: code.into(), message: message.into() }
	}

	/// A coded error from an optional static code, falling back to
	/// [`UNKNOWN_CODE`] when absent.
	pub fn coded(code: Option<&str>, message: impl Into<String>) -> Self {
		Self::new(code.unwrap_or(UNKNOWN_CODE), message)
	}
}

/// Derive `From<$error> for CodedError` for core errors that expose an
/// optional stable `code()` and a `Display` message.
#[macro_export]
macro_rules! coded_from {
	($($error:ty),+ $(,)?) => {
		$(
			impl From<$error> for $crate::error::CodedError {
				fn from(error: $error) -> Self {
					$crate::error::CodedError::coded(error.code(), error.to_string())
				}
			}
		)+
	};
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::string::ToString;
	use core::fmt;

	enum SampleError {
		Coded,
		Uncoded,
	}

	impl SampleError {
		fn code(&self) -> Option<&'static str> {
			match self {
				Self::Coded => Some("SAMPLE_CODED"),
				Self::Uncoded => None,
			}
		}
	}

	impl fmt::Display for SampleError {
		fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
			formatter.write_str("sample failure")
		}
	}

	coded_from!(SampleError);

	#[test]
	fn new_sets_code_and_message() {
		let coded = CodedError::new("CODE", "message");
		assert_eq!(coded.code, "CODE");
		assert_eq!(coded.message, "message");
	}

	#[test]
	fn coded_falls_back_to_unknown_when_absent() {
		let coded = CodedError::coded(None, "message");
		assert_eq!(coded.code, UNKNOWN_CODE);
	}

	#[test]
	fn coded_preserves_an_explicit_code() {
		let coded = CodedError::coded(Some("EXPLICIT"), "message");
		assert_eq!(coded.code, "EXPLICIT");
	}

	#[test]
	fn from_maps_a_coded_error() {
		let coded = CodedError::from(SampleError::Coded);
		assert_eq!(coded.code, "SAMPLE_CODED");
		assert_eq!(coded.message, "sample failure");
	}

	#[test]
	fn from_maps_an_uncoded_error_to_unknown() {
		let coded = CodedError::from(SampleError::Uncoded);
		assert_eq!(coded.code, UNKNOWN_CODE);
	}
}

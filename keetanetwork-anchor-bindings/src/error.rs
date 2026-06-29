//! Boundary error shared by the anchor binding crates.

pub use keetanetwork_bindings::error::{CodedError, UNKNOWN_CODE};

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
		NonCoded,
	}

	impl SampleError {
		fn code(&self) -> Option<&'static str> {
			match self {
				Self::Coded => Some("SAMPLE_CODED"),
				Self::NonCoded => None,
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
		let coded = CodedError::from(SampleError::NonCoded);
		assert_eq!(coded.code, UNKNOWN_CODE);
	}
}

//! Shared helpers for the structured-codec unit tests.

use alloc::vec::Vec;

use serde_json::Value;

/// Decode a hex string into the bytes of a DER test fixture.
pub(crate) fn from_hex(hex: &str) -> Vec<u8> {
	(0..hex.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
		.collect()
}

/// Assert that decoded JSON bytes equal an expected JSON document, comparing as
/// parsed values so key ordering does not matter.
pub(crate) fn assert_json_eq(actual: &[u8], expected: &str) {
	let actual: Value = serde_json::from_slice(actual).expect("parse actual json");
	let expected: Value = serde_json::from_str(expected).expect("parse expected json");
	assert_eq!(actual, expected);
}

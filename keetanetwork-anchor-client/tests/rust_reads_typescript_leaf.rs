//! The Rust core must read a TypeScript-issued leaf.

mod harness;

use std::error::Error;

use keetanetwork_anchor::testing::read_sensitive_attribute;
use serde_json::Value;

use harness::{attribute_cases, decoded_to_value, issue_attributes, KycHarness, SUBJECT_SEED};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn rust_reads_typescript_issued_leaf() -> TestResult {
	let cases = attribute_cases();

	// The reference anchor issues a populated leaf for the subject seed.
	let mut harness = KycHarness::start()?;
	harness.start_kyc_anchor(Some(&["US"]), true)?;

	let issued = harness.issue_certificate(SUBJECT_SEED, &issue_attributes())?;
	let leaf_pem = issued
		.get("leaf")
		.and_then(Value::as_str)
		.ok_or("issued response is missing its leaf")?
		.to_string();

	harness.shutdown()?;

	// The core, given only the subject seed, must recover every attribute it
	// carries, matching the value the reference reader emits.
	for case in &cases {
		let bytes = read_sensitive_attribute(&leaf_pem, SUBJECT_SEED, &case.name);
		let actual = decoded_to_value(&case.expected, bytes);
		assert_eq!(actual, case.expected, "the core must recover `{}` from the TypeScript-issued leaf", case.name);
	}

	Ok(())
}

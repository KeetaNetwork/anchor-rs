//! The reference TypeScript reader must read a Rust-issued leaf.

mod harness;

use std::error::Error;

use keetanetwork_anchor::testing::issue_leaf_pem;
use serde_json::{Map, Value};

use harness::{attribute_cases, KycHarness, SUBJECT_SEED};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn typescript_reads_rust_issued_leaf() -> TestResult {
	let cases = attribute_cases();

	let mut expected = Map::new();
	for case in &cases {
		expected.insert(case.name.clone(), case.expected.clone());
	}

	// The Rust core issues the leaf; the reference reader, given only the subject
	// seed, must recover every attribute it carries.
	let attrs: Vec<(&str, &[u8], bool)> = cases
		.iter()
		.map(|case| (case.name.as_str(), case.semantic.as_slice(), case.sensitive))
		.collect();
	let (leaf_pem, _ca_pem) = issue_leaf_pem(SUBJECT_SEED, &attrs);

	let mut harness = KycHarness::start()?;
	let names: Vec<&str> = cases.iter().map(|case| case.name.as_str()).collect();
	let decoded = harness.decode_certificate(&leaf_pem, SUBJECT_SEED, &names)?;

	harness.shutdown()?;

	let read_back = decoded
		.get("attributes")
		.and_then(Value::as_object)
		.ok_or("decode response is missing its attributes")?;

	assert_eq!(read_back, &expected, "the reference reader must recover the Rust-issued attributes");
	Ok(())
}

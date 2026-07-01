//! The Rust core must open a TypeScript-exported sharable bundle.

mod harness;

use std::error::Error;

use keetanetwork_anchor::testing::open_sharable_buffer;
use keetanetwork_anchor_client::decode_base64;
use serde_json::{json, Value};

use harness::SharableHarness;

type TestResult = Result<(), Box<dyn Error>>;

/// The subject seed the leaf is issued for on both sides.
const SUBJECT_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// The recipient seed the bundle is sealed to on both sides.
const RECIPIENT_SEED: &str = "3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn rust_reads_typescript_exported_sharable() -> TestResult {
	let attributes = json!([
		{ "name": "email", "sensitive": true, "value": "user@example.com" },
		{ "name": "fullName", "sensitive": true, "value": "Test User" },
	]);
	let names = ["email", "fullName"];

	// The reference exports the bundle; the core, given only the recipient key,
	// must recover the same disclosed buffers.
	let mut harness = SharableHarness::start()?;
	let built = harness.build_sharable(SUBJECT_SEED, RECIPIENT_SEED, &attributes)?;
	harness.shutdown()?;

	let pem = built
		.get("pem")
		.and_then(Value::as_str)
		.ok_or("built response is missing its pem")?
		.to_string();
	let buffers = built
		.get("buffers")
		.and_then(Value::as_object)
		.ok_or("built response is missing its buffers")?;

	for name in names {
		let encoded = buffers
			.get(name)
			.and_then(Value::as_str)
			.ok_or("the reference must return a buffer for each name")?;
		let expected = decode_base64(encoded)?;
		let actual =
			open_sharable_buffer(&pem, RECIPIENT_SEED, name).ok_or("the core must disclose the attribute buffer")?;
		assert_eq!(actual, expected, "the core must recover `{name}` from the reference-exported bundle");
	}

	Ok(())
}

//! The reference TypeScript reader must open a Rust-exported sharable bundle.

mod harness;

use std::error::Error;

use keetanetwork_anchor::testing::{export_sharable_pem, open_sharable_buffer};
use keetanetwork_anchor_client::decode_base64;
use serde_json::Value;

use harness::SharableHarness;

type TestResult = Result<(), Box<dyn Error>>;

/// The subject seed the leaf is issued for on both sides.
const SUBJECT_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// The recipient seed the bundle is sealed to on both sides.
const RECIPIENT_SEED: &str = "3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn typescript_reads_rust_exported_sharable() -> TestResult {
	let attributes: [(&str, &[u8], bool); 2] = [("email", b"user@example.com", true), ("fullName", b"Test User", true)];
	let names: Vec<&str> = attributes.iter().map(|(name, _, _)| *name).collect();

	// The Rust core exports the bundle; the reference reader, given only the
	// recipient key, must recover the same disclosed buffers.
	let pem = export_sharable_pem(SUBJECT_SEED, RECIPIENT_SEED, &attributes);

	let mut harness = SharableHarness::start()?;
	let read = harness.read_sharable(&pem, RECIPIENT_SEED, &names)?;
	harness.shutdown()?;

	let buffers = read
		.get("buffers")
		.and_then(Value::as_object)
		.ok_or("read response is missing its buffers")?;

	for name in &names {
		let expected =
			open_sharable_buffer(&pem, RECIPIENT_SEED, name).ok_or("the core must disclose the attribute buffer")?;
		let encoded = buffers
			.get(*name)
			.and_then(Value::as_str)
			.ok_or("the reference must return a buffer for each name")?;
		let actual = decode_base64(encoded)?;
		assert_eq!(actual, expected, "the reference reader must recover `{name}` byte-for-byte");
	}

	Ok(())
}

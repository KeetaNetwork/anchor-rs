//! Live cross-implementation signing parity against the REAL TypeScript anchor.

mod common;
mod support;

use std::borrow::Cow;
use std::error::Error;

use common::{
	account_from_seed, decode_account, harness_data, options_at_signed_time, rust_data, vectors, NONCE, TIMESTAMP,
};
use hex::FromHex;
use keetanetwork_account::{Account, KeyECDSASECP256K1};
use keetanetwork_anchor::signing::{
	object_to_signable, sign_with, verification_data, verify, SignParams, Signable, Signed, VerifyOptions,
};
use serde_json::{json, Value};
use support::AnchorHarness;

type TestResult = Result<(), Box<dyn Error>>;

/// The accounts, params, and options a parity round-trip needs, plus a live
/// harness sharing the same fixed nonce/timestamp on both sides.
struct Fixture {
	harness: AnchorHarness,
	/// The harness-owned signer, so Rust can verify TypeScript-made signatures.
	verifier: Account<KeyECDSASECP256K1>,
	/// A deterministic Rust signer, whose `publicKeyAndType` TypeScript verifies.
	account: Account<KeyECDSASECP256K1>,
	account_hex: String,
	params: SignParams,
	options: VerifyOptions,
}

impl Fixture {
	fn start() -> Result<Self, Box<dyn Error>> {
		let harness = AnchorHarness::start()?;
		let signer_hex = harness.signer_public_key_and_type()?.to_string();
		let verifier = Account::<KeyECDSASECP256K1>::from_hex(&signer_hex)?;
		let account = account_from_seed(0x11);
		let account_hex = hex::encode(account.to_public_key_with_type());

		Ok(Self {
			harness,
			verifier,
			account,
			account_hex,
			params: SignParams::new(NONCE, TIMESTAMP),
			options: options_at_signed_time(),
		})
	}

	/// Assert byte-for-byte and bidirectional parity for one payload: the
	/// TypeScript DER bytes match Rust's, TypeScript's signature verifies in
	/// Rust, and Rust's signature verifies in TypeScript.
	fn assert_round_trip(&mut self, name: &str, data: &[Signable], wire: Value) -> TestResult {
		let signed = self.harness.sign(NONCE, TIMESTAMP, wire.clone())?;

		let verification = verification_data(&self.verifier, data, &self.params)?;
		let rust_bytes = hex::encode(verification);
		assert_eq!(rust_bytes, signed.verification_data, "DER verification bytes diverge from TypeScript for `{name}`");

		let envelope =
			Signed { nonce: NONCE.to_string(), timestamp: TIMESTAMP.to_string(), signature: signed.signature };
		let rust_accepts_ts = verify(&self.verifier, data, &envelope, &self.options).is_ok();
		assert!(rust_accepts_ts, "TypeScript signature rejected by Rust for `{name}`");

		let rust_signed = sign_with(&self.account, data, &self.params)?;
		let ts_accepts_rust = self
			.harness
			.verify(&self.account_hex, NONCE, TIMESTAMP, &rust_signed.signature, wire)?;
		assert!(ts_accepts_rust, "Rust signature rejected by TypeScript for `{name}`");

		Ok(())
	}
}

#[test]
fn signable_vectors_round_trip_through_typescript() -> TestResult {
	let mut fixture = Fixture::start()?;
	let secondary = decode_account(fixture.harness.secondary_public_key_and_type()?);
	for (name, specs) in vectors() {
		let data = rust_data(&specs, &secondary);
		fixture.assert_round_trip(name, &data, harness_data(&specs))?;
	}

	fixture.harness.shutdown()?;

	Ok(())
}

/// Structured JSON inputs whose JCS canonicalization (RFC 8785) must agree with
/// the TypeScript `objectToSignable`. Mirrors the valid cases in the reference
/// `signing.test.ts` (omitting forms `serde_json::Value` cannot represent, e.g.
/// `undefined`, `Date`, sparse arrays).
fn canonical_vectors() -> Vec<(&'static str, Value)> {
	vec![
		("flat key sort", json!({ "z": 1, "a": "first", "m": "middle" })),
		("nested object", json!({ "outer": { "inner": "v" }, "top": "t" })),
		("array order", json!({ "items": ["a", "b", "c"] })),
		("null kept", json!({ "a": "kept", "c": null })),
		("booleans", json!({ "yes": true, "no": false })),
		("marker keys", json!({ "a": "first", "m": "middle", "{": "a", "}": "{" })),
		("top-level scalar", json!("lonely")),
		("top-level array", json!(["x", "y"])),
		("nested mixed", json!({ "a": 1, "b": { "c": "x", "d": "y" } })),
	]
}

/// Project canonical string parts into the harness string-part wire format.
fn harness_strings(parts: &[String]) -> Value {
	let wire: Vec<Value> = parts
		.iter()
		.map(|part| json!({ "t": "s", "v": part }))
		.collect();

	Value::Array(wire)
}

#[test]
fn object_to_signable_matches_and_round_trips_through_typescript() -> TestResult {
	let mut fixture = Fixture::start()?;
	for (name, value) in canonical_vectors() {
		let ts_parts = fixture.harness.object_to_signable(&value)?;
		let rust_parts = object_to_signable(&value)?;

		let expected: Vec<Signable> = ts_parts
			.iter()
			.map(|part| Signable::Text(Cow::Owned(part.clone())))
			.collect();
		assert_eq!(rust_parts, expected, "canonical signable diverges from TypeScript for `{name}`");

		fixture.assert_round_trip(name, &rust_parts, harness_strings(&ts_parts))?;
	}

	fixture.harness.shutdown()?;

	Ok(())
}

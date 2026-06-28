//! Shared test fixtures: deterministic accounts, vectors, and verify options.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use hex::FromHex;
use keetanetwork_account::{Account, Accountable, KeyECDSASECP256K1, KeyPair, Keyable};
use keetanetwork_anchor::signing::{Signable, VerifyOptions};
use keetanetwork_crypto::prelude::IntoSecret;
use serde_json::{json, Value};

/// A fixed nonce so signatures are reproducible across runs and languages.
pub const NONCE: &str = "11111111-1111-1111-1111-111111111111";
/// A fixed signing timestamp (millisecond precision, `Z` zone).
pub const TIMESTAMP: &str = "2024-01-02T03:04:05.678Z";

/// Build a deterministic SECP256K1 account from a single seed byte.
pub fn account_from_seed(seed_byte: u8) -> Account<KeyECDSASECP256K1> {
	let keyable = Keyable::Seed(([seed_byte; 32].into_secret(), 0));
	let accountable = Accountable::KeyAndType(keyable, KeyECDSASECP256K1::KEY_PAIR_TYPE);

	Account::<KeyECDSASECP256K1>::try_from(accountable).expect("account builds from seed")
}

/// The instant encoded by [`TIMESTAMP`].
pub fn reference_time() -> DateTime<Utc> {
	let fixed = DateTime::parse_from_rfc3339(TIMESTAMP).expect("fixed timestamp parses");
	fixed.with_timezone(&Utc)
}

/// Verify options anchored at the signing instant so skew is deterministic.
pub fn options_at_signed_time() -> VerifyOptions {
	VerifyOptions { max_skew_ms: 60_000, reference_time: reference_time() }
}

/// Decode a `publicKeyAndType` hex string into bytes.
pub fn decode_account(hex: &str) -> Vec<u8> {
	Vec::from_hex(hex).expect("public key hex decodes")
}

/// One signable element, described once and projected into each implementation.
pub enum Spec {
	/// A UTF-8 string part.
	Text(&'static str),
	/// An integer part.
	Int(i64),
	/// An account part (the harness/secondary account's `publicKeyAndType`).
	Account,
}

/// The shared test matrix: one entry per element kind plus a mixed payload.
pub fn vectors() -> Vec<(&'static str, Vec<Spec>)> {
	vec![
		("empty", vec![]),
		("string", vec![Spec::Text("test-string")]),
		("integer", vec![Spec::Int(12345)]),
		("account", vec![Spec::Account]),
		("mixed", vec![Spec::Text("string"), Spec::Int(67890), Spec::Account]),
	]
}

/// Project a spec into Rust [`Signable`] parts.
pub fn rust_data(specs: &[Spec], account_public_key_and_type: &[u8]) -> Vec<Signable<'static>> {
	specs
		.iter()
		.map(|spec| match spec {
			Spec::Text(value) => Signable::from((*value).to_string()),
			Spec::Int(value) => Signable::from(*value),
			Spec::Account => Signable::Account(account_public_key_and_type.to_vec().into()),
		})
		.collect()
}

/// Project a spec into the harness transport format.
pub fn harness_data(specs: &[Spec]) -> Value {
	let parts: Vec<Value> = specs
		.iter()
		.map(|spec| match spec {
			Spec::Text(value) => json!({ "t": "s", "v": value }),
			Spec::Int(value) => json!({ "t": "i", "v": value }),
			Spec::Account => json!({ "t": "a" }),
		})
		.collect();

	Value::Array(parts)
}

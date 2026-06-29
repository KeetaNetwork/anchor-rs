//! Live signing interop against a running anchor: signatures cross-verify and
//! DER bytes agree in both directions.

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
	add_signature_to_url, object_to_signable, parse_signature_from_url, sign_with, verification_data, verify,
	verify_body, verify_url, RequestError, SignParams, Signable, Signed, Url, VerifyOptions,
};
use serde_json::{json, Value};
use support::SigningHarness;

type TestResult = Result<(), Box<dyn Error>>;

/// The accounts, params, and options a round-trip needs, plus a live harness
/// sharing the same fixed nonce/timestamp on both sides.
struct Fixture {
	harness: SigningHarness,
	/// The harness-owned signer, so Rust can verify anchor-made signatures.
	verifier: Account<KeyECDSASECP256K1>,
	/// A deterministic Rust signer, whose `publicKeyAndType` the anchor verifies.
	account: Account<KeyECDSASECP256K1>,
	account_hex: String,
	params: SignParams,
	options: VerifyOptions,
}

impl Fixture {
	fn start() -> Result<Self, Box<dyn Error>> {
		let harness = SigningHarness::start()?;
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

	/// Assert byte-for-byte, bidirectional agreement for one payload: the
	/// anchor's DER bytes match Rust's, the anchor's signature verifies in
	/// Rust, and Rust's signature verifies in the anchor.
	fn assert_round_trip(&mut self, name: &str, data: &[Signable], transport: Value) -> TestResult {
		let signed = self.harness.sign(NONCE, TIMESTAMP, transport.clone())?;

		let verification = verification_data(&self.verifier, data, &self.params)?;
		let rust_bytes = hex::encode(verification);
		assert_eq!(rust_bytes, signed.verification_data, "DER verification bytes diverge from the anchor for `{name}`");

		let nonce = NONCE.to_string();
		let timestamp = TIMESTAMP.to_string();
		let signature = signed.signature;
		let envelope = Signed { nonce, timestamp, signature };
		let rust_accepts_anchor = verify(&self.verifier, data, &envelope, &self.options).is_ok();
		assert!(rust_accepts_anchor, "anchor signature rejected by Rust for `{name}`");

		let rust_signed = sign_with(&self.account, data, &self.params)?;
		let anchor_accepts_rust =
			self.harness
				.verify(&self.account_hex, NONCE, TIMESTAMP, &rust_signed.signature, transport)?;
		assert!(anchor_accepts_rust, "Rust signature rejected by the anchor for `{name}`");

		Ok(())
	}
}

#[test]
fn signable_vectors_round_trip_through_the_anchor() -> TestResult {
	let mut fixture = Fixture::start()?;
	let secondary = decode_account(fixture.harness.secondary_public_key_and_type()?);
	for (name, specs) in vectors() {
		let data = rust_data(&specs, &secondary);
		fixture.assert_round_trip(name, &data, harness_data(&specs))?;
	}

	fixture.harness.shutdown()?;

	Ok(())
}

/// Signed-request setup shared by both directions: a live harness, a
/// deterministic Rust account, and fresh (current-time) params so the
/// anchor's default five-minute skew window accepts.
struct RequestFixture {
	harness: SigningHarness,
	account: Account<KeyECDSASECP256K1>,
	/// The Rust account's `keeta_...` string (the URL/body `account` value).
	account_string: String,
	/// The harness signer's `keeta_...` string.
	signer_string: String,
	params: SignParams,
	options: VerifyOptions,
	base: Url,
}

impl RequestFixture {
	fn start() -> Result<Self, Box<dyn Error>> {
		let harness = SigningHarness::start()?;
		let signer_string = harness.signer_public_key_string()?.to_string();
		let account = account_from_seed(0x11);

		Ok(Self {
			account_string: account.to_string(),
			account,
			signer_string,
			harness,
			params: SignParams::generate(),
			options: VerifyOptions::default(),
			base: Url::parse("https://anchor.example/v1/resource")?,
		})
	}
}

/// The empty signable that the KYC auth flows (`createVerification`,
/// `getVerificationStatus`) sign: the request itself carries no extra payload.
const EMPTY_SIGNABLE: &[Signable] = &[];

#[test]
fn rust_signed_requests_verify_in_the_anchor() -> TestResult {
	let mut fixture = RequestFixture::start()?;
	let transport = json!([]);
	let account = fixture.account_string.clone();
	let base = fixture.base.clone();

	let signed = sign_with(&fixture.account, EMPTY_SIGNABLE, &fixture.params)?;
	let rust_url = add_signature_to_url(&base, &account, &signed)?;
	let anchor_url = fixture
		.harness
		.add_signature_to_url(base.as_str(), &account, &signed)?;
	assert_eq!(rust_url.as_str(), anchor_url, "signed URL diverges from addSignatureToURL");

	let url_account = fixture
		.harness
		.verify_url(rust_url.as_str(), transport.clone())?;
	assert_eq!(url_account.as_deref(), Some(account.as_str()), "verifyURLAuth rejected the Rust-signed URL");

	let body_account = fixture.harness.verify_body(&account, &signed, transport)?;
	assert_eq!(body_account.as_deref(), Some(account.as_str()), "verifyBodyAuth rejected the Rust-signed body");

	fixture.harness.shutdown()?;

	Ok(())
}

#[test]
fn anchor_signed_requests_verify_in_rust() -> TestResult {
	let mut fixture = RequestFixture::start()?;
	let transport = json!([]);
	let nonce = fixture.params.nonce.clone();
	let timestamp = fixture.params.timestamp.clone();
	let signer = fixture.signer_string.clone();
	let base = fixture.base.clone();

	let anchor_signed = fixture.harness.sign(&nonce, &timestamp, transport)?;
	let signature = anchor_signed.signature;
	let envelope = Signed { nonce, timestamp, signature };

	let built_url = fixture
		.harness
		.add_signature_to_url(base.as_str(), signer.as_str(), &envelope)?;
	let signed_url = Url::parse(&built_url)?;

	let (parsed_account, parsed_envelope) = parse_signature_from_url(&signed_url)?;
	assert_eq!(parsed_account, signer, "parsed account diverges from the signed URL");
	assert_eq!(parsed_envelope, envelope, "parsed envelope diverges from the signed URL");

	let url_account = verify_url(&signed_url, EMPTY_SIGNABLE, &fixture.options)?;
	assert_eq!(url_account.to_string(), signer, "verify_url rejected the anchor-signed URL");

	let body_account = verify_body(&signer, &envelope, EMPTY_SIGNABLE, &fixture.options)?;
	assert_eq!(body_account.to_string(), signer, "verify_body rejected the anchor-signed body");

	fixture.harness.shutdown()?;

	Ok(())
}

#[test]
fn signed_url_rejects_double_signing() -> TestResult {
	let envelope = Signed { nonce: "n".to_string(), timestamp: "t".to_string(), signature: "s".to_string() };
	let base = Url::parse("https://anchor.example/v1/resource")?;

	let signed_url = add_signature_to_url(&base, "keeta_account", &envelope)?;
	let duplicate = add_signature_to_url(&signed_url, "keeta_account", &envelope);
	assert!(
		matches!(duplicate, Err(RequestError::DuplicateParameter { .. })),
		"re-signing an already-signed URL must be rejected"
	);

	Ok(())
}

#[test]
fn parsing_rejects_unsigned_url() -> TestResult {
	let bare = Url::parse("https://anchor.example/v1/resource")?;
	let parsed = parse_signature_from_url(&bare);
	assert!(matches!(parsed, Err(RequestError::MissingAuthentication)), "URL carrying no credentials must be rejected");

	Ok(())
}

#[test]
fn parsing_rejects_partial_signature() -> TestResult {
	let partial = Url::parse("https://anchor.example/v1/resource?signed.nonce=n")?;
	let parsed = parse_signature_from_url(&partial);
	assert!(
		matches!(parsed, Err(RequestError::IncompleteSignature)),
		"URL with only some signed.* fields must be rejected"
	);

	Ok(())
}

/// Structured JSON inputs whose JCS canonicalization (RFC 8785) must agree with
/// the anchor's `objectToSignable`.
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

/// Project canonical string parts into the harness string-part transport format.
fn harness_strings(parts: &[String]) -> Value {
	let transport: Vec<Value> = parts
		.iter()
		.map(|part| json!({ "t": "s", "v": part }))
		.collect();

	Value::Array(transport)
}

#[test]
fn object_to_signable_matches_and_round_trips_through_the_anchor() -> TestResult {
	let mut fixture = Fixture::start()?;
	for (name, value) in canonical_vectors() {
		let anchor_parts = fixture.harness.object_to_signable(&value)?;
		let rust_parts = object_to_signable(&value)?;

		let expected: Vec<Signable> = anchor_parts
			.iter()
			.map(|part| Signable::Text(Cow::Owned(part.clone())))
			.collect();
		assert_eq!(rust_parts, expected, "canonical signable diverges from the anchor for `{name}`");

		fixture.assert_round_trip(name, &rust_parts, harness_strings(&anchor_parts))?;
	}

	fixture.harness.shutdown()?;

	Ok(())
}

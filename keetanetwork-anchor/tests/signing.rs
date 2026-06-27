//! Tests for the public signing API.

use std::borrow::Cow;
use std::error::Error;

use chrono::{DateTime, Duration, Utc};
use keetanetwork_account::{Account, Accountable, KeyECDSASECP256K1, KeyPair, Keyable};
use keetanetwork_anchor::signing::{
	object_to_signable, sign, sign_with, verify, SignParams, Signable, Signed, ToSignable, VerifyError, VerifyOptions,
};
use keetanetwork_crypto::prelude::IntoSecret;
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

/// A fixed nonce so signatures are reproducible across runs and languages.
const NONCE: &str = "11111111-1111-1111-1111-111111111111";
/// A fixed signing timestamp (millisecond precision, `Z` zone).
const TIMESTAMP: &str = "2024-01-02T03:04:05.678Z";

/// Build a deterministic SECP256K1 account from a single seed byte.
fn account_from_seed(seed_byte: u8) -> Account<KeyECDSASECP256K1> {
	let keyable = Keyable::Seed(([seed_byte; 32].into_secret(), 0));
	let accountable = Accountable::KeyAndType(keyable, KeyECDSASECP256K1::KEY_PAIR_TYPE);

	Account::<KeyECDSASECP256K1>::try_from(accountable).expect("account builds from seed")
}

/// The instant encoded by [`TIMESTAMP`].
fn reference_time() -> DateTime<Utc> {
	let fixed = DateTime::parse_from_rfc3339(TIMESTAMP).expect("fixed timestamp parses");
	fixed.with_timezone(&Utc)
}

/// Verify options anchored at the signing instant so skew is deterministic.
fn options_at_signed_time() -> VerifyOptions {
	VerifyOptions { max_skew_ms: 60_000, reference_time: reference_time() }
}

/// A representative request: the kind of domain type a consumer signs.
struct DemoRequest {
	action: String,
	amount: i64,
	account: Vec<u8>,
}

impl ToSignable for DemoRequest {
	fn to_signable(&self) -> Vec<Signable<'_>> {
		vec![
			Signable::from(self.action.as_str()),
			Signable::from(self.amount),
			Signable::Account(Cow::Borrowed(&self.account)),
		]
	}
}

fn demo(account: &Account<KeyECDSASECP256K1>) -> DemoRequest {
	DemoRequest { action: "transfer".to_string(), amount: 100, account: account.to_public_key_with_type() }
}

#[test]
fn valid_payloads_round_trip() -> TestResult {
	let account = account_from_seed(0x11);
	let public_key = account.to_public_key_with_type();
	let params = SignParams::new(NONCE, TIMESTAMP);
	let options = options_at_signed_time();

	let bridged = object_to_signable(&json!({ "amount": 100, "memo": "hi", "nested": { "b": 2, "a": 1 } }))?;
	let payloads: Vec<(&str, Vec<Signable<'static>>)> = vec![
		("empty", vec![]),
		("text", vec![Signable::from("transfer".to_string())]),
		("integer", vec![Signable::from(100_i64)]),
		("account", vec![Signable::Account(public_key.clone().into())]),
		(
			"mixed domain fields",
			vec![
				Signable::from("transfer".to_string()),
				Signable::from(100_i64),
				Signable::Account(public_key.clone().into()),
			],
		),
		("structured json bridge", bridged),
	];

	for (name, data) in payloads {
		let signed = sign_with(&account, &data, &params)?;
		let outcome = verify(&account, &data, &signed, &options);
		assert!(outcome.is_ok(), "payload `{name}` must round-trip, got {outcome:?}");
	}

	Ok(())
}

#[test]
fn fresh_params_round_trip() -> TestResult {
	let account = account_from_seed(0x22);
	let request = demo(&account);
	let options = VerifyOptions::default();

	let signed = sign(&account, &request)?;

	verify(&account, &request, &signed, &options)?;

	Ok(())
}

/// A corruption applied to a freshly signed envelope before re-verifying.
struct RejectionCase {
	name: &'static str,
	corrupt: fn(VerifyInputs) -> VerifyInputs,
	is_expected: fn(&VerifyError) -> bool,
}

/// Everything `verify` consumes, bundled so a corruption can rewrite any part.
struct VerifyInputs {
	account: Account<KeyECDSASECP256K1>,
	data: DemoRequest,
	signed: Signed,
	options: VerifyOptions,
}

fn valid_inputs() -> Result<VerifyInputs, Box<dyn Error>> {
	let account = account_from_seed(0x11);
	let data = demo(&account);
	let params = SignParams::new(NONCE, TIMESTAMP);
	let signed = sign_with(&account, &data, &params)?;
	let options = options_at_signed_time();

	Ok(VerifyInputs { account, data, signed, options })
}

fn corrupt_payload(mut inputs: VerifyInputs) -> VerifyInputs {
	inputs.data.amount = 999;
	inputs
}

fn corrupt_account(mut inputs: VerifyInputs) -> VerifyInputs {
	inputs.account = account_from_seed(0x99);
	inputs
}

fn corrupt_skew(mut inputs: VerifyInputs) -> VerifyInputs {
	let skewed_reference = reference_time() + Duration::minutes(10);
	inputs.options = VerifyOptions { max_skew_ms: 300_000, reference_time: skewed_reference };
	inputs
}

fn corrupt_timestamp(mut inputs: VerifyInputs) -> VerifyInputs {
	inputs.signed.timestamp = "2024-01-02T03:04:05+00:00".to_string();
	inputs
}

fn corrupt_signature(mut inputs: VerifyInputs) -> VerifyInputs {
	inputs.signed.signature = "not base64!!!".to_string();
	inputs
}

fn rejection_cases() -> Vec<RejectionCase> {
	vec![
		RejectionCase {
			name: "tampered payload",
			corrupt: corrupt_payload,
			is_expected: |error| matches!(error, VerifyError::SignatureMismatch),
		},
		RejectionCase {
			name: "wrong account",
			corrupt: corrupt_account,
			is_expected: |error| matches!(error, VerifyError::SignatureMismatch),
		},
		RejectionCase {
			name: "clock skew",
			corrupt: corrupt_skew,
			is_expected: |error| matches!(error, VerifyError::ClockSkew { skew_ms: 600_000, max_ms: 300_000 }),
		},
		RejectionCase {
			name: "non-canonical timestamp",
			corrupt: corrupt_timestamp,
			is_expected: |error| matches!(error, VerifyError::MalformedTimestamp),
		},
		RejectionCase {
			name: "malformed signature",
			corrupt: corrupt_signature,
			is_expected: |error| matches!(error, VerifyError::MalformedSignature { .. }),
		},
	]
}

#[test]
fn verify_rejects_corrupted_envelopes() -> TestResult {
	for case in rejection_cases() {
		let inputs = (case.corrupt)(valid_inputs()?);
		let outcome = verify(&inputs.account, &inputs.data, &inputs.signed, &inputs.options);

		let rejected = matches!(&outcome, Err(error) if (case.is_expected)(error));
		assert!(rejected, "case `{}`: unexpected verify outcome {outcome:?}", case.name);
	}

	Ok(())
}

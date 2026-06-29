//! wasmtime P2 KYC component end-to-end test.
//!
//! Boots the `KeetaNetKYCAnchorHTTPServer` via the TypeScript KYC harness, which
//! initializes a chain and publishes the service metadata on-chain, then drives
//! the exported `client` resource over `wasi:http`.

use serde_json::{json, Value};

mod common;
mod wasmtime_p2;

use common::{field_str, issue_attributes, BoxError, KycHarness, SUBJECT_SEED};
use wasmtime_p2::bindings::exports::keeta::anchor::kyc::{
	CertificatesOutcome, KycProvider, StatusOutcome, VerificationOutcome,
};
use wasmtime_p2::{coded, instantiate};

/// Project a decrypted attribute's bytes into the JSON value the oracle holds: a
/// scalar attribute is its UTF-8 text; a structured attribute is its JSON object.
fn decoded_to_value(expected: &Value, bytes: Vec<u8>) -> Result<Value, BoxError> {
	let text = String::from_utf8(bytes)?;
	let value = match expected {
		Value::String(_) => Value::String(text),
		_ => serde_json::from_str(&text)?,
	};
	Ok(value)
}

#[tokio::test]
#[ignore = "requires `make node-harness` and the built wasm32-wasip2 component"]
async fn p2_kyc_signs_against_live_anchor() -> Result<(), BoxError> {
	let mut harness = KycHarness::start()?;

	// Boot the real KYC anchor advertising a signed, US-bound provider, with its
	// metadata published on-chain to a root account.
	let started = harness.request("startKycAnchor", json!({ "sign": true, "countryCodes": ["US"] }))?;
	let provider_id = field_str(&started, "providerId")?;
	let node_url = field_str(&started, "api")?;
	let root = field_str(&started, "root")?;

	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let kyc = bindings.keeta_anchor_kyc();

	// Derive a deterministic secp256k1 signing account from a 32-byte seed as a
	// `crypto` account resource, then bind a client borrowing it. The component
	// resolves the root account over wasi:http.
	let account = crypto
		.account()
		.call_from_seed(&mut store, &"11".repeat(32), 0, "ecdsa_secp256k1")
		.await?
		.map_err(coded)?;
	let client = kyc
		.client()
		.call_with_account(&mut store, &node_url, &root, account)
		.await?
		.map_err(coded)?;

	// Discovery: exactly the one advertised provider must surface, proving the
	// metadata fetch and entry-signature verification match the TS reference.
	let countries = vec!["US".to_string()];
	let providers = kyc
		.client()
		.call_providers(&mut store, client, &countries)
		.await?
		.map_err(coded)?;
	assert_eq!(providers.len(), 1, "exactly one provider must serve the requested country");
	let provider: KycProvider = providers
		.into_iter()
		.next()
		.expect("the provider list is non-empty");
	assert_eq!(provider.id, provider_id, "the discovered provider id must match the harness");

	// SignedBody parity: the real TS server verifies the signature on the empty
	// `create-verification` payload, or the whole request is rejected.
	let outcome = kyc
		.client()
		.call_create_verification(&mut store, client, &provider, &countries, None)
		.await?
		.map_err(coded)?;
	let verification = match outcome {
		VerificationOutcome::Ready(verification) => verification,
		VerificationOutcome::Retry(after) => {
			panic!("create-verification must be ready, got retry after {after}ms")
		}
	};
	assert!(!verification.id.is_empty(), "the verification must carry an id");
	assert!(!verification.web_url.is_empty(), "the verification must carry a web url");

	// SignedUrl parity: status reads sign the request URL; the TS server must
	// accept it and report the harness-configured pending status.
	let status = kyc
		.client()
		.call_get_verification_status(&mut store, client, &provider, &verification.id)
		.await?
		.map_err(coded)?;
	let status = match status {
		StatusOutcome::Ready(status) => status,
		StatusOutcome::Retry(after) => panic!("status must be ready, got retry after {after}ms"),
	};
	assert!(!status.status.is_empty(), "the status must be non-empty");

	// SignedUrl parity on the certificate path: the server accepts the signed
	// request and returns either the issued certificates or a retry.
	let certificates = kyc
		.client()
		.call_get_certificates(&mut store, client, &provider, &verification.id)
		.await?
		.map_err(coded)?;
	assert!(
		matches!(certificates, CertificatesOutcome::Ready(_) | CertificatesOutcome::Retry(_)),
		"the certificate read must yield a ready or retry outcome"
	);

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
#[ignore = "requires `make node-harness` and the built wasm32-wasip2 component"]
async fn p2_kyc_decrypts_issued_leaf_to_oracle() -> Result<(), BoxError> {
	let mut harness = KycHarness::start()?;
	harness.request("startKycAnchor", json!({ "sign": true, "countryCodes": ["US"] }))?;

	// The reference anchor issues a populated leaf for our subject and returns the
	// `getValue()` oracle it reads back, the ground truth for the binding decode.
	let issued = harness.request(
		"issueCertificate",
		json!({ "subjectSeed": SUBJECT_SEED, "attributes": issue_attributes() }),
	)?;
	let leaf_pem = field_str(&issued, "leaf")?;
	let oracle = issued
		.get("oracle")
		.and_then(Value::as_object)
		.ok_or("issued certificate is missing its oracle")?;

	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let certificates = bindings.keeta_anchor_certificates();

	// The same seed yields the same secp256k1 account that the leaf was encrypted
	// to, so the binding can decrypt every sensitive attribute.
	let account = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, "ecdsa_secp256k1")
		.await?
		.map_err(coded)?;
	let leaf = certificates
		.kyc_certificate()
		.call_parse(&mut store, &leaf_pem)
		.await?
		.map_err(coded)?;

	// Every attribute the binding decodes through the shared core must equal the
	// reference oracle: scalars by value, structured types field-for-field.
	for (name, expected) in oracle {
		let bytes = certificates
			.kyc_certificate()
			.call_decrypt_attribute(&mut store, leaf, name, account)
			.await?
			.map_err(coded)?;
		let actual = decoded_to_value(expected, bytes)?;
		assert_eq!(&actual, expected, "decoded attribute `{name}` must match the reference oracle");
	}

	harness.shutdown()?;
	Ok(())
}

//! wasmtime P2 KYC component end-to-end test

use serde_json::{json, Value};

mod common;
mod wasmtime_p2;

use common::{field_str, issue_attributes, BoxError, Harness, SUBJECT_SEED};
use wasmtime_p2::bindings::exports::keeta::anchor::certificates::IssueAttribute;
use wasmtime_p2::bindings::exports::keeta::anchor::kyc::{
	CertificatesOutcome, KycProvider, StatusOutcome, VerificationOutcome,
};
use wasmtime_p2::{coded, instantiate};

/// Project a decrypted attribute's bytes into the JSON value the reference holds:
/// a scalar attribute is its UTF-8 text; a structured attribute is its JSON object.
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
	let mut harness = Harness::kyc()?;

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
		.ok_or("the provider list is non-empty")?;
	assert_eq!(provider.id, provider_id, "the discovered provider id must match the harness");

	// SignedBody parity: the real TS server verifies the signature on the
	// `create-verification` payload (here carrying a redirect URL), or the
	// whole request is rejected.
	let redirect = Some("https://example.test/done");
	let outcome = kyc
		.client()
		.call_create_verification(&mut store, client, &provider, &countries, redirect)
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
	// accept it and report the harness-configured pending status together with
	// its manual-review flag.
	let status = kyc
		.client()
		.call_get_verification_status(&mut store, client, &provider, &verification.id)
		.await?
		.map_err(coded)?;
	let status = match status {
		StatusOutcome::Ready(status) => status,
		StatusOutcome::Retry(after) => panic!("status must be ready, got retry after {after}ms"),
	};
	assert_eq!(status.status, "pending", "the harness reports every verification pending");
	assert_eq!(
		status.requires_manual_verification,
		Some(true),
		"the manual-review flag must survive the status decode"
	);

	// A not-yet-issued certificate reports as a retry (the server's 404), the
	// promise the caller polls on.
	let pending = kyc
		.client()
		.call_get_certificates(&mut store, client, &provider, "pending")
		.await?
		.map_err(coded)?;
	assert!(matches!(pending, CertificatesOutcome::Retry(_)), "a pending certificate must yield a retry outcome");

	// A leaf issued for a verification is served back as its full `[leaf, ca]`
	// chain over the same certificate path.
	let issued = harness.request("issueCertificate", json!({ "subjectSeed": SUBJECT_SEED, "attributes": issue_attributes() }))?;
	let verification_id = field_str(&issued, "verificationID")?;
	let certificates = kyc
		.client()
		.call_get_certificates(&mut store, client, &provider, &verification_id)
		.await?
		.map_err(coded)?;
	let CertificatesOutcome::Ready(groups) = certificates else {
		panic!("an issued verification must serve its certificates")
	};
	assert_eq!(groups.len(), 2, "the issued verification must serve its leaf and ca chain");

	// The on-chain ledger read: a fresh holder publishes two certificate
	// records (with and without intermediates). Both must read back through
	// the same client resource with the recorded CA bundle intact.
	let chain = harness.request("publishCertificateChain", json!({}))?;
	let chain_account = field_str(&chain, "account")?;
	let chain_ca = field_str(&chain, "ca")?;
	let published = kyc
		.client()
		.call_get_all_certificates(&mut store, client, &chain_account)
		.await?
		.map_err(coded)?;
	assert_eq!(published.len(), 2, "both published records must read back");

	let with_intermediates = published
		.iter()
		.find(|record| !record.intermediates.is_empty())
		.ok_or("a record with intermediates must read back")?;
	assert_eq!(with_intermediates.intermediates, [chain_ca], "the recorded CA bundle must survive the round trip");
	assert!(
		published
			.iter()
			.any(|record| record.intermediates.is_empty()),
		"a record published without intermediates must decode as empty"
	);

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
#[ignore = "requires the built wasm32-wasip2 component"]
async fn p2_kyc_issues_a_leaf_across_algorithms() -> Result<(), BoxError> {
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let certificates = bindings.keeta_anchor_certificates();

	// Subject and issuer deliberately use different algorithms: the component
	// must encrypt sensitive attributes to the ed25519 subject while signing the
	// leaf with the secp256k1 issuer.
	let subject = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, "ed25519")
		.await?
		.map_err(coded)?;
	let issuer = crypto
		.account()
		.call_from_seed(&mut store, &"22".repeat(32), 0, "ecdsa_secp256k1")
		.await?
		.map_err(coded)?;

	let attributes = vec![
		IssueAttribute { name: "postalCode".to_string(), sensitive: false, value: b"12345".to_vec() },
		IssueAttribute { name: "email".to_string(), sensitive: true, value: b"john@example.com".to_vec() },
	];

	let leaf = certificates
		.kyc_certificate()
		.call_issue(
			&mut store,
			subject,
			issuer,
			"Subject",
			"Issuer",
			7,
			1_700_000_000,
			1_731_536_000,
			false,
			&attributes,
		)
		.await?
		.map_err(coded)?;

	// The issued leaf must survive a PEM round-trip, proving the encoding is the
	// unambiguous form the reference reader accepts.
	let pem = certificates
		.kyc_certificate()
		.call_pem(&mut store, leaf)
		.await?
		.map_err(coded)?;
	let re_parsed = certificates
		.kyc_certificate()
		.call_parse(&mut store, &pem)
		.await?
		.map_err(coded)?;

	let plain = certificates
		.kyc_certificate()
		.call_plain_attribute(&mut store, re_parsed, "postalCode")
		.await?
		.map_err(coded)?;
	assert_eq!(plain, b"12345".to_vec(), "the plain attribute must round-trip through issuance and pem");

	let decrypted = certificates
		.kyc_certificate()
		.call_decrypt_attribute(&mut store, re_parsed, "email", subject)
		.await?
		.map_err(coded)?;
	assert_eq!(decrypted, b"john@example.com".to_vec(), "the sensitive attribute must decrypt to the issued value");

	// The subject can prove the sensitive attribute, and the proof validates back
	// against the leaf with the subject's public key alone.
	let proof = certificates
		.kyc_certificate()
		.call_prove(&mut store, re_parsed, "email", subject)
		.await?
		.map_err(coded)?;
	let valid = certificates
		.kyc_certificate()
		.call_validate_proof(&mut store, re_parsed, "email", subject, &proof)
		.await?
		.map_err(coded)?;
	assert!(valid, "the sensitive attribute proof must validate against the issued leaf");

	Ok(())
}

#[tokio::test]
#[ignore = "requires `make node-harness` and the built wasm32-wasip2 component"]
async fn p2_kyc_decrypts_issued_leaf_to_reference_values() -> Result<(), BoxError> {
	let mut harness = Harness::kyc()?;
	harness.request("startKycAnchor", json!({ "sign": true, "countryCodes": ["US"] }))?;

	// The reference anchor issues a populated leaf for our subject and returns the
	// `getValue()` values it reads back, the ground truth for the binding decode.
	let issued = harness
		.request("issueCertificate", json!({ "subjectSeed": SUBJECT_SEED, "attributes": issue_attributes() }))?;
	let leaf_pem = field_str(&issued, "leaf")?;
	let attributes = issued
		.get("attributes")
		.and_then(Value::as_object)
		.ok_or("issued certificate is missing its attributes")?;

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
	// reference value: scalars by value, structured types field-for-field.
	for (name, expected) in attributes {
		let bytes = certificates
			.kyc_certificate()
			.call_decrypt_attribute(&mut store, leaf, name, account)
			.await?
			.map_err(coded)?;
		let actual = decoded_to_value(expected, bytes)?;
		assert_eq!(&actual, expected, "decoded attribute `{name}` must match the reference value");
	}

	harness.shutdown()?;
	Ok(())
}

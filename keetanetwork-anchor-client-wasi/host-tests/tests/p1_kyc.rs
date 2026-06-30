//! wasmtime P1 KYC core-module end-to-end test: issue a leaf, then read it back
//! through the same module, with no node, harness, or network.

mod common;
mod dotnet;
mod wasmtime_p1;

use common::{BoxError, SUBJECT_SEED};
use serde_json::json;
use wasmtime_p1::P1;

#[test]
#[ignore = "requires the built wasm32-wasip1 module"]
fn p1_kyc_issues_a_leaf_across_algorithms() -> Result<(), BoxError> {
	if !dotnet::module_path().exists() {
		eprintln!("skipping P1 issuance e2e: build the wasm32-wasip1 module first (make build-wasi)");
		return Ok(());
	}

	let mut p1 = P1::instantiate()?;

	// Subject and issuer deliberately use different algorithms
	let subject = p1.account_from_seed(SUBJECT_SEED, 0, "ed25519")?;
	let issuer = p1.account_from_seed(&"22".repeat(32), 0, "ecdsa_secp256k1")?;

	let params = json!({
		"subjectDn": "Subject",
		"issuerDn": "Issuer",
		"serial": 7,
		"notBefore": 1_700_000_000,
		"notAfter": 1_731_536_000,
		"isCa": false,
		"attributes": [
			{ "name": "postalCode", "sensitive": false, "value": b"12345".to_vec() },
			{ "name": "email", "sensitive": true, "value": b"john@example.com".to_vec() },
		],
	});

	let params = serde_json::to_vec(&params)?;
	let leaf = p1.issue(subject, issuer, &params)?;

	let pem = String::from_utf8(p1.pem(leaf)?)?;
	assert!(pem.contains("BEGIN CERTIFICATE"), "the issued leaf must encode to PEM");

	let plain = p1.plain_attribute(leaf, "postalCode")?;
	assert_eq!(plain, b"12345".to_vec(), "the plain attribute must round-trip through P1 issuance");

	let decrypted = p1.decrypt_attribute(leaf, "email", subject)?;
	assert_eq!(decrypted, b"john@example.com".to_vec(), "the sensitive attribute must decrypt to the issued value");

	// The subject proves the sensitive attribute, and the proof validates back
	// against the leaf.
	let proof = p1.prove(leaf, "email", subject)?;
	let valid = p1.validate_proof(leaf, "email", subject, &proof)?;
	assert_eq!(valid, 1, "the sensitive attribute proof must validate against the issued leaf");

	Ok(())
}

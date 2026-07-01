//! wasmtime P1 sharable-attributes core-module test: issue a leaf, seal a
//! selected subset of its attributes for a recipient, then open the PEM envelope
//! and read the disclosed values back — no node, harness, or network.

mod common;
mod dotnet;
mod wasmtime_p1;

use common::{BoxError, SUBJECT_SEED};
use serde_json::json;
use wasmtime_p1::P1;

/// A seed the issuer derives from at index 0.
const ISSUER_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// A seed the recipient derives from at index 0.
const RECIPIENT_SEED: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const ALGORITHM: &str = "ecdsa_secp256k1";

#[test]
#[ignore = "requires the built wasm32-wasip1 module"]
fn p1_sharable_discloses_selected_attributes_to_a_recipient() -> Result<(), BoxError> {
	if !dotnet::module_path().exists() {
		eprintln!("skipping P1 sharable e2e: build the wasm32-wasip1 module first (make build-wasi)");
		return Ok(());
	}

	let mut p1 = P1::instantiate()?;

	let subject = p1.account_from_seed(SUBJECT_SEED, 0, ALGORITHM)?;
	let issuer = p1.account_from_seed(ISSUER_SEED, 0, ALGORITHM)?;
	let recipient = p1.account_from_seed(RECIPIENT_SEED, 0, ALGORITHM)?;

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

	// Seal both attributes for the recipient, then export the PEM envelope.
	let bundle = p1.sharable_from_certificate(leaf, subject, &[], &["postalCode", "email"])?;
	p1.sharable_grant_access(bundle, &[recipient])?;
	let pem = p1.sharable_to_pem(bundle)?;

	// The recipient opens the envelope and reads both disclosed values back.
	let opened = p1.sharable_from_pem(&pem, &[recipient])?;

	let plain = p1.sharable_attribute_value(opened, "postalCode")?;
	assert_eq!(plain, b"12345".to_vec(), "the recipient must read the disclosed plain attribute");

	let sensitive = p1.sharable_attribute_value(opened, "email")?;
	assert_eq!(sensitive, b"john@example.com".to_vec(), "the recipient must read the disclosed sensitive attribute");

	let mut names: Vec<String> = serde_json::from_slice(&p1.sharable_attribute_names(opened)?)?;
	names.sort();
	assert_eq!(names, vec!["email".to_string(), "postalCode".to_string()], "the bundle lists the disclosed names");

	Ok(())
}

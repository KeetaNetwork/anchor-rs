//! wasmtime P2 offline `sharable-certificate-attributes` tests.
//!
//! These issue a leaf, seal a selected subset of its attributes for a recipient,
//! and read the disclosed values back through the same component.

mod common;
mod wasmtime_p2;

use common::BoxError;
use wasmtime_p2::bindings::exports::keeta::anchor::certificates::IssueAttribute;
use wasmtime_p2::bindings::exports::keeta::client::crypto::KeyAlgorithm;
use wasmtime_p2::{coded, component_built, instantiate};

/// A seed the subject (and proving account) derives from at index 0.
const SUBJECT_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// A seed the issuer derives from at index 0.
const ISSUER_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// A seed the recipient derives from at index 0.
const RECIPIENT_SEED: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const ALGORITHM: KeyAlgorithm = KeyAlgorithm::EcdsaSecp256k1;
/// The plain attribute embedded in the fixture leaf.
const PLAIN: (&str, &[u8]) = ("postalCode", b"12345");
/// The sensitive attribute embedded in the fixture leaf.
const SENSITIVE: (&str, &[u8]) = ("email", b"john@example.com");

/// Skip when the component has not been built.
macro_rules! require_component {
	() => {
		if !component_built() {
			eprintln!("skipping P2 sharable test: build the wasm32-wasip2 component first");
			return Ok(());
		}
	};
}

#[tokio::test]
async fn a_sealed_bundle_discloses_every_attribute_through_pem() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let certificates = bindings.keeta_anchor_certificates();
	let sharable = bindings.keeta_anchor_sharable();

	let subject = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let issuer = crypto
		.account()
		.call_from_seed(&mut store, ISSUER_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let recipient = crypto
		.account()
		.call_from_seed(&mut store, RECIPIENT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;

	let attributes = vec![
		IssueAttribute { name: PLAIN.0.to_string(), sensitive: false, value: PLAIN.1.to_vec() },
		IssueAttribute { name: SENSITIVE.0.to_string(), sensitive: true, value: SENSITIVE.1.to_vec() },
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

	let names = vec![PLAIN.0.to_string(), SENSITIVE.0.to_string()];
	let bundle = sharable
		.sharable_certificate_attributes()
		.call_from_certificate(&mut store, leaf, subject, &[], &names)
		.await?
		.map_err(coded)?;

	sharable
		.sharable_certificate_attributes()
		.call_grant_access(&mut store, bundle, &[recipient])
		.await?
		.map_err(coded)?;
	let pem = sharable
		.sharable_certificate_attributes()
		.call_to_pem(&mut store, bundle)
		.await?
		.map_err(coded)?;

	let opened = sharable
		.sharable_certificate_attributes()
		.call_from_pem(&mut store, &pem, &[recipient])
		.await?
		.map_err(coded)?;

	let plain = sharable
		.sharable_certificate_attributes()
		.call_attribute_value(&mut store, opened, PLAIN.0)
		.await?
		.map_err(coded)?;
	assert_eq!(plain, Some(PLAIN.1.to_vec()), "the recipient must read the disclosed plain attribute");

	let sensitive = sharable
		.sharable_certificate_attributes()
		.call_attribute_value(&mut store, opened, SENSITIVE.0)
		.await?
		.map_err(coded)?;
	assert_eq!(sensitive, Some(SENSITIVE.1.to_vec()), "the recipient must read the disclosed sensitive attribute");

	Ok(())
}

#[tokio::test]
async fn a_bundle_lists_its_disclosed_names_and_recipient() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let certificates = bindings.keeta_anchor_certificates();
	let sharable = bindings.keeta_anchor_sharable();

	let subject = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let issuer = crypto
		.account()
		.call_from_seed(&mut store, ISSUER_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let recipient = crypto
		.account()
		.call_from_seed(&mut store, RECIPIENT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;

	let attributes = vec![
		IssueAttribute { name: PLAIN.0.to_string(), sensitive: false, value: PLAIN.1.to_vec() },
		IssueAttribute { name: SENSITIVE.0.to_string(), sensitive: true, value: SENSITIVE.1.to_vec() },
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

	let names = vec![SENSITIVE.0.to_string()];
	let bundle = sharable
		.sharable_certificate_attributes()
		.call_from_certificate(&mut store, leaf, subject, &[], &names)
		.await?
		.map_err(coded)?;
	sharable
		.sharable_certificate_attributes()
		.call_grant_access(&mut store, bundle, &[recipient])
		.await?
		.map_err(coded)?;

	let disclosed = sharable
		.sharable_certificate_attributes()
		.call_attribute_names(&mut store, bundle)
		.await?
		.map_err(coded)?;
	assert_eq!(disclosed, names, "the bundle must list exactly the disclosed attribute names");

	let principals = sharable
		.sharable_certificate_attributes()
		.call_principals(&mut store, bundle)
		.await?
		.map_err(coded)?;
	let recipient_key = crypto
		.account()
		.call_public_key(&mut store, recipient)
		.await?;
	assert_eq!(
		principals.into_iter().map(hex_lower).collect::<Vec<_>>(),
		vec![recipient_key],
		"the granted recipient must be the sole principal"
	);

	Ok(())
}

/// Lowercase hex of `bytes`, matching the `account.public-key` text encoding.
fn hex_lower(bytes: Vec<u8>) -> String {
	let mut text = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		text.push_str(&format!("{byte:02x}"));
	}

	text
}

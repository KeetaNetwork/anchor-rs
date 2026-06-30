//! Service-metadata resolution and KYC provider lookup, driven against a live
//! anchor whose signed KYC entry is published on-chain and read back.

mod harness;

use std::error::Error;
use std::sync::Arc;

use harness::{HarnessError, KycHarness};
use keetanetwork_anchor_client::{decode_base64, parse_metadata, CountryCode, KycQuery, ReqwestTransport, Resolver};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// A resolver reading the on-chain metadata of `root` through the node API at
/// `api`, over a live reqwest transport.
fn resolver_for(api: &str, root: &str) -> Result<Resolver, Box<dyn Error>> {
	let transport = Arc::new(ReqwestTransport::try_default()?);
	let resolver = Resolver::new(transport, api, [root.to_string()]);
	Ok(resolver)
}

/// Project requested country codes into canonical [`CountryCode`]s.
fn requested(codes: &[&str]) -> Result<Vec<CountryCode>, Box<dyn Error>> {
	let mut canonical = Vec::with_capacity(codes.len());
	for code in codes {
		canonical.push(CountryCode::try_from(*code)?);
	}

	Ok(canonical)
}

#[test]
fn metadata_blobs_decode_to_their_source_json() -> TestResult {
	let mut harness = KycHarness::start()?;
	let vectors = vec![
		("empty services", json!({ "version": 1, "currencyMap": {}, "services": {} })),
		("currency map", json!({ "version": 1, "currencyMap": { "USD": "keeta_token" }, "services": { "kyc": {} } })),
		("array values", json!({ "version": 1, "list": [1, 2, 3], "services": {} })),
	];

	for (name, value) in vectors {
		let blob = harness.build_metadata(&value)?;
		let raw = decode_base64(&blob)?;
		let decoded = parse_metadata(&raw)?;
		assert_eq!(decoded, value, "decoded metadata diverges from source for `{name}`");
	}

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn lookup_returns_the_signed_kyc_provider() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US", "CA"]), true)?;
	let resolver = resolver_for(&anchor.api, &anchor.root)?;

	let providers = resolver.lookup::<KycQuery>(&requested(&["US"])?).await?;
	let provider = providers
		.into_iter()
		.next()
		.ok_or(HarnessError::MissingField { field: "kyc provider" })?;
	assert_eq!(provider.id, anchor.provider_id, "resolved provider id diverges");
	assert_eq!(provider.ca, anchor.ca, "resolved provider CA diverges");

	let advertised = anchor.create_verification_url()?;
	assert_eq!(
		provider.operations.create_verification.as_deref(),
		Some(advertised.as_str()),
		"createVerification endpoint diverges"
	);

	let bounded = provider
		.country_codes
		.ok_or(HarnessError::MissingField { field: "countryCodes" })?;
	assert!(bounded.contains(&CountryCode::try_from("US")?), "provider must advertise the US");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn lookup_drops_an_entry_with_a_tampered_signature() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), true)?;

	let raw = decode_base64(&anchor.blob)?;
	let provider = anchor.provider_id.as_str();

	let mut document = parse_metadata(&raw)?;
	document["services"]["kyc"][provider]["operations"]["createVerification"] =
		Value::String("https://evil.example/api/createVerification".to_string());

	let published = harness.publish_metadata(&document)?;
	let resolver = resolver_for(&published.api, &published.root)?;

	let providers = resolver.lookup::<KycQuery>(&requested(&["US"])?).await?;
	assert!(providers.is_empty(), "an entry whose signature no longer covers its operations must be dropped");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn country_filter_matches_only_covered_requests() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US", "CA"]), true)?;
	let resolver = resolver_for(&anchor.api, &anchor.root)?;

	let cases = [
		("subset", vec!["US"], true),
		("exact set", vec!["US", "CA"], true),
		("uncovered", vec!["GB"], false),
		("partly covered", vec!["US", "GB"], false),
	];

	for (name, codes, expected) in cases {
		let found = !resolver
			.lookup::<KycQuery>(&requested(&codes)?)
			.await?
			.is_empty();
		assert_eq!(found, expected, "country filter result wrong for `{name}`");
	}

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn worldwide_provider_matches_any_country() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), true)?;

	let raw = decode_base64(&anchor.blob)?;
	let provider = anchor.provider_id.as_str();

	let mut document = parse_metadata(&raw)?;
	document["services"]["kyc"][provider]
		.as_object_mut()
		.ok_or(HarnessError::MissingField { field: "kyc provider entry" })?
		.remove("countryCodes");

	let published = harness.publish_metadata(&document)?;
	let resolver = resolver_for(&published.api, &published.root)?;

	let providers = resolver.lookup::<KycQuery>(&requested(&["GB"])?).await?;
	assert!(!providers.is_empty(), "a provider with no country list must validate worldwide");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn unsigned_entry_is_accepted() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), false)?;
	let resolver = resolver_for(&anchor.api, &anchor.root)?;

	let providers = resolver.lookup::<KycQuery>(&requested(&["US"])?).await?;
	assert!(!providers.is_empty(), "an entry with neither account nor signed must be accepted");

	harness.shutdown()?;
	Ok(())
}

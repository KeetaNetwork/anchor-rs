//! Full KYC client path against the live harness anchor: discover the provider,
//! then create a verification, poll its status, and fetch certificates through
//! [`KycClient`], exercising each auth mode end to end.

mod common;
mod harness;

use std::error::Error;
use std::sync::Arc;

use common::account_from_seed;
use harness::{issue_attributes, HarnessError, KycHarness, SUBJECT_SEED};
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_client::{
	AnchorContext, AnchorOutcome, CountryCode, KeetaClient, KycClient, ReqwestTransport, Resolver, SupportedCountries,
};
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

/// A KYC client whose resolver reads the `root` account's on-chain metadata
/// through the node client at `api`, and whose caller signs with a
/// deterministic account over the live reqwest transport.
fn client_for(api: &str, root: &str) -> Result<KycClient, Box<dyn Error>> {
	let transport = Arc::new(ReqwestTransport::try_default()?);
	let resolver = Resolver::new(KeetaClient::new(api), transport.clone(), [root.to_string()]);
	let signer = Arc::new(GenericAccount::EcdsaSecp256k1(account_from_seed(0x11)));
	let context = AnchorContext::new(resolver, transport, signer);

	Ok(KycClient::new(context))
}

#[tokio::test]
async fn kyc_client_runs_the_full_verification_path() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), true)?;
	let client = client_for(&anchor.api, &anchor.root)?;

	let countries = [CountryCode::try_from("US")?];
	let providers = client.providers(&countries).await?;
	let provider = providers
		.into_iter()
		.next()
		.ok_or(HarnessError::MissingField { field: "kyc provider" })?;
	assert_eq!(provider.id, anchor.provider_id, "discovered provider id diverges");

	let verification = client
		.create_verification(&provider, &countries, None)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "verification" })?;
	assert!(!verification.id.is_empty(), "the anchor must assign a verification id");
	assert!(!verification.web_url.is_empty(), "verification must carry a web URL");
	assert!(!verification.expected_cost.token.is_empty(), "verification must carry an expected-cost token");

	// A redirect URL rides the signed create body; the server must accept the
	// extra field and still assign a verification.
	let redirected = client
		.create_verification(&provider, &countries, Some("https://example.test/done"))
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "redirected verification" })?;
	assert!(!redirected.id.is_empty(), "a redirected create must assign a verification id");

	let status = client
		.get_verification_status(&provider, &verification.id)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "verification status" })?;
	assert_eq!(status.status, "pending", "unexpected verification status");
	assert_eq!(
		status.requires_manual_verification,
		Some(true),
		"the manual-review flag must survive the status decode"
	);

	let pending = client.get_certificates(&provider, "pending").await?;
	assert!(matches!(pending, AnchorOutcome::Retry { .. }), "a pending certificate must ask the caller to retry");

	let certificates = client
		.get_certificates(&provider, "ready")
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "certificates" })?;
	assert!(!certificates.results.is_empty(), "issued certificates must not be empty");

	// A leaf issued for a verification is served back as its full `[leaf, ca]`
	// chain over the same signed-URL certificate path.
	let issued = harness.issue_certificate(SUBJECT_SEED, &issue_attributes())?;
	let verification_id = issued
		.get("verificationID")
		.and_then(Value::as_str)
		.ok_or(HarnessError::MissingField { field: "verificationID" })?;
	let chain = client
		.get_certificates(&provider, verification_id)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "issued chain" })?;
	assert_eq!(chain.results.len(), 2, "the issued verification must serve its leaf and ca chain");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn supported_countries_fold_across_the_published_providers() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US", "DE", "DE"]), true)?;
	let client = client_for(&anchor.api, &anchor.root)?;

	let supported = client.get_supported_countries().await?;
	let expected = SupportedCountries::Countries(vec![CountryCode::try_from("DE")?, CountryCode::try_from("US")?]);
	assert_eq!(supported, expected, "the published codes must fold sorted and deduplicated");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn an_unconfigured_provider_publishes_an_empty_country_union() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(None, true)?;
	let client = client_for(&anchor.api, &anchor.root)?;

	// The reference server publishes `countryCodes: []` when none are configured.
	let supported = client.get_supported_countries().await?;
	assert_eq!(supported, SupportedCountries::Countries(Vec::new()), "an unconfigured provider unions no countries");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn kyc_client_rejects_a_provider_missing_an_operation() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), true)?;
	let client = client_for(&anchor.api, &anchor.root)?;

	let countries = [CountryCode::try_from("US")?];
	let providers = client.providers(&countries).await?;
	let mut provider = providers
		.into_iter()
		.next()
		.ok_or(HarnessError::MissingField { field: "kyc provider" })?;

	provider.operations.create_verification = None;
	let outcome = client
		.create_verification(&provider, &countries, None)
		.await;
	assert!(outcome.is_err(), "a provider without createVerification must surface a typed error");

	harness.shutdown()?;
	Ok(())
}

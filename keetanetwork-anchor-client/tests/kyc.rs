//! Full KYC client path against the live harness anchor: discover the provider,
//! then create a verification, poll its status, and fetch certificates through
//! [`KycClient`], exercising each auth mode end to end.

mod common;
mod harness;

use std::error::Error;

use common::live_context;
use harness::{issue_attributes, HarnessError, KycAnchor, KycHarness, SUBJECT_SEED};
use keetanetwork_anchor_client::{AnchorOutcome, CountryCode, KycClient, KycProvider, SupportedCountries};
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

/// A started harness anchor publishing `countries`, and the live client bound
/// to it over the shared [`live_context`].
fn started_anchor(countries: Option<&[&str]>) -> Result<(KycHarness, KycAnchor, KycClient), Box<dyn Error>> {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(countries, true)?;
	let context = live_context(&anchor.api, &anchor.root)?;
	let client = KycClient::new(context);

	Ok((harness, anchor, client))
}

/// The first discovered provider, or the missing-field harness error.
fn first_provider(providers: Vec<KycProvider<'_>>) -> Result<KycProvider<'_>, HarnessError> {
	providers
		.into_iter()
		.next()
		.ok_or(HarnessError::MissingField { field: "kyc provider" })
}

#[tokio::test]
async fn kyc_client_runs_the_full_verification_path() -> TestResult {
	let (mut harness, anchor, client) = started_anchor(Some(&["US"]))?;

	let countries = [CountryCode::try_from("US")?];
	let providers = client.providers(&countries).await?;
	let provider = first_provider(providers)?;
	assert_eq!(provider.id, anchor.provider_id, "discovered provider id diverges");

	let verification = provider
		.create_verification(&countries, None)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "verification" })?;
	assert!(!verification.id.is_empty(), "the anchor must assign a verification id");
	assert!(!verification.web_url.is_empty(), "verification must carry a web URL");
	assert!(!verification.expected_cost.token.is_empty(), "verification must carry an expected-cost token");

	// A redirect URL rides the signed create body; the server must accept the
	// extra field and still assign a verification.
	let redirected = provider
		.create_verification(&countries, Some("https://example.test/done"))
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "redirected verification" })?;
	assert!(!redirected.id.is_empty(), "a redirected create must assign a verification id");

	let status = provider
		.get_verification_status(&verification.id)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "verification status" })?;
	assert_eq!(status.status, "pending", "unexpected verification status");
	assert_eq!(
		status.requires_manual_verification,
		Some(true),
		"the manual-review flag must survive the status decode"
	);

	let pending = provider.get_certificates("pending").await?;
	assert!(matches!(pending, AnchorOutcome::Retry { .. }), "a pending certificate must ask the caller to retry");

	let certificates = provider
		.get_certificates("ready")
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
	let chain = provider
		.get_certificates(verification_id)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "issued chain" })?;
	assert_eq!(chain.results.len(), 2, "the issued verification must serve its leaf and ca chain");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn supported_countries_fold_across_the_published_providers() -> TestResult {
	let (harness, _anchor, client) = started_anchor(Some(&["US", "DE", "DE"]))?;

	let supported = client.get_supported_countries().await?;
	let germany = CountryCode::try_from("DE")?;
	let united_states = CountryCode::try_from("US")?;
	let expected = SupportedCountries::Countries(vec![germany, united_states]);
	assert_eq!(supported, expected, "the published codes must fold sorted and deduplicated");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn an_unconfigured_provider_publishes_an_empty_country_union() -> TestResult {
	let (harness, _anchor, client) = started_anchor(None)?;

	// The reference server publishes `countryCodes: []` when none are configured.
	let supported = client.get_supported_countries().await?;
	assert_eq!(supported, SupportedCountries::Countries(Vec::new()), "an unconfigured provider unions no countries");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn kyc_client_rejects_a_provider_missing_an_operation() -> TestResult {
	let (harness, _anchor, client) = started_anchor(Some(&["US"]))?;

	let countries = [CountryCode::try_from("US")?];
	let providers = client.providers(&countries).await?;
	let provider = first_provider(providers)?;

	// A stored snapshot rebinds through `client.provider(info)`, here with the
	// operation stripped to prove the typed rejection.
	let mut narrowed_info = provider.into_info();
	narrowed_info.operations.create_verification = None;

	let rebound = client.provider(narrowed_info);
	let outcome = rebound.create_verification(&countries, None).await;
	assert!(outcome.is_err(), "a provider without createVerification must surface a typed error");

	harness.shutdown()?;
	Ok(())
}

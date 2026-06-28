//! Full KYC client path against the live harness anchor: discover the provider,
//! then create a verification, poll its status, and fetch certificates through
//! [`KycClient`], exercising each auth mode end to end.

mod common;
mod support;

use std::error::Error;
use std::sync::Arc;

use common::account_from_seed;
use keetanetwork_account::KeyECDSASECP256K1;
use keetanetwork_anchor_client::{AnchorContext, AnchorOutcome, CountryCode, KycClient, ReqwestTransport, Resolver};
use support::{HarnessError, KycHarness};

type TestResult = Result<(), Box<dyn Error>>;

/// A KYC client whose resolver reads the `root` account's on-chain metadata
/// through the node API at `api`, and whose caller signs with a deterministic
/// account over the live reqwest transport.
fn client_for(api: &str, root: &str) -> Result<KycClient<KeyECDSASECP256K1>, Box<dyn Error>> {
	let transport = Arc::new(ReqwestTransport::try_default()?);
	let resolver = Resolver::new(transport.clone(), api, [root.to_string()]);
	let signer = account_from_seed(0x11);
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

	let status = client
		.get_verification_status(&provider, &verification.id)
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "verification status" })?;
	assert_eq!(status.status, "pending", "unexpected verification status");

	let pending = client.get_certificates(&provider, "pending").await?;
	assert!(matches!(pending, AnchorOutcome::Retry { .. }), "a pending certificate must ask the caller to retry");

	let certificates = client
		.get_certificates(&provider, "ready")
		.await?
		.ready()
		.ok_or(HarnessError::MissingField { field: "certificates" })?;
	assert!(!certificates.results.is_empty(), "issued certificates must not be empty");

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

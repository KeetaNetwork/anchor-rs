//! Signed-request transport against a running KYC anchor: the reqwest backend's
//! signed POST/GET are accepted, and completed non-2xx responses surface
//! without erroring.

mod common;
mod harness;

use std::error::Error;

use common::account_from_seed;
use harness::{signed_request_body, KycHarness};
use keetanetwork_anchor::signing::{add_signature_to_url, sign_with, SignParams, Signable, Url};
use keetanetwork_anchor_client::{AnchorHttpTransport, ReqwestTransport};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The KYC auth flows sign the empty payload; the request carries no extra data.
const EMPTY_SIGNABLE: &[Signable] = &[];

#[tokio::test]
async fn signed_requests_round_trip_through_the_live_anchor() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), true)?;
	let transport = ReqwestTransport::try_default()?;

	let account = account_from_seed(0x11);
	let account_string = account.to_string();
	let params = SignParams::generate();
	let signed = sign_with(&account, EMPTY_SIGNABLE, &params)?;

	let create_url = anchor.create_verification_url()?;
	let payload = signed_request_body(&account_string, &signed, &["US"])?;
	let created = transport.post(&create_url, &payload).await?;
	assert_eq!(created.status, 200, "createVerification rejected a valid signed body");

	let created_body: Value = serde_json::from_slice(&created.body)?;
	assert_eq!(created_body["ok"], Value::Bool(true), "createVerification did not acknowledge success");
	assert!(
		created_body["id"].as_str().is_some_and(|id| !id.is_empty()),
		"createVerification must assign a verification id"
	);

	let status_base = Url::parse(&anchor.get_verification_status_url("ver_test")?)?;
	let signed_status_url = add_signature_to_url(&status_base, &account_string, &signed)?;
	let status = transport.get(signed_status_url.as_str()).await?;
	assert_eq!(status.status, 200, "getVerificationStatus rejected a valid signed URL");

	let status_body: Value = serde_json::from_slice(&status.body)?;
	assert_eq!(status_body["status"], Value::String("pending".to_string()), "unexpected verification status");

	let pending_url = anchor.get_certificates_url("pending")?;
	let pending = transport.get(&pending_url).await?;
	assert_eq!(pending.status, 404, "a pending certificate must surface as a 404, not a transport error");
	assert!(!pending.is_success(), "404 must not report success");

	let ready_url = anchor.get_certificates_url("ready")?;
	let ready = transport.get(&ready_url).await?;
	assert_eq!(ready.status, 200, "an issued certificate must return 200");

	let ready_body: Value = serde_json::from_slice(&ready.body)?;
	assert!(ready_body["results"].is_array(), "certificate results must be an array");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn anchor_rejects_an_invalid_signature() -> TestResult {
	let mut harness = KycHarness::start()?;
	let anchor = harness.start_kyc_anchor(Some(&["US"]), true)?;
	let transport = ReqwestTransport::try_default()?;

	let account = account_from_seed(0x11);
	let account_string = account.to_string();
	let create_url = anchor.create_verification_url()?;
	let body = json!({
		"request": {
			"countryCodes": ["US"],
			"account": account_string,
			"signed": { "nonce": "n", "timestamp": "2024-01-02T03:04:05.678Z", "signature": "AA==" },
		},
	});
	let payload = serde_json::to_vec(&body)?;

	let rejected = transport.post(&create_url, &payload).await?;
	assert_eq!(rejected.status, 400, "an unverifiable signed body must be rejected with 400");

	harness.shutdown()?;
	Ok(())
}

//! Full asset-movement client path over a capturing transport: discover the
//! provider from published metadata, then run operations end to end, asserting
//! each one shapes its flat body/URL and decodes its typed response through the
//! public [`AssetMovementClient`] surface.

mod common;

use std::collections::VecDeque;
use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common::account_from_seed;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_client::error::TransportError;
use keetanetwork_anchor_client::{
	AccountStatus, AnchorContext, AnchorHttpTransport, AssetMovementClient, AssetOrPair, HttpResponse, Resolver,
	TransferDestination, TransferRequest, TransferSource,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The node API the resolver reads roots through.
const API: &str = "http://node.test";
/// The root account whose on-chain metadata advertises the provider.
const ROOT: &str = "keeta_root";
/// The provider id under `services.assetMovement`.
const PROVIDER_ID: &str = "am_test";

/// A transport that serves the published metadata for discovery, records every
/// request, and replays a queued response per operation call.
#[derive(Debug)]
struct MockTransport {
	metadata: String,
	responses: Mutex<VecDeque<HttpResponse>>,
	posts: Mutex<Vec<(String, Value)>>,
	gets: Mutex<Vec<String>>,
}

impl MockTransport {
	/// A transport publishing `document` as the root's on-chain metadata, with
	/// `responses` replayed (in order) for the operation calls.
	fn new(document: &Value, responses: impl IntoIterator<Item = HttpResponse>) -> Self {
		let metadata = STANDARD.encode(serde_json::to_vec(document).expect("metadata serializes"));
		Self {
			metadata,
			responses: Mutex::new(responses.into_iter().collect()),
			posts: Mutex::new(Vec::new()),
			gets: Mutex::new(Vec::new()),
		}
	}

	/// The account-state body the resolver reads a root's metadata from.
	fn ledger_state(&self) -> HttpResponse {
		let state = json!({ "info": { "metadata": self.metadata } });
		HttpResponse::new(200, serde_json::to_vec(&state).expect("state serializes"))
	}

	/// The next queued operation response, or a service error when exhausted.
	fn next_response(&self) -> HttpResponse {
		self.responses
			.lock()
			.expect("responses lock")
			.pop_front()
			.unwrap_or_else(|| HttpResponse::new(500, b"{\"ok\":false}".to_vec()))
	}

	/// The single recorded POST body, by operation URL suffix.
	fn post_body(&self, suffix: &str) -> Option<Value> {
		self.posts
			.lock()
			.expect("posts lock")
			.iter()
			.find(|(url, _)| url.contains(suffix))
			.map(|(_, body)| body.clone())
	}

	/// The single recorded GET URL, by operation URL suffix.
	fn get_url(&self, suffix: &str) -> Option<String> {
		self.gets
			.lock()
			.expect("gets lock")
			.iter()
			.find(|url| url.contains(suffix))
			.cloned()
	}
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl AnchorHttpTransport for MockTransport {
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
		if url.contains("/node/ledger/account/") {
			return Ok(self.ledger_state());
		}

		self.gets.lock().expect("gets lock").push(url.to_string());
		Ok(self.next_response())
	}

	async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, TransportError> {
		let parsed = serde_json::from_slice(body).unwrap_or(Value::Null);
		self.posts
			.lock()
			.expect("posts lock")
			.push((url.to_string(), parsed));
		Ok(self.next_response())
	}
}

/// The metadata document a full-featured provider publishes.
fn provider_metadata() -> Value {
	json!({
		"version": 1,
		"services": {
			"assetMovement": {
				PROVIDER_ID: {
					"operations": {
						"simulateTransfer": "http://anchor.test/api/simulateTransfer",
						"initiateTransfer": {
							"url": "http://anchor.test/api/initiateTransfer",
							"options": { "authentication": { "type": "required" } }
						},
						"getTransferStatus": {
							"url": "http://anchor.test/api/getTransferStatus/{id}",
							"options": { "authentication": { "type": "required" } }
						},
						"getAccountStatus": "http://anchor.test/api/getAccountStatus"
					}
				}
			}
		}
	})
}

/// A client and its transport over `document` with the given queued responses.
fn client_over(
	document: &Value,
	responses: impl IntoIterator<Item = HttpResponse>,
) -> (AssetMovementClient, Arc<MockTransport>) {
	let transport = Arc::new(MockTransport::new(document, responses));
	let resolver = Resolver::new(transport.clone(), API, [ROOT.to_string()]);
	let signer = Arc::new(GenericAccount::EcdsaSecp256k1(account_from_seed(0x11)));
	let context = AnchorContext::new(resolver, transport.clone(), signer);
	(AssetMovementClient::new(context), transport)
}

/// A transfer request moving USD from a bank account to an EVM address.
fn transfer_request(recipient: Option<Value>) -> TransferRequest {
	TransferRequest {
		asset: AssetOrPair::from("USD"),
		from: TransferSource { location: "bank-account:CHECKING".to_string(), source: None },
		to: TransferDestination { location: "chain:evm:1".to_string(), recipient, deposit_message: None },
		value: "1000".to_string(),
		allowed_rails: Vec::new(),
	}
}

#[tokio::test]
async fn discovery_reads_the_published_provider() -> TestResult {
	let (client, _transport) = client_over(&provider_metadata(), []);

	let providers = client.providers().await?;
	assert_eq!(providers.len(), 1, "exactly one provider is published");
	let provider = &providers[0];
	assert_eq!(provider.id, PROVIDER_ID, "discovered provider id diverges");
	assert!(client.is_operation_supported(provider, "simulateTransfer"), "simulateTransfer must be advertised");
	assert!(!client.is_operation_supported(provider, "shareKYC"), "shareKYC is not advertised by this provider");

	Ok(())
}

#[tokio::test]
async fn simulate_transfer_sends_an_unsigned_flat_body() -> TestResult {
	let response = HttpResponse::new(200, br#"{"ok":true,"instructionChoices":[{"type":"ACH"}]}"#.to_vec());
	let (client, transport) = client_over(&provider_metadata(), [response]);

	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	let simulated = client
		.simulate_transfer(&provider, &transfer_request(None))
		.await?;
	assert_eq!(simulated.instruction_choices.len(), 1, "the simulated choices decode from the body");

	let body = transport
		.post_body("simulateTransfer")
		.ok_or("simulateTransfer was not called")?;
	assert_eq!(body["value"], json!("1000"), "the transfer value is carried verbatim");
	assert_eq!(body["asset"], json!("USD"), "a single asset serializes as a bare string");
	assert_eq!(body["from"]["location"], json!("bank-account:CHECKING"), "the source location is carried");
	assert_eq!(body["account"].as_str(), Some(provider_signer().as_str()), "the signer account is injected");
	assert!(body.get("signed").is_none(), "an unauthenticated operation carries no signature");

	Ok(())
}

#[tokio::test]
async fn initiate_transfer_signs_the_flat_body() -> TestResult {
	let response = HttpResponse::new(200, br#"{"ok":true,"id":"tx_1","instructionChoices":[]}"#.to_vec());
	let (client, transport) = client_over(&provider_metadata(), [response]);

	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	let recipient = json!({ "address": "0xabc" });
	let transfer = client
		.initiate_transfer(&provider, &transfer_request(Some(recipient.clone())))
		.await?;
	assert_eq!(transfer.id, "tx_1", "the transfer id decodes from the body");

	let body = transport
		.post_body("initiateTransfer")
		.ok_or("initiateTransfer was not called")?;
	assert_eq!(body["to"]["recipient"], recipient, "the recipient is carried in the destination");
	let signed = body
		.get("signed")
		.ok_or("a required operation must carry a signature")?;
	assert!(signed["nonce"].is_string(), "the signature carries a nonce");
	assert!(signed["timestamp"].is_string(), "the signature carries a timestamp");
	assert!(signed["signature"].is_string(), "the signature carries signature bytes");

	Ok(())
}

#[tokio::test]
async fn initiate_transfer_requires_a_recipient() -> TestResult {
	let (client, _transport) = client_over(&provider_metadata(), []);

	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	let outcome = client
		.initiate_transfer(&provider, &transfer_request(None))
		.await;
	assert!(outcome.is_err(), "initiating a transfer without a recipient must fail before any request");

	Ok(())
}

#[tokio::test]
async fn transfer_status_signs_the_url() -> TestResult {
	let response = HttpResponse::new(200, br#"{"ok":true,"transaction":{"id":"tx_1"}}"#.to_vec());
	let (client, transport) = client_over(&provider_metadata(), [response]);

	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	let status = client.transfer_status(&provider, "tx_1").await?;
	assert_eq!(status.transaction["id"], json!("tx_1"), "the transaction decodes from the body");

	let url = transport
		.get_url("getTransferStatus/tx_1")
		.ok_or("getTransferStatus was not called with the id")?;
	assert!(url.contains("signed.signature="), "a signed GET carries its signature on the URL");
	assert!(url.contains("account="), "a signed GET carries the account on the URL");

	Ok(())
}

#[tokio::test]
async fn account_status_resolves_ready_and_blocked() -> TestResult {
	let ready = HttpResponse::new(200, br#"{"ok":true,"actionRequired":false}"#.to_vec());
	let (client, _transport) = client_over(&provider_metadata(), [ready]);
	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	assert_eq!(client.account_status(&provider).await?, AccountStatus::Ready, "a ready account resolves to Ready");

	let blocked = HttpResponse::new(200, br#"{"ok":true,"actionRequired":true,"errors":[{"name":"n","code":"KEETA_ANCHOR_ASSET_MOVEMENT_ADDITIONAL_KYC_NEEDED","error":"e","data":{"toCompleteFlow":null}}]}"#.to_vec());
	let (client, _transport) = client_over(&provider_metadata(), [blocked]);
	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	let status = client.account_status(&provider).await?;
	assert!(
		matches!(status, AccountStatus::ActionRequired { blockers } if blockers.len() == 1),
		"a blocked account lists its blockers"
	);

	Ok(())
}

#[tokio::test]
async fn an_unadvertised_operation_is_rejected() -> TestResult {
	let (client, _transport) = client_over(&provider_metadata(), []);

	let provider = client
		.provider_by_id(PROVIDER_ID)
		.await?
		.ok_or("provider missing")?;
	let outcome = client
		.list_transactions(&provider, &Default::default())
		.await;
	assert!(outcome.is_err(), "an operation the provider does not advertise must surface a typed error");

	Ok(())
}

/// The deterministic signer's account string, used to assert body injection.
fn provider_signer() -> String {
	GenericAccount::EcdsaSecp256k1(account_from_seed(0x11)).to_string()
}

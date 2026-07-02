//! Full asset-movement client path against the live harness anchor: discover
//! the provider from on-chain metadata through the real node API, then drive
//! every advertised operation end to end over the reqwest transport, through
//! the public [`AssetMovementClient`] surface.

mod common;
mod harness;

use core::sync::atomic::{AtomicU32, Ordering};
use std::error::Error;
use std::sync::Arc;

use common::account_from_seed;
use harness::{AssetAnchor, AssetHarness, HarnessError};
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_client::{
	parse_total, AccountStatus, AnchorClientError, AnchorContext, AssetMovementClient, AssetMovementProvider,
	AssetOrPair, CreateForwardingAddressRequest, CreateForwardingTemplateRequest, ExecuteTransferRequest,
	ForwardingAddressFilter, ForwardingDestination, InitiateForwardingTemplateRequest, ListForwardingAddressesRequest,
	ListForwardingTemplatesRequest, ListTransactionsRequest, Pagination, PersistentAddressFilter, PollOptions,
	ProviderSearch, ReqwestTransport, Resolver, ShareKycRequest, TransactionEndpointFilter, TransferDestination,
	TransferRequest, TransferSource,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The canonical bank source location the pull fixtures use.
const BANK_LOCATION: &str = "bank-account:us";
/// The canonical EVM source location the push fixtures use.
const EVM_LOCATION: &str = "chain:evm:100";
/// The canonical Keeta destination location the fixtures use.
const KEETA_LOCATION: &str = "chain:keeta:100";

/// An asset-movement client whose resolver reads the `root` account's on-chain
/// metadata through the node API at `api`, and whose caller signs with a
/// deterministic account over the live reqwest transport.
fn client_for(api: &str, root: &str) -> Result<AssetMovementClient, Box<dyn Error>> {
	let transport = Arc::new(ReqwestTransport::try_default()?);
	let resolver = Resolver::new(transport.clone(), api, [root.to_string()]);
	let signer = Arc::new(GenericAccount::EcdsaSecp256k1(account_from_seed(0x11)));
	let context = AnchorContext::new(resolver, transport, signer);

	Ok(AssetMovementClient::new(context))
}

/// The single provider the running anchor publishes.
async fn discovered_provider(
	client: &AssetMovementClient,
	anchor: &AssetAnchor,
) -> Result<AssetMovementProvider, Box<dyn Error>> {
	let provider = client
		.provider_by_id(&anchor.provider_id)
		.await?
		.ok_or(HarnessError::MissingField { field: "asset provider" })?;
	Ok(provider)
}

/// A push transfer moving the base token from the EVM location to Keeta.
fn push_transfer(anchor: &AssetAnchor, recipient: Option<Value>) -> TransferRequest {
	TransferRequest {
		asset: AssetOrPair::from(anchor.asset.clone()),
		from: TransferSource { location: EVM_LOCATION.to_string(), source: None },
		to: TransferDestination { location: KEETA_LOCATION.to_string(), recipient, deposit_message: None },
		value: "100".to_string(),
		allowed_rails: Vec::new(),
	}
}

/// A pull transfer debiting a persistent bank address into the base token.
fn pull_transfer(anchor: &AssetAnchor) -> TransferRequest {
	let source = json!({ "type": "persistent-address", "persistentAddressId": "TEST_PERSISTENT_ADDRESS_ID" });
	TransferRequest {
		asset: AssetOrPair::Pair { from: "USD".to_string(), to: anchor.asset.clone() },
		from: TransferSource { location: BANK_LOCATION.to_string(), source: Some(source) },
		to: TransferDestination {
			location: KEETA_LOCATION.to_string(),
			recipient: Some(Value::String(anchor.send_to_address.clone())),
			deposit_message: Some("integration".to_string()),
		},
		value: "100".to_string(),
		allowed_rails: Vec::new(),
	}
}

/// The share-KYC request the poll tests submit, with `attributes` selecting the
/// harness fixture path (any value containing `promise` reports pending).
fn share_kyc_request(attributes: &str) -> ShareKycRequest {
	ShareKycRequest { attributes: attributes.to_string(), tos_agreement: None }
}

#[tokio::test]
async fn discovery_reads_the_published_provider() -> TestResult {
	let mut harness = AssetHarness::start()?;
	let anchor = harness.start_asset_anchor(true)?;
	let client = client_for(&anchor.api, &anchor.root)?;

	let providers = client.providers().await?;
	assert_eq!(providers.len(), 1, "exactly one provider is published");
	assert_eq!(providers[0].id, anchor.provider_id, "discovered provider id diverges");
	assert!(client.is_operation_supported(&providers[0], "simulateTransfer"), "simulateTransfer must be advertised");

	let by_account = client
		.provider_by_account(
			anchor
				.signer
				.clone()
				.ok_or(HarnessError::MissingField { field: "signer" })?,
		)
		.await?;
	assert!(by_account.is_some(), "the provider must resolve by its signing account");

	let search = ProviderSearch::for_asset(anchor.asset.clone())
		.from(EVM_LOCATION)
		.to(KEETA_LOCATION);
	let matches = client.providers_for_transfer(&search).await?;
	assert_eq!(matches.len(), 1, "the provider must satisfy a search over its published path");

	let none = client
		.providers_for_transfer(&ProviderSearch::for_asset("evm:0xdeadbeef"))
		.await?;
	assert!(none.is_empty(), "an unadvertised asset must match no provider");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn transfers_run_end_to_end_against_the_live_anchor() -> TestResult {
	let mut harness = AssetHarness::start()?;
	let anchor = harness.start_asset_anchor(true)?;
	let client = client_for(&anchor.api, &anchor.root)?;
	let provider = discovered_provider(&client, &anchor).await?;

	let status = client.account_status(&provider).await?;
	assert_eq!(status, AccountStatus::Ready, "the fixture account must be ready");

	let recipient = Value::String(anchor.send_to_address.clone());
	let simulated = client
		.simulate_transfer(&provider, &push_transfer(&anchor, Some(recipient.clone())))
		.await?;
	assert_eq!(simulated.instruction_choices.len(), 1, "the simulation must offer one instruction");
	assert_eq!(
		simulated.instruction_choices[0]["type"],
		json!("KEETA_SEND"),
		"a push transfer must simulate to a crypto send"
	);

	let transfer = client
		.initiate_transfer(&provider, &push_transfer(&anchor, Some(recipient)))
		.await?;
	assert_eq!(transfer.id, "123", "the anchor must assign the fixture transfer id");
	assert_eq!(
		transfer.instruction_choices[0]["sendToAddress"],
		json!(anchor.send_to_address),
		"the initiated instruction must resolve the send-to address"
	);

	let missing_recipient = client
		.initiate_transfer(&provider, &push_transfer(&anchor, None))
		.await;
	assert!(missing_recipient.is_err(), "initiating without a recipient must fail before any request");

	let status = client.transfer_status(&provider, &transfer.id).await?;
	assert_eq!(status.transaction["id"], json!("123"), "the signed status URL must serve the transaction");
	assert_eq!(status.transaction["status"], json!("COMPLETED"), "the fixture transaction reports completed");

	let pull = client
		.initiate_transfer(&provider, &pull_transfer(&anchor))
		.await?;
	let instruction = pull
		.instruction_choices
		.first()
		.cloned()
		.ok_or(HarnessError::MissingField { field: "pull instruction" })?;
	assert_eq!(instruction["type"], json!("ACH_DEBIT"), "a bank-sourced transfer must offer a fiat pull");

	let executed = client
		.execute_transfer(&provider, &ExecuteTransferRequest { id: pull.id.clone(), instruction })
		.await?;
	assert_eq!(
		executed.transaction["status"],
		json!("EXECUTED"),
		"executing the pull instruction must report the executed transaction"
	);

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn forwarding_and_listing_run_against_the_live_anchor() -> TestResult {
	let mut harness = AssetHarness::start()?;
	let anchor = harness.start_asset_anchor(true)?;
	let client = client_for(&anchor.api, &anchor.root)?;
	let provider = discovered_provider(&client, &anchor).await?;
	let asset = AssetOrPair::from(anchor.asset.clone());

	let session = client
		.initiate_forwarding_template(
			&provider,
			&InitiateForwardingTemplateRequest { asset: asset.clone(), location: EVM_LOCATION.to_string() },
		)
		.await?;
	assert_eq!(session.id, "test-session-id", "the anchor must open the fixture session");
	assert_eq!(session.data["plaidLinkToken"], json!("link-sandbox-test-token"), "the session data must decode");

	let template = client
		.create_forwarding_template(
			&provider,
			&CreateForwardingTemplateRequest::Direct {
				asset: asset.clone(),
				location: EVM_LOCATION.to_string(),
				address: Value::String(anchor.send_to_address.clone()),
			},
		)
		.await?;
	assert_eq!(template.id, "template-id", "a direct create must return the fixture template");

	let completed = client
		.create_forwarding_template(
			&provider,
			&CreateForwardingTemplateRequest::Completion {
				id: Some(session.id.clone()),
				data: json!({
					"type": "plaid",
					"plaidPublicToken": "public-sandbox-token",
					"plaidAccountId": "account-1",
				}),
			},
		)
		.await?;
	assert_eq!(completed.id, "template-id", "a session completion must return the fixture template");

	let templates = client
		.list_forwarding_templates(
			&provider,
			&ListForwardingTemplatesRequest {
				asset: Some(vec![anchor.asset.clone()]),
				location: Some(vec![EVM_LOCATION.to_string()]),
			},
		)
		.await?;
	assert_eq!(templates.templates.len(), 1, "the template listing must serve the fixture page");
	assert_eq!(parse_total(&templates.total), Some(1), "the template listing must carry its total");

	let created = client
		.create_forwarding_address(
			&provider,
			&CreateForwardingAddressRequest {
				source_location: EVM_LOCATION.to_string(),
				asset: asset.clone(),
				outgoing_rail: Some("KEETA_SEND".to_string()),
				incoming_rail: None,
				destination: ForwardingDestination::Address {
					location: KEETA_LOCATION.to_string(),
					address: Value::String(anchor.send_to_address.clone()),
				},
			},
		)
		.await?;
	assert_eq!(created["address"], json!(anchor.send_to_address), "the created address must decode");
	assert_eq!(created["fees"]["total"], json!("10"), "the created address must carry its fee total");

	let from_template = client
		.create_forwarding_address(
			&provider,
			&CreateForwardingAddressRequest {
				source_location: EVM_LOCATION.to_string(),
				asset: asset.clone(),
				outgoing_rail: None,
				incoming_rail: None,
				destination: ForwardingDestination::Template { persistent_address_template_id: template.id.clone() },
			},
		)
		.await?;
	assert_eq!(from_template["address"], json!(anchor.send_to_address), "a template-backed create must decode");

	let addresses = client
		.list_forwarding_addresses(
			&provider,
			&ListForwardingAddressesRequest {
				search: Some(vec![ForwardingAddressFilter {
					source_location: Some(EVM_LOCATION.to_string()),
					asset: Some(anchor.asset.clone()),
					..ForwardingAddressFilter::default()
				}]),
				pagination: Pagination { limit: Some(10), offset: Some(0) },
			},
		)
		.await?;
	assert_eq!(addresses.addresses.len(), 1, "the address listing must serve the fixture page");
	assert_eq!(parse_total(&addresses.total), Some(1), "the address listing must carry its total");

	let transactions = client
		.list_transactions(
			&provider,
			&ListTransactionsRequest {
				persistent_addresses: Some(vec![PersistentAddressFilter {
					location: EVM_LOCATION.to_string(),
					persistent_address: Some(anchor.send_to_address.clone()),
					persistent_address_template: None,
				}]),
				from: Some(TransactionEndpointFilter {
					location: EVM_LOCATION.to_string(),
					user_address: Some(anchor.send_to_address.clone()),
					asset: Some(anchor.asset.clone()),
				}),
				to: None,
				transactions: None,
				pagination: Pagination { limit: Some(10), offset: None },
			},
		)
		.await?;
	assert_eq!(transactions.transactions.len(), 1, "the transaction listing must serve the fixture page");
	assert_eq!(
		transactions.transactions[0]["id"],
		json!("123"),
		"the listed transaction must be the fixture transaction"
	);

	client
		.deactivate_forwarding_template(&provider, &template.id)
		.await?;
	client
		.deactivate_forwarding_address(&provider, &template.id)
		.await?;

	let missing = client
		.deactivate_forwarding_template(&provider, "does-not-exist")
		.await;
	assert!(missing.is_err(), "deactivating an unknown template must surface the anchor error");

	let mut narrowed = provider.clone();
	narrowed.operations = narrowed
		.operations
		.iter()
		.filter(|(name, _)| *name != "listTransactions")
		.map(|(name, endpoint)| (name.to_string(), endpoint.clone()))
		.collect();
	let unadvertised = client
		.list_transactions(&narrowed, &ListTransactionsRequest::default())
		.await;
	assert!(
		matches!(unadvertised, Err(AnchorClientError::UnsupportedOperation { .. })),
		"an unadvertised operation must surface a typed error, got {unadvertised:?}"
	);

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn share_kyc_settles_and_polls_against_the_live_anchor() -> TestResult {
	let mut harness = AssetHarness::start()?;
	let anchor = harness.start_asset_anchor(true)?;
	let client = client_for(&anchor.api, &anchor.root)?;
	let provider = discovered_provider(&client, &anchor).await?;

	let settled = client
		.share_kyc(&provider, &share_kyc_request("exported-attributes"))
		.await?;
	assert!(!settled.is_pending, "a plain share must settle immediately");

	let without_polling = client
		.share_kyc_await(
			&provider,
			&share_kyc_request("exported-attributes"),
			PollOptions::default(),
			|_millis| async { panic!("a settled share must not sleep") },
		)
		.await?;
	assert!(!without_polling.is_pending, "a settled share must return without polling");

	// The promise route reports pending (202 + Retry-After) for the first two
	// polls and settles on the third, so the await must sleep exactly twice.
	let polls = Arc::new(AtomicU32::new(0));
	let counter = Arc::clone(&polls);
	let options = PollOptions { interval_ms: 1, timeout_ms: 60_000 };
	let outcome = client
		.share_kyc_await(&provider, &share_kyc_request("promise-flow"), options, move |_millis| {
			let counter = Arc::clone(&counter);
			async move {
				counter.fetch_add(1, Ordering::Relaxed);
			}
		})
		.await?;
	assert!(!outcome.is_pending, "the polled promise must settle");
	assert_eq!(polls.load(Ordering::Relaxed), 2, "the poll must sleep once per pending response");

	let options = PollOptions { interval_ms: 1_000, timeout_ms: 500 };
	let timed_out = client
		.share_kyc_await(&provider, &share_kyc_request("promise-stall"), options, |_millis| async {})
		.await;
	assert!(
		matches!(timed_out, Err(AnchorClientError::Timeout { .. })),
		"an unsettled promise must surface a typed timeout, got {timed_out:?}"
	);

	harness.shutdown()?;
	Ok(())
}

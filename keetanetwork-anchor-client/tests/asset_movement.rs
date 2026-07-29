//! Full asset-movement client path against the live harness anchor: discover
//! the provider from on-chain metadata through the real node API, then drive
//! every advertised operation end to end over the reqwest transport, through
//! the public [`AssetMovementClient`] surface.

mod common;
mod harness;

use core::sync::atomic::{AtomicU32, Ordering};
use std::error::Error;
use std::sync::Arc;

use common::live_context;
use harness::{AssetAnchor, AssetHarness, HarnessError};
use keetanetwork_anchor_client::{
	parse_total, AccountStatus, AnchorClientError, AssetMovementClient, AssetMovementProvider, AssetOrPair,
	AwaitOptions, ClientRenderableContent, CreatePersistentForwardingAddressRequest,
	CreatePersistentForwardingTemplateRequest, Disclaimer, DisclaimerPurpose, ExecuteTransferRequest,
	ForwardingAddressFilter, ForwardingDestination, InitiatePersistentForwardingTemplateRequest,
	ListForwardingAddressTemplatesRequest, ListForwardingAddressesRequest, ListTransactionsRequest, Pagination,
	PersistentAddressFilter, ProviderSearch, ShareKycRequest, TokenLocationMetadata, TransactionEndpointFilter,
	TransferDestination, TransferRequest, TransferSource,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The canonical bank source location the pull fixtures use.
const BANK_LOCATION: &str = "bank-account:us";
/// The EVM-side asset id the harness publishes location metadata for.
const EVM_ASSET: &str = "evm:0xc0634090F2Fe6c6d75e61Be2b949464aBB498973";
/// The canonical EVM source location the push fixtures use.
const EVM_LOCATION: &str = "chain:evm:100";
/// The canonical Keeta destination location the fixtures use.
const KEETA_LOCATION: &str = "chain:keeta:100";

/// A started harness anchor and the live client bound to it over the shared
/// [`live_context`].
fn started_anchor() -> Result<(AssetHarness, AssetAnchor, AssetMovementClient), Box<dyn Error>> {
	let mut harness = AssetHarness::start()?;
	let anchor = harness.start_asset_anchor(true)?;
	let context = live_context(&anchor.api, &anchor.root)?;
	let client = AssetMovementClient::new(context);

	Ok((harness, anchor, client))
}

/// The single provider the running anchor publishes.
async fn discovered_provider<'c>(
	client: &'c AssetMovementClient,
	anchor: &AssetAnchor,
) -> Result<AssetMovementProvider<'c>, Box<dyn Error>> {
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
fn share_kyc_attributes_request(attributes: &str) -> ShareKycRequest {
	ShareKycRequest { attributes: attributes.to_string(), tos_agreement: None }
}

#[tokio::test]
async fn discovery_reads_the_published_provider() -> TestResult {
	let (harness, anchor, client) = started_anchor()?;

	let providers = client.providers().await?;
	assert_eq!(providers.len(), 1, "exactly one provider is published");
	assert_eq!(providers[0].id, anchor.provider_id, "discovered provider id diverges");
	assert!(providers[0].is_operation_supported("simulateTransfer"), "simulateTransfer must be advertised");

	let signer = anchor
		.signer
		.clone()
		.ok_or(HarnessError::MissingField { field: "signer" })?;
	let by_account = client.provider_by_account(signer).await?;
	assert!(by_account.is_some(), "the provider must resolve by its signing account");

	let search = ProviderSearch::for_asset(anchor.asset.clone())
		.from(EVM_LOCATION)
		.to(KEETA_LOCATION);
	let matches = client.providers_for_transfer(&search).await?;
	assert_eq!(matches.len(), 1, "the provider must satisfy a search over its published path");

	let unadvertised_search = ProviderSearch::for_asset("evm:0xdeadbeef");
	let none = client.providers_for_transfer(&unadvertised_search).await?;
	assert!(none.is_empty(), "an unadvertised asset must match no provider");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn published_legal_and_location_metadata_decode() -> TestResult {
	let (harness, anchor, client) = started_anchor()?;
	let provider = discovered_provider(&client, &anchor).await?;

	let disclaimers = provider
		.legal_disclaimers()
		.ok_or(HarnessError::MissingField { field: "legal disclaimers" })?;
	let expected_disclaimer = Disclaimer {
		purpose: DisclaimerPurpose::General,
		content: ClientRenderableContent::Markdown { content: "Transfers are final.".to_string() },
	};
	assert_eq!(disclaimers, vec![expected_disclaimer], "the published disclaimer must decode");

	let by_id = client
		.provider_legal_disclaimers_by_id(&anchor.provider_id)
		.await?;
	assert_eq!(by_id, Some(disclaimers), "the by-id lookup must serve the same disclaimers");

	let metadata = provider.asset_metadata_for_location(EVM_LOCATION, EVM_ASSET);
	let expected_metadata = TokenLocationMetadata {
		decimal_places: 6,
		logo_uri: Some("https://cdn.example/usdc.svg".to_string()),
		display_name: Some("Harness USDC".to_string()),
		ticker: Some("$USDC".to_string()),
	};
	assert_eq!(metadata, Some(expected_metadata), "the published token metadata must decode");

	let unadvertised = provider.asset_metadata_for_location(EVM_LOCATION, "evm:0xdeadbeef");
	assert_eq!(unadvertised, None, "an unadvertised asset must carry no metadata");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn transfers_run_end_to_end_against_the_live_anchor() -> TestResult {
	let (harness, anchor, client) = started_anchor()?;
	let provider = discovered_provider(&client, &anchor).await?;

	let status = provider.account_status().await?;
	assert_eq!(status, AccountStatus::Ready, "the fixture account must be ready");

	let recipient = Value::String(anchor.send_to_address.clone());
	let push_request = push_transfer(&anchor, Some(recipient));
	let simulated = provider.simulate_transfer(&push_request).await?;
	assert_eq!(simulated.instruction_choices.len(), 1, "the simulation must offer one instruction");
	assert_eq!(
		simulated.instruction_choices[0]["type"],
		json!("KEETA_SEND"),
		"a push transfer must simulate to a crypto send"
	);

	let transfer = provider.initiate_transfer(&push_request).await?;
	assert_eq!(transfer.id, "123", "the anchor must assign the fixture transfer id");
	assert_eq!(
		transfer.instruction_choices[0]["sendToAddress"],
		json!(anchor.send_to_address),
		"the initiated instruction must resolve the send-to address"
	);

	let recipientless_request = push_transfer(&anchor, None);
	let missing_recipient = provider.initiate_transfer(&recipientless_request).await;
	assert!(missing_recipient.is_err(), "initiating without a recipient must fail before any request");

	let status = provider.transfer_status(&transfer.id).await?;
	assert_eq!(status.transaction["id"], json!("123"), "the signed status URL must serve the transaction");
	assert_eq!(status.transaction["status"], json!("COMPLETED"), "the fixture transaction reports completed");

	let pull_request = pull_transfer(&anchor);
	let pull = provider.initiate_transfer(&pull_request).await?;
	let instruction = pull
		.instruction_choices
		.first()
		.cloned()
		.ok_or(HarnessError::MissingField { field: "pull instruction" })?;
	assert_eq!(instruction["type"], json!("ACH_DEBIT"), "a bank-sourced transfer must offer a fiat pull");

	let execute_request = ExecuteTransferRequest { id: pull.id.clone(), instruction };
	let executed = provider.execute_transfer(&execute_request).await?;
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
	let (harness, anchor, client) = started_anchor()?;
	let provider = discovered_provider(&client, &anchor).await?;
	let asset = AssetOrPair::from(anchor.asset.clone());

	let initiate_request =
		InitiatePersistentForwardingTemplateRequest { asset: asset.clone(), location: EVM_LOCATION.to_string() };
	let session = provider
		.initiate_persistent_forwarding_template(&initiate_request)
		.await?;
	assert_eq!(session.id, "test-session-id", "the anchor must open the fixture session");
	assert_eq!(session.data["plaidLinkToken"], json!("link-sandbox-test-token"), "the session data must decode");

	let direct_request = CreatePersistentForwardingTemplateRequest::Direct {
		asset: asset.clone(),
		location: EVM_LOCATION.to_string(),
		address: Value::String(anchor.send_to_address.clone()),
	};
	let template = provider
		.create_persistent_forwarding_template(&direct_request)
		.await?;
	assert_eq!(template.id, "template-id", "a direct create must return the fixture template");

	let completion_request = CreatePersistentForwardingTemplateRequest::Completion {
		id: Some(session.id.clone()),
		data: json!({
			"type": "plaid",
			"plaidPublicToken": "public-sandbox-token",
			"plaidAccountId": "account-1",
		}),
	};
	let completed = provider
		.create_persistent_forwarding_template(&completion_request)
		.await?;
	assert_eq!(completed.id, "template-id", "a session completion must return the fixture template");

	let list_templates_request = ListForwardingAddressTemplatesRequest {
		asset: Some(vec![anchor.asset.clone()]),
		location: Some(vec![EVM_LOCATION.to_string()]),
	};
	let templates = provider
		.list_forwarding_address_templates(&list_templates_request)
		.await?;
	assert_eq!(templates.templates.len(), 1, "the template listing must serve the fixture page");
	assert_eq!(parse_total(&templates.total), Some(1), "the template listing must carry its total");

	let create_address_request = CreatePersistentForwardingAddressRequest {
		source_location: EVM_LOCATION.to_string(),
		asset: asset.clone(),
		outgoing_rail: Some("KEETA_SEND".to_string()),
		incoming_rail: None,
		destination: ForwardingDestination::Address {
			location: KEETA_LOCATION.to_string(),
			address: Value::String(anchor.send_to_address.clone()),
		},
	};
	let created = provider
		.create_persistent_forwarding_address(&create_address_request)
		.await?;
	assert_eq!(created.address, json!(anchor.send_to_address), "the created address must decode");

	let fees = created
		.fees
		.ok_or(HarnessError::MissingField { field: "fees" })?;
	assert_eq!(fees.total.as_deref(), Some("10"), "the created address must carry its fee total");
	assert_eq!(fees.line_items.len(), 1, "the fee breakdown must carry its line item");
	let basis_points = fees.line_items[0]
		.basis_points
		.as_ref()
		.and_then(serde_json::Number::as_u64);
	assert_eq!(basis_points, Some(50), "the variable fee must carry its basis points");

	let template_backed_request = CreatePersistentForwardingAddressRequest {
		source_location: EVM_LOCATION.to_string(),
		asset: asset.clone(),
		outgoing_rail: None,
		incoming_rail: None,
		destination: ForwardingDestination::Template { persistent_address_template_id: template.id.clone() },
	};
	let from_template = provider
		.create_persistent_forwarding_address(&template_backed_request)
		.await?;
	assert_eq!(from_template.address, json!(anchor.send_to_address), "a template-backed create must decode");

	let address_filter = ForwardingAddressFilter {
		source_location: Some(EVM_LOCATION.to_string()),
		asset: Some(asset.clone()),
		..ForwardingAddressFilter::default()
	};
	let list_addresses_request = ListForwardingAddressesRequest {
		search: Some(vec![address_filter]),
		pagination: Pagination { limit: Some(10), offset: Some(0) },
	};
	let addresses = provider
		.list_forwarding_addresses(&list_addresses_request)
		.await?;
	assert_eq!(addresses.addresses.len(), 1, "the address listing must serve the fixture page");
	assert_eq!(parse_total(&addresses.total), Some(1), "the address listing must carry its total");

	let persistent_address_filter = PersistentAddressFilter {
		location: EVM_LOCATION.to_string(),
		persistent_address: Some(anchor.send_to_address.clone()),
		persistent_address_template: None,
	};
	let from_filter = TransactionEndpointFilter {
		location: EVM_LOCATION.to_string(),
		user_address: Some(anchor.send_to_address.clone()),
		asset: Some(anchor.asset.clone()),
	};
	let list_transactions_request = ListTransactionsRequest {
		persistent_addresses: Some(vec![persistent_address_filter]),
		from: Some(from_filter),
		to: None,
		transactions: None,
		pagination: Pagination { limit: Some(10), offset: None },
	};
	let transactions = provider
		.list_transactions(&list_transactions_request)
		.await?;
	assert_eq!(transactions.transactions.len(), 1, "the transaction listing must serve the fixture page");
	assert_eq!(
		transactions.transactions[0]["id"],
		json!("123"),
		"the listed transaction must be the fixture transaction"
	);

	provider
		.deactivate_persistent_forwarding_template(&template.id)
		.await?;
	provider
		.deactivate_persistent_forwarding_address(&template.id)
		.await?;

	let missing = provider
		.deactivate_persistent_forwarding_template("does-not-exist")
		.await;
	assert!(missing.is_err(), "deactivating an unknown template must surface the anchor error");

	// A stored snapshot rebinds through `client.provider(info)`, the primitive
	// the FFI layers use.
	let mut narrowed_info = provider.info().clone();
	let retained_operations = narrowed_info
		.operations
		.iter()
		.filter(|(name, _)| *name != "listTransactions")
		.map(|(name, endpoint)| (name.to_string(), endpoint.clone()))
		.collect();
	narrowed_info.operations = retained_operations;

	let rebound = client.provider(narrowed_info);
	let unadvertised = rebound
		.list_transactions(&ListTransactionsRequest::default())
		.await;
	assert!(
		matches!(unadvertised, Err(AnchorClientError::UnsupportedOperation { .. })),
		"an unadvertised operation must surface a typed error, got {unadvertised:?}"
	);

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn asset_canonicalization_matches_the_reference_client() -> TestResult {
	let mut harness = AssetHarness::start()?;

	// EIP-55 vectors (mixed, lower, upper input casings), non-EVM assets the
	// canonicalization must pass through untouched, and the degenerate bodies
	// the reference still checksums (its hex check only tests the `0x`
	// prefix): non-hex ASCII, odd length, and empty.
	let inputs = [
		"evm:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
		"evm:0xFB6916095CA1DF60BB79CE92CE3EA74C37C5D359",
		"evm:0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"evm:0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
		"evm:0xZZ99ff00abcdef",
		"evm:0xabc",
		"evm:0x",
		"tron:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
		"solana:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"USD",
		"$CUSTOM",
	];
	for input in inputs {
		let reference = harness.canonicalize_asset(input)?;
		let canonical = keetanetwork_anchor_client::canonicalize_asset(input);
		assert_eq!(canonical, reference, "Rust canonicalization diverges from the reference for `{input}`");
	}

	// The reference `parseEVMAsset` errors on a further `:` separator; the
	// infallible Rust canonicalization passes such inputs through verbatim.
	let rejected = harness.canonicalize_asset("evm:0xabc:def");
	assert!(
		matches!(rejected, Err(HarnessError::CommandFailed { .. })),
		"the reference must reject an EVM asset with an extra separator, got {rejected:?}"
	);
	assert_eq!(
		keetanetwork_anchor_client::canonicalize_asset("evm:0xabc:def"),
		"evm:0xabc:def",
		"Rust must pass a malformed EVM asset through verbatim"
	);

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn share_kyc_attributes_settles_and_polls_against_the_live_anchor() -> TestResult {
	let (harness, anchor, client) = started_anchor()?;
	let provider = discovered_provider(&client, &anchor).await?;

	let settling_request = share_kyc_attributes_request("exported-attributes");
	let settled = provider.share_kyc_attributes(&settling_request).await?;
	assert!(!settled.is_pending, "a plain share must settle immediately");

	let without_polling = provider
		.share_kyc_attributes_and_wait(&settling_request, AwaitOptions::default(), |_millis| async {
			panic!("a settled share must not sleep")
		})
		.await?;
	assert!(!without_polling.is_pending, "a settled share must return without polling");

	// The promise route reports pending (202 + Retry-After) for the first two
	// polls and settles on the third, so the await must sleep exactly twice.
	let polls = Arc::new(AtomicU32::new(0));
	let counter = Arc::clone(&polls);
	let options = AwaitOptions { interval_ms: 1, timeout_ms: 60_000 };
	let promise_request = share_kyc_attributes_request("promise-flow");
	let outcome = provider
		.share_kyc_attributes_and_wait(&promise_request, options, move |_millis| {
			let counter = Arc::clone(&counter);
			async move {
				counter.fetch_add(1, Ordering::Relaxed);
			}
		})
		.await?;
	assert!(!outcome.is_pending, "the polled promise must settle");
	assert_eq!(polls.load(Ordering::Relaxed), 2, "the poll must sleep once per pending response");

	let options = AwaitOptions { interval_ms: 1_000, timeout_ms: 500 };
	let stalling_request = share_kyc_attributes_request("promise-stall");
	let timed_out = provider
		.share_kyc_attributes_and_wait(&stalling_request, options, |_millis| async {})
		.await;
	assert!(
		matches!(timed_out, Err(AnchorClientError::Timeout { .. })),
		"an unsettled promise must surface a typed timeout, got {timed_out:?}"
	);

	harness.shutdown()?;
	Ok(())
}

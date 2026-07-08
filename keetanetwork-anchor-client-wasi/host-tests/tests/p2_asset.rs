//! wasmtime P2 asset-movement component end-to-end test
//!
//! Boots the live reference asset-movement anchor, publishes
//! signed service metadata on-chain, then drives every operation
//! of the P2 component's generated `asset-movement` bindings
//! over `wasi:http`.

use serde_json::{json, Value};

mod common;
mod wasmtime_p2;

use common::{field_str, BoxError, Harness};
use wasmtime_p2::bindings::exports::keeta::anchor::asset_movement::AwaitOptions;
use wasmtime_p2::bindings::exports::keeta::client::crypto::KeyAlgorithm;
use wasmtime_p2::{account_from_address, coded, instantiate};

/// Parse a JSON document returned across the component boundary.
fn parse(document: &str) -> Result<Value, BoxError> {
	Ok(serde_json::from_str(document)?)
}

#[tokio::test]
#[ignore = "requires `make node-harness` and the built wasm32-wasip2 component"]
async fn p2_asset_movement_signs_against_live_anchor() -> Result<(), BoxError> {
	let mut harness = Harness::asset()?;

	// Boot the real asset-movement anchor advertising a signed provider, with its
	// metadata published on-chain to a root account.
	let started = harness.request("startAssetAnchor", json!({ "sign": true }))?;
	let provider_id = field_str(&started, "providerId")?;
	let node_url = field_str(&started, "api")?;
	let root = field_str(&started, "root")?;
	let asset = field_str(&started, "asset")?;
	let signer = field_str(&started, "signer")?;
	let send_to = field_str(&started, "sendToAddress")?;

	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let asset_movement = bindings.keeta_anchor_asset_movement();

	// Derive a deterministic signing account and bind a client borrowing it. The
	// component resolves the root account over wasi:http.
	let account = crypto
		.account()
		.call_from_seed(&mut store, &"11".repeat(32), 0, KeyAlgorithm::EcdsaSecp256k1)
		.await?
		.map_err(coded)?;
	let root_account = account_from_address(&mut store, &bindings, &root).await?;
	let client = asset_movement
		.asset_client()
		.call_with_account(&mut store, &node_url, root_account, account)
		.await?
		.map_err(coded)?;

	// Discovery: the advertised provider must surface, proving the metadata fetch
	// and entry-signature verification match the TS reference.
	let providers = asset_movement
		.asset_client()
		.call_providers(&mut store, client)
		.await?
		.map_err(coded)?;
	let providers = parse(&providers)?;
	let ids: Vec<&str> = providers
		.as_array()
		.ok_or("providers must be a JSON array")?
		.iter()
		.filter_map(|provider| provider.get("id").and_then(Value::as_str))
		.collect();
	assert!(ids.contains(&provider_id.as_str()), "discovery must surface the harness provider, got {ids:?}");

	// The single-provider lookup returns the same provider as a JSON document,
	// which is handed back verbatim to each operation.
	let provider = asset_movement
		.asset_client()
		.call_provider_by_id(&mut store, client, &provider_id)
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&provider)?.get("id").and_then(Value::as_str),
		Some(provider_id.as_str()),
		"provider-by-id must return the advertised provider"
	);

	// Provider search: the advertised evm->keeta KEETA_SEND path satisfies a
	// directional search, so the provider surfaces; an unadvertised source
	// location excludes it.
	let search = json!({
		"asset": asset,
		"from": "chain:evm:100",
		"to": "chain:keeta:100",
		"inboundRails": ["KEETA_SEND"],
		"outboundRails": ["KEETA_SEND"]
	})
	.to_string();
	let matched = asset_movement
		.asset_client()
		.call_providers_for_transfer(&mut store, client, &search)
		.await?
		.map_err(coded)?;
	let matched = parse(&matched)?;
	let matched_ids: Vec<&str> = matched
		.as_array()
		.ok_or("providers-for-transfer must be a JSON array")?
		.iter()
		.filter_map(|entry| entry.get("id").and_then(Value::as_str))
		.collect();
	assert!(
		matched_ids.contains(&provider_id.as_str()),
		"provider search must surface the provider, got {matched_ids:?}"
	);

	let unmatched_search = json!({ "asset": asset, "from": "chain:evm:1" }).to_string();
	let unmatched = asset_movement
		.asset_client()
		.call_providers_for_transfer(&mut store, client, &unmatched_search)
		.await?
		.map_err(coded)?;
	let unmatched = parse(&unmatched)?;
	let unmatched_ids: Vec<&str> = unmatched
		.as_array()
		.ok_or("providers-for-transfer must be a JSON array")?
		.iter()
		.filter_map(|entry| entry.get("id").and_then(Value::as_str))
		.collect();
	assert!(
		!unmatched_ids.contains(&provider_id.as_str()),
		"a search over an unadvertised source location must exclude the provider, got {unmatched_ids:?}"
	);

	let request = json!({
		"asset": asset,
		"from": { "location": "chain:keeta:100" },
		"to": { "location": "chain:evm:100", "recipient": "recipient-123" },
		"value": "100"
	})
	.to_string();

	// Unsigned parity: `simulate-transfer` is published unauthenticated, so the TS
	// server must accept the unsigned body and return instruction choices without
	// an id.
	let simulated = asset_movement
		.asset_client()
		.call_simulate_transfer(&mut store, client, &provider, &request)
		.await?
		.map_err(coded)?;
	let simulated = parse(&simulated)?;
	assert!(simulated.get("id").is_none(), "a simulated transfer must not carry an id");

	let choices = simulated
		.get("instructionChoices")
		.and_then(Value::as_array)
		.ok_or("the simulation must carry instruction choices")?;
	assert_eq!(
		choices
			.first()
			.and_then(|choice| choice.get("type"))
			.and_then(Value::as_str),
		Some("KEETA_SEND"),
		"the first instruction choice must be a KEETA_SEND"
	);

	// SignedBody parity: `initiate-transfer` is authenticated, so the TS server
	// verifies the signature over the request body, or the whole request rejects.
	let transfer = asset_movement
		.asset_client()
		.call_initiate_transfer(&mut store, client, &provider, &request)
		.await?
		.map_err(coded)?;
	let transfer = parse(&transfer)?;
	assert_eq!(transfer.get("id").and_then(Value::as_str), Some("123"), "the initiated transfer must carry its id");
	assert!(
		transfer
			.get("instructionChoices")
			.and_then(Value::as_array)
			.is_some_and(|choices| !choices.is_empty()),
		"the initiated transfer must carry instruction choices"
	);

	// SignedUrl parity: status reads sign the request URL; the TS server must
	// accept it and report the harness-configured transaction.
	let status = asset_movement
		.asset_client()
		.call_transfer_status(&mut store, client, &provider, "123")
		.await?
		.map_err(coded)?;
	let status = parse(&status)?;
	assert_eq!(
		status
			.get("transaction")
			.and_then(|transaction| transaction.get("id"))
			.and_then(Value::as_str),
		Some("123"),
		"the transfer status must report the harness transaction"
	);

	// SignedBody parity on the account-status path: the ready account resolves
	// with `actionRequired: false`.
	let account_status = asset_movement
		.asset_client()
		.call_account_status(&mut store, client, &provider)
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&account_status)?
			.get("actionRequired")
			.and_then(Value::as_bool),
		Some(false),
		"a ready account must report actionRequired false"
	);

	// Account-based discovery: the provider's entry is signed by the harness
	// metadata signer, so a lookup by that account surfaces it.
	let signer_account = account_from_address(&mut store, &bindings, &signer).await?;
	let by_account = asset_movement
		.asset_client()
		.call_provider_by_account(&mut store, client, signer_account)
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&by_account)?.get("id").and_then(Value::as_str),
		Some(provider_id.as_str()),
		"provider-by-account must surface the provider signed by the metadata signer"
	);

	// Execute a fiat pull instruction (the only shape `executeTransfer`
	// accepts); the harness reports the transaction executed.
	let execute = json!({
		"id": "123",
		"instruction": {
			"type": "ACH_DEBIT",
			"pullFrom": { "type": "persistent-address", "persistentAddressId": "pa-1" }
		}
	})
	.to_string();
	let executed = asset_movement
		.asset_client()
		.call_execute_transfer(&mut store, client, &provider, &execute)
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&executed)?
			.get("transaction")
			.and_then(|transaction| transaction.get("status"))
			.and_then(Value::as_str),
		Some("EXECUTED"),
		"execute-transfer must report the executed transaction"
	);

	// Persistent-forwarding lifecycle: open a template session, create a
	// template directly, list templates, create an address for a destination
	// pair, list addresses, then deactivate both.
	let initiate_template = json!({ "asset": asset, "location": "chain:evm:100" }).to_string();
	let session = asset_movement
		.asset_client()
		.call_initiate_persistent_forwarding_template(&mut store, client, &provider, &initiate_template)
		.await?
		.map_err(coded)?;
	let session = parse(&session)?;
	assert_eq!(
		session.get("id").and_then(Value::as_str),
		Some("test-session-id"),
		"the template session must carry the harness session id"
	);
	assert_eq!(
		session
			.get("data")
			.and_then(|data| data.get("type"))
			.and_then(Value::as_str),
		Some("plaid"),
		"the template session must carry the provider-specific data"
	);

	let create_template = json!({ "asset": asset, "location": "chain:evm:100", "address": send_to }).to_string();
	let template = asset_movement
		.asset_client()
		.call_create_persistent_forwarding_template(&mut store, client, &provider, &create_template)
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&template)?.get("id").and_then(Value::as_str),
		Some("template-id"),
		"the created template must carry the harness template id"
	);

	let templates = asset_movement
		.asset_client()
		.call_list_forwarding_address_templates(&mut store, client, &provider, "{}")
		.await?
		.map_err(coded)?;
	let templates = parse(&templates)?;
	assert_eq!(
		templates
			.get("templates")
			.and_then(Value::as_array)
			.map(Vec::len),
		Some(1),
		"the template list must carry the harness template"
	);
	assert_eq!(templates.get("total").and_then(Value::as_str), Some("1"), "the template list must carry its total");

	let create_address = json!({
		"sourceLocation": "chain:evm:100",
		"asset": asset,
		"destinationLocation": "chain:keeta:100",
		"destinationAddress": send_to
	})
	.to_string();
	let address = asset_movement
		.asset_client()
		.call_create_persistent_forwarding_address(&mut store, client, &provider, &create_address)
		.await?
		.map_err(coded)?;
	assert!(
		parse(&address)?
			.get("address")
			.and_then(Value::as_str)
			.is_some(),
		"the created forwarding address must carry its address"
	);

	let addresses = asset_movement
		.asset_client()
		.call_list_forwarding_addresses(&mut store, client, &provider, "{}")
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&addresses)?
			.get("addresses")
			.and_then(Value::as_array)
			.map(Vec::len),
		Some(1),
		"the address list must carry the harness address"
	);

	asset_movement
		.asset_client()
		.call_deactivate_persistent_forwarding_template(&mut store, client, &provider, "template-id")
		.await?
		.map_err(coded)?;
	asset_movement
		.asset_client()
		.call_deactivate_persistent_forwarding_address(&mut store, client, &provider, "template-id")
		.await?
		.map_err(coded)?;

	// The transaction query returns the canonical harness transaction.
	let transactions = asset_movement
		.asset_client()
		.call_list_transactions(&mut store, client, &provider, "{}")
		.await?
		.map_err(coded)?;
	let transactions = parse(&transactions)?;
	assert_eq!(
		transactions
			.get("transactions")
			.and_then(Value::as_array)
			.and_then(|entries| entries.first())
			.and_then(|entry| entry.get("id"))
			.and_then(Value::as_str),
		Some("123"),
		"list-transactions must carry the harness transaction"
	);

	// A settled share resolves immediately; the outcome is not pending.
	let share = json!({ "attributes": "immediate-attributes" }).to_string();
	let settled = asset_movement
		.asset_client()
		.call_share_kyc_attributes(&mut store, client, &provider, &share)
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&settled)?.get("isPending").and_then(Value::as_bool),
		Some(false),
		"a settled share must not be pending"
	);

	// A pending share hands back a promise URL; the await variant polls it
	// (two 202s, then a 200) to the settled outcome, paced by the options.
	let pending_share = json!({ "attributes": "test-promise" }).to_string();
	let options = AwaitOptions { interval_ms: 50, timeout_ms: 30_000 };
	let awaited = asset_movement
		.asset_client()
		.call_share_kyc_attributes_and_wait(&mut store, client, &provider, &pending_share, Some(options))
		.await?
		.map_err(coded)?;
	assert_eq!(
		parse(&awaited)?.get("isPending").and_then(Value::as_bool),
		Some(false),
		"an awaited pending share must settle"
	);

	harness.shutdown()?;
	Ok(())
}

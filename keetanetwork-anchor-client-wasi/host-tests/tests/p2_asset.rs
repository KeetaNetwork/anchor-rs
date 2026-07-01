//! wasmtime P2 asset-movement component end-to-end test
//!
//! Boots the live reference asset-movement anchor (production
//! `KeetaNetAssetMovementAnchorHTTPServer`), publishes signed service metadata
//! on-chain, then drives the P2 component's generated `asset-movement` bindings
//! over `wasi:http`: discovery, an unsigned `simulate-transfer`, a signed
//! `initiate-transfer`, a signed-URL `transfer-status`, and `account-status`.
//! Each result is a JSON document byte-identical to the reference.

use serde_json::{json, Value};

mod common;
mod wasmtime_p2;

use common::{field_str, BoxError, Harness};
use wasmtime_p2::{coded, instantiate};

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

	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let asset_movement = bindings.keeta_anchor_asset_movement();

	// Derive a deterministic signing account and bind a client borrowing it. The
	// component resolves the root account over wasi:http.
	let account = crypto
		.account()
		.call_from_seed(&mut store, &"11".repeat(32), 0, "ecdsa_secp256k1")
		.await?
		.map_err(coded)?;
	let client = asset_movement
		.asset_client()
		.call_with_account(&mut store, &node_url, &root, account)
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

	harness.shutdown()?;
	Ok(())
}

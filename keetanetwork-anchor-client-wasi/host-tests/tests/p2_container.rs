//! wasmtime P2 offline `encrypted-container` tests.
//!
//! These drive the exported `encrypted-container` resource with no network and
//! no harness - only the prebuilt component and the reused `account` resource.

mod common;
mod wasmtime_p2;

use common::BoxError;
use wasmtime_p2::bindings::exports::keeta::client::crypto::KeyAlgorithm;
use wasmtime_p2::{coded, component_built, instantiate};

/// A seed the encryption principal derives from at index 0.
const PRINCIPAL_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// A seed the signer derives from at index 0.
const SIGNER_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// A seed a second reader derives from at index 0.
const READER_SEED: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const ALGORITHM: KeyAlgorithm = KeyAlgorithm::EcdsaSecp256k1;

/// Skip when the component has not been built.
macro_rules! require_component {
	() => {
		if !component_built() {
			eprintln!("skipping P2 container test: build the wasm32-wasip2 component first");
			return Ok(());
		}
	};
}

#[tokio::test]
async fn plaintext_round_trips_through_its_encoding() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let containers = bindings.keeta_anchor_containers();
	let payload = b"container over wasi".to_vec();

	let plain = containers
		.encrypted_container()
		.call_from_plaintext(&mut store, &payload, &[], None, None)
		.await?;
	let encoded = containers
		.encrypted_container()
		.call_get_encoded(&mut store, plain)
		.await?
		.map_err(coded)?;

	let restored = containers
		.encrypted_container()
		.call_from_encoded(&mut store, &encoded, &[])
		.await?
		.map_err(coded)?;
	let plaintext = containers
		.encrypted_container()
		.call_get_plaintext(&mut store, restored)
		.await?
		.map_err(coded)?;
	assert_eq!(plaintext, payload, "the plaintext must round-trip through its encoding");

	let encrypted = containers
		.encrypted_container()
		.call_is_encrypted(&mut store, restored)
		.await?;
	assert!(!encrypted, "a plaintext container must not report as encrypted");

	Ok(())
}

#[tokio::test]
async fn an_encrypted_container_round_trips_for_a_principal() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let containers = bindings.keeta_anchor_containers();
	let payload = b"sealed over wasi".to_vec();

	let owner = crypto
		.account()
		.call_from_seed(&mut store, PRINCIPAL_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;

	let sealed = containers
		.encrypted_container()
		.call_from_plaintext(&mut store, &payload, &[owner], Some(false), None)
		.await?;
	let encrypted = containers
		.encrypted_container()
		.call_is_encrypted(&mut store, sealed)
		.await?;
	assert!(encrypted, "a container with principals must report as encrypted");
	let encoded = containers
		.encrypted_container()
		.call_get_encoded(&mut store, sealed)
		.await?
		.map_err(coded)?;

	let opened = containers
		.encrypted_container()
		.call_from_encrypted(&mut store, &encoded, &[owner])
		.await?
		.map_err(coded)?;
	let plaintext = containers
		.encrypted_container()
		.call_get_plaintext(&mut store, opened)
		.await?
		.map_err(coded)?;
	assert_eq!(plaintext, payload, "the principal must decrypt the sealed payload");

	Ok(())
}

#[tokio::test]
async fn a_signed_container_verifies_and_recovers_its_signer() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let containers = bindings.keeta_anchor_containers();
	let payload = b"authentic over wasi".to_vec();

	let signer = crypto
		.account()
		.call_from_seed(&mut store, SIGNER_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;

	let signed = containers
		.encrypted_container()
		.call_from_plaintext(&mut store, &payload, &[], Some(false), Some(signer))
		.await?;
	let encoded = containers
		.encrypted_container()
		.call_get_encoded(&mut store, signed)
		.await?
		.map_err(coded)?;

	let restored = containers
		.encrypted_container()
		.call_from_encoded(&mut store, &encoded, &[])
		.await?
		.map_err(coded)?;
	let is_signed = containers
		.encrypted_container()
		.call_is_signed(&mut store, restored)
		.await?;
	assert!(is_signed, "a signed container must report as signed");

	let verified = containers
		.encrypted_container()
		.call_verify_signature(&mut store, restored)
		.await?
		.map_err(coded)?;
	assert!(verified, "the detached signature must verify");

	let recovered = containers
		.encrypted_container()
		.call_signing_account(&mut store, restored)
		.await?
		.map_err(coded)?;
	let signer_key = crypto.account().call_public_key(&mut store, signer).await?;
	assert_eq!(recovered.map(hex_lower), Some(signer_key), "the recovered signer key must match the signing account");

	Ok(())
}

#[tokio::test]
async fn granting_then_revoking_keeps_the_principal_count() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let containers = bindings.keeta_anchor_containers();
	let payload = b"shared over wasi".to_vec();

	let owner = crypto
		.account()
		.call_from_seed(&mut store, PRINCIPAL_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let reader = crypto
		.account()
		.call_from_seed(&mut store, READER_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;

	let container = containers
		.encrypted_container()
		.call_from_plaintext(&mut store, &payload, &[owner], Some(false), None)
		.await?;

	let owner_keys = containers
		.encrypted_container()
		.call_principals(&mut store, container)
		.await?
		.map_err(coded)?;
	assert_eq!(owner_keys.len(), 1, "a single-principal container reports one key");
	let owner_key = owner_keys
		.into_iter()
		.next()
		.ok_or("the sealed container must report its owner key")?;

	containers
		.encrypted_container()
		.call_grant_access(&mut store, container, &[reader])
		.await?
		.map_err(coded)?;
	let granted = containers
		.encrypted_container()
		.call_principals(&mut store, container)
		.await?
		.map_err(coded)?;
	assert_eq!(granted.len(), 2, "granting access must add a principal");

	let reader_key = granted
		.into_iter()
		.find(|key| key != &owner_key)
		.ok_or("the granted reader key must be present")?;
	containers
		.encrypted_container()
		.call_revoke_access(&mut store, container, &reader_key)
		.await?
		.map_err(coded)?;
	let remaining = containers
		.encrypted_container()
		.call_principals(&mut store, container)
		.await?
		.map_err(coded)?;
	assert_eq!(remaining, vec![owner_key], "revoking access must leave only the owner");

	Ok(())
}

/// Lowercase hex of `bytes`, matching the `account.public-key` text encoding.
fn hex_lower(bytes: Vec<u8>) -> String {
	let mut text = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		text.push_str(&format!("{byte:02x}"));
	}

	text
}

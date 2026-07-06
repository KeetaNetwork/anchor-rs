//! The networked asset-movement surface of the P1 core module.
//!
//! Each export reads its JSON arguments from guest memory through the shared
//! node readers, drives the shared [`AssetMovementClient`] to completion on the
//! host I/O shim, and returns a JSON payload bytes handle (or records a coded
//! error) on the shared `handle + last_error` ABI.

use core::cell::RefCell;

use std::collections::BTreeMap;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_anchor_client::{
	AnchorClientError, AnchorContext, AssetMovementClient, AssetMovementProvider, AwaitOptions, ProviderFilter,
	Resolver,
};
use keetanetwork_client_wasi::{account, bytes_result, string_in};

use crate::asset_json::{
	create_address_request, create_template_request, encode, encode_account_status, encode_ack, encode_provider,
	encode_providers, execute_request, filter_providers, initiate_template_request, list_addresses_request,
	list_templates_request, list_transactions_request, parse_provider, parse_provider_search,
	share_kyc_attributes_request, transfer_request,
};

use super::transport::{block_on, host_sleep_ms, host_transport};

thread_local! {
	static SESSIONS: RefCell<Sessions> = RefCell::new(Sessions::default());
}

/// The live asset-movement clients, each under a monotonically increasing handle.
#[derive(Default)]
struct Sessions {
	next: i32,
	clients: BTreeMap<i32, AssetMovementClient>,
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/// Build an asset-movement client resolving `root`'s on-chain metadata via the
/// node API at `node_url`, signed by the account behind `account_handle`;
/// returns a client handle (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` pair MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_with_account(
	node_url_ptr: i32,
	node_url_len: i32,
	root_ptr: i32,
	root_len: i32,
	account_handle: i32,
) -> i32 {
	let (Some(node_url), Some(root)) =
		(unsafe { string_in(node_url_ptr, node_url_len) }, unsafe { string_in(root_ptr, root_len) })
	else {
		return 0;
	};
	let Some(signer) = account(account_handle) else {
		return 0;
	};

	insert(build_client(node_url, root, signer))
}

/// Every asset-movement provider, as a JSON array; returns a bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub extern "C" fn keeta_asset_providers(handle: i32) -> i32 {
	bytes_result(providers(handle, ProviderFilter::default()))
}

/// Every provider whose published `supportedAssets` satisfies the JSON
/// `search`, as a JSON array; returns a bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_providers_for_transfer(handle: i32, search_ptr: i32, search_len: i32) -> i32 {
	let Some(search_json) = (unsafe { string_in(search_ptr, search_len) }) else {
		return 0;
	};

	bytes_result(providers_for_transfer(handle, &search_json))
}

/// The provider with `id` (JSON provider, or `null` when absent); returns a
/// bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_provider_by_id(handle: i32, id_ptr: i32, id_len: i32) -> i32 {
	let Some(id) = (unsafe { string_in(id_ptr, id_len) }) else {
		return 0;
	};

	bytes_result(provider_one(handle, ProviderFilter::by_id(id)))
}

/// The provider signed by `account` (JSON provider, or `null` when absent);
/// returns a bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_provider_by_account(handle: i32, account_ptr: i32, account_len: i32) -> i32 {
	let Some(account) = (unsafe { string_in(account_ptr, account_len) }) else {
		return 0;
	};

	bytes_result(provider_one(handle, ProviderFilter::by_account(account)))
}

/// Simulate a transfer; returns a JSON simulated-transfer bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_simulate_transfer(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = transfer_request(request)?;
		let outcome = with_session(handle, |client| block_on(client.simulate_transfer(&provider, &request)))?;
		encode(&outcome)
	})
}

/// Initiate a transfer; returns a JSON transfer bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_initiate_transfer(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = transfer_request(request)?;
		let outcome = with_session(handle, |client| block_on(client.initiate_transfer(&provider, &request)))?;
		encode(&outcome)
	})
}

/// Execute a pull instruction for a transfer; returns a JSON transfer-status
/// bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_execute_transfer(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = execute_request(request)?;
		let outcome = with_session(handle, |client| block_on(client.execute_transfer(&provider, &request)))?;
		encode(&outcome)
	})
}

/// The status of transfer `id`; returns a JSON transfer-status bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_transfer_status(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	id_ptr: i32,
	id_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, id_ptr, id_len, |provider, id| {
		let outcome = with_session(handle, |client| block_on(client.transfer_status(&provider, id)))?;
		encode(&outcome)
	})
}

/// The signer's account status with the provider; returns a JSON account-status
/// bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_account_status(handle: i32, provider_ptr: i32, provider_len: i32) -> i32 {
	let Some(provider_json) = (unsafe { string_in(provider_ptr, provider_len) }) else {
		return 0;
	};

	bytes_result((|| {
		let provider = parse_provider(&provider_json)?;
		let status = with_session(handle, |client| block_on(client.account_status(&provider)))?;
		encode_account_status(&status)
	})())
}

/// Open a persistent-forwarding template session; returns a JSON session bytes
/// handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_initiate_persistent_forwarding_template(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = initiate_template_request(request)?;
		let outcome = with_session(handle, |client| {
			block_on(client.initiate_persistent_forwarding_template(&provider, &request))
		})?;

		encode(&outcome)
	})
}

/// Create a persistent-forwarding template; returns a JSON template bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_create_persistent_forwarding_template(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = create_template_request(request)?;
		let outcome =
			with_session(handle, |client| block_on(client.create_persistent_forwarding_template(&provider, &request)))?;

		encode(&outcome)
	})
}

/// List persistent-forwarding templates; returns a JSON page bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_list_forwarding_address_templates(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = list_templates_request(request)?;
		let outcome =
			with_session(handle, |client| block_on(client.list_forwarding_address_templates(&provider, &request)))?;

		encode(&outcome)
	})
}

/// Create a persistent-forwarding address; returns a JSON details bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_create_persistent_forwarding_address(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = create_address_request(request)?;
		let details =
			with_session(handle, |client| block_on(client.create_persistent_forwarding_address(&provider, &request)))?;

		encode(&details)
	})
}

/// List persistent-forwarding addresses; returns a JSON page bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_list_forwarding_addresses(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = list_addresses_request(request)?;
		let outcome = with_session(handle, |client| block_on(client.list_forwarding_addresses(&provider, &request)))?;
		encode(&outcome)
	})
}

/// Deactivate a persistent-forwarding template by id; returns a JSON `{}` bytes
/// handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_deactivate_persistent_forwarding_template(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	id_ptr: i32,
	id_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, id_ptr, id_len, |provider, id| {
		with_session(handle, |client| block_on(client.deactivate_persistent_forwarding_template(&provider, id)))?;
		encode_ack()
	})
}

/// Deactivate a persistent-forwarding address by id; returns a JSON `{}` bytes
/// handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_deactivate_persistent_forwarding_address(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	id_ptr: i32,
	id_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, id_ptr, id_len, |provider, id| {
		with_session(handle, |client| block_on(client.deactivate_persistent_forwarding_address(&provider, id)))?;
		encode_ack()
	})
}

/// List asset-movement transactions; returns a JSON page bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_list_transactions(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = list_transactions_request(request)?;
		let outcome = with_session(handle, |client| block_on(client.list_transactions(&provider, &request)))?;
		encode(&outcome)
	})
}

/// Share KYC attributes with the provider; returns a JSON outcome bytes handle
/// (`0` on error).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_share_kyc_attributes(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = share_kyc_attributes_request(request)?;
		let outcome = with_session(handle, |client| block_on(client.share_kyc_attributes(&provider, &request)))?;
		encode(&outcome)
	})
}

/// Share KYC attributes and poll the returned promise URL to completion,
/// pausing between polls through the host timer; returns a JSON outcome bytes
/// handle (`0` on error).
///
/// A non-positive `interval_ms` or `timeout_ms` selects that bound's default
/// ([`AwaitOptions::default`]).
///
/// # Safety
///
/// See [`keeta_asset_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_asset_share_kyc_attributes_and_wait(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	request_ptr: i32,
	request_len: i32,
	interval_ms: i32,
	timeout_ms: i32,
) -> i32 {
	dispatch2(provider_ptr, provider_len, request_ptr, request_len, |provider, request| {
		let request = share_kyc_attributes_request(request)?;
		let options = await_options(interval_ms, timeout_ms);
		let outcome = with_session(handle, |client| {
			block_on(client.share_kyc_attributes_and_wait(&provider, &request, options, |millis| async move {
				host_sleep_ms(u64::from(millis))
			}))
		})?;

		encode(&outcome)
	})
}

/// The poll bounds for a share-KYC await: each positive argument overrides its
/// default.
fn await_options(interval_ms: i32, timeout_ms: i32) -> AwaitOptions {
	let defaults = AwaitOptions::default();
	AwaitOptions {
		interval_ms: u32::try_from(interval_ms)
			.ok()
			.filter(|value| *value > 0)
			.unwrap_or(defaults.interval_ms),
		timeout_ms: u32::try_from(timeout_ms)
			.ok()
			.filter(|value| *value > 0)
			.unwrap_or(defaults.timeout_ms),
	}
}

/// Release a client handle, ignoring an unknown one.
#[no_mangle]
pub extern "C" fn keeta_asset_free(handle: i32) {
	SESSIONS.with_borrow_mut(|sessions| sessions.clients.remove(&handle));
}

// ---------------------------------------------------------------------------
// Operation bodies
// ---------------------------------------------------------------------------

fn providers(handle: i32, filter: ProviderFilter) -> Result<Vec<u8>, CodedError> {
	let providers = with_session(handle, |client| block_on(lookup(client, &filter)))?;
	encode_providers(providers)
}

fn providers_for_transfer(handle: i32, search_json: &str) -> Result<Vec<u8>, CodedError> {
	let search = parse_provider_search(search_json)?;
	let providers = with_session(handle, |client| block_on(client.providers_for_transfer(&search)))?;
	encode_providers(providers)
}

fn provider_one(handle: i32, filter: ProviderFilter) -> Result<Vec<u8>, CodedError> {
	let providers = with_session(handle, |client| block_on(lookup(client, &filter)))?;
	encode_provider(providers.into_iter().next())
}

/// Discover providers matching `filter` through the client's public surface.
async fn lookup(
	client: &AssetMovementClient,
	filter: &ProviderFilter,
) -> Result<Vec<AssetMovementProvider>, AnchorClientError> {
	let all = client.providers().await?;
	Ok(filter_providers(all, filter))
}

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// Build a networked asset-movement client signed by `signer`.
fn build_client(node_url: String, root: String, signer: Arc<GenericAccount>) -> AssetMovementClient {
	let transport = host_transport();
	let client = super::node::node_client(&node_url);
	let resolver = Resolver::new(client, transport.clone(), [root]);
	let context = AnchorContext::new(resolver, transport, signer);

	AssetMovementClient::new(context)
}

/// Store `client` under a fresh handle and return it.
fn insert(client: AssetMovementClient) -> i32 {
	SESSIONS.with_borrow_mut(|sessions| {
		sessions.next = sessions.next.wrapping_add(1).max(1);

		let handle = sessions.next;
		sessions.clients.insert(handle, client);

		handle
	})
}

/// Resolve `handle` and run `call` against the stored client, recording an
/// error for a missing handle or a client failure.
fn with_session<T>(
	handle: i32,
	call: impl FnOnce(&AssetMovementClient) -> Result<T, AnchorClientError>,
) -> Result<T, CodedError> {
	SESSIONS.with_borrow(|sessions| {
		let client = sessions.clients.get(&handle).ok_or_else(unknown_handle)?;
		call(client).map_err(coded)
	})
}

/// Read a `(provider, argument)` pair from guest memory and run `body`, wiring
/// the result onto the bytes ABI. Records `INVALID_INPUT` for an unreadable
/// buffer.
fn dispatch2(
	provider_ptr: i32,
	provider_len: i32,
	arg_ptr: i32,
	arg_len: i32,
	body: impl FnOnce(AssetMovementProvider, &str) -> Result<Vec<u8>, CodedError>,
) -> i32 {
	let result = (|| {
		let provider_json = unsafe { string_in(provider_ptr, provider_len) }.ok_or_else(unreadable)?;
		let argument = unsafe { string_in(arg_ptr, arg_len) }.ok_or_else(unreadable)?;
		let provider = parse_provider(&provider_json)?;
		body(provider, &argument)
	})();

	bytes_result(result)
}

/// The coded error for an unreadable guest buffer.
fn unreadable() -> CodedError {
	CodedError::new("INVALID_INPUT", "unreadable argument buffer")
}

/// The coded error for an anchor client failure.
fn coded(error: AnchorClientError) -> CodedError {
	CodedError::new(error.code(), error.to_string())
}

/// The coded error for a request referencing an unknown client handle.
fn unknown_handle() -> CodedError {
	CodedError::new("INVALID_HANDLE", "unknown client handle")
}

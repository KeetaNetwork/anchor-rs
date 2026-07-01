//! The networked asset-movement resource of the P2 component.
//!
//! Each method projects its JSON arguments to and from the shared
//! [`AssetMovementClient`] through [`crate::asset_json`] (byte-identical to the
//! P1 core module), drives the client to completion on the `wstd` reactor, and
//! returns a JSON document string.

use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_bindings::error::CodedError as CoreCodedError;
use keetanetwork_anchor_client::resilience::{ResilientTransport, WasiRuntime};
use keetanetwork_anchor_client::{
	AnchorContext, AnchorHttpTransport, AssetMovementClient, ProviderFilter, Resolver, WasiTransport,
};

use crate::asset_json::{
	create_address_request, create_template_request, encode, encode_account_status, encode_ack, encode_provider,
	encode_providers, execute_request, filter_providers, initiate_template_request, list_addresses_request,
	list_templates_request, list_transactions_request, parse_provider, share_kyc_request, transfer_request,
};

use super::exports::keeta::anchor::asset_movement::{
	AssetClient as WitAssetClient, Guest as AssetMovementGuest, GuestAssetClient,
};
use super::exports::keeta::client::crypto::AccountBorrow;
use super::{run, AccountResource, CodedError, Component};

/// The resource state backing the exported `asset-client`.
pub(crate) struct AssetSession {
	inner: AssetMovementClient,
}

impl AssetMovementGuest for Component {
	type AssetClient = AssetSession;
}

impl GuestAssetClient for AssetSession {
	fn with_account(node_url: String, root: String, signer: AccountBorrow<'_>) -> Result<WitAssetClient, CodedError> {
		let account = Arc::clone(&signer.get::<AccountResource>().account);
		Ok(WitAssetClient::new(Self { inner: build_client(node_url, root, account) }))
	}

	fn providers(&self) -> Result<String, CodedError> {
		let all = run(self.inner.providers())?;
		text(encode_providers(filter_providers(all, &ProviderFilter::default())))
	}

	fn provider_by_id(&self, id: String) -> Result<String, CodedError> {
		let all = run(self.inner.providers())?;
		let one = filter_providers(all, &ProviderFilter::by_id(id))
			.into_iter()
			.next();
		text(encode_provider(one))
	}

	fn provider_by_account(&self, account: String) -> Result<String, CodedError> {
		let all = run(self.inner.providers())?;
		let one = filter_providers(all, &ProviderFilter::by_account(account))
			.into_iter()
			.next();
		text(encode_provider(one))
	}

	fn simulate_transfer(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(transfer_request(&request))?;
		let outcome = run(self.inner.simulate_transfer(&provider, &request))?;
		text(encode(&outcome))
	}

	fn initiate_transfer(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(transfer_request(&request))?;
		let outcome = run(self.inner.initiate_transfer(&provider, &request))?;
		text(encode(&outcome))
	}

	fn execute_transfer(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(execute_request(&request))?;
		let outcome = run(self.inner.execute_transfer(&provider, &request))?;
		text(encode(&outcome))
	}

	fn transfer_status(&self, provider: String, id: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let outcome = run(self.inner.transfer_status(&provider, &id))?;
		text(encode(&outcome))
	}

	fn account_status(&self, provider: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let status = run(self.inner.account_status(&provider))?;
		text(encode_account_status(&status))
	}

	fn initiate_forwarding_template(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(initiate_template_request(&request))?;
		let outcome = run(self.inner.initiate_forwarding_template(&provider, &request))?;
		text(encode(&outcome))
	}

	fn create_forwarding_template(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(create_template_request(&request))?;
		let outcome = run(self.inner.create_forwarding_template(&provider, &request))?;
		text(encode(&outcome))
	}

	fn list_forwarding_templates(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(list_templates_request(&request))?;
		let outcome = run(self.inner.list_forwarding_templates(&provider, &request))?;
		text(encode(&outcome))
	}

	fn create_forwarding_address(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(create_address_request(&request))?;
		let details = run(self.inner.create_forwarding_address(&provider, &request))?;
		text(encode(&details))
	}

	fn list_forwarding_addresses(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(list_addresses_request(&request))?;
		let outcome = run(self.inner.list_forwarding_addresses(&provider, &request))?;
		text(encode(&outcome))
	}

	fn deactivate_forwarding_template(&self, provider: String, id: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		run(self.inner.deactivate_forwarding_template(&provider, &id))?;
		text(encode_ack())
	}

	fn deactivate_forwarding_address(&self, provider: String, id: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		run(self.inner.deactivate_forwarding_address(&provider, &id))?;
		text(encode_ack())
	}

	fn list_transactions(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(list_transactions_request(&request))?;
		let outcome = run(self.inner.list_transactions(&provider, &request))?;
		text(encode(&outcome))
	}

	fn share_kyc(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(share_kyc_request(&request))?;
		let outcome = run(self.inner.share_kyc(&provider, &request))?;
		text(encode(&outcome))
	}
}

/// Build a networked asset-movement client signed by `signer`: a `wasi:http`
/// transport wrapped in the resilience policy, a metadata resolver reading
/// `root` via the node API at `node_url`, and the bound `signer`.
fn build_client(node_url: String, root: String, signer: Arc<GenericAccount>) -> AssetMovementClient {
	let base: Arc<dyn AnchorHttpTransport> = Arc::new(WasiTransport::default());
	let transport: Arc<dyn AnchorHttpTransport> = Arc::new(ResilientTransport::new(base, WasiRuntime));
	let resolver = Resolver::new(transport.clone(), node_url, [root]);
	let context = AnchorContext::new(resolver, transport, signer);

	AssetMovementClient::new(context)
}

/// Lift a shared coded error to the WIT boundary error.
fn core<T>(result: Result<T, CoreCodedError>) -> Result<T, CodedError> {
	result.map_err(CodedError::from)
}

/// Decode encoded JSON result bytes into the boundary string, lifting a shared
/// coded error and rejecting non-UTF-8 output.
fn text(bytes: Result<Vec<u8>, CoreCodedError>) -> Result<String, CodedError> {
	let bytes = core(bytes)?;
	String::from_utf8(bytes).map_err(|_| CodedError {
		code: "ENCODE".into(),
		message: "asset-movement response was not valid UTF-8".into(),
	})
}

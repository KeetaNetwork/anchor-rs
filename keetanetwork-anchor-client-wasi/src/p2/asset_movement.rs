//! The networked asset-movement resource of the P2 component.
//!
//! Each method projects its JSON arguments to and from the shared
//! [`AssetMovementClient`] through [`crate::asset_json`] (byte-identical to the
//! P1 core module), drives the client to completion on the `wstd` reactor, and
//! returns a JSON document string.

use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_bindings::error::CodedError as CoreCodedError;
use keetanetwork_anchor_client::resilience::{ResilienceRuntime, ResilientTransport, WasiRuntime};
use keetanetwork_anchor_client::{
	AnchorContext, AnchorHttpTransport, AssetMovementClient, AwaitOptions, ProviderFilter, Resolver, WasiTransport,
};

use crate::asset_json::{
	create_address_request, create_template_request, encode, encode_account_status, encode_ack, encode_provider,
	encode_providers, execute_request, filter_providers, initiate_template_request, list_addresses_request,
	list_templates_request, list_transactions_request, parse_provider, parse_provider_search,
	share_kyc_attributes_request, transfer_request,
};

use super::exports::keeta::anchor::asset_movement::{
	AssetClient as WitAssetClient, AwaitOptions as WitAwaitOptions, Guest as AssetMovementGuest, GuestAssetClient,
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

	fn providers_for_transfer(&self, search: String) -> Result<String, CodedError> {
		let search = core(parse_provider_search(&search))?;
		let providers = run(self.inner.providers_for_transfer(&search))?;
		text(encode_providers(providers))
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

	fn initiate_persistent_forwarding_template(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(initiate_template_request(&request))?;
		let outcome = run(self
			.inner
			.initiate_persistent_forwarding_template(&provider, &request))?;

		text(encode(&outcome))
	}

	fn create_persistent_forwarding_template(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(create_template_request(&request))?;
		let outcome = run(self
			.inner
			.create_persistent_forwarding_template(&provider, &request))?;

		text(encode(&outcome))
	}

	fn list_forwarding_address_templates(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(list_templates_request(&request))?;
		let outcome = run(self
			.inner
			.list_forwarding_address_templates(&provider, &request))?;

		text(encode(&outcome))
	}

	fn create_persistent_forwarding_address(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(create_address_request(&request))?;
		let details = run(self
			.inner
			.create_persistent_forwarding_address(&provider, &request))?;

		text(encode(&details))
	}

	fn list_forwarding_addresses(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(list_addresses_request(&request))?;
		let outcome = run(self.inner.list_forwarding_addresses(&provider, &request))?;

		text(encode(&outcome))
	}

	fn deactivate_persistent_forwarding_template(&self, provider: String, id: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		run(self
			.inner
			.deactivate_persistent_forwarding_template(&provider, &id))?;
		text(encode_ack())
	}

	fn deactivate_persistent_forwarding_address(&self, provider: String, id: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		run(self
			.inner
			.deactivate_persistent_forwarding_address(&provider, &id))?;
		text(encode_ack())
	}

	fn list_transactions(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(list_transactions_request(&request))?;
		let outcome = run(self.inner.list_transactions(&provider, &request))?;

		text(encode(&outcome))
	}

	fn share_kyc_attributes(&self, provider: String, request: String) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(share_kyc_attributes_request(&request))?;
		let outcome = run(self.inner.share_kyc_attributes(&provider, &request))?;

		text(encode(&outcome))
	}

	fn share_kyc_attributes_and_wait(
		&self,
		provider: String,
		request: String,
		options: Option<WitAwaitOptions>,
	) -> Result<String, CodedError> {
		let provider = core(parse_provider(&provider))?;
		let request = core(share_kyc_attributes_request(&request))?;
		let options = options.map_or_else(AwaitOptions::default, |options| AwaitOptions {
			interval_ms: options.interval_ms,
			timeout_ms: options.timeout_ms,
		});
		let outcome =
			run(self
				.inner
				.share_kyc_attributes_and_wait(&provider, &request, options, |millis| async move {
					WasiRuntime.sleep_ms(u64::from(millis)).await;
				}))?;

		text(encode(&outcome))
	}
}

/// Build a networked asset-movement client signed by `signer`: a `wasi:http`
/// transport wrapped in the resilience policy, a metadata resolver reading
/// `root` through the node client at `node_url`, and the bound `signer`.
fn build_client(node_url: String, root: String, signer: Arc<GenericAccount>) -> AssetMovementClient {
	let base: Arc<dyn AnchorHttpTransport> = Arc::new(WasiTransport::default());
	let transport: Arc<dyn AnchorHttpTransport> = Arc::new(ResilientTransport::new(base, WasiRuntime));
	let client = super::node_client(&node_url);
	let resolver = Resolver::new(client, transport.clone(), [root]);
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

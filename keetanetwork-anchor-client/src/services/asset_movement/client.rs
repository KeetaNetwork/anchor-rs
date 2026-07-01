//! The asset-movement anchor client: discover providers and run every
//! operation over the shared service layer.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;

use keetanetwork_anchor::signing::Signable;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::error::{AccountStatus, AssetMovementBlocker};
use super::metadata::{AssetMovementProvider, AssetMovementQuery, EndpointAuth, ProviderFilter, ProviderSearch};
use super::request::{
	id_literal, literal, CreateForwardingAddressRequest, CreateForwardingTemplateRequest, ExecuteTransferRequest,
	InitiateForwardingTemplateRequest, ListForwardingAddressesRequest, ListForwardingTemplatesRequest,
	ListTransactionsRequest, ShareKycRequest, TransferRequest,
};
use super::response::{
	AddressPage, ForwardingTemplate, ShareKycOutcome, SimulatedTransfer, TemplatePage, TemplateSession,
	TransactionPage, Transfer, TransferStatus,
};
use crate::error::AnchorClientError;
use crate::service::{pending_delay, AnchorContext, AnchorOutcome, Auth, BodyEnvelope, Call, Endpoint, Method};

/// The transport request fields, keyed by name.
type Fields = Map<String, Value>;

/// How to pace and bound a polled operation (e.g. awaiting a share-KYC
/// promise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollOptions {
	/// The minimum delay between polls, in milliseconds. The provider's
	/// `retryAfter` hint overrides this when it is longer.
	pub interval_ms: u32,
	/// The overall deadline, in milliseconds, after which the poll gives up.
	pub timeout_ms: u32,
}

impl Default for PollOptions {
	fn default() -> Self {
		Self { interval_ms: 2_000, timeout_ms: 300_000 }
	}
}

/// An asset-movement anchor client over a shared [`AnchorContext`].
///
/// Discovery finds providers; each operation fills, signs, and sends a request
/// through the context's caller. Operation methods take the resolved
/// [`AssetMovementProvider`] so a caller can reuse one discovery across many
/// operations.
pub struct AssetMovementClient {
	context: AnchorContext,
}

impl AssetMovementClient {
	/// A client discovering and signing through `context`.
	pub fn new(context: AnchorContext) -> Self {
		Self { context }
	}

	/// Every asset-movement provider across all roots.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError`] when no metadata root can be read.
	pub async fn providers(&self) -> Result<Vec<AssetMovementProvider>, AnchorClientError> {
		let providers = self.lookup(ProviderFilter::default()).await?;
		Ok(providers)
	}

	/// Every provider whose published `supportedAssets` satisfies `search`
	/// (asset, endpoints, and rails).
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError`] when no metadata root can be read.
	pub async fn providers_for_transfer(
		&self,
		search: &ProviderSearch,
	) -> Result<Vec<AssetMovementProvider>, AnchorClientError> {
		let providers = self.providers().await?;
		Ok(providers
			.into_iter()
			.filter(|provider| search.accepts(provider))
			.collect())
	}

	/// The provider with `id`, when one advertises asset movement.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError`] when no metadata root can be read.
	pub async fn provider_by_id(
		&self,
		id: impl Into<String>,
	) -> Result<Option<AssetMovementProvider>, AnchorClientError> {
		let providers = self.lookup(ProviderFilter::by_id(id)).await?;
		Ok(providers.into_iter().next())
	}

	/// The provider whose entry was signed by `account`, when present.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError`] when no metadata root can be read.
	pub async fn provider_by_account(
		&self,
		account: impl Into<String>,
	) -> Result<Option<AssetMovementProvider>, AnchorClientError> {
		let providers = self.lookup(ProviderFilter::by_account(account)).await?;
		Ok(providers.into_iter().next())
	}

	/// Whether `provider` advertises `operation`.
	pub fn is_operation_supported(&self, provider: &AssetMovementProvider, operation: &str) -> bool {
		provider.operations.contains(operation)
	}

	/// Simulate a transfer, returning the instruction choices without committing.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `simulateTransfer`, or any request failure.
	pub async fn simulate_transfer(
		&self,
		provider: &AssetMovementProvider,
		request: &TransferRequest,
	) -> Result<SimulatedTransfer, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "simulateTransfer")?;
		let signed = request.signable()?;
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// Initiate a transfer. The request's recipient is required.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `initiateTransfer`, [`AnchorClientError::Body`] when
	/// the recipient is missing, or any request failure.
	pub async fn initiate_transfer(
		&self,
		provider: &AssetMovementProvider,
		request: &TransferRequest,
	) -> Result<Transfer, AnchorClientError> {
		if request.to.recipient.is_none() {
			return Err(AnchorClientError::Body { reason: "initiateTransfer requires a recipient".to_string() });
		}

		let (endpoint, auth) = operation(provider, "initiateTransfer")?;
		let signed = request.signable()?;
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// Execute a pull instruction for a transfer.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `executeTransfer`, or any request failure.
	pub async fn execute_transfer(
		&self,
		provider: &AssetMovementProvider,
		request: &ExecuteTransferRequest,
	) -> Result<TransferStatus, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "executeTransfer")?;
		let signed = request.signable()?;
		let params = [("id", request.id.as_str())];
		self.post(&endpoint, auth, &params, request.transport_fields(), &signed)
			.await
	}

	/// Read the status of transfer `id` (signed URL).
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `getTransferStatus`, or any request failure.
	pub async fn transfer_status(
		&self,
		provider: &AssetMovementProvider,
		id: &str,
	) -> Result<TransferStatus, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "getTransferStatus")?;
		let signed = id_literal("get-transaction", id);
		let params = [("id", id)];
		self.get(&endpoint, auth, &params, &signed).await
	}

	/// Read whether the signer's account is ready to use this provider.
	///
	/// Resolves the transport `actionRequired` discriminant into [`AccountStatus`],
	/// folding a recognized asset-movement blocker returned as an error into
	/// [`AccountStatus::ActionRequired`]. A request-level failure still errors.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `getAccountStatus`, [`AnchorClientError::Service`]
	/// when the anchor returns an unrecognized error, or any request failure.
	pub async fn account_status(&self, provider: &AssetMovementProvider) -> Result<AccountStatus, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "getAccountStatus")?;
		let signed = literal(&["get-account-status"]);
		let mut fields = Fields::new();
		fields.insert("account".into(), Value::String(self.account().to_string()));
		let auth = post_auth(auth);
		let call = Call {
			endpoint: &endpoint,
			params: &[],
			method: Method::Post,
			auth,
			signed: &signed,
			envelope: BodyEnvelope::Flat,
			body: Some(Value::Object(fields)),
		};

		let response = self.context.caller().send(call).await?;
		let body: Value = serde_json::from_slice(&response.body)
			.map_err(|error| AnchorClientError::Body { reason: error.to_string() })?;
		resolve_account_status(&body, response.status)
	}

	/// Deactivate a persistent-forwarding template by id.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `deactivatePersistentForwardingTemplate`, or any
	/// request failure.
	pub async fn deactivate_forwarding_template(
		&self,
		provider: &AssetMovementProvider,
		id: &str,
	) -> Result<(), AnchorClientError> {
		self.deactivate(
			provider,
			"deactivatePersistentForwardingTemplate",
			"deactivate-persistent-forwarding-template",
			id,
		)
		.await
	}

	/// Deactivate a persistent-forwarding address by id.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `deactivatePersistentForwarding`, or any request
	/// failure.
	pub async fn deactivate_forwarding_address(
		&self,
		provider: &AssetMovementProvider,
		id: &str,
	) -> Result<(), AnchorClientError> {
		self.deactivate(provider, "deactivatePersistentForwarding", "deactivate-persistent-forwarding-address", id)
			.await
	}

	/// Open a persistent-forwarding template session.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `initiatePersistentForwardingTemplate`, or any
	/// request failure.
	pub async fn initiate_forwarding_template(
		&self,
		provider: &AssetMovementProvider,
		request: &InitiateForwardingTemplateRequest,
	) -> Result<TemplateSession, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "initiatePersistentForwardingTemplate")?;
		let signed = request.signable()?;

		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// Create a persistent-forwarding template.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `createPersistentForwardingTemplate`, or any request
	/// failure.
	pub async fn create_forwarding_template(
		&self,
		provider: &AssetMovementProvider,
		request: &CreateForwardingTemplateRequest,
	) -> Result<ForwardingTemplate, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "createPersistentForwardingTemplate")?;
		let signed = request.signable()?;
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// List persistent-forwarding templates.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `listPersistentForwardingTemplate`, or any request
	/// failure.
	pub async fn list_forwarding_templates(
		&self,
		provider: &AssetMovementProvider,
		request: &ListForwardingTemplatesRequest,
	) -> Result<TemplatePage, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "listPersistentForwardingTemplate")?;
		let signed = request.signable();
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// Create a persistent-forwarding address, returning its (obfuscated)
	/// details.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `createPersistentForwarding`, or any request failure.
	pub async fn create_forwarding_address(
		&self,
		provider: &AssetMovementProvider,
		request: &CreateForwardingAddressRequest,
	) -> Result<Value, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "createPersistentForwarding")?;
		let signed = request.signable()?;
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// List persistent-forwarding addresses.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `listPersistentForwarding`, or any request failure.
	pub async fn list_forwarding_addresses(
		&self,
		provider: &AssetMovementProvider,
		request: &ListForwardingAddressesRequest,
	) -> Result<AddressPage, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "listPersistentForwarding")?;
		let signed = request.signable();
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// List asset-movement transactions.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `listTransactions`, or any request failure.
	pub async fn list_transactions(
		&self,
		provider: &AssetMovementProvider,
		request: &ListTransactionsRequest,
	) -> Result<TransactionPage, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "listTransactions")?;
		let signed = request.signable();
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// Share KYC attributes with the provider.
	///
	/// Returns the anchor's outcome; when [`ShareKycOutcome::is_pending`] is set
	/// the caller polls [`ShareKycOutcome::promise_url`] until it completes.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `shareKYC`, or any request failure.
	pub async fn share_kyc(
		&self,
		provider: &AssetMovementProvider,
		request: &ShareKycRequest,
	) -> Result<ShareKycOutcome, AnchorClientError> {
		let (endpoint, auth) = operation(provider, "shareKYC")?;
		let signed = request.signable();
		self.post(&endpoint, auth, &[], request.transport_fields(), &signed)
			.await
	}

	/// Share KYC attributes and, when the anchor reports the share pending with
	/// a promise URL, poll that URL to completion.
	///
	/// `sleep` pauses between polls; `options` bounds the interval and overall
	/// deadline. Elapsed time is summed from the observed delays, so no wall
	/// clock is required.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
	/// does not advertise `shareKYC`, [`AnchorClientError::Timeout`] when the
	/// promise does not resolve within `options.timeout_ms`, or any request
	/// failure.
	pub async fn share_kyc_await<S, Fut>(
		&self,
		provider: &AssetMovementProvider,
		request: &ShareKycRequest,
		options: PollOptions,
		sleep: S,
	) -> Result<ShareKycOutcome, AnchorClientError>
	where
		S: Fn(u32) -> Fut,
		Fut: Future<Output = ()>,
	{
		let outcome = self.share_kyc(provider, request).await?;
		let Some(promise_url) = outcome.promise_url.clone().filter(|_| outcome.is_pending) else {
			return Ok(outcome);
		};

		let url = self.resolve_promise_url(provider, &promise_url)?;
		self.poll_promise(&url, options, sleep).await
	}

	/// The signer's account string.
	fn account(&self) -> &str {
		self.context.caller().account()
	}

	/// Deactivate the resource `id` through the advertised `operation_name`,
	/// signing the `signed_name` literal, discarding the response body.
	async fn deactivate(
		&self,
		provider: &AssetMovementProvider,
		operation_name: &'static str,
		signed_name: &'static str,
		id: &str,
	) -> Result<(), AnchorClientError> {
		let (endpoint, auth) = operation(provider, operation_name)?;
		let signed = id_literal(signed_name, id);
		let params = [("id", id)];
		let _: Value = self
			.post(&endpoint, auth, &params, Fields::new(), &signed)
			.await?;

		Ok(())
	}

	/// Discover providers matching `filter`.
	async fn lookup(&self, filter: ProviderFilter) -> Result<Vec<AssetMovementProvider>, AnchorClientError> {
		let providers = self
			.context
			.resolver()
			.lookup::<AssetMovementQuery>(&filter)
			.await?;

		Ok(providers)
	}

	/// Fill, sign, and send a `POST`, injecting the signer's account into the
	/// body and decoding the ready response into `T`.
	async fn post<T: DeserializeOwned>(
		&self,
		endpoint: &Endpoint,
		auth_meta: EndpointAuth,
		params: &[(&str, &str)],
		mut fields: Fields,
		signed: &[Signable<'_>],
	) -> Result<T, AnchorClientError> {
		fields.insert("account".into(), Value::String(self.account().to_string()));
		let call = Call {
			endpoint,
			params,
			method: Method::Post,
			auth: post_auth(auth_meta),
			signed,
			envelope: BodyEnvelope::Flat,
			body: Some(Value::Object(fields)),
		};
		let outcome = self.context.caller().invoke(call).await?;
		expect_ready(outcome)
	}

	/// Fill, sign, and send a `GET`, decoding the ready response into `T`.
	async fn get<T: DeserializeOwned>(
		&self,
		endpoint: &Endpoint,
		auth_meta: EndpointAuth,
		params: &[(&str, &str)],
		signed: &[Signable<'_>],
	) -> Result<T, AnchorClientError> {
		let auth = match auth_meta.signs() {
			true => Auth::SignedUrl,
			false => Auth::None,
		};
		let call =
			Call { endpoint, params, method: Method::Get, auth, signed, envelope: BodyEnvelope::Flat, body: None };
		let outcome = self.context.caller().invoke(call).await?;

		expect_ready(outcome)
	}

	/// Resolve a (possibly relative) share-KYC promise URL against the
	/// provider's `shareKYC` endpoint.
	fn resolve_promise_url(
		&self,
		provider: &AssetMovementProvider,
		promise_url: &str,
	) -> Result<String, AnchorClientError> {
		let (endpoint, _auth) = operation(provider, "shareKYC")?;
		let base = endpoint.url(&[])?;
		join_promise_url(base.as_str(), promise_url)
	}

	/// Poll `url` until the anchor reports the pending share complete, pausing
	/// with `sleep` between polls and giving up once the summed delay exceeds
	/// `options.timeout_ms`.
	///
	/// The promise contract is status-only (a settled `200` may carry any
	/// body), so the poll reads the raw response instead of decoding it.
	async fn poll_promise<S, Fut>(
		&self,
		url: &str,
		options: PollOptions,
		sleep: S,
	) -> Result<ShareKycOutcome, AnchorClientError>
	where
		S: Fn(u32) -> Fut,
		Fut: Future<Output = ()>,
	{
		let endpoint = Endpoint::from(url);
		let signed: [Signable<'_>; 0] = [];
		let mut elapsed_ms: u32 = 0;

		loop {
			let call = Call {
				endpoint: &endpoint,
				params: &[],
				method: Method::Get,
				auth: Auth::None,
				signed: &signed,
				envelope: BodyEnvelope::Flat,
				body: None,
			};

			let response = self.context.caller().send(call).await?;
			let Some(after_ms) = pending_delay(&response) else {
				if !response.is_success() {
					return Err(AnchorClientError::Service { status: response.status });
				}

				return Ok(ShareKycOutcome { is_pending: false, promise_url: None });
			};

			let wait = after_ms.max(options.interval_ms).max(1);
			if elapsed_ms.saturating_add(wait) > options.timeout_ms {
				return Err(AnchorClientError::Timeout { operation: "shareKYC", timeout_ms: options.timeout_ms });
			}

			sleep(wait).await;
			elapsed_ms = elapsed_ms.saturating_add(wait);
		}
	}
}

/// Resolve a promise URL against the share-KYC endpoint `base`. An absolute
/// promise URL replaces the base; a root- or path-relative one is joined onto
/// it.
fn join_promise_url(base: &str, promise: &str) -> Result<String, AnchorClientError> {
	let base = url::Url::parse(base)?;
	let joined = base.join(promise)?;
	Ok(joined.to_string())
}

/// The endpoint and authentication for an advertised operation, or a typed
/// error naming the missing one.
fn operation(
	provider: &AssetMovementProvider,
	name: &'static str,
) -> Result<(Endpoint, EndpointAuth), AnchorClientError> {
	let endpoint = provider
		.operations
		.get(name)
		.ok_or(AnchorClientError::UnsupportedOperation { operation: name })?;
	Ok((Endpoint::from(endpoint.url.as_str()), endpoint.auth))
}

/// The `POST` auth mode for a metadata auth requirement.
fn post_auth(auth: EndpointAuth) -> Auth {
	match auth.signs() {
		true => Auth::SignedBody,
		false => Auth::None,
	}
}

/// The ready value, or a body error when the anchor asked to retry a
/// non-pollable operation.
fn expect_ready<T>(outcome: AnchorOutcome<T>) -> Result<T, AnchorClientError> {
	outcome
		.ready()
		.ok_or(AnchorClientError::Body { reason: "anchor asked to retry a non-pollable operation".to_string() })
}

/// Resolve a `getAccountStatus` body into an [`AccountStatus`].
fn resolve_account_status(body: &Value, status: u16) -> Result<AccountStatus, AnchorClientError> {
	if body.get("ok").and_then(Value::as_bool) == Some(false) {
		let blocker = AssetMovementBlocker::from_transport(body);
		return match blocker {
			AssetMovementBlocker::Other { .. } => Err(AnchorClientError::Service { status }),
			recognized => Ok(AccountStatus::ActionRequired { blockers: vec![recognized] }),
		};
	}

	let action_required = body
		.get("actionRequired")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	if !action_required {
		return Ok(AccountStatus::Ready);
	}

	let blockers = body
		.get("errors")
		.and_then(Value::as_array)
		.map(|errors| {
			errors
				.iter()
				.map(AssetMovementBlocker::from_transport)
				.collect()
		})
		.unwrap_or_default();
	Ok(AccountStatus::ActionRequired { blockers })
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	#[test]
	fn a_ready_account_resolves_to_ready() -> Result<(), AnchorClientError> {
		let body = json!({ "ok": true, "actionRequired": false });
		assert_eq!(resolve_account_status(&body, 200)?, AccountStatus::Ready);
		Ok(())
	}

	#[test]
	fn a_blocked_account_collects_its_errors() -> Result<(), AnchorClientError> {
		let body = json!({
			"ok": true,
			"actionRequired": true,
			"errors": [{ "name": "n", "code": "KEETA_ANCHOR_ASSET_MOVEMENT_ADDITIONAL_KYC_NEEDED", "error": "e", "data": { "toCompleteFlow": null } }]
		});
		let status = resolve_account_status(&body, 200)?;
		assert!(matches!(status, AccountStatus::ActionRequired { blockers } if blockers.len() == 1));
		Ok(())
	}

	#[test]
	fn a_thrown_asset_movement_error_folds_into_action_required() -> Result<(), AnchorClientError> {
		let body = json!({
			"ok": false,
			"name": "KeetaAssetMovementAnchorKYCShareNeededError",
			"code": "KEETA_ANCHOR_ASSET_MOVEMENT_KYC_SHARE_NEEDED",
			"error": "share needed",
			"data": { "shareWithPrincipals": ["keeta_p"], "acceptedIssuers": [] }
		});
		let status = resolve_account_status(&body, 403)?;
		assert!(matches!(status, AccountStatus::ActionRequired { .. }));
		Ok(())
	}

	#[test]
	fn an_unrecognized_error_is_a_service_failure() {
		let body = json!({ "ok": false, "name": "Other", "code": "NOPE", "error": "boom" });
		assert!(matches!(resolve_account_status(&body, 500), Err(AnchorClientError::Service { status: 500 })));
	}

	#[test]
	fn a_root_relative_promise_url_resolves_against_the_share_endpoint() -> Result<(), AnchorClientError> {
		let resolved = join_promise_url("https://anchor.example/api/shareKYC", "/_promises/abc")?;
		assert_eq!(resolved, "https://anchor.example/_promises/abc");
		Ok(())
	}

	#[test]
	fn a_path_relative_promise_url_resolves_beside_the_endpoint() -> Result<(), AnchorClientError> {
		let resolved = join_promise_url("https://anchor.example/api/shareKYC", "status/42")?;
		assert_eq!(resolved, "https://anchor.example/api/status/42");
		Ok(())
	}

	#[test]
	fn an_absolute_promise_url_replaces_the_base() -> Result<(), AnchorClientError> {
		let resolved = join_promise_url("https://anchor.example/api/shareKYC", "https://other.example/p/1")?;
		assert_eq!(resolved, "https://other.example/p/1");
		Ok(())
	}
}

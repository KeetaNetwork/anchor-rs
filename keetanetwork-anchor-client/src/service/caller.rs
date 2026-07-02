//! Sign and dispatch a single anchor operation over a transport.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::signing::{add_signature_to_url, sign_with, SignParams, Signable, Signed, Url};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};

use super::endpoint::Endpoint;
use super::envelope::{classify, AnchorOutcome};
use crate::error::AnchorClientError;
use crate::transport::{AnchorHttpTransport, HttpResponse};

/// How a request authenticates to the anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
	/// No signature.
	None,

	/// Sign the [`Call::signed`] payload and attach it to the URL query.
	SignedUrl,

	/// Sign the [`Call::signed`] payload and carry the signature in the body.
	SignedBody,
}

/// How a `POST` body is shaped around the request fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyEnvelope {
	/// Wrap the fields as `{ "request": <fields> }`, merging `account` and
	/// `signed` into `<fields>` when the request is signed. The KYC anchor's
	/// shape.
	Request,

	/// Send the fields as-is, merging `signed` at the top level when the
	/// request is signed. The `account` is expected to already sit in the
	/// fields. The asset-movement anchor's shape.
	Flat,
}

/// The HTTP method an operation uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
	/// `GET`.
	Get,

	/// `POST`.
	Post,
}

/// A single anchor operation: which endpoint to fill, how to reach it, how to
/// authenticate, and the request fields to carry.
pub struct Call<'a> {
	/// The operation endpoint template.
	pub endpoint: &'a Endpoint,

	/// The `{param}` substitutions applied to the endpoint.
	pub params: &'a [(&'a str, &'a str)],

	/// The HTTP method.
	pub method: Method,

	/// The authentication mode.
	pub auth: Auth,

	/// The payload signed when [`auth`](Self::auth) is
	/// [`SignedUrl`](Auth::SignedUrl) or [`SignedBody`](Auth::SignedBody).
	/// Empty for the KYC auth flows; a canonical object or a fixed string tuple
	/// for asset-movement operations.
	pub signed: &'a [Signable<'a>],

	/// How the `POST` body is shaped. Ignored for a `GET`.
	pub envelope: BodyEnvelope,

	/// The service-specific request fields, as a JSON object. See
	/// [`BodyEnvelope`] for how they are wrapped. Ignored for a `GET`.
	pub body: Option<Value>,
}

/// Signs and dispatches anchor operations over a shared transport.
///
/// The caller owns the request spine every service shares: fill the endpoint,
/// attach the signature the [`Auth`] mode requires, send it, and decode the
/// response into an [`AnchorOutcome`].
pub struct AnchorCaller {
	transport: Arc<dyn AnchorHttpTransport>,
	signer: Arc<GenericAccount>,
	account: String,
}

impl AnchorCaller {
	/// A caller signing requests with `signer` over `transport`.
	pub fn new(transport: Arc<dyn AnchorHttpTransport>, signer: impl Into<Arc<GenericAccount>>) -> Self {
		let signer = signer.into();
		let account = signer.to_string();
		Self { transport, signer, account }
	}

	/// The signer's account string (the `keeta_...` public key).
	pub fn account(&self) -> &str {
		&self.account
	}

	/// Fill, authenticate, send, and decode `call`.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError`] when the endpoint is not a valid URL, the
	/// signature cannot be produced, the transport fails, or the response does
	/// not decode into `T`.
	pub async fn invoke<T>(&self, call: Call<'_>) -> Result<AnchorOutcome<T>, AnchorClientError>
	where
		T: DeserializeOwned,
	{
		let url = call.endpoint.url(call.params)?;
		let response = self.dispatch(&call, url).await?;
		classify(response)
	}

	/// Fill, authenticate, and send `call`, returning the raw response without
	/// classifying it.
	///
	/// Most operations want [`invoke`](Self::invoke), which turns a non-2xx or
	/// `ok: false` response into an error. An operation whose failure body is
	/// itself meaningful (e.g. an account-status blocker returned with a `403`)
	/// reads the raw response instead.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError`] when the endpoint is not a valid URL, the
	/// signature cannot be produced, or the transport fails.
	pub async fn send(&self, call: Call<'_>) -> Result<HttpResponse, AnchorClientError> {
		let url = call.endpoint.url(call.params)?;
		self.dispatch(&call, url).await
	}

	async fn dispatch(&self, call: &Call<'_>, url: Url) -> Result<HttpResponse, AnchorClientError> {
		match call.method {
			Method::Get => self.send_get(call.auth, call.signed, url).await,
			Method::Post => self.send_post(call, url).await,
		}
	}

	async fn send_get(&self, auth: Auth, signed: &[Signable<'_>], url: Url) -> Result<HttpResponse, AnchorClientError> {
		let target = self.authenticated_url(auth, signed, url)?;
		let response = self.transport.get(target.as_str()).await?;
		Ok(response)
	}

	async fn send_post(&self, call: &Call<'_>, url: Url) -> Result<HttpResponse, AnchorClientError> {
		let payload = self.request_body(call.auth, call.envelope, call.signed, call.body.clone())?;
		let response = self.transport.post(url.as_str(), &payload).await?;
		Ok(response)
	}

	/// Attach a query signature when the [`Auth`] mode calls for it.
	fn authenticated_url(&self, auth: Auth, signed: &[Signable<'_>], url: Url) -> Result<Url, AnchorClientError> {
		match auth {
			Auth::SignedUrl => {
				let envelope = self.sign(signed)?;
				let signed_url = add_signature_to_url(&url, &self.account, &envelope)?;
				Ok(signed_url)
			}
			_ => Ok(url),
		}
	}

	/// Shape the `POST` body per [`BodyEnvelope`], merging the signature (and,
	/// for [`BodyEnvelope::Request`], the `account`) when the request is signed.
	fn request_body(
		&self,
		auth: Auth,
		envelope: BodyEnvelope,
		signed: &[Signable<'_>],
		body: Option<Value>,
	) -> Result<Vec<u8>, AnchorClientError> {
		let mut fields = match body {
			Some(Value::Object(map)) => map,
			_ => Map::new(),
		};

		let signature = match auth {
			Auth::SignedBody => Some(self.sign(signed)?),
			_ => None,
		};

		let shaped = match envelope {
			BodyEnvelope::Request => {
				if let Some(signature) = signature {
					fields.insert("account".into(), Value::String(self.account.clone()));
					fields.insert("signed".into(), signed_field(&signature));
				}
				json!({ "request": Value::Object(fields) })
			}
			BodyEnvelope::Flat => {
				if let Some(signature) = signature {
					fields.insert("signed".into(), signed_field(&signature));
				}
				Value::Object(fields)
			}
		};

		let bytes = serde_json::to_vec(&shaped)?;
		Ok(bytes)
	}

	fn sign(&self, payload: &[Signable<'_>]) -> Result<Signed, AnchorClientError> {
		let params = SignParams::generate();
		let signed = sign_with(self.signer.as_ref(), payload, &params)?;
		Ok(signed)
	}
}

/// The transport `{ nonce, timestamp, signature }` object for a signature.
fn signed_field(signed: &Signed) -> Value {
	json!({ "nonce": signed.nonce, "timestamp": signed.timestamp, "signature": signed.signature })
}

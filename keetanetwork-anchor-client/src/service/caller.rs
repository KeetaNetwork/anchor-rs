//! Sign and dispatch a single anchor operation over a transport.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::{Account, KeyPair};
use keetanetwork_anchor::signing::{add_signature_to_url, sign_with, SignParams, Signable, Signed, Url};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};

use super::endpoint::Endpoint;
use super::envelope::{classify, AnchorOutcome};
use crate::error::AnchorClientError;
use crate::transport::{AnchorHttpTransport, HttpResponse};

/// The KYC auth flows sign the empty payload; no request data is signed.
const EMPTY: &[Signable] = &[];

/// How a request authenticates to the anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
	/// No signature.
	None,

	/// Sign the empty payload and attach it to the URL query.
	SignedUrl,

	/// Sign the empty payload and carry `{ account, signed }` in the body.
	SignedBody,
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

	/// The service-specific request fields, as a JSON object. Anchors wrap a
	/// `POST` body as `{ "request": <fields> }`; [`Auth::SignedBody`] merges
	/// `account` and `signed` into `<fields>` before wrapping. Ignored for a
	/// `GET`.
	pub body: Option<Value>,
}

/// Signs and dispatches anchor operations over a shared transport.
///
/// The caller owns the request spine every service shares: fill the endpoint,
/// attach the signature the [`Auth`] mode requires, send it, and decode the
/// response into an [`AnchorOutcome`].
pub struct AnchorCaller<K>
where
	K: KeyPair,
{
	transport: Arc<dyn AnchorHttpTransport>,
	signer: Account<K>,
	account: String,
}

impl<K> AnchorCaller<K>
where
	K: KeyPair,
{
	/// A caller signing requests with `signer` over `transport`.
	pub fn new(transport: Arc<dyn AnchorHttpTransport>, signer: Account<K>) -> Self {
		let account = signer.to_string();
		Self { transport, signer, account }
	}

	/// The signer's account string (the `keeta_…` public key).
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
		let response = self
			.dispatch(call.method, call.auth, url, call.body)
			.await?;
		classify(response)
	}

	async fn dispatch(
		&self,
		method: Method,
		auth: Auth,
		url: Url,
		body: Option<Value>,
	) -> Result<HttpResponse, AnchorClientError> {
		match method {
			Method::Get => self.send_get(auth, url).await,
			Method::Post => self.send_post(auth, url, body).await,
		}
	}

	async fn send_get(&self, auth: Auth, url: Url) -> Result<HttpResponse, AnchorClientError> {
		let target = self.authenticated_url(auth, url)?;
		let response = self.transport.get(target.as_str()).await?;
		Ok(response)
	}

	async fn send_post(&self, auth: Auth, url: Url, body: Option<Value>) -> Result<HttpResponse, AnchorClientError> {
		let payload = self.request_body(auth, body)?;
		let response = self.transport.post(url.as_str(), &payload).await?;
		Ok(response)
	}

	/// Attach a query signature when the [`Auth`] mode calls for it.
	fn authenticated_url(&self, auth: Auth, url: Url) -> Result<Url, AnchorClientError> {
		match auth {
			Auth::SignedUrl => {
				let signed = self.sign_empty()?;
				let signed_url = add_signature_to_url(&url, &self.account, &signed)?;
				Ok(signed_url)
			}
			_ => Ok(url),
		}
	}

	/// Build the wrapped `POST` body `{ "request": <fields> }`. For
	/// [`Auth::SignedBody`], `account` and the signed empty-payload envelope are
	/// merged into `<fields>` first.
	fn request_body(&self, auth: Auth, body: Option<Value>) -> Result<Vec<u8>, AnchorClientError> {
		let mut fields = match body {
			Some(Value::Object(map)) => map,
			_ => Map::new(),
		};

		if let Auth::SignedBody = auth {
			let signed = self.sign_empty()?;
			fields.insert("account".into(), Value::String(self.account.clone()));
			fields.insert(
				"signed".into(),
				json!({ "nonce": signed.nonce, "timestamp": signed.timestamp, "signature": signed.signature }),
			);
		}

		let envelope = json!({ "request": Value::Object(fields) });
		let bytes = serde_json::to_vec(&envelope)?;
		Ok(bytes)
	}

	fn sign_empty(&self) -> Result<Signed, AnchorClientError> {
		let params = SignParams::generate();
		let signed = sign_with(&self.signer, EMPTY, &params)?;
		Ok(signed)
	}
}

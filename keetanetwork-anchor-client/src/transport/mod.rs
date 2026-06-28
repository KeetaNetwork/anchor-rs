//! The pluggable HTTP surface anchors are reached over.
//!
//! The transport stays free of signing: callers attach credentials to the URL
//! or body with the core signing helpers.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use async_trait::async_trait;

use crate::error::TransportError;
use crate::marker::{MaybeSend, MaybeSync};

/// A completed HTTP response: the status code and raw body bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
	/// The HTTP status code.
	pub status: u16,
	/// The raw response body.
	pub body: Vec<u8>,
}

impl HttpResponse {
	/// Whether the status is in the 2xx success range.
	pub fn is_success(&self) -> bool {
		(200..300).contains(&self.status)
	}
}

/// A raw HTTP transport targeting a single anchor.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait AnchorHttpTransport: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Issue a `GET` for `url` and return the completed response.
	///
	/// # Errors
	///
	/// Returns [`TransportError::Request`] when the request cannot be sent or
	/// no response is received.
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError>;

	/// `POST` a JSON `body` to `url` and return the completed response.
	///
	/// # Errors
	///
	/// Returns [`TransportError::Request`] when the request cannot be sent or
	/// no response is received.
	async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, TransportError>;
}

/// Builds an [`AnchorHttpTransport`], letting callers bind a shared HTTP client
/// once and hand out transports without naming a concrete backend.
pub trait AnchorHttpTransportFactory: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Create a transport over the shared client.
	fn create(&self) -> Arc<dyn AnchorHttpTransport>;
}

#[cfg(feature = "http")]
pub use backend::{ReqwestTransport, ReqwestTransportFactory};

#[cfg(feature = "http")]
mod backend {
	use alloc::boxed::Box;
	use alloc::sync::Arc;
	use alloc::vec::Vec;

	use async_trait::async_trait;
	use reqwest::Client;

	use super::{AnchorHttpTransport, AnchorHttpTransportFactory, HttpResponse};
	use crate::error::TransportError;

	const ACCEPT_JSON: (&str, &str) = ("accept", "application/json");
	const CONTENT_TYPE_JSON: (&str, &str) = ("content-type", "application/json");

	/// Production [`AnchorHttpTransport`] over a shared `reqwest` client.
	#[derive(Clone, Debug)]
	pub struct ReqwestTransport {
		client: Client,
	}

	impl ReqwestTransport {
		/// Wrap a pre-built `reqwest` client.
		///
		/// The client is built by the caller so this constructor cannot panic
		/// on TLS-backend initialization.
		pub fn new(client: Client) -> Self {
			Self { client }
		}

		/// Build a transport over a default `reqwest` client.
		///
		/// # Errors
		///
		/// Returns [`TransportError::Request`] when the client cannot be built
		/// (e.g. TLS-backend initialization failure).
		pub fn try_default() -> Result<Self, TransportError> {
			let client = Client::builder().build()?;
			Ok(Self::new(client))
		}
	}

	async fn into_response(response: reqwest::Response) -> Result<HttpResponse, TransportError> {
		let status = response.status().as_u16();
		let bytes = response.bytes().await?;
		let body: Vec<u8> = bytes.to_vec();
		Ok(HttpResponse { status, body })
	}

	#[cfg_attr(not(target_family = "wasm"), async_trait)]
	#[cfg_attr(target_family = "wasm", async_trait(?Send))]
	impl AnchorHttpTransport for ReqwestTransport {
		async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
			let request = self.client.get(url).header(ACCEPT_JSON.0, ACCEPT_JSON.1);
			let response = request.send().await?;
			into_response(response).await
		}

		async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, TransportError> {
			let payload = body.to_vec();
			let request = self
				.client
				.post(url)
				.header(CONTENT_TYPE_JSON.0, CONTENT_TYPE_JSON.1)
				.header(ACCEPT_JSON.0, ACCEPT_JSON.1)
				.body(payload);
			let response = request.send().await?;
			into_response(response).await
		}
	}

	/// Builds [`ReqwestTransport`]s over a shared `reqwest` client.
	#[derive(Clone, Debug)]
	pub struct ReqwestTransportFactory {
		client: Client,
	}

	impl ReqwestTransportFactory {
		/// A factory over the shared `client`.
		pub fn new(client: Client) -> Self {
			Self { client }
		}

		/// Build a factory over a default `reqwest` client.
		///
		/// # Errors
		///
		/// Returns [`TransportError::Request`] when the client cannot be built.
		pub fn try_default() -> Result<Self, TransportError> {
			let client = Client::builder().build()?;
			Ok(Self::new(client))
		}
	}

	impl AnchorHttpTransportFactory for ReqwestTransportFactory {
		fn create(&self) -> Arc<dyn AnchorHttpTransport> {
			Arc::new(ReqwestTransport::new(self.client.clone()))
		}
	}
}

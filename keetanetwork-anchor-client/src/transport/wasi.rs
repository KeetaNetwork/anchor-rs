//! WASI Preview 2 transport backend over `wstd`'s outbound `wasi:http` client.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::str::FromStr;

use async_trait::async_trait;
use wstd::http::{Body, Client, HeaderMap, Method, Request};

use super::{AnchorHttpTransport, AnchorHttpTransportFactory, HttpResponse, RetryAfter};
use crate::error::TransportError;

const ACCEPT_JSON: (&str, &str) = ("accept", "application/json");
const CONTENT_TYPE_JSON: (&str, &str) = ("content-type", "application/json");
const RETRY_AFTER: &str = "retry-after";

/// Reduce a `wstd`/`http` failure to a [`TransportError::Request`], matching the
/// `reqwest` backend's string-reason projection.
fn request_error(error: impl core::fmt::Display) -> TransportError {
	TransportError::Request { reason: error.to_string() }
}

/// The response's `Retry-After` header, parsed, when present and readable.
fn parse_retry_after(headers: &HeaderMap) -> Option<RetryAfter> {
	let header = headers.get(RETRY_AFTER)?;
	let value = header.to_str().ok()?;

	RetryAfter::from_str(value).ok()
}

/// Production [`AnchorHttpTransport`] over `wstd`'s outbound `wasi:http`.
#[derive(Clone, Debug, Default)]
pub struct WasiTransport {
	client: Client,
}

impl WasiTransport {
	/// Send `request`, then collect the status, body, and `Retry-After` hint.
	async fn send(&self, request: Request<Body>) -> Result<HttpResponse, TransportError> {
		let mut response = self.client.send(request).await.map_err(request_error)?;
		let status = response.status().as_u16();
		let retry_after = parse_retry_after(response.headers());
		let bytes = response
			.body_mut()
			.bytes_contents()
			.await
			.map_err(request_error)?;
		let body: Vec<u8> = bytes.to_vec();

		Ok(HttpResponse::new(status, body).with_retry_after(retry_after))
	}
}

#[async_trait(?Send)]
impl AnchorHttpTransport for WasiTransport {
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
		let request = Request::builder()
			.method(Method::GET)
			.uri(url)
			.header(ACCEPT_JSON.0, ACCEPT_JSON.1)
			.body(Body::empty())
			.map_err(request_error)?;

		let response = self.send(request).await?;
		Ok(response)
	}

	async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, TransportError> {
		let payload = Body::from(body.to_vec());
		let request = Request::builder()
			.method(Method::POST)
			.uri(url)
			.header(CONTENT_TYPE_JSON.0, CONTENT_TYPE_JSON.1)
			.header(ACCEPT_JSON.0, ACCEPT_JSON.1)
			.body(payload)
			.map_err(request_error)?;

		let response = self.send(request).await?;
		Ok(response)
	}
}

/// Builds [`WasiTransport`]s over `wstd`'s outbound `wasi:http`.
#[derive(Clone, Debug, Default)]
pub struct WasiTransportFactory;

impl AnchorHttpTransportFactory for WasiTransportFactory {
	fn create(&self) -> Arc<dyn AnchorHttpTransport> {
		Arc::new(WasiTransport::default())
	}
}

//! Host-shimmed HTTP transport and resilience runtime for the P1 core module.
//!
//! The networked KYC client runs inside the module; every outbound request and
//! every backoff sleep is delegated to a host import so each embedding supplies
//! its own HTTP stack and timer.

#![allow(clippy::arc_with_non_send_sync)]

use core::future::Future;
use core::pin::pin;
use core::str::FromStr;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use keetanetwork_anchor_client::{
	AnchorHttpTransport, HttpResponse, ResilienceRuntime, ResilientTransport, RetryAfter, TransportError,
};

// Host imports the embedding supplies. `fetch` performs the request described by
// the JSON at `(request_ptr, request_len)` and returns the length of the JSON
// response it has buffered; `take` copies that buffered response into guest
// memory at `response_ptr`; `sleep` blocks for `millis` milliseconds.
#[link(wasm_import_module = "keeta:anchor/host")]
extern "C" {
	fn keeta_anchor_host_fetch(request_ptr: u32, request_len: u32) -> u32;
	fn keeta_anchor_host_take(response_ptr: u32);
	fn keeta_anchor_host_sleep(millis: u64);
}

/// The request handed to the host: an HTTP `method`, an absolute `url`, and an
/// optional base64 `body`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostRequest<'request> {
	method: &'request str,
	url: &'request str,
	#[serde(skip_serializing_if = "Option::is_none")]
	body: Option<String>,
}

/// The response the host returns: an HTTP `status`, a base64 `body`, the raw
/// `retry_after` header value when present, and an `error` reason when the
/// request could not be completed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostResponse {
	#[serde(default)]
	status: u16,
	#[serde(default)]
	body: String,
	#[serde(default)]
	retry_after: Option<String>,
	#[serde(default)]
	error: Option<String>,
}

/// An [`AnchorHttpTransport`] over the host fetch import.
#[derive(Debug, Default)]
pub(super) struct HostTransport;

#[async_trait(?Send)]
impl AnchorHttpTransport for HostTransport {
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
		fetch("GET", url, None)
	}

	async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, TransportError> {
		fetch("POST", url, Some(body))
	}
}

/// A [`ResilienceRuntime`] over the host sleep import and the wasip1 clock.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct HostRuntime;

#[async_trait(?Send)]
impl ResilienceRuntime for HostRuntime {
	async fn sleep_ms(&self, millis: u64) {
		unsafe { keeta_anchor_host_sleep(millis) };
	}

	fn now_millis(&self) -> u64 {
		monotonic_millis()
	}
}

/// Block the guest for `millis` milliseconds through the host timer import.
///
/// Backs the share-KYC promise poll: the host sleep is synchronous, so an
/// `async` caller awaiting it resolves on the first poll under [`block_on`].
pub(super) fn host_sleep_ms(millis: u64) {
	unsafe { keeta_anchor_host_sleep(millis) };
}

/// The resilient host transport the KYC client runs on: the host fetch shim
/// wrapped in the shared retry/backoff policy driven by the host timer.
pub(super) fn host_transport() -> Arc<dyn AnchorHttpTransport> {
	let base: Arc<dyn AnchorHttpTransport> = Arc::new(HostTransport);
	Arc::new(ResilientTransport::new(base, HostRuntime))
}

/// Drive `future` to completion on the current thread.
///
/// Every await point resolves through a synchronous host import, so the future
/// is always ready on the first poll; the loop is a guard, not a spin wait.
pub(super) fn block_on<F>(future: F) -> F::Output
where
	F: Future,
{
	let mut future = pin!(future);
	let waker = noop_waker();
	let mut context = Context::from_waker(&waker);

	loop {
		match future.as_mut().poll(&mut context) {
			Poll::Ready(value) => return value,
			Poll::Pending => core::hint::spin_loop(),
		}
	}
}

/// Perform one request through the host shim and decode the response.
fn fetch(method: &str, url: &str, body: Option<&[u8]>) -> Result<HttpResponse, TransportError> {
	let request = HostRequest { method, url, body: body.map(|bytes| STANDARD.encode(bytes)) };
	let request_bytes = serde_json::to_vec(&request).map_err(request_error)?;
	let response_bytes = exchange(&request_bytes);
	let response: HostResponse = serde_json::from_slice(&response_bytes).map_err(request_error)?;

	if let Some(reason) = response.error {
		return Err(TransportError::Request { reason });
	}

	let body = decode_body(&response.body)?;
	let retry_after = response
		.retry_after
		.as_deref()
		.and_then(|value| RetryAfter::from_str(value).ok());

	Ok(HttpResponse::new(response.status, body).with_retry_after(retry_after))
}

/// Call the two-step host fetch protocol: request the response length, then copy
/// the buffered bytes into a guest-owned buffer.
fn exchange(request: &[u8]) -> Vec<u8> {
	let request_ptr = request.as_ptr() as u32;
	let request_len = request.len() as u32;
	let length = unsafe { keeta_anchor_host_fetch(request_ptr, request_len) } as usize;

	let mut response = vec![0u8; length];
	if length > 0 {
		unsafe { keeta_anchor_host_take(response.as_mut_ptr() as u32) };
	}

	response
}

/// Decode a base64 response body, projecting a decode failure to a transport
/// error. An empty body is an empty payload.
fn decode_body(encoded: &str) -> Result<Vec<u8>, TransportError> {
	if encoded.is_empty() {
		return Ok(Vec::new());
	}

	STANDARD
		.decode(encoded)
		.map_err(|error| TransportError::Request { reason: error.to_string() })
}

/// Project a JSON (de)serialization failure on the host boundary to a transport
/// error, matching how the other backends report a malformed exchange.
fn request_error(error: serde_json::Error) -> TransportError {
	TransportError::Request { reason: error.to_string() }
}

/// Monotonic milliseconds from a process-fixed origin, backed by the wasip1
/// clock through `std::time`.
fn monotonic_millis() -> u64 {
	use std::sync::OnceLock;
	use std::time::Instant;

	static ORIGIN: OnceLock<Instant> = OnceLock::new();
	ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// A waker that does nothing: [`block_on`] never parks, so wake-ups are unused.
fn noop_waker() -> Waker {
	const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
	const RAW: RawWaker = RawWaker::new(core::ptr::null(), &VTABLE);

	unsafe { Waker::from_raw(RAW) }
}

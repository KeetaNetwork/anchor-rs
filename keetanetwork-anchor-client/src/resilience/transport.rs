//! The resilience decorator: a transport wrapping another, adding rate-limit
//! pacing and retry/backoff while implementing the same [`AnchorHttpTransport`]
//! seam, so callers compose it transparently.

use alloc::boxed::Box;
use alloc::sync::Arc;

use async_trait::async_trait;
use spin::Mutex;

use super::error::ResilienceError;
use super::rate_limit::TokenBucket;
use super::retry::RetryPolicy;
use super::runtime::ResilienceRuntime;
use crate::error::TransportError;
use crate::transport::{AnchorHttpTransport, AnchorHttpTransportFactory, HttpResponse};

/// Wraps an [`AnchorHttpTransport`] with a [`RetryPolicy`] and an optional
/// per-transport token bucket.
#[derive(Debug)]
pub struct ResilientTransport<R> {
	inner: Arc<dyn AnchorHttpTransport>,
	runtime: R,
	retry: RetryPolicy,
	limiter: Option<Mutex<TokenBucket>>,
}

impl<R> ResilientTransport<R>
where
	R: ResilienceRuntime,
{
	/// Wrap `inner`, driven by `runtime`, with the default retry policy and no
	/// rate limit.
	pub fn new(inner: Arc<dyn AnchorHttpTransport>, runtime: R) -> Self {
		Self { inner, runtime, retry: RetryPolicy::default(), limiter: None }
	}

	/// Use `retry` in place of the default policy.
	#[must_use]
	pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
		self.retry = retry;
		self
	}

	/// Pace requests through a token bucket of `capacity` refilling at
	/// `refill_per_sec`.
	#[must_use]
	pub fn with_rate_limit(mut self, capacity: u32, refill_per_sec: u32) -> Self {
		let bucket = TokenBucket::new(capacity, refill_per_sec, self.runtime.now_millis());
		self.limiter = Some(Mutex::new(bucket));
		self
	}

	/// Wait for a rate-limit token, sleeping until one is available.
	async fn acquire(&self) -> Result<(), TransportError> {
		let Some(limiter) = self.limiter.as_ref() else {
			return Ok(());
		};

		loop {
			let now = self.runtime.now_millis();
			let wait = match limiter.lock().try_take(now) {
				Ok(()) => return Ok(()),
				Err(wait) => wait,
			};

			if wait == u64::MAX {
				return Err(TransportError::from(ResilienceError::RateLimited { retry_after_ms: wait }));
			}

			self.runtime.sleep_ms(wait).await;
		}
	}
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl<R> AnchorHttpTransport for ResilientTransport<R>
where
	R: ResilienceRuntime,
{
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
		self.acquire().await?;
		self.retry.run(&self.runtime, || self.inner.get(url)).await
	}

	async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, TransportError> {
		self.acquire().await?;
		self.retry
			.run(&self.runtime, || self.inner.post(url, body))
			.await
	}
}

/// Builds [`ResilientTransport`]s over an inner factory, applying the same retry
/// policy and rate limit to each created transport.
#[derive(Debug)]
pub struct ResilientTransportFactory<R> {
	inner: Arc<dyn AnchorHttpTransportFactory>,
	runtime: R,
	retry: RetryPolicy,
	rate_limit: Option<(u32, u32)>,
}

impl<R> ResilientTransportFactory<R>
where
	R: ResilienceRuntime + Clone + 'static,
{
	/// A factory wrapping `inner`, driven by `runtime`, with the default retry
	/// policy and no rate limit.
	pub fn new(inner: Arc<dyn AnchorHttpTransportFactory>, runtime: R) -> Self {
		Self { inner, runtime, retry: RetryPolicy::default(), rate_limit: None }
	}

	/// Use `retry` in place of the default policy.
	#[must_use]
	pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
		self.retry = retry;
		self
	}

	/// Pace each created transport through a token bucket of `capacity`
	/// refilling at `refill_per_sec`.
	#[must_use]
	pub fn with_rate_limit(mut self, capacity: u32, refill_per_sec: u32) -> Self {
		self.rate_limit = Some((capacity, refill_per_sec));
		self
	}
}

impl<R> AnchorHttpTransportFactory for ResilientTransportFactory<R>
where
	R: ResilienceRuntime + Clone + 'static,
{
	fn create(&self) -> Arc<dyn AnchorHttpTransport> {
		let mut transport = ResilientTransport::new(self.inner.create(), self.runtime.clone()).with_retry(self.retry);
		if let Some((capacity, refill_per_sec)) = self.rate_limit {
			transport = transport.with_rate_limit(capacity, refill_per_sec);
		}

		Arc::new(transport)
	}
}

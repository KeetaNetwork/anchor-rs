//! The resilience decorator over a scripted in-memory transport: retries
//! transient faults and retryable statuses, honors a `Retry-After` hint, paces
//! through the token bucket, and surfaces terminal outcomes. A virtual-clock
//! runtime advances time on `sleep`, so the suite is exact and never waits.

#![cfg(feature = "resilience")]

use std::error::Error;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use keetanetwork_anchor_client::{
	AnchorHttpTransport, Backoff, HttpResponse, ResilienceError, ResilienceRuntime, ResilientTransport, RetryAfter,
	RetryPolicy, TransportError,
};

type TestResult = Result<(), Box<dyn Error>>;

/// The URL every scenario drives; the scripted transport ignores it.
const URL: &str = "https://anchor.test/op";

/// A runtime whose clock only moves when work sleeps: deterministic and instant.
#[derive(Clone, Debug, Default)]
struct VirtualRuntime {
	now_ms: Arc<AtomicU64>,
}

impl VirtualRuntime {
	fn elapsed_ms(&self) -> u64 {
		self.now_ms.load(Ordering::SeqCst)
	}
}

#[async_trait]
impl ResilienceRuntime for VirtualRuntime {
	async fn sleep_ms(&self, millis: u64) {
		self.now_ms.fetch_add(millis, Ordering::SeqCst);
	}

	fn now_millis(&self) -> u64 {
		self.now_ms.load(Ordering::SeqCst)
	}
}

/// One scripted transport response.
#[derive(Clone, Debug)]
enum Step {
	/// The request could not be sent (a transient transport fault).
	Fail,
	/// A terminal, non-retryable transport fault.
	Terminal,
	/// A completed response with `status` and an optional `Retry-After`.
	Respond(u16, Option<RetryAfter>),
}

/// A transport that replays `steps` by call index, repeating the last step.
#[derive(Debug)]
struct ScriptedTransport {
	calls: AtomicU32,
	steps: Vec<Step>,
}

impl ScriptedTransport {
	fn new(steps: Vec<Step>) -> Arc<Self> {
		Arc::new(Self { calls: AtomicU32::new(0), steps })
	}

	fn calls(&self) -> u32 {
		self.calls.load(Ordering::SeqCst)
	}

	fn next(&self) -> Result<HttpResponse, TransportError> {
		let index = self.calls.fetch_add(1, Ordering::SeqCst) as usize;
		let step = self.steps.get(index).or_else(|| self.steps.last()).cloned();

		match step {
			Some(Step::Respond(status, retry_after)) => {
				Ok(HttpResponse::new(status, Vec::new()).with_retry_after(retry_after))
			}
			Some(Step::Terminal) => Err(TransportError::InvalidUrl { reason: "not a url".into() }),
			_ => Err(TransportError::Request { reason: "transport unavailable".into() }),
		}
	}
}

#[async_trait]
impl AnchorHttpTransport for ScriptedTransport {
	async fn get(&self, _url: &str) -> Result<HttpResponse, TransportError> {
		self.next()
	}

	async fn post(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse, TransportError> {
		self.next()
	}
}

/// Declares a resilient transport over a scripted transport and virtual clock.
struct Scenario {
	steps: Vec<Step>,
	retry: Option<RetryPolicy>,
	rate_limit: Option<(u32, u32)>,
}

impl Scenario {
	/// A scenario replaying `steps`, with the default policy and no rate limit.
	fn new(steps: Vec<Step>) -> Self {
		Self { steps, retry: None, rate_limit: None }
	}

	/// Cap retries through a backoff with `max_retries`.
	fn max_retries(self, max_retries: u32) -> Self {
		let backoff = Backoff::default().with_max_retries(max_retries);
		self.retry(RetryPolicy::default().with_backoff(backoff))
	}

	/// Use `policy` in place of the default.
	fn retry(mut self, policy: RetryPolicy) -> Self {
		self.retry = Some(policy);
		self
	}

	/// Pace requests through a token bucket of `capacity` refilling at `refill`.
	fn rate_limit(mut self, capacity: u32, refill: u32) -> Self {
		self.rate_limit = Some((capacity, refill));
		self
	}

	/// Wire the scripted transport, clock, and decorator into a live harness.
	fn build(self) -> Harness {
		let inner = ScriptedTransport::new(self.steps);
		let runtime = VirtualRuntime::default();

		let mut resilient = ResilientTransport::new(inner.clone(), runtime.clone());
		if let Some(policy) = self.retry {
			resilient = resilient.with_retry(policy);
		}
		if let Some((capacity, refill)) = self.rate_limit {
			resilient = resilient.with_rate_limit(capacity, refill);
		}

		Harness { inner, runtime, resilient }
	}
}

/// A built scenario: the decorator under test, plus handles to assert the
/// underlying call count and the time the virtual clock advanced.
struct Harness {
	inner: Arc<ScriptedTransport>,
	runtime: VirtualRuntime,
	resilient: ResilientTransport<VirtualRuntime>,
}

impl Harness {
	/// Drive one request through the decorator.
	async fn get(&self) -> Result<HttpResponse, TransportError> {
		self.resilient.get(URL).await
	}

	/// Requests that reached the underlying transport.
	fn calls(&self) -> u32 {
		self.inner.calls()
	}

	/// Milliseconds the virtual clock advanced (time slept).
	fn elapsed_ms(&self) -> u64 {
		self.runtime.elapsed_ms()
	}
}

#[tokio::test]
async fn transient_faults_are_retried_until_success() -> TestResult {
	let harness = Scenario::new(vec![Step::Fail, Step::Fail, Step::Respond(200, None)]).build();

	let response = harness.get().await?;
	assert_eq!(response.status, 200, "the decorator must return the eventual success");
	assert_eq!(harness.calls(), 3, "the decorator must retry until the call succeeds");
	assert!(harness.elapsed_ms() > 0, "retrying must consume backoff time");
	Ok(())
}

#[tokio::test]
async fn the_retry_budget_is_bounded_by_max_retries() -> TestResult {
	let harness = Scenario::new(vec![Step::Fail]).max_retries(2).build();

	let outcome = harness.get().await;
	assert!(
		matches!(&outcome, Err(TransportError::Resilience { source }) if matches!(**source, ResilienceError::RetryExhausted { attempts: 3, .. })),
		"exhaustion must report the attempt count, got {outcome:?}"
	);
	assert_eq!(harness.calls(), 3, "max_retries of 2 must yield three attempts");
	Ok(())
}

#[tokio::test]
async fn a_terminal_transport_error_is_not_retried() -> TestResult {
	let harness = Scenario::new(vec![Step::Terminal]).build();

	let outcome = harness.get().await;
	assert!(matches!(outcome, Err(TransportError::InvalidUrl { .. })), "a non-transient error must surface unchanged");
	assert_eq!(harness.calls(), 1, "a terminal error must not be retried");
	Ok(())
}

#[tokio::test]
async fn a_retry_after_header_paces_the_next_attempt() -> TestResult {
	let steps = vec![Step::Respond(503, Some(RetryAfter::Seconds(2))), Step::Respond(200, None)];
	let harness = Scenario::new(steps).build();

	let response = harness.get().await?;
	assert_eq!(response.status, 200, "the decorator must retry past the 503 to success");
	assert_eq!(harness.calls(), 2, "a single retry must follow the 503");
	assert!(harness.elapsed_ms() >= 2_000, "the Retry-After hint of 2s must be honored");
	Ok(())
}

#[tokio::test]
async fn an_exhausted_retryable_status_is_handed_back() -> TestResult {
	let harness = Scenario::new(vec![Step::Respond(503, None)])
		.max_retries(1)
		.build();

	let response = harness.get().await?;
	assert_eq!(response.status, 503, "a budget spent on a retryable status returns that response");
	assert_eq!(harness.calls(), 2, "max_retries of 1 must yield two attempts");
	Ok(())
}

#[tokio::test]
async fn the_token_bucket_paces_successive_requests() -> TestResult {
	let harness = Scenario::new(vec![Step::Respond(200, None)])
		.rate_limit(1, 1)
		.build();

	for _ in 0..3 {
		let response = harness.get().await?;
		assert_eq!(response.status, 200, "every paced request still completes");
	}

	assert_eq!(harness.elapsed_ms(), 2_000, "a 1-token, 1/sec bucket spaces three calls by two seconds");
	assert_eq!(harness.calls(), 3, "pacing must not drop requests");
	Ok(())
}

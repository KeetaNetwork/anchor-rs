//! The async seam the resilience layer needs: sleeping (for backoff and rate
//! pacing) and a monotonic clock (for budgets and bucket refills), behind
//! [`ResilienceRuntime`] so the policies never name a concrete executor.

use alloc::boxed::Box;

use async_trait::async_trait;

use crate::marker::{MaybeSend, MaybeSync};

/// WASI targets carry `std`; name it explicitly under `no_std` so the monotonic
/// clock can use `std::time`.
#[cfg(all(not(feature = "std"), target_os = "wasi"))]
extern crate std;

/// Monotonic milliseconds from a process-fixed origin, backed by `std::time`.
#[cfg(any(feature = "std", target_os = "wasi"))]
fn monotonic_millis() -> u64 {
	use std::sync::OnceLock;
	use std::time::Instant;

	static ORIGIN: OnceLock<Instant> = OnceLock::new();
	ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Asynchronous services a resilience policy needs: sleeping and a monotonic
/// clock.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait ResilienceRuntime: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Sleep for `millis` milliseconds.
	async fn sleep_ms(&self, millis: u64);

	/// Monotonic milliseconds from an arbitrary, runtime-fixed origin.
	fn now_millis(&self) -> u64;
}

/// Production [`ResilienceRuntime`] backed by `tokio`.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioRuntime;

#[cfg(feature = "std")]
#[async_trait]
impl ResilienceRuntime for TokioRuntime {
	async fn sleep_ms(&self, millis: u64) {
		tokio::time::sleep(core::time::Duration::from_millis(millis)).await;
	}

	fn now_millis(&self) -> u64 {
		monotonic_millis()
	}
}

/// Production [`ResilienceRuntime`] for the browser: `setTimeout` sleeps and
/// `performance.now()` for the monotonic clock.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct WasmRuntime;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[async_trait(?Send)]
impl ResilienceRuntime for WasmRuntime {
	async fn sleep_ms(&self, millis: u64) {
		let millis = u32::try_from(millis).unwrap_or(u32::MAX);
		gloo_timers::future::TimeoutFuture::new(millis).await;
	}

	fn now_millis(&self) -> u64 {
		web_sys::window()
			.and_then(|window| window.performance())
			.map(|performance| performance.now())
			.unwrap_or_else(js_sys::Date::now) as u64
	}
}

/// Production [`ResilienceRuntime`] for WASI Preview 2: `wstd` timers and the
/// wasip2 monotonic clock (via `std::time`).
#[cfg(target_os = "wasi")]
#[derive(Clone, Copy, Debug, Default)]
pub struct WasiRuntime;

#[cfg(target_os = "wasi")]
#[async_trait(?Send)]
impl ResilienceRuntime for WasiRuntime {
	async fn sleep_ms(&self, millis: u64) {
		wstd::task::sleep(wstd::time::Duration::from_millis(millis)).await;
	}

	fn now_millis(&self) -> u64 {
		monotonic_millis()
	}
}

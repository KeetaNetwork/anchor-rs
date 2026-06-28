//! Client-side resilience: retry/backoff, token-bucket rate limiting, and
//! lease budgets, applied as a transport decorator over an
//! [`AnchorHttpTransport`](crate::transport::AnchorHttpTransport).

mod backoff;
mod error;
mod lease;
mod rate_limit;
mod retry;
mod runtime;
mod transport;

pub use backoff::{Backoff, Jitter};
pub use error::{retryable_status, transient, ResilienceError};
pub use lease::{lease_work_budget_ms, DEFAULT_LEASE_MS};
pub use rate_limit::TokenBucket;
pub use retry::RetryPolicy;
pub use runtime::ResilienceRuntime;
pub use transport::{ResilientTransport, ResilientTransportFactory};

#[cfg(feature = "std")]
pub use runtime::TokioRuntime;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use runtime::WasmRuntime;

#[cfg(target_os = "wasi")]
pub use runtime::WasiRuntime;

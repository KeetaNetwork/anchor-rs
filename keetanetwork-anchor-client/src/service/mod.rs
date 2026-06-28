//! The shared service layer every per-service client builds on: endpoint
//! templating, response decoding, and signed request execution.
//!
//! A service client declares only its service name, selection criteria,
//! provider parsing, and per-operation auth modes; this layer owns the rest.

mod endpoint;
mod envelope;

pub use endpoint::Endpoint;
pub use envelope::AnchorOutcome;

#[cfg(feature = "http")]
mod caller;
#[cfg(feature = "http")]
mod context;

#[cfg(feature = "http")]
pub use caller::{AnchorCaller, Auth, Call, Method};
#[cfg(feature = "http")]
pub use context::AnchorContext;

//! The shared service layer every per-service client builds on: endpoint
//! templating, response decoding, and signed request execution.
//!
//! A service client declares only its service name, selection criteria,
//! provider parsing, and per-operation auth modes; this layer owns the rest.

mod endpoint;
mod envelope;

pub use endpoint::Endpoint;
pub use envelope::AnchorOutcome;

mod caller;
mod context;

pub use caller::{AnchorCaller, Auth, Call, Method};
pub use context::AnchorContext;

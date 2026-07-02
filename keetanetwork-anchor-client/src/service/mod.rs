//! The shared service layer every per-service client builds on: endpoint
//! templating, response decoding, and signed request execution.

mod endpoint;
mod envelope;

pub use endpoint::Endpoint;
pub use envelope::AnchorOutcome;

#[cfg(feature = "asset")]
pub(crate) use envelope::pending_delay;

mod caller;
mod context;

pub use caller::{AnchorCaller, Auth, BodyEnvelope, Call, Method};
pub use context::AnchorContext;

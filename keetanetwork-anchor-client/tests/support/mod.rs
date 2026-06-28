//! Test-only drivers for the TypeScript interop harnesses.
//!
//! A shared [`driver`] spawns a harness entry (`node node-harness/dist/<name>.js`)
//! and exchanges one JSON object per line; each domain harness
//! ([`SigningHarness`], [`KycHarness`]) exposes only the commands relevant to
//! it.

#![allow(dead_code, unused_imports)]

mod driver;
mod kyc;
mod signing;

pub use driver::HarnessError;
pub use kyc::{signed_request_body, KycAnchor, KycHarness, PublishedRoot};
pub use signing::{HarnessSignature, SigningHarness};

//! Test-only drivers for the TypeScript interop harnesses.
//!
//! A shared [`driver`] spawns a harness entry (`node node-harness/dist/<name>.js`)
//! and exchanges one JSON object per line; each domain harness ([`SigningHarness`],
//! [`KycHarness`]) exposes only the commands relevant to
//! it.

#![allow(dead_code, unused_imports)]

mod asset;
mod driver;
mod kyc;
mod sharable;
mod signing;

pub use asset::{AssetAnchor, AssetHarness};
pub use driver::HarnessError;
pub use kyc::{
	attribute_cases, decoded_to_value, issue_attributes, signed_request_body, AttributeCase, KycAnchor, KycHarness,
	PublishedChain, PublishedRoot, SUBJECT_SEED,
};
pub use sharable::SharableHarness;
pub use signing::{HarnessSignature, SigningHarness};

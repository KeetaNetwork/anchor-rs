//! WASI Preview 1 core module: anchor's KYC surface on the shared node
//! `handle + last_error` C ABI.

use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_client_wasi::fail;

mod asset_movement;
mod encrypted_container;
mod kyc;
mod kyc_certificate;
mod node;
mod sharable;
mod transport;

/// Reduce a registry lookup to its value, recording the coded error on the
/// shared `last_error` slot and yielding `None` for an unknown handle.
fn ok_or_fail<R>(result: Result<R, CodedError>) -> Option<R> {
	match result {
		Ok(value) => Some(value),
		Err(error) => {
			fail(error);
			None
		}
	}
}

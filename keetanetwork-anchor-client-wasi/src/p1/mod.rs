//! WASI Preview 1 core module: anchor's KYC surface on the shared node
//! `handle + last_error` C ABI.

use core::str::FromStr;

use std::sync::Arc;

use keetanetwork_account::GenericAccount;
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

/// Parse a textual `keeta_…` address into a shared typed account, recording an
/// `INVALID_ACCOUNT` error and returning `None` on a malformed address.
fn parse_account(address: &str) -> Option<Arc<GenericAccount>> {
	match GenericAccount::from_str(address) {
		Ok(account) => Some(Arc::new(account)),
		Err(error) => {
			fail(CodedError::new("INVALID_ACCOUNT", error.to_string()));
			None
		}
	}
}

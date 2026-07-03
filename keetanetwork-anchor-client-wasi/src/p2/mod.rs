//! WASI Preview 2 component: the `crypto` primitives plus the networked KYC `client`.
//!
//! The generated bindings, the `Component` that fulfills the world, and the
//! shared helpers live here; each exported resource has its own module.

#![allow(clippy::arc_with_non_send_sync)]

mod account;
mod asset_movement;
mod certificate;
mod encrypted_container;
mod kyc;
mod kyc_certificate;
mod sharable;

use core::future::Future;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_bindings::error::CodedError as CoreCodedError;
use keetanetwork_anchor_client::keetanetwork_client::{
	ClientConfig, KeetaClient, RepPart, WasiRuntime as NodeWasiRuntime, WasiTransportFactory,
};
use keetanetwork_anchor_client::AnchorClientError;
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use num_bigint::BigInt;
use wstd::runtime::block_on;

wit_bindgen::generate!({
	world: "keeta-anchor-kyc",
	path: "wit",
	// The world re-exports the vendored `keeta:client` `crypto` interface and
	// `use`s its `types`, so generate bindings for those foreign interfaces too.
	generate_all,
});

use account::AccountResource;
use certificate::CertificateResource;
use exports::keeta::client::crypto::{AccountBorrow, CertificateBorrow};
use keeta::client::types::CodedError;

/// The component fulfilling every exported interface of the world. Each resource
/// module binds it to the resource backing its interface.
struct Component;

/// An erased Keeta account shared by reference across the `crypto` boundary.
type AccountRef = Arc<GenericAccount>;

/// Multiply Unix `seconds` into milliseconds for the millisecond-based cores,
/// rejecting a value that would overflow.
fn seconds_to_millis(seconds: i64) -> Result<i64, CodedError> {
	seconds
		.checked_mul(1000)
		.ok_or_else(|| CodedError { code: "INVALID_DATE".into(), message: "unix seconds out of range".into() })
}

/// Clone each borrowed account out as a shared reference for the container ops.
fn collect_accounts(borrows: &[AccountBorrow<'_>]) -> Vec<AccountRef> {
	borrows
		.iter()
		.map(|borrow| Arc::clone(&borrow.get::<AccountResource>().account))
		.collect()
}

/// View a resolved principal set as an optional slice: an empty set is `None`
/// (plaintext or no-principal decode), matching the core's optionality.
fn optional_slice(principals: &[AccountRef]) -> Option<&[AccountRef]> {
	match principals.is_empty() {
		true => None,
		false => Some(principals),
	}
}

/// Clone each borrowed base certificate out for the chain evaluator.
fn collect_certificates(borrows: &[CertificateBorrow<'_>]) -> Vec<X509Certificate> {
	borrows
		.iter()
		.map(|borrow| borrow.get::<CertificateResource>().certificate.clone())
		.collect()
}

/// An anonymous single-representative node client targeting `node_url` over
/// the node client's `wasi:http` transport, keyed by its URL (no account).
fn node_client(node_url: &str) -> KeetaClient {
	let part = RepPart { key: node_url.to_owned(), url: node_url.to_owned(), weight: BigInt::from(1u8) };
	KeetaClient::with_parts(
		[part],
		Arc::new(WasiTransportFactory),
		Arc::new(NodeWasiRuntime),
		ClientConfig::default(),
		true,
	)
}

/// Drive an async client call to completion on the `wstd` reactor, projecting
/// its error to the WIT boundary type.
fn run<T>(future: impl Future<Output = Result<T, AnchorClientError>>) -> Result<T, CodedError> {
	block_on(future).map_err(CodedError::from)
}

impl From<AnchorClientError> for CodedError {
	fn from(error: AnchorClientError) -> Self {
		Self { code: error.code().into(), message: error.to_string() }
	}
}

impl From<CoreCodedError> for CodedError {
	fn from(error: CoreCodedError) -> Self {
		Self { code: error.code, message: error.message }
	}
}

export!(Component);

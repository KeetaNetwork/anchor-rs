//! The KYC leaf certificate surface of the P1 core module.
//!
//! Account and base-certificate handles are reused from the node core module's
//! `keeta_account_*` / `keeta_certificate_*` registries (resolved here through
//! its public [`account`]/[`certificate`] resolvers and produced through
//! [`store_certificate`]). This module keeps only the KYC leaf registry and
//! exposes `keeta_kyc_certificate_*` on the shared `handle + last_error` ABI.

use core::cell::RefCell;

use std::collections::BTreeMap;

use keetanetwork_anchor::certificates::KycCertificate;
use keetanetwork_anchor_bindings::certificate as cert_ops;
use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_client_wasi::{account, bytes_in, bytes_result, certificate, fail, store_certificate, string_in};
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use serde::Serialize;

thread_local! {
	static LEAVES: RefCell<Leaves> = RefCell::new(Leaves::default());
}

/// The live KYC leaf certificates, each under a monotonically increasing handle.
#[derive(Default)]
struct Leaves {
	next: i32,
	certificates: BTreeMap<i32, KycCertificate>,
}

/// Store `certificate` under a fresh handle and return it.
fn store_leaf(certificate: KycCertificate) -> i32 {
	LEAVES.with_borrow_mut(|leaves| {
		leaves.next += 1;
		let handle = leaves.next;
		leaves.certificates.insert(handle, certificate);
		handle
	})
}

/// Resolve `handle` to a clone of its leaf, recording an `INVALID_HANDLE` error
/// when unknown.
fn leaf(handle: i32) -> Option<KycCertificate> {
	let value = LEAVES.with_borrow(|leaves| leaves.certificates.get(&handle).cloned());
	if value.is_none() {
		fail(CodedError::new("INVALID_HANDLE", "unknown kyc-certificate handle"));
	}

	value
}

/// Parse a PEM-encoded KYC leaf certificate; returns a leaf handle (`0` on
/// error; see the last error).
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_certificate_parse(ptr: i32, len: i32) -> i32 {
	let Some(pem) = (unsafe { string_in(ptr, len) }) else {
		return 0;
	};

	match cert_ops::from_pem(&pem) {
		Ok(certificate) => store_leaf(certificate),
		Err(error) => fail(error),
	}
}

/// The leaf's base certificate as a fresh `keeta_certificate_*` handle (`0` on
/// an unknown leaf handle).
#[no_mangle]
pub extern "C" fn keeta_kyc_certificate_base(handle: i32) -> i32 {
	match leaf(handle) {
		Some(certificate) => store_certificate(certificate.to_x509().clone()),
		None => 0,
	}
}

/// Whether the leaf is valid at `unix_millis`: `1` valid, `0` invalid, `-1` on
/// error (an unknown handle or out-of-range moment; see the last error).
#[no_mangle]
pub extern "C" fn keeta_kyc_certificate_valid_at(handle: i32, unix_millis: i64) -> i32 {
	let Some(certificate) = leaf(handle) else {
		return -1;
	};

	match cert_ops::valid_at(&certificate, unix_millis) {
		Ok(true) => 1,
		Ok(false) => 0,
		Err(error) => {
			fail(error);
			-1
		}
	}
}

/// Whether the leaf chains to one of `roots` at `unix_millis`, bridged by
/// `intermediates`; both buffers are little-endian `i32` `keeta_certificate_*`
/// handles. Returns `1`/`0`/`-1` (error; see the last error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_certificate_verify(
	handle: i32,
	roots_ptr: i32,
	roots_len: i32,
	intermediates_ptr: i32,
	intermediates_len: i32,
	unix_millis: i64,
) -> i32 {
	let Some(certificate) = leaf(handle) else {
		return -1;
	};
	let Some(roots) = (unsafe { resolve_certificates(roots_ptr, roots_len) }) else {
		return -1;
	};
	let Some(intermediates) = (unsafe { resolve_certificates(intermediates_ptr, intermediates_len) }) else {
		return -1;
	};

	match cert_ops::verify(&certificate, &roots, &intermediates, unix_millis) {
		Ok(true) => 1,
		Ok(false) => 0,
		Err(error) => {
			fail(error);
			-1
		}
	}
}

/// The leaf's KYC attributes as a JSON array of `{ name, sensitive }` records;
/// returns a bytes handle (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_kyc_certificate_attributes(handle: i32) -> i32 {
	let Some(certificate) = leaf(handle) else {
		return 0;
	};

	let listed: Vec<AttributeDto> = cert_ops::attributes(&certificate)
		.into_iter()
		.map(|(name, sensitive)| AttributeDto { name, sensitive })
		.collect();

	bytes_result(serde_json::to_vec(&listed).map_err(|error| CodedError::new("ENCODE", error.to_string())))
}

/// The plain (unencrypted) value of attribute `name`; returns a bytes handle
/// (`0` on error).
///
/// # Safety
///
/// `(name_ptr, name_len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_certificate_plain_attribute(handle: i32, name_ptr: i32, name_len: i32) -> i32 {
	let Some(certificate) = leaf(handle) else {
		return 0;
	};
	let Some(name) = (unsafe { string_in(name_ptr, name_len) }) else {
		return 0;
	};

	bytes_result(cert_ops::plain_attribute(&certificate, &name))
}

/// The decrypted value of sensitive attribute `name`, using the account
/// `account_handle` (from the shared `keeta_account_*` registry); returns a
/// bytes handle (`0` on error).
///
/// # Safety
///
/// `(name_ptr, name_len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_certificate_decrypt_attribute(
	handle: i32,
	name_ptr: i32,
	name_len: i32,
	account_handle: i32,
) -> i32 {
	let Some(certificate) = leaf(handle) else {
		return 0;
	};
	let Some(name) = (unsafe { string_in(name_ptr, name_len) }) else {
		return 0;
	};
	let Some(account) = account(account_handle) else {
		return 0;
	};

	bytes_result(cert_ops::decrypt_attribute_with_account(&certificate, &name, &account))
}

/// Release a KYC leaf handle, ignoring an unknown one.
#[no_mangle]
pub extern "C" fn keeta_kyc_certificate_free(handle: i32) {
	LEAVES.with_borrow_mut(|leaves| leaves.certificates.remove(&handle));
}

/// Read a `(ptr, len)` buffer of little-endian `i32` certificate handles and
/// resolve each through the shared certificate registry.
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable guest buffer.
unsafe fn resolve_certificates(ptr: i32, len: i32) -> Option<Vec<X509Certificate>> {
	let bytes = unsafe { bytes_in(ptr, len) };
	if !bytes.len().is_multiple_of(4) {
		fail(CodedError::new("INVALID_HANDLE_LIST", "handle list must be 4-byte aligned"));
		return None;
	}

	bytes
		.chunks_exact(4)
		.map(|chunk| certificate(i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
		.collect()
}

/// One KYC attribute: its OID `name` and whether its value is `sensitive`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttributeDto {
	name: String,
	sensitive: bool,
}

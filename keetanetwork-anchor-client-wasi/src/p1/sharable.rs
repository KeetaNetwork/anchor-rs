//! The sharable certificate-attributes surface of the P1 core module.
//!
//! A sharable bundle seals a selected subset of a leaf's attributes for a
//! recipient set. Leaf, account, and base-certificate handles are reused from
//! the sibling KYC-certificate and container registries and the node core
//! module's shared `keeta_account_*` registry.

use core::cell::RefCell;
use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use keetanetwork_anchor::sharable_attributes::{ExternalBlobs, SharableCertificateAttributes};
use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_anchor_bindings::registry::HandleRegistry;
use keetanetwork_anchor_bindings::sharable_attributes as sharable_ops;
use keetanetwork_bindings::x509::certificate_pem;
use keetanetwork_client_wasi::{account, bytes_in, bytes_result, fail, string_in};
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use serde::Serialize;

use crate::p1::encrypted_container::resolve_accounts;
use crate::p1::kyc_certificate::{resolve_certificates, store_leaf, with_leaf};
use crate::p1::ok_or_fail;

thread_local! {
	static SHARABLE: RefCell<HandleRegistry<SharableCertificateAttributes>> =
		const { RefCell::new(HandleRegistry::new("sharable-attributes")) };
}

/// Store `bundle` under a fresh handle and return it.
fn store(bundle: SharableCertificateAttributes) -> i32 {
	SHARABLE.with_borrow_mut(|state| state.store(bundle))
}

/// Run `body` against the bundle at `handle`, recording an `INVALID_HANDLE`
/// error and yielding `None` when the handle is unknown.
fn with_bundle<R>(handle: i32, body: impl FnOnce(&SharableCertificateAttributes) -> R) -> Option<R> {
	ok_or_fail(SHARABLE.with_borrow(|state| state.with(handle, body)))
}

/// Run `body` against the mutable bundle at `handle`, recording an
/// `INVALID_HANDLE` error and yielding `None` when the handle is unknown.
fn with_bundle_mut<R>(handle: i32, body: impl FnOnce(&mut SharableCertificateAttributes) -> R) -> Option<R> {
	ok_or_fail(SHARABLE.with_borrow_mut(|state| state.with_mut(handle, body)))
}

/// Build a sharable bundle from the leaf `certificate_handle`, proving or
/// copying each attribute in the JSON string array at `(names_ptr, names_len)`
/// with the subject account `subject_handle` and bridging with the base
/// certificate handle list at `(intermediates_ptr, intermediates_len)`. Returns
/// a bundle handle (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_from_certificate(
	certificate_handle: i32,
	subject_handle: i32,
	intermediates_ptr: i32,
	intermediates_len: i32,
	names_ptr: i32,
	names_len: i32,
) -> i32 {
	let Some(subject) = account(subject_handle) else {
		return 0;
	};
	let Some(intermediates) = (unsafe { resolve_certificates(intermediates_ptr, intermediates_len) }) else {
		return 0;
	};
	let Some(names) = (unsafe { decode_names(names_ptr, names_len) }) else {
		return 0;
	};

	let outcome = with_leaf(certificate_handle, |certificate| {
		sharable_ops::from_certificate(certificate, &subject, &intermediates, &names)
	});
	match outcome {
		Some(Ok(bundle)) => store(bundle),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// Build a sharable bundle like [`keeta_sharable_from_certificate`],
/// additionally ingesting the caller-fetched blobs in the JSON object: each named
/// attribute's discovered reference with a supplied blob is decrypted with the
/// subject, digest-verified, and inlined.
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_from_certificate_with_references(
	certificate_handle: i32,
	subject_handle: i32,
	intermediates_ptr: i32,
	intermediates_len: i32,
	names_ptr: i32,
	names_len: i32,
	blobs_ptr: i32,
	blobs_len: i32,
) -> i32 {
	let Some(subject) = account(subject_handle) else {
		return 0;
	};
	let Some(intermediates) = (unsafe { resolve_certificates(intermediates_ptr, intermediates_len) }) else {
		return 0;
	};
	let Some(names) = (unsafe { decode_names(names_ptr, names_len) }) else {
		return 0;
	};
	let Some(blobs) = (unsafe { decode_blobs(blobs_ptr, blobs_len) }) else {
		return 0;
	};

	let outcome = with_leaf(certificate_handle, |certificate| {
		sharable_ops::from_certificate_with_references(certificate, &subject, &intermediates, &names, blobs)
	});
	match outcome {
		Some(Ok(bundle)) => store(bundle),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// Open a sharable bundle from the encoded container bytes at `(data_ptr,
/// data_len)`, resolving the principal handle list at `(principals_ptr,
/// principals_len)`. Returns a bundle handle (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_from_encoded(
	data_ptr: i32,
	data_len: i32,
	principals_ptr: i32,
	principals_len: i32,
) -> i32 {
	let data = unsafe { bytes_in(data_ptr, data_len) };
	let Some(principals) = (unsafe { resolve_accounts(principals_ptr, principals_len) }) else {
		return 0;
	};

	match sharable_ops::from_encoded(&data, &principals) {
		Ok(bundle) => store(bundle),
		Err(error) => fail(error),
	}
}

/// Open a sharable bundle from the PEM envelope at `(pem_ptr, pem_len)`,
/// resolving the principal handle list at `(principals_ptr, principals_len)`.
/// Returns a bundle handle (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_from_pem(
	pem_ptr: i32,
	pem_len: i32,
	principals_ptr: i32,
	principals_len: i32,
) -> i32 {
	let Some(pem) = (unsafe { string_in(pem_ptr, pem_len) }) else {
		return 0;
	};
	let Some(principals) = (unsafe { resolve_accounts(principals_ptr, principals_len) }) else {
		return 0;
	};

	match sharable_ops::from_pem(&pem, &principals) {
		Ok(bundle) => store(bundle),
		Err(error) => fail(error),
	}
}

/// Grant the principal handle list at `(principals_ptr, principals_len)` access:
/// `1` success, `-1` on error (see the last error).
///
/// # Safety
///
/// `(principals_ptr, principals_len)` MUST describe an initialized, readable
/// guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_grant_access(handle: i32, principals_ptr: i32, principals_len: i32) -> i32 {
	let Some(accounts) = (unsafe { resolve_accounts(principals_ptr, principals_len) }) else {
		return -1;
	};

	match with_bundle_mut(handle, |bundle| sharable_ops::grant_access(bundle, &accounts)) {
		Some(Ok(())) => 1,
		Some(Err(error)) => {
			fail(error);
			-1
		}
		None => -1,
	}
}

/// Revoke the account whose type-prefixed public key is at `(key_ptr, key_len)`:
/// `1` success, `-1` on error (see the last error).
///
/// # Safety
///
/// `(key_ptr, key_len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_revoke_access(handle: i32, key_ptr: i32, key_len: i32) -> i32 {
	let key = unsafe { bytes_in(key_ptr, key_len) };
	match with_bundle_mut(handle, |bundle| sharable_ops::revoke_access(bundle, &key)) {
		Some(Ok(())) => 1,
		Some(Err(error)) => {
			fail(error);
			-1
		}
		None => -1,
	}
}

/// The bundle's principal public keys as a bytes handle holding a JSON array of
/// type-prefixed key byte arrays (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_sharable_principals(handle: i32) -> i32 {
	match with_bundle(handle, sharable_ops::principals) {
		Some(Ok(keys)) => bytes_result(encode_json(&keys)),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// The bundle's DER-encoded container bytes as a bytes handle (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_sharable_export(handle: i32) -> i32 {
	match with_bundle_mut(handle, sharable_ops::export) {
		Some(result) => bytes_result(result),
		None => 0,
	}
}

/// The bundle's PEM envelope as a bytes handle (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_sharable_to_pem(handle: i32) -> i32 {
	match with_bundle_mut(handle, sharable_ops::to_pem) {
		Some(result) => bytes_result(result.map(String::into_bytes)),
		None => 0,
	}
}

/// The bundle's leaf certificate as a fresh `keeta_kyc_certificate_*` handle
/// (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_sharable_certificate(handle: i32) -> i32 {
	match with_bundle_mut(handle, sharable_ops::certificate) {
		Some(Ok(certificate)) => store_leaf(certificate),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// The bundle's intermediate chain as a bytes handle holding a JSON array of PEM
/// strings (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_sharable_intermediates(handle: i32) -> i32 {
	match with_bundle_mut(handle, sharable_ops::intermediates) {
		Some(Ok(intermediates)) => bytes_result(encode_pem_chain(&intermediates)),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// The bundle's disclosed attribute names as a bytes handle holding a JSON
/// string array (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_sharable_attribute_names(handle: i32) -> i32 {
	match with_bundle_mut(handle, sharable_ops::attribute_names) {
		Some(Ok(names)) => bytes_result(encode_json(&names)),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// The validated raw disclosed value for attribute `name` as a bytes handle; an
/// empty payload means the attribute is absent (`0` on error).
///
/// # Safety
///
/// `(name_ptr, name_len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_attribute_buffer(handle: i32, name_ptr: i32, name_len: i32) -> i32 {
	let Some(name) = (unsafe { string_in(name_ptr, name_len) }) else {
		return 0;
	};

	match with_bundle_mut(handle, |bundle| sharable_ops::attribute_buffer(bundle, &name)) {
		Some(result) => bytes_result(result.map(Option::unwrap_or_default)),
		None => 0,
	}
}

/// The schema-decoded semantic value for attribute `name` as a bytes handle; an
/// empty payload means the attribute is absent (`0` on error).
///
/// # Safety
///
/// `(name_ptr, name_len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_attribute_value(handle: i32, name_ptr: i32, name_len: i32) -> i32 {
	let Some(name) = (unsafe { string_in(name_ptr, name_len) }) else {
		return 0;
	};

	match with_bundle_mut(handle, |bundle| sharable_ops::attribute_value(bundle, &name)) {
		Some(result) => bytes_result(result.map(Option::unwrap_or_default)),
		None => 0,
	}
}

/// The inlined, digest-verified blob for reference `id` on the disclosed
/// attribute `name` as a bytes handle; an empty payload means the attribute,
/// entry, or matching reference node is absent (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_sharable_reference_blob(
	handle: i32,
	name_ptr: i32,
	name_len: i32,
	id_ptr: i32,
	id_len: i32,
) -> i32 {
	let Some(name) = (unsafe { string_in(name_ptr, name_len) }) else {
		return 0;
	};
	let Some(id) = (unsafe { string_in(id_ptr, id_len) }) else {
		return 0;
	};

	match with_bundle_mut(handle, |bundle| sharable_ops::reference_blob(bundle, &name, &id)) {
		Some(result) => bytes_result(result.map(Option::unwrap_or_default)),
		None => 0,
	}
}

/// Release a sharable-bundle handle, ignoring an unknown one.
#[no_mangle]
pub extern "C" fn keeta_sharable_free(handle: i32) {
	SHARABLE.with_borrow_mut(|state| state.remove(handle));
}

/// Decode a `(ptr, len)` buffer holding a JSON string array into attribute
/// names, recording a `DECODE` error and yielding `None` when malformed.
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable guest buffer.
unsafe fn decode_names(ptr: i32, len: i32) -> Option<Vec<String>> {
	let bytes = unsafe { bytes_in(ptr, len) };
	match serde_json::from_slice(&bytes) {
		Ok(names) => Some(names),
		Err(error) => {
			fail(CodedError::new("DECODE", error.to_string()));
			None
		}
	}
}

/// Decode a `(ptr, len)` buffer holding a JSON `{ id: base64 }` object into
/// caller-fetched external blobs, recording a `DECODE` error and yielding
/// `None` when malformed.
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable guest buffer.
unsafe fn decode_blobs(ptr: i32, len: i32) -> Option<ExternalBlobs> {
	let bytes = unsafe { bytes_in(ptr, len) };
	let encoded: BTreeMap<String, String> = match serde_json::from_slice(&bytes) {
		Ok(encoded) => encoded,
		Err(error) => {
			fail(CodedError::new("DECODE", error.to_string()));
			return None;
		}
	};

	let mut blobs = ExternalBlobs::default();
	for (id, value) in encoded {
		let raw = match STANDARD.decode(&value) {
			Ok(raw) => raw,
			Err(error) => {
				fail(CodedError::new("DECODE", error.to_string()));
				return None;
			}
		};
		blobs.insert(id, raw);
	}

	Some(blobs)
}

/// JSON-encode a serializable value for transport across the bytes boundary.
fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CodedError> {
	serde_json::to_vec(value).map_err(|error| CodedError::new("ENCODE", error.to_string()))
}

/// JSON-encode an intermediate chain as an array of PEM strings.
fn encode_pem_chain(intermediates: &[X509Certificate]) -> Result<Vec<u8>, CodedError> {
	let mut pem_certs = Vec::with_capacity(intermediates.len());
	for intermediate in intermediates {
		pem_certs.push(certificate_pem(intermediate)?);
	}

	encode_json(&pem_certs)
}

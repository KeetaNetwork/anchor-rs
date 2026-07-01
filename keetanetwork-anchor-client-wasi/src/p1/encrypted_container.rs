//! The encrypted-container surface of the P1 core module

use core::cell::RefCell;

use std::collections::BTreeMap;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::encrypted_container::EncryptedContainer;
use keetanetwork_anchor_bindings::encrypted_container as ec_ops;
use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_client_wasi::{account, bytes_in, bytes_result, fail};

thread_local! {
	static CONTAINERS: RefCell<Containers> = RefCell::new(Containers::default());
}

/// The live containers, each under a monotonically increasing handle.
#[derive(Default)]
struct Containers {
	next: i32,
	containers: BTreeMap<i32, EncryptedContainer>,
}

/// Store `container` under a fresh handle and return it.
fn store_container(container: EncryptedContainer) -> i32 {
	CONTAINERS.with_borrow_mut(|state| {
		state.next = state.next.wrapping_add(1).max(1);

		let handle = state.next;
		state.containers.insert(handle, container);

		handle
	})
}

/// Run `body` against the container at `handle`, recording an `INVALID_HANDLE`
/// error and yielding `None` when the handle is unknown.
fn with_container<R>(handle: i32, body: impl FnOnce(&EncryptedContainer) -> R) -> Option<R> {
	let result = CONTAINERS.with_borrow(|state| state.containers.get(&handle).map(body));
	if result.is_none() {
		fail(CodedError::new("INVALID_HANDLE", "unknown encrypted-container handle"));
	}

	result
}

/// Run `body` against the mutable container at `handle`, recording an
/// `INVALID_HANDLE` error and yielding `None` when the handle is unknown.
fn with_container_mut<R>(handle: i32, body: impl FnOnce(&mut EncryptedContainer) -> R) -> Option<R> {
	let result = CONTAINERS.with_borrow_mut(|state| state.containers.get_mut(&handle).map(body));
	if result.is_none() {
		fail(CodedError::new("INVALID_HANDLE", "unknown encrypted-container handle"));
	}

	result
}

/// Decode the tri-state `locked` flag: negative is the default policy, `0` is
/// unlocked, anything else is locked.
fn decode_locked(locked: i32) -> Option<bool> {
	match locked {
		locked if locked < 0 => None,
		0 => Some(false),
		_ => Some(true),
	}
}

/// Build a plaintext container, optionally sealing it to the principal handle
/// list at `(principals_ptr, principals_len)` and attaching the signer at
/// `signer_handle` (`0` for none). `locked` is the tri-state plaintext policy.
/// Returns a container handle (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_encrypted_container_from_plaintext(
	data_ptr: i32,
	data_len: i32,
	principals_ptr: i32,
	principals_len: i32,
	locked: i32,
	signer_handle: i32,
) -> i32 {
	let data = unsafe { bytes_in(data_ptr, data_len) };
	let Some(principals) = (unsafe { resolve_optional_accounts(principals_ptr, principals_len) }) else {
		return 0;
	};
	let signer = match signer_handle {
		0 => None,
		handle => match account(handle) {
			Some(account) => Some(account),
			None => return 0,
		},
	};

	let container = ec_ops::from_plaintext(data, principals.as_deref(), decode_locked(locked), signer.as_ref());
	store_container(container)
}

/// Build a container from an encoded blob that may be plaintext or encrypted,
/// resolving the optional principal handle list. Returns a container handle
/// (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_encrypted_container_from_encoded(
	data_ptr: i32,
	data_len: i32,
	principals_ptr: i32,
	principals_len: i32,
) -> i32 {
	let data = unsafe { bytes_in(data_ptr, data_len) };
	let Some(principals) = (unsafe { resolve_optional_accounts(principals_ptr, principals_len) }) else {
		return 0;
	};

	match ec_ops::from_encoded(&data, principals.as_deref()) {
		Ok(container) => store_container(container),
		Err(error) => fail(error),
	}
}

/// Build a container from a blob that must be encrypted, resolving the required
/// principal handle list. Returns a container handle (`0` on error).
///
/// # Safety
///
/// Each `(ptr, len)` MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_encrypted_container_from_encrypted(
	data_ptr: i32,
	data_len: i32,
	principals_ptr: i32,
	principals_len: i32,
) -> i32 {
	let data = unsafe { bytes_in(data_ptr, data_len) };
	let Some(principals) = (unsafe { resolve_accounts(principals_ptr, principals_len) }) else {
		return 0;
	};

	match ec_ops::from_encrypted(&data, &principals) {
		Ok(container) => store_container(container),
		Err(error) => fail(error),
	}
}

/// The container's plaintext as a bytes handle (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_get_plaintext(handle: i32) -> i32 {
	match with_container_mut(handle, ec_ops::get_plaintext) {
		Some(result) => bytes_result(result),
		None => 0,
	}
}

/// The container's DER encoding as a bytes handle (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_get_encoded(handle: i32) -> i32 {
	match with_container_mut(handle, ec_ops::get_encoded) {
		Some(result) => bytes_result(result),
		None => 0,
	}
}

/// Whether the container is encrypted: `1`/`0`/`-1` (unknown handle).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_is_encrypted(handle: i32) -> i32 {
	match with_container(handle, ec_ops::is_encrypted) {
		Some(true) => 1,
		Some(false) => 0,
		None => -1,
	}
}

/// Whether the container is signed: `1`/`0`/`-1` (unknown handle).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_is_signed(handle: i32) -> i32 {
	match with_container(handle, ec_ops::is_signed) {
		Some(true) => 1,
		Some(false) => 0,
		None => -1,
	}
}

/// Verify the container's detached signature: `1`/`0`/`-1` (error or unknown
/// handle; see the last error).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_verify_signature(handle: i32) -> i32 {
	match with_container_mut(handle, ec_ops::verify_signature) {
		Some(Ok(true)) => 1,
		Some(Ok(false)) => 0,
		Some(Err(error)) => {
			fail(error);
			-1
		}
		None => -1,
	}
}

/// The type-prefixed public key of the signing account as a bytes handle; an
/// empty payload means the container is unsigned (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_signing_account(handle: i32) -> i32 {
	match with_container(handle, ec_ops::signing_account) {
		Some(Ok(Some(key))) => bytes_result(Ok(key)),
		Some(Ok(None)) => bytes_result(Ok(Vec::new())),
		Some(Err(error)) => fail(error),
		None => 0,
	}
}

/// The container's principal public keys as a bytes handle holding a JSON array
/// of type-prefixed key byte arrays (`0` on error).
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_principals(handle: i32) -> i32 {
	match with_container(handle, ec_ops::principals) {
		Some(Ok(keys)) => bytes_result(encode_principals(&keys)),
		Some(Err(error)) => fail(error),
		None => 0,
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
pub unsafe extern "C" fn keeta_encrypted_container_grant_access(
	handle: i32,
	principals_ptr: i32,
	principals_len: i32,
) -> i32 {
	let Some(accounts) = (unsafe { resolve_accounts(principals_ptr, principals_len) }) else {
		return -1;
	};

	match with_container_mut(handle, |container| ec_ops::grant_access(container, &accounts)) {
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
pub unsafe extern "C" fn keeta_encrypted_container_revoke_access(handle: i32, key_ptr: i32, key_len: i32) -> i32 {
	let key = unsafe { bytes_in(key_ptr, key_len) };
	match with_container_mut(handle, |container| ec_ops::revoke_access(container, &key)) {
		Some(Ok(())) => 1,
		Some(Err(error)) => {
			fail(error);
			-1
		}
		None => -1,
	}
}

/// Release a container handle, ignoring an unknown one.
#[no_mangle]
pub extern "C" fn keeta_encrypted_container_free(handle: i32) {
	CONTAINERS.with_borrow_mut(|state| state.containers.remove(&handle));
}

/// JSON-encode principal public keys for transport across the bytes boundary.
fn encode_principals(keys: &[Vec<u8>]) -> Result<Vec<u8>, CodedError> {
	serde_json::to_vec(keys).map_err(|error| CodedError::new("ENCODE", error.to_string()))
}

/// Resolve a `(ptr, len)` buffer of little-endian `i32` account handles into
/// shared accounts, recording an error and yielding `None` on a bad handle or
/// misaligned buffer.
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable guest buffer.
pub(crate) unsafe fn resolve_accounts(ptr: i32, len: i32) -> Option<Vec<Arc<GenericAccount>>> {
	let bytes = unsafe { bytes_in(ptr, len) };
	if !bytes.len().is_multiple_of(4) {
		fail(CodedError::new("INVALID_HANDLE_LIST", "handle list must be 4-byte aligned"));
		return None;
	}

	bytes
		.chunks_exact(4)
		.map(|chunk| account(i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
		.collect()
}

/// Resolve an optional principal handle list: an empty buffer is `Some(None)`
/// (no principals); a populated buffer resolves as in [`resolve_accounts`].
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable guest buffer.
unsafe fn resolve_optional_accounts(ptr: i32, len: i32) -> Option<Option<Vec<Arc<GenericAccount>>>> {
	if len <= 0 {
		return Some(None);
	}

	unsafe { resolve_accounts(ptr, len) }.map(Some)
}

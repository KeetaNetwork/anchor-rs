//! WASI Preview 1 core module: a flat C ABI over the offline KYC primitives
//!
//! # ABI
//!
//! The host writes inputs into guest memory with [`keeta_anchor_alloc`] and
//! reads results from an [`Output`] record returned by each operation. An
//! `Output` with `code == 0` carries the result bytes at `(ptr, len)`; a
//! non-zero `code` carries a UTF-8 error message there instead. The host frees
//! every result with [`keeta_anchor_output_free`] and every input buffer with
//! [`keeta_anchor_free`].

use core::slice;
use core::str;

use keetanetwork_account::account::AccountSigner;
use keetanetwork_account::Keyable;
use keetanetwork_anchor_bindings::account::from_keyable;
use keetanetwork_anchor_bindings::error::CodedError;

/// A single operation result handed back across the C ABI.
#[repr(C)]
pub struct Output {
	/// `0` on success; non-zero when `(ptr, len)` is an error message.
	code: u32,
	/// Pointer to the result (or error message) bytes.
	ptr: u32,
	/// Length of the result bytes.
	len: u32,
}

/// Allocate a `len`-byte buffer in guest memory for the host to write into.
///
/// The buffer is an exact-`len` boxed slice so [`keeta_anchor_free`] can release
/// it under the same layout, without relying on a `Vec`'s unspecified capacity.
#[no_mangle]
pub extern "C" fn keeta_anchor_alloc(len: usize) -> *mut u8 {
	let buffer: Box<[u8]> = vec![0u8; len].into_boxed_slice();
	Box::into_raw(buffer).cast::<u8>()
}

/// Free a buffer of `len` bytes previously returned by [`keeta_anchor_alloc`].
///
/// # Safety
///
/// `ptr` MUST come from [`keeta_anchor_alloc`] with the same `len` and not have
/// been freed already.
#[no_mangle]
pub unsafe extern "C" fn keeta_anchor_free(ptr: *mut u8, len: usize) {
	if ptr.is_null() {
		return;
	}

	let slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
	drop(unsafe { Box::from_raw(slice) });
}

/// Free an [`Output`] and its result bytes.
///
/// # Safety
///
/// `output` MUST come from an operation in this module and not have been freed.
#[no_mangle]
pub unsafe extern "C" fn keeta_anchor_output_free(output: *mut Output) {
	if output.is_null() {
		return;
	}

	let boxed = unsafe { Box::from_raw(output) };
	if boxed.ptr != 0 && boxed.len != 0 {
		let bytes = boxed.ptr as *mut u8;
		let len = boxed.len as usize;
		let slice = core::ptr::slice_from_raw_parts_mut(bytes, len);

		drop(unsafe { Box::from_raw(slice) });
	}
}

/// The textual `keeta_…` address for the account derived from `seed`/`index`
/// under `algorithm`.
///
/// # Safety
///
/// Each `(ptr, len)` pair MUST describe an initialized, readable buffer for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn keeta_anchor_account_address(
	seed_ptr: *const u8,
	seed_len: usize,
	index: u32,
	algorithm_ptr: *const u8,
	algorithm_len: usize,
) -> *mut Output {
	let result = unsafe { account_address(seed_ptr, seed_len, index, algorithm_ptr, algorithm_len) };
	into_output(result)
}

/// The signature of `message` by the account derived from `seed`/`index` under
/// `algorithm`.
///
/// # Safety
///
/// Each `(ptr, len)` pair MUST describe an initialized, readable buffer for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn keeta_anchor_sign(
	seed_ptr: *const u8,
	seed_len: usize,
	index: u32,
	algorithm_ptr: *const u8,
	algorithm_len: usize,
	message_ptr: *const u8,
	message_len: usize,
) -> *mut Output {
	let result = unsafe { sign(seed_ptr, seed_len, index, algorithm_ptr, algorithm_len, message_ptr, message_len) };
	into_output(result)
}

/// # Safety
///
/// See [`keeta_anchor_account_address`].
unsafe fn account_address(
	seed_ptr: *const u8,
	seed_len: usize,
	index: u32,
	algorithm_ptr: *const u8,
	algorithm_len: usize,
) -> Result<Vec<u8>, CodedError> {
	let seed = unsafe { read_str(seed_ptr, seed_len) }?;
	let algorithm = unsafe { read_str(algorithm_ptr, algorithm_len) }?;
	let account = from_keyable(Keyable::from((seed, index)), algorithm)?;

	Ok(account.to_string().into_bytes())
}

/// # Safety
///
/// See [`keeta_anchor_sign`].
#[allow(clippy::too_many_arguments)]
unsafe fn sign(
	seed_ptr: *const u8,
	seed_len: usize,
	index: u32,
	algorithm_ptr: *const u8,
	algorithm_len: usize,
	message_ptr: *const u8,
	message_len: usize,
) -> Result<Vec<u8>, CodedError> {
	let seed = unsafe { read_str(seed_ptr, seed_len) }?;
	let algorithm = unsafe { read_str(algorithm_ptr, algorithm_len) }?;
	let message = unsafe { read_bytes(message_ptr, message_len) };
	let account = from_keyable(Keyable::from((seed, index)), algorithm)?;

	account
		.sign(message, None)
		.map_err(|_| CodedError::new("SIGN", "signing failed"))
}

/// Borrow `len` bytes at `ptr` as a slice.
///
/// # Safety
///
/// `(ptr, len)` MUST describe an initialized, readable buffer for the call.
unsafe fn read_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
	if ptr.is_null() || len == 0 {
		return &[];
	}

	unsafe { slice::from_raw_parts(ptr, len) }
}

/// Borrow `(ptr, len)` as UTF-8, projecting invalid bytes to a coded error.
///
/// # Safety
///
/// See [`read_bytes`].
unsafe fn read_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, CodedError> {
	let bytes = unsafe { read_bytes(ptr, len) };
	str::from_utf8(bytes).map_err(|_| CodedError::new("INVALID_UTF8", "input must be UTF-8"))
}

/// Box a result into an [`Output`]: code `0` with the bytes on success, or code
/// `1` with the `code: message` text on failure.
fn into_output(result: Result<Vec<u8>, CodedError>) -> *mut Output {
	match result {
		Ok(bytes) => output(0, bytes),
		Err(error) => output(1, format!("{}: {}", error.code, error.message).into_bytes()),
	}
}

/// Leak `bytes` and box an [`Output`] pointing at them.
///
/// `bytes` is leaked as an exact-`len` boxed slice so [`keeta_anchor_output_free`]
/// can release it under the same layout.
fn output(code: u32, bytes: Vec<u8>) -> *mut Output {
	let boxed: Box<[u8]> = bytes.into_boxed_slice();
	let len = boxed.len();
	let ptr = Box::into_raw(boxed).cast::<u8>();

	Box::into_raw(Box::new(Output { code, ptr: ptr as u32, len: len as u32 }))
}

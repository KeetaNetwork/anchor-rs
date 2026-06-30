//! Decode the on-chain service-metadata blob into JSON.

use alloc::vec::Vec;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

use crate::error::ResolverError;

/// The `external` discriminator of an `ExternalURL` indirection node.
const EXTERNAL_URL_MARKER: &str = "2b828e33-2692-46e9-817e-9b93d63f28fd";

/// Decode the base64 metadata field into its raw, compressed bytes.
///
/// # Errors
///
/// Returns [`ResolverError::Base64`] when `blob` is not valid base64.
///
/// # Examples
///
/// ```
/// use keetanetwork_anchor_client::resolver::decode_base64;
///
/// let raw = decode_base64("aGk=")?;
/// assert_eq!(raw, b"hi");
/// # Ok::<(), keetanetwork_anchor_client::ResolverError>(())
/// ```
pub fn decode_base64(blob: impl AsRef<str>) -> Result<Vec<u8>, ResolverError> {
	let trimmed = blob.as_ref().trim();
	let raw = STANDARD.decode(trimmed)?;
	Ok(raw)
}

/// Parse raw metadata bytes (post-base64) into a JSON [`Value`].
///
/// Inflate is attempted first; bytes that do not decompress are parsed as
/// uncompressed JSON.
///
/// # Errors
///
/// Returns [`ResolverError::Utf8`] when the bytes are not UTF-8, or
/// [`ResolverError::Json`] when the text is not valid JSON.
///
/// # Examples
///
/// ```
/// use keetanetwork_anchor_client::resolver::parse_metadata;
///
/// let value = parse_metadata(br#"{"version":1}"#)?;
/// assert_eq!(value["version"], 1);
/// # Ok::<(), keetanetwork_anchor_client::ResolverError>(())
/// ```
pub fn parse_metadata(raw: impl AsRef<[u8]>) -> Result<Value, ResolverError> {
	let raw = raw.as_ref();
	let inflated = miniz_oxide::inflate::decompress_to_vec_zlib(raw).ok();
	let bytes: &[u8] = match inflated {
		Some(ref decompressed) => decompressed.as_slice(),
		None => raw,
	};

	let text = core::str::from_utf8(bytes).map_err(|_| ResolverError::Utf8)?;
	let value = serde_json::from_str(text)?;
	Ok(value)
}

/// The target URL when `value` is an `ExternalURL` indirection node.
pub(crate) fn as_external_url(value: &Value) -> Option<&str> {
	let object = value.as_object()?;
	let marker = object.get("external")?.as_str()?;
	if marker != EXTERNAL_URL_MARKER {
		return None;
	}

	object.get("url")?.as_str()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_metadata_reads_uncompressed_json() -> Result<(), ResolverError> {
		let value = parse_metadata(br#"{"version":1}"#)?;
		assert_eq!(value["version"], 1);
		Ok(())
	}

	#[test]
	fn as_external_url_requires_the_canonical_marker() {
		let wrong = serde_json::json!({ "external": "nope", "url": "https://x" });
		assert!(as_external_url(&wrong).is_none());

		let right = serde_json::json!({ "external": EXTERNAL_URL_MARKER, "url": "https://x" });
		assert_eq!(as_external_url(&right), Some("https://x"));
	}
}

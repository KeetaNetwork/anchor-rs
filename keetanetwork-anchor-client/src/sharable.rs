//! Networked convenience for sharable-attribute external references.
//!
//! The core [`SharableCertificateAttributes`] ingests external blobs but never
//! performs I/O. This module fetches each discovered reference through the
//! transport layer, decoding `data:` URLs inline.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::certificates::KycCertificate;
use keetanetwork_anchor::kyc_schema::AttributeReference;
use keetanetwork_anchor::sharable_attributes::{ExternalBlobs, FromCertificateOptions, SharableCertificateAttributes};
use serde_json::Value;

use crate::error::AnchorClientError;
use crate::transport::AnchorHttpTransport;

/// Fetch every reference's blob: `data:` URLs decoded inline, http(s) URLs
/// through `transport`, keyed by the reference's digest id. The raw fetched
/// bytes are returned as stored - still sealed when the reference names an
/// encryption algorithm; the core ingest decrypts and digest-verifies.
///
/// # Errors
///
/// Returns [`AnchorClientError::ReferenceFetch`] when a URL cannot be decoded
/// or the server does not answer 200.
pub async fn fetch_external_blobs(
	transport: &dyn AnchorHttpTransport,
	references: impl IntoIterator<Item = &AttributeReference>,
) -> Result<ExternalBlobs, AnchorClientError> {
	let mut blobs = ExternalBlobs::default();
	for reference in references {
		let bytes = fetch_reference(transport, reference).await?;
		blobs.insert(reference.id(), bytes);
	}

	Ok(blobs)
}

/// Discover the named attributes' references, fetch their blobs, and build the
/// sharable bundle with them ingested, in one call. Blobs already present in
/// `options` are kept; fetched ones are added alongside.
///
/// # Errors
///
/// - As [`fetch_external_blobs`].
/// - [`AnchorClientError::Sharable`] -- discovery or the core build failed.
pub async fn sharable_with_references(
	transport: &dyn AnchorHttpTransport,
	certificate: &KycCertificate,
	subject: &Arc<GenericAccount>,
	names: impl IntoIterator<Item = impl AsRef<str>>,
	options: FromCertificateOptions<'_>,
) -> Result<SharableCertificateAttributes, AnchorClientError> {
	let names: Vec<String> = names
		.into_iter()
		.map(|name| name.as_ref().to_string())
		.collect();
	let discovered = certificate.external_references(subject.as_ref(), &names)?;

	let mut options = options;
	for reference in discovered.values().flatten() {
		let bytes = fetch_reference(transport, reference).await?;
		options.blobs.insert(reference.id(), bytes);
	}

	let sharable = SharableCertificateAttributes::from_certificate(certificate, subject, &names, options)?;
	Ok(sharable)
}

/// Fetch one reference's raw stored bytes from its URL.
async fn fetch_reference(
	transport: &dyn AnchorHttpTransport,
	reference: &AttributeReference,
) -> Result<Vec<u8>, AnchorClientError> {
	let url = reference.external.url.as_str();
	if let Some(rest) = url.strip_prefix("data:") {
		return decode_data_url(url, rest);
	}

	let response = transport.get(url).await?;
	if response.status != 200 {
		return Err(AnchorClientError::ReferenceFetch { url: url.to_string(), status: response.status });
	}

	unwrap_container_payload(url, response.body)
}

/// Decode a `data:<mediatype>[;base64],<data>` URL body.
fn decode_data_url(url: &str, rest: &str) -> Result<Vec<u8>, AnchorClientError> {
	let fetch_failed = || AnchorClientError::ReferenceFetch { url: url.to_string(), status: 0 };
	let (header, data) = rest.split_once(',').ok_or_else(fetch_failed)?;
	if !header.ends_with(";base64") {
		return Ok(data.as_bytes().to_vec());
	}

	STANDARD.decode(data).map_err(|_| fetch_failed())
}

/// Unwrap the storage-service container-payload convention: a JSON body of
/// exactly `{data, mimeType}` (both strings) carries the base64 stored bytes;
/// anything else is the stored bytes themselves.
///
/// # Errors
///
/// Returns [`AnchorClientError::ReferenceFetch`] (status `0`) when the wrapper
/// shape is detected but its base64 payload does not decode, so a corrupted
/// wrapper surfaces here instead of as a later decryption failure.
fn unwrap_container_payload(url: &str, body: Vec<u8>) -> Result<Vec<u8>, AnchorClientError> {
	let Ok(parsed) = serde_json::from_slice::<Value>(&body) else {
		return Ok(body);
	};
	let Some(fields) = parsed.as_object().filter(|fields| fields.len() == 2) else {
		return Ok(body);
	};

	let data = fields.get("data").and_then(Value::as_str);
	let mime_type = fields.get("mimeType").and_then(Value::as_str);
	match (data, mime_type) {
		(Some(data), Some(_)) => {
			let decoded = STANDARD
				.decode(data)
				.map_err(|_| AnchorClientError::ReferenceFetch { url: url.to_string(), status: 0 })?;

			Ok(decoded)
		}
		_ => Ok(body),
	}
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	const URL: &str = "https://example.test/blob";

	#[test]
	fn unwraps_an_exact_container_payload() -> Result<(), AnchorClientError> {
		let body = serde_json::to_vec(&json!({ "data": "aGk=", "mimeType": "image/png" })).unwrap_or_default();
		assert_eq!(unwrap_container_payload(URL, body)?, b"hi");
		Ok(())
	}

	#[test]
	fn passes_other_json_bodies_through() -> Result<(), AnchorClientError> {
		let body =
			serde_json::to_vec(&json!({ "data": "aGk=", "mimeType": "image/png", "extra": 1 })).unwrap_or_default();
		assert_eq!(unwrap_container_payload(URL, body.clone())?, body);
		Ok(())
	}

	#[test]
	fn passes_raw_bodies_through() -> Result<(), AnchorClientError> {
		assert_eq!(unwrap_container_payload(URL, b"\x01\x02".to_vec())?, b"\x01\x02");
		Ok(())
	}

	#[test]
	fn a_wrapper_with_invalid_base64_fails_loud() {
		let body = serde_json::to_vec(&json!({ "data": "not base64!", "mimeType": "image/png" })).unwrap_or_default();

		let outcome = unwrap_container_payload(URL, body);
		assert!(matches!(outcome, Err(AnchorClientError::ReferenceFetch { status: 0, .. })));
	}

	#[test]
	fn decodes_a_base64_data_url() {
		let url = "data:application/octet-string;base64,aGk=";
		let decoded = decode_data_url(url, "application/octet-string;base64,aGk=");
		assert_eq!(decoded.unwrap_or_default(), b"hi");
	}

	#[test]
	fn rejects_a_malformed_data_url() {
		let outcome = decode_data_url("data:nope", "nope");
		assert!(matches!(outcome, Err(AnchorClientError::ReferenceFetch { status: 0, .. })));
	}
}

//! Typed external document references carried by KYC attribute values.
//!
//! Document attributes (e.g. `documentDriversLicense`) embed `Reference`
//! structures pointing at externally stored blobs: a URL and content type, an
//! RFC 3447 `DigestInfo` over the blob plaintext, and the encryption algorithm
//! sealing the stored form.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use keetanetwork_asn1::{ObjectIdentifier, ObjectIdentifierExt};
use keetanetwork_crypto::prelude::HashAlgorithm;
use serde_json::Value;

use crate::asn1::oids;
use crate::kyc_schema::error::KycSchemaError;
use crate::kyc_schema::iso20022_engine::{oid_from_name, oid_to_name};

/// The Keeta encrypted container OID. Not yet published in the
/// `keetanetwork-asn1` OID database, so pinned here until it is.
const KEETA_CONTAINER_OID: &str = "1.3.6.1.4.1.62675.2";

/// Resolve a digest algorithm identifier - a symbolic name or a dotted OID -
/// to the crate hash algorithm, through the shared algorithm map and the
/// schema codec's name table.
fn digest_algorithm_from_identifier(value: &str) -> Result<HashAlgorithm, KycSchemaError> {
	let unsupported = || KycSchemaError::UnsupportedDigestAlgorithm { oid: value.to_string() };
	let oid = match oids::ALGORITHM_ATTRIBUTES.get(value) {
		Some(known) => known.clone(),
		None => {
			let dotted = oid_from_name(value);
			ObjectIdentifier::from_str(&dotted).map_err(|_| unsupported())?
		}
	};
	if oid == oids::SHA3_256 {
		return Ok(HashAlgorithm::Sha3_256);
	}
	if oid == oids::SHA2_256 {
		return Ok(HashAlgorithm::Sha2_256);
	}

	Err(unsupported())
}

/// The encryption algorithm sealing a referenced blob's stored form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceEncryption {
	/// A Keeta encrypted container (`1.3.6.1.4.1.62675.2`), opened with the
	/// certificate subject's account.
	KeetaEncryptedContainerV1,
}

impl ReferenceEncryption {
	/// The symbolic name the reference implementation uses for this algorithm.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::KeetaEncryptedContainerV1 => "KeetaEncryptedContainerV1",
		}
	}
}

impl TryFrom<&str> for ReferenceEncryption {
	type Error = KycSchemaError;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		match value {
			"KeetaEncryptedContainerV1" | KEETA_CONTAINER_OID => Ok(Self::KeetaEncryptedContainerV1),
			other => Err(KycSchemaError::UnsupportedEncryptionAlgorithm { oid: other.to_string() }),
		}
	}
}

impl fmt::Display for ReferenceEncryption {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.as_str())
	}
}

/// Where a referenced blob can be fetched and what it contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalReference {
	/// The URL serving the stored (possibly sealed) blob.
	pub url: String,
	/// The MIME type of the blob plaintext.
	pub content_type: String,
}

/// The digest certifying a referenced blob's plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestInfo {
	/// The digest algorithm.
	pub algorithm: HashAlgorithm,
	/// The expected digest bytes.
	pub digest: Vec<u8>,
}

impl DigestInfo {
	/// Whether `data` hashes to the expected digest.
	pub fn matches(&self, data: impl AsRef<[u8]>) -> bool {
		self.algorithm.hash(data) == self.digest
	}

	/// The symbolic name the schema codec renders for the digest algorithm
	/// (e.g. `sha3-256`, `sha256`), falling back to the crate name for an
	/// algorithm outside the codec's table.
	pub fn algorithm_name(&self) -> String {
		let oid = match self.algorithm {
			HashAlgorithm::Sha3_256 => oids::SHA3_256,
			HashAlgorithm::Sha2_256 => oids::SHA2_256,
			_ => return self.algorithm.name().to_string(),
		};

		oid_to_name(&oid.to_string())
	}
}

/// One external blob reference discovered in a decoded attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeReference {
	/// Where the stored blob lives.
	pub external: ExternalReference,
	/// The digest certifying the blob plaintext.
	pub digest: DigestInfo,
	/// How the stored blob is sealed.
	pub encryption: ReferenceEncryption,
}

impl AttributeReference {
	/// The reference identifier: the digest bytes as uppercase hex, the key
	/// the reference implementation files inlined blobs under.
	pub fn id(&self) -> String {
		hex::encode_upper(&self.digest.digest)
	}

	/// Every reference discovered in the decoded attribute `value`.
	///
	/// Walks the JSON tree iteratively; an object carrying `external` and
	/// `digest` objects is a reference node.
	pub(crate) fn collect(value: &Value) -> Result<Vec<Self>, KycSchemaError> {
		let mut references = Vec::new();
		let mut pending = alloc::vec![value];
		while let Some(node) = pending.pop() {
			match node {
				Value::Object(object) => {
					if is_reference_shape(object) {
						if let Some(reference) = parse_reference(object)? {
							references.push(reference);
						}

						continue;
					}

					pending.extend(object.values());
				}
				Value::Array(items) => pending.extend(items),
				_ => {}
			}
		}

		Ok(references)
	}
}

/// Whether `object` matches the reference detection heuristic: `external` and
/// `digest` fields that are both objects.
fn is_reference_shape(object: &serde_json::Map<String, Value>) -> bool {
	let external_is_object = object.get("external").is_some_and(Value::is_object);
	let digest_is_object = object.get("digest").is_some_and(Value::is_object);

	external_is_object && digest_is_object
}

/// Parse a reference-shaped `object`; `None` for a structurally malformed node,
/// an error for an unknown algorithm identifier.
fn parse_reference(object: &serde_json::Map<String, Value>) -> Result<Option<AttributeReference>, KycSchemaError> {
	let Some(external) = parse_external(object) else {
		return Ok(None);
	};
	let Some((algorithm_name, digest)) = parse_digest_parts(object) else {
		return Ok(None);
	};
	let Some(encryption_name) = object.get("encryptionAlgorithm").and_then(Value::as_str) else {
		return Ok(None);
	};

	let algorithm = digest_algorithm_from_identifier(algorithm_name)?;
	let encryption = ReferenceEncryption::try_from(encryption_name)?;

	Ok(Some(AttributeReference { external, digest: DigestInfo { algorithm, digest }, encryption }))
}

/// The `external` half of a reference node, requiring string `url` and
/// `contentType` fields like the reference heuristic.
fn parse_external(object: &serde_json::Map<String, Value>) -> Option<ExternalReference> {
	let external = object.get("external")?.as_object()?;
	let url = external.get("url")?.as_str()?;
	let content_type = external.get("contentType")?.as_str()?;

	Some(ExternalReference { url: url.to_string(), content_type: content_type.to_string() })
}

/// The `digest` half of a reference node: its algorithm identifier and the
/// digest bytes from their Node `Buffer` JSON form.
fn parse_digest_parts(object: &serde_json::Map<String, Value>) -> Option<(&str, Vec<u8>)> {
	let digest_info = object.get("digest")?.as_object()?;
	let algorithm = digest_info.get("digestAlgorithm")?.as_str()?;
	let digest = bytes_from_buffer_value(digest_info.get("digest")?)?;

	Some((algorithm, digest))
}

/// Decode a Node `Buffer` JSON form (`{"type":"Buffer","data":[..]}`) into
/// bytes, rejecting non-byte entries.
fn bytes_from_buffer_value(value: &Value) -> Option<Vec<u8>> {
	let data = value.as_object()?.get("data")?.as_array()?;
	let mut bytes = Vec::with_capacity(data.len());
	for entry in data {
		let byte = entry
			.as_u64()
			.filter(|candidate| *candidate <= u64::from(u8::MAX))?;
		bytes.push(byte as u8);
	}

	Some(bytes)
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	fn reference_json(digest_algorithm: &str, encryption: &str) -> Value {
		json!({
			"external": { "url": "data:application/octet-string;base64,AAAA", "contentType": "image/png" },
			"digest": { "digestAlgorithm": digest_algorithm, "digest": { "type": "Buffer", "data": [1, 2, 3] } },
			"encryptionAlgorithm": encryption,
		})
	}

	#[test]
	fn collects_a_nested_reference() {
		let value =
			json!({ "documentNumber": "DL1", "front": reference_json("sha3-256", "KeetaEncryptedContainerV1") });

		let references = AttributeReference::collect(&value).unwrap_or_default();
		assert_eq!(references.len(), 1);
		assert_eq!(references[0].external.content_type, "image/png");
		assert_eq!(references[0].digest.algorithm, HashAlgorithm::Sha3_256);
		assert_eq!(references[0].id(), "010203");
	}

	#[test]
	fn accepts_dotted_oids() {
		let value = reference_json(&oids::SHA2_256.to_string(), KEETA_CONTAINER_OID);

		let references = AttributeReference::collect(&value).unwrap_or_default();
		assert_eq!(references.len(), 1);
		assert_eq!(references[0].digest.algorithm, HashAlgorithm::Sha2_256);
		assert_eq!(references[0].encryption, ReferenceEncryption::KeetaEncryptedContainerV1);
	}

	#[test]
	fn accepts_every_reference_digest_identifier() {
		// The identifiers the reference implementation's checkHashWithOID
		// accepts: symbolic names, the sha2 alias, and dotted OIDs.
		for (identifier, algorithm) in [
			("sha3-256", HashAlgorithm::Sha3_256),
			("sha256", HashAlgorithm::Sha2_256),
			("sha2-256", HashAlgorithm::Sha2_256),
			("2.16.840.1.101.3.4.2.8", HashAlgorithm::Sha3_256),
			("2.16.840.1.101.3.4.2.1", HashAlgorithm::Sha2_256),
		] {
			let value = reference_json(identifier, "KeetaEncryptedContainerV1");
			let references = AttributeReference::collect(&value).unwrap_or_default();
			assert_eq!(references.len(), 1);
			assert_eq!(references[0].digest.algorithm, algorithm);
		}
	}

	#[test]
	fn renders_the_codec_symbolic_names() {
		let sha3 = DigestInfo { algorithm: HashAlgorithm::Sha3_256, digest: Vec::new() };
		let sha2 = DigestInfo { algorithm: HashAlgorithm::Sha2_256, digest: Vec::new() };
		assert_eq!(sha3.algorithm_name(), "sha3-256");
		assert_eq!(sha2.algorithm_name(), "sha256");
	}

	#[test]
	fn skips_a_structurally_malformed_node() {
		let value = json!({
			"front": {
				"external": { "url": "https://x/y" },
				"digest": { "digestAlgorithm": "sha3-256", "digest": { "type": "Buffer", "data": [1] } },
				"encryptionAlgorithm": "KeetaEncryptedContainerV1",
			}
		});

		let references = AttributeReference::collect(&value).unwrap_or_default();
		assert!(references.is_empty());
	}

	#[test]
	fn rejects_an_unknown_digest_algorithm() {
		let value = reference_json("md5", "KeetaEncryptedContainerV1");

		let outcome = AttributeReference::collect(&value);
		assert!(matches!(outcome, Err(KycSchemaError::UnsupportedDigestAlgorithm { .. })));
	}

	#[test]
	fn rejects_an_unknown_encryption_algorithm() {
		let value = reference_json("sha3-256", "aes-256-gcm");

		let outcome = AttributeReference::collect(&value);
		assert!(matches!(outcome, Err(KycSchemaError::UnsupportedEncryptionAlgorithm { .. })));
	}

	#[test]
	fn digest_matches_the_hashed_plaintext() {
		let plaintext = b"NOT REALLY A PNG\n";
		let digest = HashAlgorithm::Sha3_256.hash(plaintext);

		let info = DigestInfo { algorithm: HashAlgorithm::Sha3_256, digest };
		assert!(info.matches(plaintext));
		assert!(!info.matches(b"corrupted"));
	}
}

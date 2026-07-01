//! ISO 20022 attribute projection over the schema-driven DER codec.
//!
//! The generic, projection-free codec lives in
//! [`keetanetwork_asn1::schema_codec`]: it maps DER bytes to and from an
//! [`Asn1`] tree under a declarative [`Schema`]. This module is the KYC-specific
//! projection on top of it — mapping that tree onto the reference TypeScript
//! `ValidateASN1` JSON shapes: `serde_json` values, symbolic OID names, Node
//! `Buffer` objects, and ISO-8601 dates. The schema descriptors are generated
//! from `oids.json` (see [`crate::generated::iso20022_schema`]), so both
//! languages derive their wire format from one source.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use keetanetwork_asn1::schema_codec::{
	der_decode, der_encode, is_optional, match_tuple, unwrap_context_tags, Asn1, Field, Schema,
};
use serde_json::{Map, Value};

use crate::asn1::error::AnchorAsn1Error;
use crate::generated::iso20022_schema::attribute_schema;

/// Encode a semantic JSON attribute value into its positional ASN.1 DER.
///
/// Returns an error for tokens without a schema so the caller can fall back to
/// the raw bytes.
pub fn encode_structured(token: impl AsRef<str>, json: impl AsRef<[u8]>) -> Result<Vec<u8>, AnchorAsn1Error> {
	let schema = attribute_schema(token.as_ref()).ok_or_else(|| encode_error("unmapped structured attribute"))?;
	let value: Value = serde_json::from_slice(json.as_ref()).map_err(encode_error)?;
	let asn1 = encode_schema(&value, &schema)?;

	der_encode(&asn1).map_err(encode_error)
}

/// Decode positional ASN.1 DER into the validator JSON form.
///
/// The current (context-tagged) schema is tried first; a legacy certificate
/// encoded before context tags were added is then decoded against the
/// context-stripped schema, matching the reference's two-schema fallback.
pub fn decode_structured(token: impl AsRef<str>, der: impl AsRef<[u8]>) -> Result<Vec<u8>, AnchorAsn1Error> {
	let schema = attribute_schema(token.as_ref()).ok_or_else(|| decode_error("unmapped structured attribute"))?;
	let asn1 = der_decode(der.as_ref()).map_err(decode_error)?;
	let legacy_schema = unwrap_context_tags(&schema);
	let value = decode_schema(&asn1, &schema).or_else(|_| decode_schema(&asn1, &legacy_schema))?;

	serde_json::to_vec(&value).map_err(encode_error)
}

/// Build an `Asn1EncodeError` from any displayable reason.
fn encode_error(reason: impl ToString) -> AnchorAsn1Error {
	AnchorAsn1Error::Asn1EncodeError { reason: reason.to_string() }
}

/// Build an `Asn1DecodeError` from any displayable reason.
fn decode_error(reason: impl ToString) -> AnchorAsn1Error {
	AnchorAsn1Error::Asn1DecodeError { reason: reason.to_string() }
}

// -- Encode: JSON + Schema -> Asn1 -----------------------------------------

/// Convert a semantic JSON value into its ASN.1 intermediate per the schema.
fn encode_schema(value: &Value, schema: &Schema) -> Result<Asn1, AnchorAsn1Error> {
	match schema {
		Schema::Optional(inner) => encode_schema(value, inner),
		Schema::Context(tag, inner) => {
			let contains = encode_schema(value, inner)?;
			Ok(Asn1::Context(*tag, Box::new(contains)))
		}
		Schema::Choice(alternatives) => encode_choice(value, alternatives),
		Schema::SequenceOf(inner) => encode_sequence_of(value, inner),
		Schema::Struct(fields) => encode_struct(value, fields),
		Schema::Utf8 => {
			let text = as_str(value)?;
			Ok(Asn1::Str(text.to_owned()))
		}
		Schema::Oid => {
			let name = as_str(value)?;
			let dotted = oid_from_name(name);
			Ok(Asn1::Oid(dotted))
		}
		Schema::OctetString => {
			let bytes = bytes_from_buffer_json(value)?;
			Ok(Asn1::Octets(bytes))
		}
		Schema::Date => {
			let iso = as_str(value)?;
			encode_date(iso)
		}
	}
}

/// Encode a value against the first choice alternative that accepts it.
fn encode_choice(value: &Value, alternatives: &[Schema]) -> Result<Asn1, AnchorAsn1Error> {
	alternatives
		.iter()
		.find_map(|alternative| encode_schema(value, alternative).ok())
		.ok_or_else(|| encode_error("no matching choice alternative"))
}

/// Encode a JSON array against a `SEQUENCE OF` inner schema.
fn encode_sequence_of(value: &Value, inner: &Schema) -> Result<Asn1, AnchorAsn1Error> {
	let array = value
		.as_array()
		.ok_or_else(|| encode_error("expected an array for SEQUENCE OF"))?;

	let mut items = Vec::with_capacity(array.len());
	for element in array {
		let item = encode_schema(element, inner)?;
		items.push(item);
	}

	Ok(Asn1::Seq(items))
}

/// Encode a JSON object against a struct schema, eliding absent optional members
/// and erroring on an absent required member so the caller can fall back.
fn encode_struct(value: &Value, fields: &[Field]) -> Result<Asn1, AnchorAsn1Error> {
	let map = value
		.as_object()
		.ok_or_else(|| encode_error("expected an object for SEQUENCE"))?;

	let mut components = Vec::with_capacity(fields.len());
	for field in fields {
		let present = map.get(field.name).filter(|value| !value.is_null());
		match present {
			Some(field_value) => {
				let component = encode_schema(field_value, &field.schema)?;
				components.push(component);
			}
			None if is_optional(&field.schema) => {}
			None => return Err(encode_error(format!("missing required field {}", field.name))),
		}
	}

	Ok(Asn1::Seq(components))
}

/// Borrow a JSON string, erroring when the value is not one.
fn as_str(value: &Value) -> Result<&str, AnchorAsn1Error> {
	value
		.as_str()
		.ok_or_else(|| encode_error("expected a JSON string"))
}

// -- Decode: Asn1 + Schema -> JSON -----------------------------------------

/// Convert an ASN.1 intermediate value into semantic JSON per the schema,
/// erroring on any mismatch so a choice alternative or the legacy schema can be
/// tried instead.
fn decode_schema(value: &Asn1, schema: &Schema) -> Result<Value, AnchorAsn1Error> {
	match schema {
		Schema::Optional(inner) => decode_schema(value, inner),
		Schema::Context(tag, inner) => match value {
			Asn1::Context(actual, contains) if actual == tag => decode_schema(contains, inner),
			_ => Err(decode_error("context tag mismatch")),
		},
		Schema::Choice(alternatives) => alternatives
			.iter()
			.find_map(|alternative| decode_schema(value, alternative).ok())
			.ok_or_else(|| decode_error("no matching choice alternative")),
		Schema::SequenceOf(inner) => decode_sequence_of(value, inner),
		Schema::Struct(fields) => decode_struct(value, fields),
		Schema::Utf8 => match value {
			Asn1::Str(text) => Ok(Value::String(text.clone())),
			_ => Err(decode_error("expected a string")),
		},
		Schema::Oid => match value {
			Asn1::Oid(oid) => {
				let name = oid_to_name(oid);
				Ok(Value::String(name))
			}
			_ => Err(decode_error("expected an OID")),
		},
		Schema::OctetString => match value {
			Asn1::Octets(bytes) => {
				let buffer = buffer_json(bytes);
				Ok(buffer)
			}
			_ => Err(decode_error("expected an OCTET STRING")),
		},
		Schema::Date => match value {
			Asn1::Date(time) => decode_date(time),
			_ => Err(decode_error("expected a date")),
		},
	}
}

/// Decode a `SEQUENCE OF` value into a JSON array.
fn decode_sequence_of(value: &Asn1, inner: &Schema) -> Result<Value, AnchorAsn1Error> {
	let Asn1::Seq(items) = value else {
		return Err(decode_error("expected a SEQUENCE OF"));
	};

	let mut out = Vec::with_capacity(items.len());
	for item in items {
		let decoded = decode_schema(item, inner)?;
		out.push(decoded);
	}

	Ok(Value::Array(out))
}

/// Decode a `SEQUENCE` struct into a JSON object, projecting each member the
/// positional matcher bound to a component.
fn decode_struct(value: &Asn1, fields: &[Field]) -> Result<Value, AnchorAsn1Error> {
	let Asn1::Seq(components) = value else {
		return Err(decode_error("expected a SEQUENCE"));
	};

	let schemas: Vec<&Schema> = fields.iter().map(|field| &field.schema).collect();
	let matched = match_tuple(components, &schemas).map_err(decode_error)?;
	let mut map = Map::new();
	for (field, component) in fields.iter().zip(matched) {
		if let Some(component) = component {
			let decoded = decode_schema(component, &field.schema)?;
			map.insert(field.name.to_string(), decoded);
		}
	}

	Ok(Value::Object(map))
}

// -- Dates ------------------------------------------------------------------

/// Encode an ISO-8601 string as a date leaf. `GeneralizedTime` is the canonical
/// KYC time form; the underlying codec accepts `UTCTime` only on decode.
#[cfg(feature = "chrono")]
fn encode_date(iso: &str) -> Result<Asn1, AnchorAsn1Error> {
	use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
	use keetanetwork_asn1::Asn1Time;

	let datetime = DateTime::parse_from_rfc3339(iso)
		.map(|value| value.with_timezone(&Utc))
		.or_else(|_| NaiveDateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%S%.fZ").map(|naive| naive.and_utc()))
		.or_else(|_| {
			NaiveDate::parse_from_str(iso, "%Y-%m-%d")
				.ok()
				.and_then(|date| date.and_hms_opt(0, 0, 0))
				.map(|naive| naive.and_utc())
				.ok_or(())
		})
		.map_err(|_| encode_error(format!("invalid date/time: {iso}")))?;

	Ok(Asn1::Date(Asn1Time::new(datetime)))
}

/// Render a decoded date leaf as an ISO-8601 string with millisecond precision.
#[cfg(feature = "chrono")]
fn decode_date(time: &keetanetwork_asn1::Asn1Time) -> Result<Value, AnchorAsn1Error> {
	let iso = time.as_datetime().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
	Ok(Value::String(iso))
}

/// Without `chrono`, a date cannot be rendered: its presence errors so the
/// caller falls back to the raw bytes.
#[cfg(not(feature = "chrono"))]
fn encode_date(_iso: &str) -> Result<Asn1, AnchorAsn1Error> {
	Err(encode_error("date component requires the chrono feature"))
}

/// Without `chrono`, a date cannot be encoded: presence errors so the caller
/// falls back to the raw bytes.
#[cfg(not(feature = "chrono"))]
fn decode_date(_time: &keetanetwork_asn1::Asn1Time) -> Result<Value, AnchorAsn1Error> {
	Err(decode_error("date component requires the chrono feature"))
}

// -- OID and buffer helpers -------------------------------------------------

/// The reference OID <-> symbolic-name table, mirroring the TypeScript
/// `oidMapDB`. A decoded OID renders as its symbolic name when known (else its
/// dotted-decimal form), and a symbolic name resolves back to its OID on encode.
const OID_NAME_TABLE: [(&str, &str); 14] = [
	("sha256", "2.16.840.1.101.3.4.2.1"),
	("sha3-256", "2.16.840.1.101.3.4.2.8"),
	("sha3-256WithEcDSA", "2.16.840.1.101.3.4.3.10"),
	("sha256WithEcDSA", "1.2.840.10045.4.3.2"),
	("ecdsa", "1.2.840.10045.2.1"),
	("ed25519", "1.3.101.112"),
	("secp256k1", "1.3.132.0.10"),
	("secp256r1", "1.2.840.10045.3.1.7"),
	("account", "2.23.42.2.7.11"),
	("serialNumber", "2.5.4.5"),
	("member", "2.5.4.31"),
	("commonName", "2.5.4.3"),
	("hash", "1.3.6.1.4.1.8301.3.2.2.1.1"),
	("hashData", "2.16.840.1.101.3.3.1.3"),
];

/// Render a dotted-decimal OID as its symbolic name if known, else unchanged.
fn oid_to_name(dotted: &str) -> String {
	OID_NAME_TABLE
		.iter()
		.find_map(|(name, mapped)| (*mapped == dotted).then(|| (*name).to_string()))
		.unwrap_or_else(|| dotted.to_owned())
}

/// Resolve a symbolic name to its dotted-decimal OID, passing an already-dotted
/// value through unchanged.
fn oid_from_name(name: &str) -> String {
	OID_NAME_TABLE
		.iter()
		.find_map(|(candidate, mapped)| (*candidate == name).then(|| (*mapped).to_string()))
		.unwrap_or_else(|| name.to_owned())
}

/// Render bytes as the Node `Buffer` JSON form (`{"type":"Buffer","data":[..]}`).
fn buffer_json(bytes: &[u8]) -> Value {
	let data = bytes.iter().map(|byte| Value::from(*byte)).collect();

	let mut map = Map::new();
	map.insert("type".to_string(), Value::String("Buffer".to_string()));
	map.insert("data".to_string(), Value::Array(data));

	Value::Object(map)
}

/// Parse a Node `Buffer` JSON form (`{"type":"Buffer","data":[..]}`) into bytes.
fn bytes_from_buffer_json(value: &Value) -> Result<Vec<u8>, AnchorAsn1Error> {
	let data = value
		.as_object()
		.and_then(|map| map.get("data"))
		.and_then(Value::as_array)
		.ok_or_else(|| encode_error("buffer json missing data array"))?;

	let mut out = Vec::with_capacity(data.len());
	for entry in data {
		let byte = entry
			.as_u64()
			.filter(|value| *value <= u64::from(u8::MAX))
			.ok_or_else(|| encode_error("buffer json data entry out of range"))?;
		out.push(byte as u8);
	}

	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::kyc_schema::testing::{assert_json_eq, from_hex};

	fn round_trip(token: &str, json: &str) {
		let der = encode_structured(token, json.as_bytes()).expect("encode structured");
		let decoded = decode_structured(token, &der).expect("decode structured");
		assert_json_eq(&decoded, json);
	}

	#[test]
	fn address_choice_round_trips() {
		round_trip(
			"Address",
			r#"{"addressLines":["100 Belgrave Street"],"addressType":"HOME","postalCode":"34677","townName":"Oldsmar"}"#,
		);
	}

	#[test]
	fn address_choice_is_bare_positional() -> Result<(), Box<dyn std::error::Error>> {
		// A bare CHOICE member carries its alternative's own tag: SEQUENCE { [0]
		// EXPLICIT UTF8String "HOME" } — no positional [1] wrapper.
		let der = encode_structured("Address", br#"{"addressType":"HOME"}"#)?;
		assert_eq!(der[0], 0x30);
		assert_eq!(der[2], 0xa0);
		assert_eq!(der[4], 0x0c);
		Ok(())
	}

	#[test]
	fn address_only_choice_round_trips() {
		// The bare addressType [0] collides with addressLines [0]; positional
		// backtracking must still recover the addressType.
		round_trip("Address", r#"{"addressType":"HOME"}"#);
	}

	#[test]
	fn entity_type_person_round_trips() {
		round_trip("EntityType", r#"{"person":[{"id":"123-45-6789","issuer":"US","schemeName":"SSN"}]}"#);
	}

	#[test]
	fn entity_type_person_scheme_only_round_trips() {
		// Bare schemeName [0] collides with id [0]; issuer [1] absent.
		round_trip("EntityType", r#"{"person":[{"id":"123-45-6789","schemeName":"SSN"}]}"#);
	}

	#[test]
	fn document_scalars_round_trip() {
		round_trip(
			"DocumentPassport",
			r#"{"documentNumber":"X1234567","fullName":"Jane Doe","issuingCountry":"US","nationality":"US"}"#,
		);
	}

	#[test]
	fn document_with_address_round_trips() {
		round_trip(
			"DocumentPassport",
			r#"{"documentNumber":"A7","address":{"country":"US","postalCode":"34677","townName":"Oldsmar"}}"#,
		);
	}

	#[cfg(feature = "chrono")]
	#[test]
	fn document_with_date_round_trips() {
		round_trip("DocumentPassport", r#"{"documentNumber":"P999","dob":"1990-01-01T00:00:00.000Z"}"#);
	}

	#[test]
	fn document_with_reference_round_trips() {
		round_trip(
			"DocumentPassport",
			r#"{"documentNumber":"P1","front":{"external":{"url":"https://x/y","contentType":"image/png"},"digest":{"digestAlgorithm":"sha3-256","digest":{"type":"Buffer","data":[1,2,3]}},"encryptionAlgorithm":"1.3.6.1.4.1.62675.2"}}"#,
		);
	}

	#[test]
	fn date_and_place_of_birth_round_trips() {
		round_trip(
			"DateAndPlaceOfBirth",
			r#"{"birthDate":"1990-01-01T00:00:00.000Z","cityOfBirth":"Oldsmar","countryOfBirth":"US","provinceOfBirth":"FL"}"#,
		);
	}

	#[test]
	fn contact_details_round_trips() {
		round_trip("ContactDetails", r#"{"emailAddress":"a@b.com","phoneNumber":"+15551234567"}"#);
	}

	#[test]
	fn document_malformed_reference_errors_for_fallback() {
		// A `front` missing its required members cannot encode, so the caller
		// falls back to the raw bytes rather than dropping it.
		let result = encode_structured("DocumentPassport", br#"{"documentNumber":"X","front":{}}"#);
		assert!(matches!(result, Err(AnchorAsn1Error::Asn1EncodeError { .. })));
	}

	#[test]
	fn unmapped_token_errors_for_raw_fallback() {
		assert!(matches!(
			encode_structured("Nonexistent", b"{}"),
			Err(AnchorAsn1Error::Asn1EncodeError { .. })
		));
		assert!(matches!(
			decode_structured("Nonexistent", [0x30, 0x00]),
			Err(AnchorAsn1Error::Asn1DecodeError { .. })
		));
	}

	/// Live `Address` attribute DER issued by the reference TypeScript harness.
	const ADDRESS_DER: &str = "304aa01730150c133130302042656c677261766520537472656574a4040c02464ca6070c053334363737a7150c133130302042656c677261766520537472656574a9090c074f6c64736d6172";
	/// Oracle the reference harness emits for that address.
	const ADDRESS_ORACLE: &str = r#"{"addressLines":["100 Belgrave Street"],"countrySubDivision":"FL","postalCode":"34677","streetName":"100 Belgrave Street","townName":"Oldsmar"}"#;
	/// Live `EntityType` attribute DER issued by the reference TypeScript harness.
	const ENTITY_TYPE_DER: &str = "301ca11a30183016a00d0c0b3132332d34352d36373839a0050c0353534e";
	/// Oracle the reference harness emits for that entity type.
	const ENTITY_TYPE_ORACLE: &str = r#"{"person":[{"id":"123-45-6789","schemeName":"SSN"}]}"#;

	#[test]
	fn decodes_reference_issued_address() {
		let decoded = decode_structured("Address", from_hex(ADDRESS_DER)).expect("decode address");
		assert_json_eq(&decoded, ADDRESS_ORACLE);
	}

	#[test]
	fn decodes_reference_issued_entity_type() {
		let decoded = decode_structured("EntityType", from_hex(ENTITY_TYPE_DER)).expect("decode entity type");
		assert_json_eq(&decoded, ENTITY_TYPE_ORACLE);
	}

	/// A `Document` carrying `documentNumber` and a legacy `UTCTime` `dob`.
	#[cfg(feature = "chrono")]
	const LEGACY_UTC_DOCUMENT_DER: &str = "3017a0040c025031a70f170d3930303130313030303030305a";

	#[cfg(feature = "chrono")]
	#[test]
	fn decodes_legacy_utc_time_date() {
		let decoded = decode_structured("DocumentPassport", from_hex(LEGACY_UTC_DOCUMENT_DER)).expect("decode legacy");
		assert_json_eq(&decoded, r#"{"documentNumber":"P1","dob":"1990-01-01T00:00:00.000Z"}"#);
	}
}

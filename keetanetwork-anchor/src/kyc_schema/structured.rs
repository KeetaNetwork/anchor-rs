//! Structured KYC attribute decoding to the reference `getValue()` JSON shape.
//!
//! The reference TypeScript encodes structured attributes with positional ASN.1
//! components: a `SEQUENCE` field is carried under its explicit context tag
//! (the field's position), a `SEQUENCE OF` becomes a tagged list, and a `CHOICE`
//! field is carried *bare* so the alternative's own tag survives. That bare
//! CHOICE reuses tags that collide with sibling fields, which a tag-driven
//! decoder cannot model, so the DER is walked positionally here - mirroring the
//! reference `decodeWithSchema` - and mapped straight to the oracle JSON shape.

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Map, Value};

use crate::asn1::error::AnchorAsn1Error;

/// Decode a structured attribute DER value into the oracle JSON wire form.
///
/// Returns an error for tokens without a mapping so the caller can fall back to
/// the raw bytes, mirroring the reference decoder's tolerant behaviour.
pub fn decode_structured(token: &str, der: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	let value = match token {
		"Address" => address_json(der)?,
		"EntityType" => entity_type_json(der)?,
		_ => return Err(AnchorAsn1Error::Asn1DecodeError { reason: "unmapped structured attribute".to_string() }),
	};

	serde_json::to_vec(&value).map_err(|error| AnchorAsn1Error::Asn1EncodeError { reason: error.to_string() })
}

/// A single DER tag-length-value, borrowing its contents.
struct Tlv<'a> {
	tag: u8,
	value: &'a [u8],
}

/// Read one short/long-form DER TLV, returning it and the trailing bytes.
fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), AnchorAsn1Error> {
	let truncated = || AnchorAsn1Error::Asn1DecodeError { reason: "truncated structured DER".to_string() };

	let tag = *input.first().ok_or_else(truncated)?;
	let first_len = usize::from(*input.get(1).ok_or_else(truncated)?);

	let (length, header) = if first_len < 0x80 {
		(first_len, 2)
	} else {
		let count = first_len & 0x7f;
		let bytes = input.get(2..2 + count).ok_or_else(truncated)?;
		(bytes.iter().fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte)), 2 + count)
	};

	let end = header.checked_add(length).ok_or_else(truncated)?;
	let value = input.get(header..end).ok_or_else(truncated)?;
	Ok((Tlv { tag, value }, &input[end..]))
}

/// Split a constructed value into its sequence of component TLVs.
fn components(body: &[u8]) -> Result<Vec<Tlv<'_>>, AnchorAsn1Error> {
	let mut out = Vec::new();
	let mut rest = body;
	while !rest.is_empty() {
		let (tlv, next) = read_tlv(rest)?;
		out.push(tlv);
		rest = next;
	}

	Ok(out)
}

/// Components of the top-level `SEQUENCE` in a structured attribute value.
fn sequence_components(der: &[u8]) -> Result<Vec<Tlv<'_>>, AnchorAsn1Error> {
	let (sequence, _) = read_tlv(der)?;
	components(sequence.value)
}

/// The context-specific tag number of `tag`, if it is context-class.
fn context_number(tag: u8) -> Option<u8> {
	(tag & 0xc0 == 0x80).then_some(tag & 0x1f)
}

/// Unwrap a single explicitly tagged inner TLV.
fn explicit_inner<'a>(tlv: &Tlv<'a>) -> Result<Tlv<'a>, AnchorAsn1Error> {
	Ok(read_tlv(tlv.value)?.0)
}

/// Read a leaf `UTF8String` value as an owned string.
fn utf8(tlv: &Tlv<'_>) -> Result<String, AnchorAsn1Error> {
	core::str::from_utf8(tlv.value)
		.map(ToOwned::to_owned)
		.map_err(|error| AnchorAsn1Error::Asn1DecodeError { reason: error.to_string() })
}

/// Collapse an explicit context tag (or bare CHOICE alternative) wrapping a
/// `UTF8String` to its string value.
fn context_utf8(tlv: &Tlv<'_>) -> Result<Value, AnchorAsn1Error> {
	Ok(Value::String(utf8(&explicit_inner(tlv)?)?))
}

/// Collapse an explicit context tag wrapping a `SEQUENCE OF UTF8String` to an
/// array of strings.
fn utf8_lines(tlv: &Tlv<'_>) -> Result<Value, AnchorAsn1Error> {
	let sequence_of = explicit_inner(tlv)?;
	let mut lines = Vec::new();
	for line in components(sequence_of.value)? {
		lines.push(Value::String(utf8(&line)?));
	}

	Ok(Value::Array(lines))
}

/// The wire shape of an `Address` component.
enum AddressKind {
	Scalar,
	Lines,
	Choice,
}

/// An `Address` field with its positional context tag and wire shape.
struct AddressField {
	name: &'static str,
	index: u8,
	kind: AddressKind,
}

/// `Address` fields in schema order; CHOICE fields are bare so they are matched
/// by their alternative tags rather than the positional index.
const ADDRESS_FIELDS: &[AddressField] = &[
	AddressField { name: "addressLines", index: 0, kind: AddressKind::Lines },
	AddressField { name: "addressType", index: 1, kind: AddressKind::Choice },
	AddressField { name: "buildingNumber", index: 2, kind: AddressKind::Scalar },
	AddressField { name: "country", index: 3, kind: AddressKind::Scalar },
	AddressField { name: "countrySubDivision", index: 4, kind: AddressKind::Scalar },
	AddressField { name: "department", index: 5, kind: AddressKind::Scalar },
	AddressField { name: "postalCode", index: 6, kind: AddressKind::Scalar },
	AddressField { name: "streetName", index: 7, kind: AddressKind::Scalar },
	AddressField { name: "subDepartment", index: 8, kind: AddressKind::Scalar },
	AddressField { name: "townName", index: 9, kind: AddressKind::Scalar },
];

/// Whether `tag` matches the schema position of `field`.
fn address_field_matches(field: &AddressField, tag: u8) -> bool {
	match context_number(tag) {
		Some(number) => match field.kind {
			AddressKind::Choice => number == 0 || number == 1,
			_ => number == field.index,
		},
		None => false,
	}
}

/// Map an `Address` value to its oracle object by walking fields positionally.
fn address_json(der: &[u8]) -> Result<Value, AnchorAsn1Error> {
	let parts = sequence_components(der)?;
	let mut map = Map::new();
	let mut cursor = 0;
	for field in ADDRESS_FIELDS {
		let Some(tlv) = parts.get(cursor) else {
			break;
		};

		if !address_field_matches(field, tlv.tag) {
			continue;
		}

		let value = match field.kind {
			AddressKind::Lines => utf8_lines(tlv)?,
			_ => context_utf8(tlv)?,
		};
		map.insert(field.name.to_string(), value);
		cursor += 1;
	}

	Ok(Value::Object(map))
}

/// Map an `EntityType` value to its oracle object.
fn entity_type_json(der: &[u8]) -> Result<Value, AnchorAsn1Error> {
	let mut map = Map::new();
	for tlv in sequence_components(der)? {
		match context_number(tlv.tag) {
			Some(0) => map.insert("organization".to_string(), identifications(&tlv)?),
			Some(1) => map.insert("person".to_string(), identifications(&tlv)?),
			_ => None,
		};
	}

	Ok(Value::Object(map))
}

/// Map an explicitly tagged `SEQUENCE OF` generic identification to an array.
fn identifications(field: &Tlv<'_>) -> Result<Value, AnchorAsn1Error> {
	let sequence_of = explicit_inner(field)?;
	let mut entries = Vec::new();
	for element in components(sequence_of.value)? {
		entries.push(identification_json(&element)?);
	}

	Ok(Value::Array(entries))
}

/// Map a generic person/organization identification, disambiguating the bare
/// `schemeName` CHOICE from the optional `issuer` by schema order: a context-`1`
/// component after the id is the issuer, any remaining component is the scheme.
fn identification_json(sequence: &Tlv<'_>) -> Result<Value, AnchorAsn1Error> {
	let parts = components(sequence.value)?;
	let mut map = Map::new();

	let mut cursor = 0;
	let id = parts
		.get(cursor)
		.ok_or_else(|| AnchorAsn1Error::Asn1DecodeError { reason: "identification missing id".to_string() })?;
	map.insert("id".to_string(), context_utf8(id)?);
	cursor += 1;

	if let Some(issuer) = parts.get(cursor).filter(|tlv| context_number(tlv.tag) == Some(1)) {
		map.insert("issuer".to_string(), context_utf8(issuer)?);
		cursor += 1;
	}

	if let Some(scheme) = parts.get(cursor) {
		map.insert("schemeName".to_string(), context_utf8(scheme)?);
	}

	Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Live `Address` attribute DER issued by the reference TypeScript harness.
	const ADDRESS_DER: &str = "304aa01730150c133130302042656c677261766520537472656574a4040c02464ca6070c053334363737a7150c133130302042656c677261766520537472656574a9090c074f6c64736d6172";
	/// Oracle the reference harness emits for that address.
	const ADDRESS_ORACLE: &str = r#"{"addressLines":["100 Belgrave Street"],"countrySubDivision":"FL","postalCode":"34677","streetName":"100 Belgrave Street","townName":"Oldsmar"}"#;
	/// Live `EntityType` attribute DER issued by the reference TypeScript harness.
	const ENTITY_TYPE_DER: &str = "301ca11a30183016a00d0c0b3132332d34352d36373839a0050c0353534e";
	/// Oracle the reference harness emits for that entity type.
	const ENTITY_TYPE_ORACLE: &str = r#"{"person":[{"id":"123-45-6789","schemeName":"SSN"}]}"#;

	fn from_hex(hex: &str) -> Vec<u8> {
		(0..hex.len())
			.step_by(2)
			.map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
			.collect()
	}

	fn assert_matches_oracle(token: &str, der_hex: &str, oracle: &str) {
		let decoded = decode_structured(token, &from_hex(der_hex)).unwrap();
		let actual: Value = serde_json::from_slice(&decoded).unwrap();
		let expected: Value = serde_json::from_str(oracle).unwrap();
		assert_eq!(actual, expected);
	}

	#[test]
	fn address_decodes_to_oracle_shape() {
		assert_matches_oracle("Address", ADDRESS_DER, ADDRESS_ORACLE);
	}

	#[test]
	fn entity_type_decodes_to_oracle_shape() {
		assert_matches_oracle("EntityType", ENTITY_TYPE_DER, ENTITY_TYPE_ORACLE);
	}

	#[test]
	fn unmapped_token_errors_for_raw_fallback() {
		let result = decode_structured("Document", &[0x30, 0x00]);
		assert!(result.is_err());
	}
}

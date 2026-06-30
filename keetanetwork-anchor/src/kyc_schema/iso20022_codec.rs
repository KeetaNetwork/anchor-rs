//! Structured KYC attribute codec backed by the generated rasn iso20022 types

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Map, Value};

use crate::asn1::error::AnchorAsn1Error;
use crate::iso20022::{
	Address, AddressLines, AddressType, AnonymousAddressLines, BuildingNumber, Country, CountrySubDivision, Department,
	EntityType, GenericOrganizationIdentification, GenericPersonIdentification, Id, Issuer,
	OrganizationIdentificationSchemeNameChoice, PersonIdentificationSchemeNameChoice,
	PersonIdentificationSchemeNameProprietary, PostalCode, StreetName, SubDepartment, TownName,
};

/// Encode a semantic JSON attribute value into its positional ASN.1 DER.
///
/// Returns an error for tokens without a mapping so the caller can fall back to
/// the raw bytes.
pub fn encode_structured(token: &str, json: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	let value: Value = serde_json::from_slice(json).map_err(encode_error)?;
	let der = match token {
		"Address" => rasn::der::encode(&address_from_json(&value)?)?,
		"EntityType" => rasn::der::encode(&entity_type_from_json(&value)?)?,
		_ => return Err(encode_error("unmapped structured attribute")),
	};

	Ok(der)
}

/// Decode positional ASN.1 DER into the validator JSON form.
///
/// Returns an error for tokens without a mapping, or when the DER is not in the
/// positional form, so the caller can fall back to the legacy decoder.
pub fn decode_structured(token: &str, der: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	let value = match token {
		"Address" => address_to_json(&decode_canonical::<Address>(der)?),
		"EntityType" => entity_type_to_json(&decode_canonical::<EntityType>(der)?),
		_ => return Err(decode_error("unmapped structured attribute")),
	};

	serde_json::to_vec(&value).map_err(encode_error)
}

/// Decode a rasn type, accepting only the canonical (positional) DER form.
///
/// rasn tolerates a legacy bare CHOICE by silently dropping the colliding field
/// rather than failing, so the decoded value is re-encoded and compared to the
/// input. A mismatch means the input was a legacy form and the caller should
/// fall back to the bare-CHOICE walker.
fn decode_canonical<T>(der: &[u8]) -> Result<T, AnchorAsn1Error>
where
	T: rasn::Decode + rasn::Encode,
{
	let value: T = rasn::der::decode(der)?;
	if rasn::der::encode(&value)? == der {
		Ok(value)
	} else {
		Err(decode_error("non-canonical structured DER"))
	}
}

/// Build an `Asn1EncodeError` from any displayable reason.
fn encode_error(reason: impl ToString) -> AnchorAsn1Error {
	AnchorAsn1Error::Asn1EncodeError { reason: reason.to_string() }
}

/// Build an `Asn1DecodeError` from any displayable reason.
fn decode_error(reason: impl ToString) -> AnchorAsn1Error {
	AnchorAsn1Error::Asn1DecodeError { reason: reason.to_string() }
}

/// Borrow a JSON object, erroring when the value is not one.
fn as_object(value: &Value) -> Result<&Map<String, Value>, AnchorAsn1Error> {
	value
		.as_object()
		.ok_or_else(|| encode_error("expected a JSON object"))
}

/// Read an optional UTF-8 string field, erroring when present but not a string.
fn optional_text(map: &Map<String, Value>, key: &str) -> Result<Option<String>, AnchorAsn1Error> {
	match map.get(key) {
		None | Some(Value::Null) => Ok(None),
		Some(Value::String(text)) => Ok(Some(text.to_owned())),
		Some(_) => Err(encode_error(format!("field {key} must be a string"))),
	}
}

/// Read a required UTF-8 string field.
fn required_text(map: &Map<String, Value>, key: &str) -> Result<String, AnchorAsn1Error> {
	optional_text(map, key)?.ok_or_else(|| encode_error(format!("missing field {key}")))
}

/// Convert an `Address` JSON object into its rasn type.
fn address_from_json(value: &Value) -> Result<Address, AnchorAsn1Error> {
	let map = as_object(value)?;

	Ok(Address {
		address_lines: address_lines_from_json(map)?,
		// A bare string selects the `code` alternative, matching the reference encoder.
		address_type: optional_text(map, "addressType")?.map(AddressType::code),
		building_number: optional_text(map, "buildingNumber")?.map(BuildingNumber),
		country: optional_text(map, "country")?.map(Country),
		country_sub_division: optional_text(map, "countrySubDivision")?.map(CountrySubDivision),
		department: optional_text(map, "department")?.map(Department),
		postal_code: optional_text(map, "postalCode")?.map(PostalCode),
		street_name: optional_text(map, "streetName")?.map(StreetName),
		sub_department: optional_text(map, "subDepartment")?.map(SubDepartment),
		town_name: optional_text(map, "townName")?.map(TownName),
	})
}

/// Convert the optional `addressLines` array into its rasn type.
fn address_lines_from_json(map: &Map<String, Value>) -> Result<Option<AddressLines>, AnchorAsn1Error> {
	let Some(value) = map.get("addressLines").filter(|value| !value.is_null()) else {
		return Ok(None);
	};

	let array = value
		.as_array()
		.ok_or_else(|| encode_error("addressLines must be an array"))?;

	let mut lines = Vec::with_capacity(array.len());
	for line in array {
		let text = line
			.as_str()
			.ok_or_else(|| encode_error("addressLines entries must be strings"))?;
		lines.push(AnonymousAddressLines(text.to_owned()));
	}

	Ok(Some(AddressLines(lines)))
}

/// Convert an `EntityType` JSON object into its rasn type.
fn entity_type_from_json(value: &Value) -> Result<EntityType, AnchorAsn1Error> {
	let map = as_object(value)?;

	Ok(EntityType { organization: organizations_from_json(map)?, person: persons_from_json(map)? })
}

/// Convert the optional `organization` array into generic identifications.
fn organizations_from_json(
	map: &Map<String, Value>,
) -> Result<Option<Vec<GenericOrganizationIdentification>>, AnchorAsn1Error> {
	let Some(entries) = identification_entries(map, "organization")? else {
		return Ok(None);
	};

	let mut out = Vec::with_capacity(entries.len());
	for entry in entries {
		out.push(GenericOrganizationIdentification {
			id: Id(required_text(entry, "id")?),
			issuer: optional_text(entry, "issuer")?.map(Issuer),
			scheme_name: optional_text(entry, "schemeName")?.map(OrganizationIdentificationSchemeNameChoice::code),
		});
	}

	Ok(Some(out))
}

/// Convert the optional `person` array into generic identifications.
fn persons_from_json(map: &Map<String, Value>) -> Result<Option<Vec<GenericPersonIdentification>>, AnchorAsn1Error> {
	let Some(entries) = identification_entries(map, "person")? else {
		return Ok(None);
	};

	let mut out = Vec::with_capacity(entries.len());
	for entry in entries {
		out.push(GenericPersonIdentification {
			id: Id(required_text(entry, "id")?),
			issuer: optional_text(entry, "issuer")?.map(Issuer),
			scheme_name: optional_text(entry, "schemeName")?.map(PersonIdentificationSchemeNameChoice::code),
		});
	}

	Ok(Some(out))
}

/// Borrow the array of identification objects under `key`, if present.
fn identification_entries<'a>(
	map: &'a Map<String, Value>,
	key: &str,
) -> Result<Option<Vec<&'a Map<String, Value>>>, AnchorAsn1Error> {
	let Some(value) = map.get(key).filter(|value| !value.is_null()) else {
		return Ok(None);
	};

	let array = value
		.as_array()
		.ok_or_else(|| encode_error(format!("{key} must be an array")))?;

	let mut entries = Vec::with_capacity(array.len());
	for element in array {
		entries.push(as_object(element)?);
	}

	Ok(Some(entries))
}

/// Convert a decoded `Address` into the validator JSON object.
fn address_to_json(address: &Address) -> Value {
	let mut map = Map::new();

	if let Some(lines) = &address.address_lines {
		let values = lines
			.0
			.iter()
			.map(|line| Value::String(line.0.clone()))
			.collect();
		map.insert("addressLines".to_string(), Value::Array(values));
	}
	if let Some(address_type) = &address.address_type {
		map.insert("addressType".to_string(), Value::String(address_type_text(address_type)));
	}

	insert_text(&mut map, "buildingNumber", address.building_number.as_ref().map(|value| &value.0));
	insert_text(&mut map, "country", address.country.as_ref().map(|value| &value.0));
	insert_text(&mut map, "countrySubDivision", address.country_sub_division.as_ref().map(|value| &value.0));
	insert_text(&mut map, "department", address.department.as_ref().map(|value| &value.0));
	insert_text(&mut map, "postalCode", address.postal_code.as_ref().map(|value| &value.0));
	insert_text(&mut map, "streetName", address.street_name.as_ref().map(|value| &value.0));
	insert_text(&mut map, "subDepartment", address.sub_department.as_ref().map(|value| &value.0));
	insert_text(&mut map, "townName", address.town_name.as_ref().map(|value| &value.0));

	Value::Object(map)
}

/// Convert a decoded `EntityType` into the validator JSON object.
fn entity_type_to_json(entity_type: &EntityType) -> Value {
	let mut map = Map::new();
	if let Some(organizations) = &entity_type.organization {
		let values = organizations.iter().map(organization_to_json).collect();
		map.insert("organization".to_string(), Value::Array(values));
	}
	if let Some(persons) = &entity_type.person {
		let values = persons.iter().map(person_to_json).collect();
		map.insert("person".to_string(), Value::Array(values));
	}

	Value::Object(map)
}

/// Convert a decoded generic organization identification into JSON.
fn organization_to_json(identification: &GenericOrganizationIdentification) -> Value {
	let mut map = Map::new();
	map.insert("id".to_string(), Value::String(identification.id.0.clone()));

	if let Some(issuer) = &identification.issuer {
		map.insert("issuer".to_string(), Value::String(issuer.0.clone()));
	}
	if let Some(scheme_name) = &identification.scheme_name {
		let text = match scheme_name {
			OrganizationIdentificationSchemeNameChoice::code(value) => value.clone(),
			OrganizationIdentificationSchemeNameChoice::proprietary(value) => value.clone(),
		};
		map.insert("schemeName".to_string(), Value::String(text));
	}

	Value::Object(map)
}

/// Convert a decoded generic person identification into JSON.
fn person_to_json(identification: &GenericPersonIdentification) -> Value {
	let mut map = Map::new();
	map.insert("id".to_string(), Value::String(identification.id.0.clone()));
	if let Some(issuer) = &identification.issuer {
		map.insert("issuer".to_string(), Value::String(issuer.0.clone()));
	}
	if let Some(scheme_name) = &identification.scheme_name {
		let text = match scheme_name {
			PersonIdentificationSchemeNameChoice::code(value) => value.clone(),
			PersonIdentificationSchemeNameChoice::proprietary(value) => person_proprietary_text(value).to_owned(),
		};
		map.insert("schemeName".to_string(), Value::String(text));
	}

	Value::Object(map)
}

/// The string value carried by an `AddressType` CHOICE, regardless of alternative.
fn address_type_text(address_type: &AddressType) -> String {
	match address_type {
		AddressType::code(value) => value.clone(),
		AddressType::proprietary(value) => value.clone(),
	}
}

/// The canonical token for a person-identification proprietary scheme value.
fn person_proprietary_text(value: &PersonIdentificationSchemeNameProprietary) -> &'static str {
	match value {
		PersonIdentificationSchemeNameProprietary::DRLC => "DRLC",
		PersonIdentificationSchemeNameProprietary::CPPT => "CPPT",
		PersonIdentificationSchemeNameProprietary::ARNU => "ARNU",
		PersonIdentificationSchemeNameProprietary::SSN => "SSN",
		PersonIdentificationSchemeNameProprietary::TXID => "TXID",
		PersonIdentificationSchemeNameProprietary::VISA => "VISA",
		PersonIdentificationSchemeNameProprietary::WPPT => "WPPT",
	}
}

/// Insert a string field when present, skipping `None`.
fn insert_text(map: &mut Map<String, Value>, key: &str, value: Option<&String>) {
	if let Some(text) = value {
		map.insert(key.to_string(), Value::String(text.clone()));
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::kyc_schema::testing::{assert_json_eq, from_hex};

	fn round_trip(token: &str, json: &str) {
		let der = encode_structured(token, json.as_bytes()).unwrap();
		let decoded = decode_structured(token, &der).unwrap();
		assert_json_eq(&decoded, json);
	}

	#[test]
	fn address_with_choice_round_trips() {
		round_trip(
			"Address",
			r#"{"addressLines":["100 Belgrave Street"],"addressType":"HOME","postalCode":"34677","townName":"Oldsmar"}"#,
		);
	}

	#[test]
	fn entity_type_person_round_trips() {
		round_trip("EntityType", r#"{"person":[{"id":"123-45-6789","issuer":"US","schemeName":"SSN"}]}"#);
	}

	#[test]
	fn entity_type_organization_round_trips() {
		round_trip("EntityType", r#"{"organization":[{"id":"ACME-1","schemeName":"LEI"}]}"#);
	}

	#[test]
	fn address_choice_is_wrapped_positionally() {
		let der = encode_structured("Address", br#"{"addressType":"HOME"}"#).unwrap();
		// SEQUENCE { [1] EXPLICIT { [0] EXPLICIT UTF8String "HOME" } }
		assert_eq!(der[0], 0x30);
		assert_eq!(der[2], 0xa1);
		assert_eq!(der[4], 0xa0);
		assert_eq!(der[6], 0x0c);
	}

	#[test]
	fn unmapped_token_errors_for_raw_fallback() {
		assert!(matches!(encode_structured("Document", b"{}"), Err(AnchorAsn1Error::Asn1EncodeError { .. })));
		assert!(matches!(decode_structured("Document", &[0x30, 0x00]), Err(AnchorAsn1Error::Asn1DecodeError { .. })));
	}

	#[test]
	fn bare_legacy_choice_is_rejected_for_fallback() {
		// Legacy EntityType with a bare `schemeName` CHOICE: the alternative's own
		// [0] tag collides with the `id` field, so the positional decoder must
		// reject it and let the caller fall back to the legacy walker.
		let bare = from_hex("301ca11a30183016a00d0c0b3132332d34352d36373839a0050c0353534e");
		assert!(decode_structured("EntityType", &bare).is_err());
	}
}

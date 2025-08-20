use asn1::Encode;
use rasn::types::ObjectIdentifier;

use crate::asn1::error::AnchorAsn1Error;
use crate::asn1::{ALGORITHM_ATTRIBUTE_OIDS, SENSITIVE_ATTRIBUTE_OIDS};

/// Lookup algorithm name by OID
pub fn get_algorithm_by_oid(oid: &ObjectIdentifier) -> Result<&'static str, AnchorAsn1Error> {
	ALGORITHM_ATTRIBUTE_OIDS
		.iter()
		.find(|(_, stored_oid)| *stored_oid == oid)
		.map(|(name, _)| *name)
		.ok_or_else(|| AnchorAsn1Error::InvalidOid { message: format!("Unknown algorithm OID: {oid}") })
}

/// Get OID for certificate attribute
pub fn get_sensitive_attribute_oid<T: AsRef<str>>(name: T) -> Result<ObjectIdentifier, AnchorAsn1Error> {
	let name_str = name.as_ref();
	SENSITIVE_ATTRIBUTE_OIDS
		.get(name_str)
		.cloned()
		.ok_or_else(|| AnchorAsn1Error::InvalidOid { message: format!("Unknown sensitive attribute: {name_str}") })
}

/// Convert an asn1 ObjectIdentifier to a rasn ObjectIdentifier via DER bytes.
#[allow(dead_code)]
pub(crate) fn as_rasn_oid(oid: asn1::ObjectIdentifier) -> Result<rasn::types::ObjectIdentifier, AnchorAsn1Error> {
	// Convert asn1 OID to DER bytes
	let der_bytes = oid.to_der().map_err(|e| AnchorAsn1Error::InvalidOid {
		message: format!("Failed to encode ObjectIdentifier to DER: {e:?}"),
	})?;

	// Decode the DER bytes as a rasn ObjectIdentifier using BER decoder
	let rasn_oid = rasn::ber::decode::<rasn::types::ObjectIdentifier>(&der_bytes)
		.map_err(|e| AnchorAsn1Error::InvalidOid { message: format!("Failed to decode ObjectIdentifier: {e:?}") })?;

	Ok(rasn_oid)
}

/// Parse an OID string into a rasn ObjectIdentifier.
///
/// Takes a string like "1.2.3.4.5" and converts it to an ObjectIdentifier
pub fn parse_oid_string<S: AsRef<str>>(oid_str: S) -> Result<ObjectIdentifier, AnchorAsn1Error> {
	let oid_str = oid_str.as_ref();

	// Parse OID string into u32 arcs
	let arcs: Result<Vec<u32>, _> = oid_str.split('.').map(|s| s.parse::<u32>()).collect();
	let arcs = match arcs {
		Ok(arcs) => arcs,
		Err(e) => return Err(AnchorAsn1Error::InvalidOid { message: format!("Failed to parse OID '{oid_str}': {e}") }),
	};

	// Create ObjectIdentifier from arcs
	match ObjectIdentifier::new(arcs) {
		Some(oid) => Ok(oid),
		None => {
			Err(AnchorAsn1Error::InvalidOid { message: format!("Failed to create ObjectIdentifier from '{oid_str}'") })
		}
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use super::*;
	use crate::asn1::AES_256_GCM_OID;

	#[test]
	fn test_get_algorithm_by_oid() {
		const ALGORITHM_TEST_DATA: &[(&ObjectIdentifier, Option<&str>)] = &[(&AES_256_GCM_OID, Some("aes-256-gcm"))];
		for (oid, expected_name) in ALGORITHM_TEST_DATA {
			let result = get_algorithm_by_oid(oid);
			match expected_name {
				Some(name) => {
					assert!(result.is_ok());
					assert_eq!(result.unwrap(), *name);
				}
				None => assert!(result.is_err()),
			}
		}

		// Test invalid OID
		let invalid_oid = ObjectIdentifier::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
		let invalid_result = get_algorithm_by_oid(&invalid_oid);
		assert!(invalid_result.is_err());
	}

	#[test]
	fn test_get_certificate_attribute_oid() {
		const SENSITIVE_ATTRIBUTE_TEST_DATA: &[(&str, bool)] = &[("fullName", true), ("invalid", false)];
		for (name, should_succeed) in SENSITIVE_ATTRIBUTE_TEST_DATA {
			// Test with &str
			let result = get_sensitive_attribute_oid(*name);
			assert_eq!(result.is_ok(), *should_succeed);

			// Test with String
			let string_result = get_sensitive_attribute_oid(String::from(*name));
			assert_eq!(string_result.is_ok(), *should_succeed);
		}
	}

	#[test]
	fn test_as_rasn_oid() {
		const AS_RASN_OID_TEST_DATA: &[&str] = &["1.2.3.4", "1.2.3.4.5.6.7.8.9.10.11.12"];
		for oid_str in AS_RASN_OID_TEST_DATA {
			let asn1_oid = asn1::ObjectIdentifier::from_str(oid_str).unwrap();
			let rasn_oid = as_rasn_oid(asn1_oid);
			assert!(rasn_oid.is_ok());

			// Verify round-trip encoding
			let rasn_der = rasn::ber::encode(&rasn_oid.unwrap()).unwrap();
			let asn1_der = asn1_oid.to_der().unwrap();
			assert_eq!(rasn_der, asn1_der);
		}
	}

	#[test]
	fn test_parse_oid_string() {
		const OID_STRING_TEST_DATA: &[(&str, bool)] = &[
			("1.2.3", true),
			("1.2.3.4.5", true),
			("0.9.2342.19200300.100.1.25", true),
			("invalid.oid", false),
			("1.2.abc", false),
			("", false),
			("1..3", false),
			("1.2.", false),
			("99.2.3", false),
		];

		for (oid_str, should_succeed) in OID_STRING_TEST_DATA {
			// Test with &str
			let result = parse_oid_string(*oid_str);
			assert_eq!(result.is_ok(), *should_succeed);

			// Test with String
			let string_result = parse_oid_string(String::from(*oid_str));
			assert_eq!(string_result.is_ok(), *should_succeed);
		}
	}
}

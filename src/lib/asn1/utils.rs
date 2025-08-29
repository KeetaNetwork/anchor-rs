use rasn::types::ObjectIdentifier;

use crate::asn1::error::AnchorAsn1Error;
use crate::asn1::oids;

/// Lookup algorithm name by OID
#[allow(dead_code)]
pub(crate) fn get_algorithm_by_oid(oid: &ObjectIdentifier) -> Result<&'static str, AnchorAsn1Error> {
	oids::ALGORITHM_ATTRIBUTES
		.iter()
		.find(|(_, stored_oid)| *stored_oid == oid)
		.map(|(name, _)| *name)
		.ok_or_else(|| AnchorAsn1Error::InvalidOid { reason: format!("Unknown algorithm OID: {oid}") })
}

/// Get OID for certificate attribute
pub(crate) fn get_sensitive_attribute_oid<T: AsRef<str>>(name: T) -> Result<ObjectIdentifier, AnchorAsn1Error> {
	let name_str = name.as_ref();
	oids::keeta::SENSITIVE_ATTRIBUTES
		.get(name_str)
		.cloned()
		.ok_or_else(|| AnchorAsn1Error::InvalidOid { reason: format!("Unknown sensitive attribute: {name_str}") })
}

pub(crate) fn get_plain_attribute_oid<T: AsRef<str>>(name: T) -> Result<ObjectIdentifier, AnchorAsn1Error> {
	let name_str = name.as_ref();
	oids::PLAIN_ATTRIBUTES
		.get(name_str)
		.cloned()
		.ok_or_else(|| AnchorAsn1Error::InvalidOid { reason: format!("Unknown plain attribute: {name_str}") })
}

/// Parse an OID string into a rasn `ObjectIdentifier`. This is required
/// because `ObjectIdentifier` does not implement `FromStr` for some reason.
///
/// Takes a string like "1.2.3.4.5" and converts it to an ObjectIdentifier
pub fn parse_oid_string<S: AsRef<str>>(oid_str: S) -> Result<ObjectIdentifier, AnchorAsn1Error> {
	let oid_str = oid_str.as_ref();
	// Parse OID string into u32 arcs
	let arcs: Result<Vec<u32>, _> = oid_str.split('.').map(|s| s.parse::<u32>()).collect();
	let arcs = match arcs {
		Ok(arcs) => arcs,
		Err(e) => return Err(AnchorAsn1Error::InvalidOid { reason: format!("Failed to parse OID '{oid_str}': {e}") }),
	};

	// Create ObjectIdentifier from arcs
	match ObjectIdentifier::new(arcs) {
		Some(oid) => Ok(oid),
		None => {
			Err(AnchorAsn1Error::InvalidOid { reason: format!("Failed to create ObjectIdentifier from '{oid_str}'") })
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::oids;

	#[test]
	fn test_get_algorithm_by_oid() {
		const ALGORITHM_TEST_DATA: &[(&ObjectIdentifier, Option<&str>)] = &[(&oids::AES_256_GCM, Some("aes-256-gcm"))];
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
		const SENSITIVE_ATTRIBUTE_TEST_DATA: &[(&str, bool)] =
			&[("fullName", true), ("email", true), ("invalid", false)];
		for (name, should_succeed) in SENSITIVE_ATTRIBUTE_TEST_DATA {
			let result = get_sensitive_attribute_oid(*name);
			assert_eq!(result.is_ok(), *should_succeed);

			if *should_succeed {
				// Verify specific expected values for known attributes
				match *name {
					"fullName" => assert_eq!(result.unwrap(), oids::keeta::FULL_NAME),
					"email" => assert_eq!(result.unwrap(), oids::keeta::EMAIL),
					_ => {}
				}
			}
		}

		// Test with String type explicitly
		let string_result = get_sensitive_attribute_oid(String::from("fullName"));
		assert!(string_result.is_ok());
		assert_eq!(string_result.unwrap(), oids::keeta::FULL_NAME);

		// Test invalid attribute with String
		let invalid_string_result = get_sensitive_attribute_oid(String::from("definitely_invalid"));
		assert!(invalid_string_result.is_err());
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

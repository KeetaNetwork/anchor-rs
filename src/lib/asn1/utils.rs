use asn1::Encode;
use rasn::types::ObjectIdentifier;

use crate::asn1::error::Asn1Error;
use crate::asn1::{ALGORITHM_ATTRIBUTE_OIDS, SENSITIVE_ATTRIBUTE_OIDS};

/// Lookup algorithm name by OID
pub fn get_algorithm_by_oid(oid: &ObjectIdentifier) -> Result<&'static str, Asn1Error> {
	ALGORITHM_ATTRIBUTE_OIDS
		.iter()
		.find(|(_, stored_oid)| *stored_oid == oid)
		.map(|(name, _)| *name)
		.ok_or_else(|| Asn1Error::InvalidOid { message: format!("Unknown algorithm OID: {oid}") })
}

/// Get OID for certificate attribute
pub fn get_certificate_attribute_oid<T: AsRef<str>>(name: T) -> Result<ObjectIdentifier, Asn1Error> {
	let name_str = name.as_ref();
	SENSITIVE_ATTRIBUTE_OIDS
		.get(name_str)
		.cloned()
		.ok_or_else(|| Asn1Error::InvalidOid { message: format!("Unknown sensitive attribute: {name_str}") })
}

/// Convert an asn1 ObjectIdentifier to a rasn ObjectIdentifier via DER bytes.
#[allow(dead_code)]
pub(crate) fn as_rasn_oid(oid: asn1::ObjectIdentifier) -> Result<rasn::types::ObjectIdentifier, Asn1Error> {
	// Convert asn1 OID to DER bytes
	let der_bytes = oid
		.to_der()
		.map_err(|e| Asn1Error::InvalidOid { message: format!("Failed to encode ObjectIdentifier to DER: {e:?}") })?;

	// Decode the DER bytes as a rasn ObjectIdentifier using BER decoder
	let rasn_oid = rasn::ber::decode::<rasn::types::ObjectIdentifier>(&der_bytes)
		.map_err(|e| Asn1Error::InvalidOid { message: format!("Failed to decode ObjectIdentifier: {e:?}") })?;

	Ok(rasn_oid)
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use super::*;
	use crate::asn1::AES_256_GCM_OID;

	#[test]
	fn test_get_algorithm_by_oid() {
		// Test valid OID
		let result = get_algorithm_by_oid(&AES_256_GCM_OID);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), "aes-256-gcm");

		// Test invalid OID
		let invalid_oid = ObjectIdentifier::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
		let invalid_result = get_algorithm_by_oid(&invalid_oid);
		assert!(invalid_result.is_err());
	}

	#[test]
	fn test_get_certificate_attribute_oid() {
		let result = get_certificate_attribute_oid("fullName");
		assert!(result.is_ok());

		let invalid_result = get_certificate_attribute_oid("invalid");
		assert!(invalid_result.is_err());
	}

	#[test]
	fn test_as_rasn_oid() {
		// Test successful conversion
		let asn1_oid = asn1::ObjectIdentifier::from_str("1.2.3.4").unwrap();
		let rasn_oid = as_rasn_oid(asn1_oid);
		assert!(rasn_oid.is_ok());

		// Verify round-trip encoding
		let rasn_der = rasn::ber::encode(&rasn_oid.unwrap()).unwrap();
		let asn1_der = asn1_oid.to_der().unwrap();
		assert_eq!(rasn_der, asn1_der);

		// Test BER decode error path with corrupted data
		let valid_oid = asn1::ObjectIdentifier::from_str("1.2.3.4").unwrap();
		let mut corrupted_bytes = valid_oid.to_der().unwrap();
		corrupted_bytes[0] = 0xFF; // Invalid tag
		let decode_result = rasn::ber::decode::<rasn::types::ObjectIdentifier>(&corrupted_bytes);
		assert!(decode_result.is_err());

		// Test with longer OID
		let long_oid = asn1::ObjectIdentifier::from_str("1.2.3.4.5.6.7.8.9.10.11.12").unwrap();
		let result = as_rasn_oid(long_oid);
		assert!(result.is_ok());
	}
}

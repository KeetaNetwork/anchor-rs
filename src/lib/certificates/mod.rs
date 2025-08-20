pub mod builder;
pub mod error;
pub mod utils;

use accounts::{Account, KeyPair};
use crypto::prelude::ExposeSecret;
use x509::certificates::Certificate as X509Certificate;

use crate::asn1::utils::get_sensitive_attribute_oid;
use crate::asn1::KYC_ATTRIBUTES_EXTENSION_OID;
use crate::generated::KYCAttributes;
use crate::kyc_schema::Attribute;
use crate::sensitive_attributes::SensitiveAttribute;

// Re-export commonly used types
pub use builder::CertificateBuilder;
pub use error::CertificateError;
// Re-export generated types
pub use crate::generated::{Attribute as KycAttribute, AttributeValue as KycAttributeValue};

/// Extended certificate that supports KYC attributes
#[derive(Debug, Clone)]
pub struct Certificate {
	/// The underlying X.509 certificate
	inner: X509Certificate,
	/// Parsed KYC attributes from the certificate
	kyc_attributes: KYCAttributes,
}

impl Certificate {
	/// Create a new certificate wrapper
	pub fn new(x509_cert: X509Certificate) -> Self {
		let kyc_attributes = Self::parse_kyc_attributes(&x509_cert);

		Self { inner: x509_cert, kyc_attributes }
	}

	/// Get the underlying X.509 certificate
	pub fn to_x509(&self) -> &X509Certificate {
		&self.inner
	}

	/// Get the parsed KYC attributes
	pub fn kyc_attributes(&self) -> &KYCAttributes {
		&self.kyc_attributes
	}

	/// Get a specific KYC attribute by name
	pub fn get_kyc_attribute(&self, name: &str) -> Option<&Attribute> {
		let oid = get_sensitive_attribute_oid(name).ok()?;
		self.kyc_attributes.find_by_object_identifier(&oid)
	}

	/// Decrypt a sensitive KYC attribute value
	pub fn decrypt_kyc_attribute<T: KeyPair>(&self, name: &str, keypair: &T) -> Result<Vec<u8>, CertificateError>
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
	{
		let attribute = self
			.get_kyc_attribute(name)
			.ok_or_else(|| CertificateError::AttributeNotFound { name: name.to_string() })?;

		if !attribute.is_sensitive() {
			return Err(CertificateError::InvalidAttributeValue {
				name: name.to_string(),
				reason: "Attribute is not sensitive".to_string(),
			});
		}

		// Decode the sensitive attribute from DER
		let sensitive_attr: SensitiveAttribute = rasn::der::decode(attribute.as_ref())?;

		// Decrypt the value
		let decrypted = sensitive_attr.decrypt(keypair)?;
		Ok(decrypted.expose_secret().clone())
	}

	/// Get a plain text KYC attribute value
	pub fn get_plain_kyc_attribute(&self, name: &str) -> Result<Vec<u8>, CertificateError> {
		let attribute = self
			.get_kyc_attribute(name)
			.ok_or_else(|| CertificateError::AttributeNotFound { name: name.to_string() })?;

		if attribute.is_sensitive() {
			return Err(CertificateError::InvalidAttributeValue {
				name: name.to_string(),
				reason: "Attribute is sensitive and requires decryption".to_string(),
			});
		}

		Ok(attribute.as_ref().to_vec())
	}

	/// Parse KYC attributes from an X.509 certificate
	fn parse_kyc_attributes(x509_cert: &X509Certificate) -> KYCAttributes {
		// Try to find the KYC attributes extension
		if let Some(extension) = x509_cert.get_extension(KYC_ATTRIBUTES_EXTENSION_OID.to_string()) {
			// Try to decode the extension value
			if let Ok(kyc_attrs) = rasn::der::decode::<KYCAttributes>(extension.value.as_bytes()) {
				return kyc_attrs;
			}
		}

		// Return empty attributes if not found or parsing failed
		KYCAttributes::new()
	}

	/// Check if the certificate has any KYC attributes
	pub fn has_kyc_attributes(&self) -> bool {
		!self.kyc_attributes.is_empty()
	}

	/// Get the number of KYC attributes
	pub fn kyc_attribute_count(&self) -> usize {
		self.kyc_attributes.count()
	}
}

#[cfg(test)]
mod tests {
	use accounts::Account;
	use crypto::bigint::U256;
	use crypto::prelude::{CryptoSignerWithOptions, SignatureEncoding};
	use x509::certificates::CertificateBuilder as X509CertificateBuilder;
	use x509::utils::create_dn;

	use super::*;
	use crate::certificates::CertificateBuilder;
	use crate::testing::create_account_from_seed;

	/// Helper function to create a test X.509 certificate.
	fn create_test_x509_cert() -> X509Certificate {
		// Create a minimal X.509 certificate for testing
		let subject_dn = create_dn(&[(x509::oids::CN, "Test")]).unwrap();
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let public_key = account.keypair.to_public_key().unwrap();

		X509CertificateBuilder::new()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(subject_dn)
			.with_subject_public_key(public_key.into())
			.with_serial_number(U256::from(1u64))
			.with_validity_days(365)
			.build(&account.keypair)
			.unwrap()
	}

	#[test]
	fn test_certificate_without_kyc_attributes() {
		let cert = Certificate::new(create_test_x509_cert());
		assert!(!cert.has_kyc_attributes());
		assert_eq!(cert.kyc_attribute_count(), 0);
		assert!(cert.get_kyc_attribute("fullName").is_none());

		// Test Certificate.to_x509
		let x509_cert = cert.to_x509();
		// Just check that we can access the X509 certificate
		assert!(x509_cert
			.get_extension(KYC_ATTRIBUTES_EXTENSION_OID.to_string())
			.is_none());

		// Test Certificate.kyc_attributes
		let kyc_attrs = cert.kyc_attributes();
		assert_eq!(kyc_attrs.count(), 0);
	}

	#[test]
	fn test_certificate_attribute_errors() {
		let cert = Certificate::new(create_test_x509_cert());
		let result = cert.get_plain_kyc_attribute("nonExistent");
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::AttributeNotFound { .. }));
	}

	fn test_certificate_building_functionality<T, S>(account: Account<T>)
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		const TEST_ATTRIBUTES: &[(&str, &str, bool)] =
			&[("fullName", "John Doe", false), ("email", "john@example.com", true)];

		let subject_dn = x509::utils::create_dn(&[(x509::oids::CN, "Test Subject")]).unwrap();
		let public_key = account.keypair.to_public_key().unwrap();
		let mut builder = CertificateBuilder::for_end_entity()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(subject_dn)
			.with_serial_number(U256::from(12345u64))
			.with_validity_days(365)
			.with_subject_public_key(public_key.into());

		// Add test attributes
		for (name, value, sensitive) in TEST_ATTRIBUTES.iter() {
			builder = if *sensitive {
				builder.with_sensitive_attribute(name, value).unwrap()
			} else {
				builder.with_plain_attribute(name, value).unwrap()
			};
		}

		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();

		// Verify certificate has KYC attributes
		assert!(certificate.has_kyc_attributes());
		assert_eq!(certificate.kyc_attribute_count(), 2);

		// Test Certificate.kyc_attributes() method when KYC attributes are present
		let kyc_attrs = certificate.kyc_attributes();
		assert_eq!(kyc_attrs.count(), 2);

		// Test both plain and sensitive attributes
		for (name, value, sensitive) in TEST_ATTRIBUTES.iter() {
			if *sensitive {
				let decrypted = certificate
					.decrypt_kyc_attribute(name, &account.keypair)
					.unwrap();
				assert_eq!(decrypted, value.as_bytes());
			} else {
				let plain = certificate.get_plain_kyc_attribute(name).unwrap();
				assert_eq!(plain, value.as_bytes());
			}
		}

		// Test error cases
		assert!(certificate.get_kyc_attribute("nonExistent").is_none());
	}

	crate::test_all_key_types!(test_certificate_building, test_certificate_building_functionality);

	fn test_certificate_attribute_type_errors<T, S>(account: Account<T>)
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		let subject_dn = x509::utils::create_dn(&[(x509::oids::CN, "Test Subject")]).unwrap();
		let public_key = account.keypair.to_public_key().unwrap();
		let builder = CertificateBuilder::for_end_entity()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(subject_dn)
			.with_serial_number(U256::from(12345u64))
			.with_validity_days(365)
			.with_subject_public_key(public_key.into())
			.with_plain_attribute("fullName", "Jane Smith")
			.unwrap()
			.with_sensitive_attribute("email", "jane@example.com")
			.unwrap();

		// Test trying to decrypt a plain attribute
		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();
		let result = certificate.decrypt_kyc_attribute("fullName", &account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::InvalidAttributeValue { .. }));

		// Test trying to get a sensitive attribute as plain
		let result = certificate.get_plain_kyc_attribute("email");
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::InvalidAttributeValue { .. }));
	}

	crate::test_all_key_types!(test_certificate_type_errors, test_certificate_attribute_type_errors);
}

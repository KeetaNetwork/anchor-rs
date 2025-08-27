pub mod builder;
pub mod error;

use accounts::KeyPair;
use crypto::prelude::ExposeSecret;
use x509::certificates::Certificate as X509Certificate;

use crate::asn1::oids;
use crate::asn1::utils::get_sensitive_attribute_oid;
use crate::generated::KYCAttributes;
use crate::kyc_schema::Attribute;
use crate::sensitive_attributes::utils::{assert_attribute_is_plain, assert_attribute_is_sensitive};
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
	pub fn new(inner: X509Certificate) -> Self {
		let kyc_attributes = Self::parse_kyc_attributes(&inner);
		Self { inner, kyc_attributes }
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
	pub fn get_kyc_attribute<N: AsRef<str>>(&self, name: N) -> Option<&Attribute> {
		let oid = get_sensitive_attribute_oid(name.as_ref()).ok()?;
		self.kyc_attributes.find_by_oid(&oid)
	}

	/// Decrypt a sensitive KYC attribute value
	pub fn decrypt_kyc_attribute<K, N>(&self, name: N, keypair: &K) -> Result<Vec<u8>, CertificateError>
	where
		K: KeyPair,
		N: AsRef<str>,
	{
		let name_str = name.as_ref();
		let attribute = self
			.get_kyc_attribute(name_str)
			.ok_or_else(|| CertificateError::AttributeNotFound { name: name_str.to_string() })?;

		assert_attribute_is_sensitive(attribute, name_str)?;

		// Decode the sensitive attribute from DER
		let sensitive_attr: SensitiveAttribute = rasn::der::decode(attribute.as_ref())?;
		let decrypted = sensitive_attr.decrypt(keypair)?;
		Ok(decrypted.expose_secret().clone())
	}

	/// Get a plain text KYC attribute value
	pub fn get_plain_kyc_attribute<N: AsRef<str>>(&self, name: N) -> Result<Vec<u8>, CertificateError> {
		let name_str = name.as_ref();
		let attribute = self
			.get_kyc_attribute(name_str)
			.ok_or_else(|| CertificateError::AttributeNotFound { name: name_str.to_string() })?;

		assert_attribute_is_plain(attribute, name_str)?;

		Ok(attribute.as_ref().to_vec())
	}

	/// Parse KYC attributes from an X.509 certificate
	fn parse_kyc_attributes(x509_cert: &X509Certificate) -> KYCAttributes {
		// Try to find the KYC attributes extension
		if let Some(extension) = x509_cert.get_extension(oids::keeta::KYC_ATTRIBUTES_EXTENSION.to_string()) {
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
	use crypto::prelude::{CryptoSignerWithOptions, IntoSecret, SignatureEncoding};
	use x509::certificates::CertificateBuilder as X509CertificateBuilder;
	use x509::utils::create_dn;

	use super::*;
	use crate::testing::{create_account_from_seed, create_test_certificate_builder};

	/// Helper function to create a test X.509 certificate.
	fn create_test_x509_cert() -> X509Certificate {
		// Create a minimal X.509 certificate for testing
		let subject_dn = create_dn(&[(x509::oids::CN, "Test")]).unwrap();
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let public_key = account.keypair.to_public_key();

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
			.get_extension(oids::keeta::KYC_ATTRIBUTES_EXTENSION.to_string())
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

		let mut builder = create_test_certificate_builder(&account);
		for (name, value, sensitive) in TEST_ATTRIBUTES.iter() {
			// Add test attributes
			builder = if *sensitive {
				let sensitive_attribute = value.as_bytes().to_vec();
				builder
					.with_sensitive_attribute(name, sensitive_attribute.into_secret())
					.unwrap()
			} else {
				builder.with_plain_attribute(name, value).unwrap()
			};
		}

		// Verify certificate has KYC attributes
		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();
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
		let sensitive_attribute = "jane@example.com".as_bytes().to_vec();
		let builder = create_test_certificate_builder(&account)
			.with_plain_attribute("fullName", "Jane Smith")
			.unwrap()
			.with_sensitive_attribute("email", sensitive_attribute.into_secret())
			.unwrap();

		// Test trying to decrypt a plain attribute
		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();
		let result = certificate.decrypt_kyc_attribute("fullName", &account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::SensitiveAttributeError { .. }));

		// Test trying to get a sensitive attribute as plain
		let result = certificate.get_plain_kyc_attribute("email");
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::SensitiveAttributeError { .. }));
	}

	crate::test_all_key_types!(test_certificate_type_errors, test_certificate_attribute_type_errors);
}

use std::collections::HashMap;

use accounts::{Account, KeyPair};
use asn1::SubjectPublicKeyInfo;
use crypto::bigint::U256;
use crypto::prelude::{CryptoSignerWithOptions, ExposeSecret, SignatureEncoding};
use x509::certificates::{Certificate as X509Certificate, CertificateBuilder as X509CertificateBuilder, Extension};
use x509::DistinguishedName;

use crate::asn1::utils::get_sensitive_attribute_oid;
use crate::asn1::KYC_ATTRIBUTES_EXTENSION_OID;
use crate::certificates::error::CertificateError;
use crate::kyc_schema::{Attribute, AttributeBuilder, KYCAttributes};
use crate::sensitive_attributes::{SensitiveAttribute, SensitiveAttributeBuilder};

/// Extended certificate builder that supports KYC attributes.
///
/// This builder extends the base X.509 certificate builder with support
/// for Keeta KYC attributes, both plain text and sensitive (encrypted).
#[derive(Debug, Clone)]
pub struct CertificateBuilder {
	/// The underlying X.509 certificate builder
	inner: X509CertificateBuilder,
	/// KYC attributes to include in the certificate
	kyc_attributes: HashMap<String, KycAttributeEntry>,
}

/// Internal representation of a KYC attribute entry.
#[derive(Debug, Clone)]
struct KycAttributeEntry {
	/// Whether this attribute is sensitive (encrypted)
	sensitive: bool,
	/// The attribute value (plain text or binary data)
	value: Vec<u8>,
}

impl CertificateBuilder {
	/// Create a new certificate builder
	pub fn new() -> Self {
		Self::default()
	}

	/// Create a certificate builder for an end-entity certificate
	pub fn for_end_entity() -> Self {
		Self { inner: X509CertificateBuilder::for_end_entity(), kyc_attributes: HashMap::new() }
	}

	/// Create a certificate builder for a CA certificate
	pub fn for_ca() -> Self {
		Self { inner: X509CertificateBuilder::for_ca(), kyc_attributes: HashMap::new() }
	}

	/// Set a KYC attribute to a given value
	///
	/// # Parameters
	/// * `name` - The attribute name (e.g., "fullName", "email")
	/// * `sensitive` - Whether to encrypt this attribute
	/// * `value` - The attribute value (string or binary data)
	pub fn with_kyc_attribute<V: AsRef<[u8]>>(
		mut self,
		name: &str,
		sensitive: bool,
		value: V,
	) -> Result<Self, CertificateError> {
		// Validate the attribute name
		get_sensitive_attribute_oid(name)?;

		self.kyc_attributes
			.insert(name.to_string(), KycAttributeEntry { sensitive, value: value.as_ref().to_vec() });

		Ok(self)
	}

	/// Set a plain text KYC attribute
	pub fn with_plain_attribute<V: AsRef<[u8]>>(self, name: &str, value: V) -> Result<Self, CertificateError> {
		self.with_kyc_attribute(name, false, value)
	}

	/// Set a sensitive (encrypted) KYC attribute
	pub fn with_sensitive_attribute<V: AsRef<[u8]>>(self, name: &str, value: V) -> Result<Self, CertificateError> {
		self.with_kyc_attribute(name, true, value)
	}

	/// Set the subject distinguished name
	pub fn with_subject_dn(mut self, subject_dn: DistinguishedName) -> Self {
		self.inner = self.inner.with_subject_dn(subject_dn);
		self
	}

	/// Set the issuer distinguished name
	pub fn with_issuer_dn(mut self, issuer_dn: DistinguishedName) -> Self {
		self.inner = self.inner.with_issuer_dn(issuer_dn);
		self
	}

	/// Set the serial number
	pub fn with_serial_number(mut self, serial: U256) -> Self {
		self.inner = self.inner.with_serial_number(serial);
		self
	}

	/// Set the validity period in days from now
	pub fn with_validity_days(mut self, days: u64) -> Self {
		self.inner = self.inner.with_validity_days(days);
		self
	}

	/// Set the subject public key
	pub fn with_subject_public_key(mut self, public_key: SubjectPublicKeyInfo) -> Self {
		self.inner = self.inner.with_subject_public_key(public_key);
		self
	}

	/// Set whether this is a CA certificate
	pub fn with_is_ca(mut self, is_ca: bool) -> Self {
		self.inner = self.inner.with_is_ca(is_ca);
		self
	}

	/// Add a custom X.509 extension
	pub fn with_extension(mut self, extension: Extension) -> Self {
		self.inner = self.inner.with_extension(extension);
		self
	}

	/// Add basic constraints extension
	pub fn with_basic_constraints(mut self, is_ca: bool, path_length: Option<u8>) -> Self {
		self.inner = self.inner.with_basic_constraints(is_ca, path_length);
		self
	}

	/// Add key usage extension
	pub fn with_key_usage(mut self, key_usage_bits: u16) -> Self {
		self.inner = self.inner.with_key_usage(key_usage_bits);
		self
	}

	/// Build the certificate with KYC attributes
	///
	/// This method creates the X.509 certificate and includes any KYC attributes
	/// as a custom extension. Sensitive attributes are encrypted using the
	/// subject's keypair.
	pub fn build<T: KeyPair, S>(
		mut self,
		subject_keypair: &T,
		signing_keypair: &T,
	) -> Result<Certificate, CertificateError>
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// If we have KYC attributes, add them as an extension
		if !self.kyc_attributes.is_empty() {
			let kyc_extension = self.build_kyc_extension(subject_keypair)?;
			self.inner = self.inner.with_extension(kyc_extension);
		}

		// Build the underlying X.509 certificate
		let x509_cert = self.inner.build(signing_keypair)?;

		// Wrap it in our Certificate type
		Ok(Certificate::new(x509_cert))
	}

	/// Build the KYC attributes extension
	fn build_kyc_extension<T: KeyPair>(&self, subject_keypair: &T) -> Result<Extension, CertificateError>
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
	{
		let mut kyc_attributes = KYCAttributes::new();

		for (name, entry) in &self.kyc_attributes {
			let oid = get_sensitive_attribute_oid(name)?;
			let kyc_attr = if entry.sensitive {
				// Create a sensitive attribute
				let sensitive_attr = SensitiveAttributeBuilder::new()
					.with_value(entry.value.clone())
					.build(subject_keypair)?;

				// Encode the sensitive attribute to DER
				let sensitive_der = rasn::der::encode(&sensitive_attr)?;

				AttributeBuilder::new()
					.with_oid(oid.to_string())
					.with_value(sensitive_der)
					.as_sensitive()
					.build()?
			} else {
				// Create a plain attribute
				AttributeBuilder::new()
					.with_oid(oid.to_string())
					.with_value(&entry.value)
					.as_plain()
					.build()?
			};

			kyc_attributes.add_attribute(kyc_attr);
		}

		// Encode the KYC attributes to DER
		let kyc_der = rasn::der::encode(&kyc_attributes)?;

		// Create the extension
		Ok(Extension::new(KYC_ATTRIBUTES_EXTENSION_OID.to_string(), kyc_der, false)?)
	}
}

impl Default for CertificateBuilder {
	fn default() -> Self {
		Self { inner: X509CertificateBuilder::new(), kyc_attributes: HashMap::new() }
	}
}

/// Extended certificate that supports KYC attributes
#[derive(Debug, Clone)]
pub struct Certificate {
	/// The underlying X.509 certificate
	inner: X509Certificate,
	/// Parsed KYC attributes from the certificate
	kyc_attributes: KYCAttributes,
	// TODO: Fix dyn KeyPair issue
	// subject_keypair: Option<Box<dyn KeyPair>>,
}

impl Certificate {
	/// Create a new certificate wrapper
	pub fn new(x509_cert: X509Certificate) -> Self {
		let kyc_attributes = Self::parse_kyc_attributes(&x509_cert);

		Self {
			inner: x509_cert,
			kyc_attributes,
			// subject_keypair: None,
		}
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
	use x509::certificates::ExtensionBuilder;
	use x509::utils::create_dn;
	use x509::DistinguishedName;

	use super::*;
	use crate::testing::create_account_from_seed;

	const TEST_ATTRIBUTES: &[(&str, &str, bool)] = &[
		("fullName", "John Doe", false),
		("email", "john@example.com", true),
		("dateOfBirth", "1990-01-01", false),
		("address", "123 Main St", true),
		("phoneNumber", "+1-555-123-4567", false),
	];

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
	fn test_certificate_builder_creation() {
		let builders = [
			("new", CertificateBuilder::new()),
			("for_end_entity", CertificateBuilder::for_end_entity()),
			("for_ca", CertificateBuilder::for_ca()),
			("default", CertificateBuilder::default()),
		];

		for (name, builder) in builders {
			assert!(builder.kyc_attributes.is_empty(), "Builder {name} should have empty attributes");
		}
	}

	#[test]
	fn test_kyc_attribute_setting() {
		let mut builder = CertificateBuilder::new();

		for (name, value, sensitive) in TEST_ATTRIBUTES {
			builder = if *sensitive {
				builder.with_sensitive_attribute(name, value).unwrap()
			} else {
				builder.with_plain_attribute(name, value).unwrap()
			};
		}

		assert_eq!(builder.kyc_attributes.len(), TEST_ATTRIBUTES.len());

		for (name, value, sensitive) in TEST_ATTRIBUTES {
			let entry = &builder.kyc_attributes[*name];
			assert_eq!(entry.sensitive, *sensitive);
			assert_eq!(entry.value, value.as_bytes());
		}
	}

	#[test]
	fn test_builder_chaining() {
		let subject_dn = DistinguishedName::new();
		let issuer_dn = DistinguishedName::new();
		let serial = U256::from(12345u64);

		// Create a test extension using ExtensionBuilder (use key usage as a simple example)
		let test_extension = ExtensionBuilder::for_key_usage(0x01).build().unwrap();
		let builder = CertificateBuilder::new()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(issuer_dn.clone())
			.with_serial_number(serial)
			.with_validity_days(365)
			.with_is_ca(true)
			.with_key_usage(0x01)
			.with_basic_constraints(true, Some(5))
			.with_extension(test_extension); // Test with_extension method

		// Test that chaining worked
		assert_eq!(builder.kyc_attributes.len(), 0);
	}

	#[test]
	fn test_invalid_attribute_name() {
		let invalid_names = ["invalidAttribute", "unknown", ""];
		for name in invalid_names {
			let result = CertificateBuilder::new().with_plain_attribute(name, "value");
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), CertificateError::Asn1Error { .. }));
		}
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
		let subject_dn = x509::utils::create_dn(&[(x509::oids::CN, "Test Subject")]).unwrap();
		let public_key = account.keypair.to_public_key().unwrap();
		let mut builder = CertificateBuilder::for_end_entity()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(subject_dn)
			.with_serial_number(U256::from(12345u64))
			.with_validity_days(365)
			.with_subject_public_key(public_key.into());

		// Add test attributes
		for (name, value, sensitive) in TEST_ATTRIBUTES.iter().take(2) {
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
		for (name, value, sensitive) in TEST_ATTRIBUTES.iter().take(2) {
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

		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();

		// Test trying to decrypt a plain attribute
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

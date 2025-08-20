use std::collections::HashMap;

use accounts::{Account, KeyPair};
use asn1::SubjectPublicKeyInfo;
use crypto::bigint::U256;
use crypto::prelude::{CryptoSignerWithOptions, ExposeSecret, SecretBox, SignatureEncoding};
use x509::certificates::{CertificateBuilder as X509CertificateBuilder, Extension, ExtensionBuilder};
use x509::DistinguishedName;

use crate::asn1::utils::get_sensitive_attribute_oid;
use crate::asn1::KYC_ATTRIBUTES_EXTENSION_OID;
use crate::certificates::{Certificate, CertificateError};
use crate::kyc_schema::{AttributeBuilder, KYCAttributes};
use crate::sensitive_attributes::SensitiveAttributeBuilder;

/// Extended certificate builder that supports KYC attributes.
///
/// This builder extends the base X.509 certificate builder with support
/// for Keeta KYC attributes, both plain text and sensitive (encrypted).
#[derive(Debug)]
pub struct CertificateBuilder {
	/// The underlying X.509 certificate builder
	inner: X509CertificateBuilder,
	/// KYC attributes to include in the certificate
	kyc_attributes: HashMap<String, KycAttributeEntry>,
}

/// Internal representation of a KYC attribute entry.
#[derive(Debug)]
pub enum KycAttributeEntry {
	/// Plain text attribute value
	PlainText(Vec<u8>),
	/// Sensitive attribute value
	Sensitive(SecretBox<Vec<u8>>),
}

impl From<&KycAttributeEntry> for SensitiveAttributeBuilder {
	fn from(entry: &KycAttributeEntry) -> Self {
		let builder = SensitiveAttributeBuilder::new();
		match entry {
			KycAttributeEntry::PlainText(value) => builder.with_value(value.to_vec()),
			KycAttributeEntry::Sensitive(secret_value) => {
				let sensitive_value = secret_value.expose_secret();
				builder.with_value(sensitive_value.clone())
			}
		}
	}
}

impl From<KycAttributeEntry> for SensitiveAttributeBuilder {
	fn from(entry: KycAttributeEntry) -> Self {
		(&entry).into()
	}
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
	/// * `entry` - The attribute entry (plain text or sensitive)
	pub fn with_kyc_attribute<N: AsRef<str>>(
		mut self,
		name: N,
		entry: KycAttributeEntry,
	) -> Result<Self, CertificateError> {
		let name = name.as_ref();

		// Validate the attribute name
		get_sensitive_attribute_oid(name)?;

		self.kyc_attributes.insert(name.to_string(), entry);
		Ok(self)
	}

	/// Set a plain text KYC attribute
	pub fn with_plain_attribute<V: AsRef<[u8]>, N: AsRef<str>>(
		self,
		name: N,
		value: V,
	) -> Result<Self, CertificateError> {
		let entry = KycAttributeEntry::PlainText(value.as_ref().to_vec());
		self.with_kyc_attribute(name, entry)
	}

	/// Set a sensitive (encrypted) KYC attribute
	pub fn with_sensitive_attribute<N: AsRef<str>>(
		self,
		name: N,
		value: SecretBox<Vec<u8>>,
	) -> Result<Self, CertificateError> {
		let entry = KycAttributeEntry::Sensitive(value);
		self.with_kyc_attribute(name, entry)
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
	pub fn build<T, S>(mut self, subject_keypair: &T, signing_keypair: &T) -> Result<Certificate, CertificateError>
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// If we have KYC attributes, add them as an extension
		if !self.kyc_attributes.is_empty() {
			let kyc_extension = self.build_kyc_extension(subject_keypair)?;
			self.inner = self.inner.with_extension(kyc_extension);
		}

		// Build the underlying X.509 certificate
		let x509_cert = self.inner.build(signing_keypair)?;
		Ok(Certificate::new(x509_cert))
	}

	/// Build the KYC attributes extension.
	fn build_kyc_extension<T: KeyPair>(&self, subject_keypair: &T) -> Result<Extension, CertificateError>
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
	{
		let mut kyc_attributes = KYCAttributes::new();
		for (name, entry) in &self.kyc_attributes {
			let oid = get_sensitive_attribute_oid(name)?;
			let attribute_builder = AttributeBuilder::new().with_oid(oid.to_string());
			let attribute_builder = match entry {
				KycAttributeEntry::PlainText(value) => attribute_builder.with_value(value).as_plain(),
				KycAttributeEntry::Sensitive(_) => {
					let sensitive_attribute_builder = SensitiveAttributeBuilder::from(entry);
					let sensitive_value = sensitive_attribute_builder.build(subject_keypair)?;

					attribute_builder
						.with_value(sensitive_value.to_der()?)
						.as_sensitive()
				}
			};

			kyc_attributes.add_attribute(attribute_builder.build()?)
		}

		// Create the extension using ExtensionBuilder
		ExtensionBuilder::new()
			.with_oid(KYC_ATTRIBUTES_EXTENSION_OID.to_string())
			.with_value(rasn::der::encode(&kyc_attributes)?)
			.with_critical(false)
			.build()
			.map_err(Into::into)
	}
}

impl Default for CertificateBuilder {
	fn default() -> Self {
		Self { inner: X509CertificateBuilder::new(), kyc_attributes: HashMap::new() }
	}
}

#[cfg(test)]
mod tests {
	use accounts::IntoSecret;
	use crypto::prelude::ExposeSecret;
	use x509::certificates::ExtensionBuilder;
	use x509::DistinguishedName;

	use super::*;
	use crate::testing::create_test_certificate_builder;

	const TEST_ATTRIBUTES: &[(&str, &str, bool)] = &[
		("fullName", "John Doe", false),
		("email", "john@example.com", true),
		("dateOfBirth", "1990-01-01", false),
		("address", "123 Main St", true),
		("phoneNumber", "+1-555-123-4567", false),
	];

	#[test]
	fn test_certificate_builder_creation() {
		let builders = [
			CertificateBuilder::new(),
			CertificateBuilder::for_end_entity(),
			CertificateBuilder::for_ca(),
			CertificateBuilder::default(),
		];

		for builder in builders {
			assert!(builder.kyc_attributes.is_empty());
		}
	}

	#[test]
	fn test_kyc_attribute_setting() {
		let mut builder = CertificateBuilder::new();
		for (name, value, sensitive) in TEST_ATTRIBUTES {
			builder = if *sensitive {
				builder
					.with_sensitive_attribute(name, value.as_bytes().to_vec().into_secret())
					.unwrap()
			} else {
				builder.with_plain_attribute(name, value).unwrap()
			};
		}

		assert_eq!(builder.kyc_attributes.len(), TEST_ATTRIBUTES.len());

		for (name, value, _sensitive) in TEST_ATTRIBUTES {
			match &builder.kyc_attributes[*name] {
				KycAttributeEntry::Sensitive(secret_value) => {
					assert_eq!(secret_value.expose_secret(), value.as_bytes());
				}
				KycAttributeEntry::PlainText(plain_value) => {
					assert_eq!(plain_value, value.as_bytes());
				}
			}
		}
	}

	#[test]
	fn test_builder_chaining() {
		let subject_dn = DistinguishedName::new();
		let issuer_dn = DistinguishedName::new();
		let serial = U256::from(12345u64);

		// Create a test extension using ExtensionBuilder
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

	fn test_kyc_attribute_entry_from_conversion<T, S>(account: Account<T>)
	where
		Account<T>: TryFrom<accounts::Accountable<T>, Error = accounts::AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		const TEST_PLAIN_DATA: &[u8] = b"plain test value";
		const TEST_SENSITIVE_DATA: &[u8] = b"sensitive test value";

		// Test PlainText variant conversion
		let plain_entry = KycAttributeEntry::PlainText(TEST_PLAIN_DATA.to_vec());
		let plain_builder = SensitiveAttributeBuilder::from(plain_entry);
		let plain_sensitive_attr = plain_builder.build(&account.keypair);
		assert!(plain_sensitive_attr.is_ok());

		// Ensure we can decrypt the sensitive attribute
		let plain_sensitive_attr = plain_sensitive_attr.unwrap();
		let decrypted_value = plain_sensitive_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_value.expose_secret(), TEST_PLAIN_DATA);

		// Test Sensitive variant conversion
		let sensitive_value = TEST_SENSITIVE_DATA.to_vec().into_secret();
		let sensitive_entry = KycAttributeEntry::Sensitive(sensitive_value);
		let sensitive_builder = SensitiveAttributeBuilder::from(sensitive_entry);
		let sensitive_sensitive_attr = sensitive_builder.build(&account.keypair);
		assert!(sensitive_sensitive_attr.is_ok());

		let sensitive_sensitive_attr = sensitive_sensitive_attr.unwrap();
		let decrypted_value = sensitive_sensitive_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_value.expose_secret(), TEST_SENSITIVE_DATA);

		// Build a certificate with both converted attributes using the helper
		let builder = create_test_certificate_builder(&account)
			.with_plain_attribute("fullName", TEST_PLAIN_DATA)
			.unwrap()
			.with_sensitive_attribute("email", TEST_SENSITIVE_DATA.to_vec().into_secret())
			.unwrap();

		// Verify the certificate builds successfully
		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();
		assert!(certificate.has_kyc_attributes());
		assert_eq!(certificate.kyc_attribute_count(), 2);

		// Verify we can decrypt the sensitive attribute
		let decrypted = certificate
			.decrypt_kyc_attribute("email", &account.keypair)
			.unwrap();
		assert_eq!(decrypted, TEST_SENSITIVE_DATA);

		// Verify we can get the plain attribute
		let plain = certificate.get_plain_kyc_attribute("fullName").unwrap();
		assert_eq!(plain, TEST_PLAIN_DATA);
	}

	crate::test_all_key_types!(
		test_kyc_attribute_entry_from_conversion_with_all_key_types,
		test_kyc_attribute_entry_from_conversion
	);
}

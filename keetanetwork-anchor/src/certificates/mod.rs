//! Certificate Module
//!
//! This module provides functionality for working with X.509 certificates that
//! contain KYC (Know Your Customer) attributes. It extends standard X.509
//! certificates with the ability to embed, parse, and access structured KYC
//! data within certificate extensions.
//!
//! # Overview
//!
//! The module provides:
//! - [`Certificate`] - A wrapper around X.509 certificates with KYC support
//! - [`CertificateBuilder`] - A builder for creating certificates with KYC attributes
//!
//! # Basic Usage
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! # use keetanetwork_x509::utils::create_dn;
//! # use keetanetwork_asn1::SubjectPublicKeyInfo;
//! use keetanetwork_anchor::certificates::{Certificate, CertificateBuilder};
//! use keetanetwork_anchor::asn1::oids;
//! use keetanetwork_crypto::prelude::IntoSecret;
//! use keetanetwork_x509::SerialNumber;
//!
//! # // Create separate issuer and subject accounts
//! # let issuer_account = doc_utils::create_secp256k1_test_account(Some(0));
//! # let subject_account = doc_utils::create_secp256k1_test_account(Some(1));
//! # let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Subject")])?;
//! # let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Issuer")])?;
//! # let subject_public_key_info = SubjectPublicKeyInfo::try_from(&subject_account)?;
//!
//! // Create a certificate with KYC attributes
//! let certificate = CertificateBuilder::for_end_entity()
//!     .with_subject_dn(subject_dn)
//!     .with_issuer_dn(issuer_dn)
//!     .with_serial_number(SerialNumber::from(12345u64))
//!     .with_validity_days(365)
//!     .with_subject_public_key(subject_public_key_info)
//!     .with_plain_attribute("postalCode", "12345")
//!     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
//!     .build(&subject_account.keypair, &issuer_account.keypair)?;
//!
//! // Access KYC attributes
//! assert!(certificate.has_kyc_attributes());
//! assert_eq!(certificate.kyc_attribute_count(), 2);
//!
//! // Get plain text attributes
//! let postal_code = certificate.get_plain_kyc_attribute("postalCode")?;
//! assert_eq!(postal_code, b"12345");
//!
//! // Decrypt sensitive attributes (requires subject's keypair)
//! let email = certificate.decrypt_kyc_attribute("email", &subject_account.keypair)?;
//! assert_eq!(email, b"john@example.com");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Working with Existing Certificates
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::certificates::Certificate;
//! use keetanetwork_x509::certificates::Certificate as X509Certificate;
//!
//! // Wrap an existing X.509 certificate
//! # let x509_cert = doc_utils::create_test_x509_cert();
//! let certificate = Certificate::new(x509_cert);
//!
//! // Check if it contains KYC attributes
//! if certificate.has_kyc_attributes() {
//!     println!("Certificate contains {} KYC attributes", certificate.kyc_attribute_count());
//!     
//!     // Access the underlying KYC data
//!     let kyc_attributes = certificate.kyc_attributes();
//!     for attr in kyc_attributes.iter() {
//!         println!("Attribute OID: {}, Sensitive: {}",
//!                  attr.name.to_string(), attr.is_sensitive());
//!     }
//! }
//! ```
//!
//! # Error Handling
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::certificates::{Certificate, CertificateError};
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! # let certificate = doc_utils::create_test_x509_cert();
//! # let certificate = Certificate::new(certificate);
//!
//! // Handle missing attributes
//! match certificate.get_plain_kyc_attribute("nonExistent") {
//!     Ok(value) => println!("Attribute value: {:?}", value),
//!     Err(CertificateError::AttributeNotFound { name }) => {
//!         println!("Attribute '{}' not found", name);
//!     }
//!     Err(e) => println!("Other error: {:?}", e),
//! }
//!
//! // Handle type mismatches
//! match certificate.decrypt_kyc_attribute("plainAttribute", &account.keypair) {
//!     Ok(value) => println!("Decrypted: {:?}", value),
//!     Err(CertificateError::SensitiveAttributeError { .. }) => {
//!         println!("Tried to decrypt a plain text attribute");
//!     }
//!     Err(e) => println!("Other error: {:?}", e),
//! }
//! ```

pub mod builder;
pub mod error;

use alloc::string::ToString;
use alloc::vec::Vec;

use keetanetwork_account::KeyPair;
use keetanetwork_crypto::prelude::ExposeSecret;
use keetanetwork_x509::certificates::Certificate as X509Certificate;

use crate::asn1::oids;
use crate::asn1::utils::{get_plain_attribute_oid, get_sensitive_attribute_oid};
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
///
/// This struct wraps a standard X.509 certificate and provides additional
/// functionality for accessing KYC (Know Your Customer) attributes that are
/// embedded in certificate extensions. It automatically parses KYC data when
/// the certificate is created and provides convenient methods for accessing
/// both plain text and sensitive (encrypted) attributes.
///
/// # Examples
///
/// ```rust
/// # use keetanetwork_anchor::doc_utils;
/// use keetanetwork_anchor::certificates::Certificate;
/// use keetanetwork_x509::certificates::Certificate as X509Certificate;
///
/// // Wrap an existing X.509 certificate
/// # let x509_cert = doc_utils::create_test_x509_cert();
/// let certificate = Certificate::new(x509_cert);
///
/// // Check for KYC attributes
/// if certificate.has_kyc_attributes() {
///     println!("Found {} KYC attributes", certificate.kyc_attribute_count());
/// } else {
///     println!("No KYC attributes found");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Certificate {
	/// The underlying X.509 certificate
	inner: X509Certificate,
	/// Parsed KYC attributes from the certificate
	kyc_attributes: KYCAttributes,
}

impl Certificate {
	/// Create a new certificate wrapper
	///
	/// Wraps an existing X.509 certificate and automatically parses any KYC
	/// attributes found in the certificate extensions. If no KYC attributes
	/// are found or parsing fails, an empty collection is used.
	///
	/// # Arguments
	///
	/// - `inner` - The X.509 certificate to wrap
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::Certificate;
	///
	/// # let x509_cert = doc_utils::create_test_x509_cert();
	/// let certificate = Certificate::new(x509_cert);
	/// assert!(!certificate.has_kyc_attributes()); // Test cert has no KYC data
	/// ```
	pub fn new(inner: X509Certificate) -> Self {
		let kyc_attributes = Self::parse_kyc_attributes(&inner);
		Self { inner, kyc_attributes }
	}

	/// Get the underlying X.509 certificate
	///
	/// Returns a reference to the wrapped X.509 certificate, allowing access
	/// to standard certificate fields and operations.
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::Certificate;
	///
	/// # let x509_cert = doc_utils::create_test_x509_cert();
	/// let certificate = Certificate::new(x509_cert);
	/// let x509_ref = certificate.to_x509();
	/// // Now you can use standard X.509 certificate methods
	/// ```
	pub fn to_x509(&self) -> &X509Certificate {
		&self.inner
	}

	/// Get the parsed KYC attributes
	///
	/// Returns a reference to the collection of KYC attributes parsed from
	/// the certificate. This provides direct access to the attributes for
	/// iteration and advanced operations.
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	///
	/// # let subject_account = doc_utils::create_secp256k1_test_account(Some(0));
	/// # let issuer_account = doc_utils::create_secp256k1_test_account(Some(1));
	/// # let certificate = doc_utils::create_test_certificate_builder(&subject_account)
	/// #     .with_sensitive_attribute("fullName", b"John Doe".to_vec().into_secret())
	/// #     .build(&subject_account.keypair, &issuer_account.keypair)?;
	/// let kyc_attributes = certificate.kyc_attributes();
	/// for attr in kyc_attributes.iter() {
	///     println!("OID: {}, Sensitive: {}", attr.name, attr.is_sensitive());
	/// }
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn kyc_attributes(&self) -> &KYCAttributes {
		&self.kyc_attributes
	}

	/// Get a specific KYC attribute by name
	///
	/// Searches for a KYC attribute with the given name and returns a reference
	/// to it if found. The name should correspond to a known attribute identifier.
	///
	/// # Arguments
	///
	/// - `name` - The attribute name to search for
	///
	/// # Returns
	///
	/// - `Some(_)` - If the attribute is found
	/// - `None` - If the attribute is not found or the name is invalid
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// # let certificate = doc_utils::create_test_certificate_builder(&account)
	/// #     .with_sensitive_attribute("fullName", b"John Doe".to_vec().into_secret())
	/// #     .build(&account.keypair, &account.keypair)?;
	/// if let Some(name_attr) = certificate.get_kyc_attribute("fullName") {
	///     println!("Found name attribute: {}", name_attr.is_sensitive());
	/// } else {
	///     println!("Name attribute not found");
	/// }
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn get_kyc_attribute<N: AsRef<str>>(&self, name: N) -> Option<&Attribute> {
		let name_str = name.as_ref();

		// Try sensitive attribute OID first
		if let Ok(oid) = get_sensitive_attribute_oid(name_str) {
			if let Some(attr) = self.kyc_attributes.find_by_oid(&oid) {
				return Some(attr);
			}
		}

		// Try plain attribute OID if sensitive didn't work
		if let Ok(oid) = get_plain_attribute_oid(name_str) {
			if let Some(attr) = self.kyc_attributes.find_by_oid(&oid) {
				return Some(attr);
			}
		}

		None
	}

	/// Decrypt a sensitive KYC attribute value
	///
	/// Retrieves and decrypts a sensitive KYC attribute using the provided keypair.
	/// The attribute must exist in the certificate and must be marked as sensitive.
	///
	/// # Arguments
	///
	/// - `name` - The name of the attribute to decrypt
	/// - `keypair` - The keypair to use for decryption
	///
	/// # Returns
	///
	/// - `Ok(_)` - The decrypted attribute value
	/// - `Err(_)` - If the attribute is not found, not sensitive, or decryption fails
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	///
	/// # let subject_account = doc_utils::create_secp256k1_test_account(Some(0));
	/// # let issuer_account = doc_utils::create_secp256k1_test_account(Some(1));
	/// # let certificate = doc_utils::create_test_certificate_builder(&subject_account)
	/// #     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
	/// #     .build(&subject_account.keypair, &issuer_account.keypair)?;
	/// // Note: Must use subject's keypair to decrypt, not issuer's
	/// let email = certificate.decrypt_kyc_attribute("email", &subject_account.keypair)?;
	/// assert_eq!(email, b"john@example.com");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
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
	///
	/// Retrieves a plain text KYC attribute value. The attribute must exist
	/// in the certificate and must be marked as plain text (not sensitive).
	///
	/// # Arguments
	///
	/// - `name` - The name of the attribute to retrieve
	///
	/// # Returns
	///
	/// - `Ok(_)` - The plain text attribute value
	/// - `Err(_)` - If the attribute is not found or is marked as sensitive
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// # let certificate = doc_utils::create_test_certificate_builder(&account)
	/// #     .with_plain_attribute("postalCode", "12345")
	/// #     .build(&account.keypair, &account.keypair)?;
	/// let postal_code = certificate.get_plain_kyc_attribute("postalCode")?;
	/// assert_eq!(postal_code, b"12345");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn get_plain_kyc_attribute<N: AsRef<str>>(&self, name: N) -> Result<Vec<u8>, CertificateError> {
		let name_str = name.as_ref();
		let attribute = self
			.get_kyc_attribute(name_str)
			.ok_or_else(|| CertificateError::AttributeNotFound { name: name_str.to_string() })?;

		assert_attribute_is_plain(attribute, name_str)?;

		Ok(attribute.as_ref().to_vec())
	}

	/// Parse KYC attributes from an X.509 certificate
	///
	/// Internal method that extracts and parses KYC attributes from the
	/// certificate's extensions. If no KYC extension is found or parsing
	/// fails, returns an empty KYC attributes collection.
	fn parse_kyc_attributes(x509_cert: &X509Certificate) -> KYCAttributes {
		// Try to find the KYC attributes extension
		if let Some(extension) = x509_cert.extension(oids::keeta::KYC_ATTRIBUTES_EXTENSION.to_string()) {
			// Try to decode the extension value
			if let Ok(kyc_attrs) = rasn::der::decode::<KYCAttributes>(extension.extn_value.as_bytes()) {
				return kyc_attrs;
			}
		}

		// Return empty attributes if not found or parsing failed
		KYCAttributes::new()
	}

	/// Check if the certificate has any KYC attributes
	///
	/// # Returns
	///
	/// - `true` if the certificate contains one or more KYC attributes,
	/// - `false` if it contains none.
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::Certificate;
	///
	/// # let x509_cert = doc_utils::create_test_x509_cert();
	/// let certificate = Certificate::new(x509_cert);
	/// if certificate.has_kyc_attributes() {
	///     println!("Certificate has KYC data");
	/// } else {
	///     println!("Standard certificate without KYC data");
	/// }
	/// ```
	pub fn has_kyc_attributes(&self) -> bool {
		!self.kyc_attributes.is_empty()
	}

	/// Get the number of KYC attributes
	///
	/// # Returns
	///
	/// - The total count of KYC attributes (both plain and sensitive)
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// # let certificate = doc_utils::create_test_certificate_builder(&account)
	/// #     .with_plain_attribute("postalCode", "12345")
	/// #     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
	/// #     .build(&account.keypair, &account.keypair)?;
	/// assert_eq!(certificate.kyc_attribute_count(), 2);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn kyc_attribute_count(&self) -> usize {
		self.kyc_attributes.count()
	}
}

#[cfg(test)]
mod tests {
	use keetanetwork_account::{Account, AccountError, Accountable, KeyECDSASECP256K1};
	use keetanetwork_crypto::prelude::{CryptoSignerWithOptions, IntoSecret, SignatureEncoding};
	use keetanetwork_x509::certificates::CertificateBuilder as X509CertificateBuilder;
	use keetanetwork_x509::utils::create_dn;
	use keetanetwork_x509::SerialNumber;

	use super::*;
	use crate::testing::{create_account_from_seed, create_test_certificate_builder};

	/// Helper function to create a test X.509 certificate.
	fn create_test_x509_cert() -> X509Certificate {
		// Create a minimal X.509 certificate for testing
		let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test")]).unwrap();
		let account = create_account_from_seed::<KeyECDSASECP256K1>(0);
		let public_key = account.keypair.to_public_key();

		X509CertificateBuilder::new()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(subject_dn)
			.with_subject_public_key(public_key.into())
			.with_serial_number(SerialNumber::from(1u64))
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
			.extension(oids::keeta::KYC_ATTRIBUTES_EXTENSION.to_string())
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
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		const TEST_ATTRIBUTES: &[(&str, &str, bool)] =
			&[("postalCode", "12345", false), ("fullName", "John Doe", true), ("email", "john@example.com", true)];

		let mut builder = create_test_certificate_builder(&account);
		for (name, value, sensitive) in TEST_ATTRIBUTES.iter() {
			// Add test attributes
			builder = if *sensitive {
				let sensitive_attribute = value.as_bytes().to_vec();
				builder.with_sensitive_attribute(name, sensitive_attribute.into_secret())
			} else {
				builder.with_plain_attribute(name, value)
			};
		}

		// Verify certificate has KYC attributes
		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();
		assert!(certificate.has_kyc_attributes());
		assert_eq!(certificate.kyc_attribute_count(), 3);

		// Test Certificate.kyc_attributes() method when KYC attributes are present
		let kyc_attrs = certificate.kyc_attributes();
		assert_eq!(kyc_attrs.count(), 3);

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

		let decrypt_result = certificate.decrypt_kyc_attribute("nonExistent", &account.keypair);
		assert!(decrypt_result.is_err());
		assert!(matches!(decrypt_result.unwrap_err(), CertificateError::AttributeNotFound { .. }));

		let plain_result = certificate.get_plain_kyc_attribute("nonExistent");
		assert!(plain_result.is_err());
		assert!(matches!(plain_result.unwrap_err(), CertificateError::AttributeNotFound { .. }));
	}

	crate::test_all_key_types!(test_certificate_building, test_certificate_building_functionality);

	fn test_certificate_attribute_type_errors<T, S>(account: Account<T>)
	where
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		let sensitive_attribute = "jane@example.com".as_bytes().to_vec();
		let builder = create_test_certificate_builder(&account)
			.with_plain_attribute("postalCode", "12345")
			.with_sensitive_attribute("email", sensitive_attribute.into_secret());

		// Test trying to decrypt a plain attribute
		let certificate = builder.build(&account.keypair, &account.keypair).unwrap();
		let result = certificate.decrypt_kyc_attribute("postalCode", &account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::SensitiveAttributeError { .. }));

		// Test trying to get a sensitive attribute as plain
		let result = certificate.get_plain_kyc_attribute("email");
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CertificateError::SensitiveAttributeError { .. }));
	}

	crate::test_all_key_types!(test_certificate_type_errors, test_certificate_attribute_type_errors);
}

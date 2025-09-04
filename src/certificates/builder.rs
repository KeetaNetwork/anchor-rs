//! Certificate Builder Module
//!
//! This module provides a fluent API for constructing X.509 certificates with
//! embedded KYC (Know Your Customer) attributes. It extends the standard X.509
//! certificate builder with support for both plain text and sensitive data.
//!
//! # Overview
//!
//! The module provides:
//! - [`CertificateBuilder`] - A builder for creating certificates with KYC attributes
//! - [`KycAttributeEntry`] - Internal representation for KYC attribute values
//!
//! # Basic Usage
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::certificates::CertificateBuilder;
//! use keetanetwork_asn1::SubjectPublicKeyInfo;
//! use keetanetwork_crypto::prelude::IntoSecret;
//! use keetanetwork_x509::SerialNumber;
//! use keetanetwork_x509::utils::create_dn;
//! use keetanetwork_x509::oids;
//!
//! # let subject_account = doc_utils::create_secp256k1_test_account(Some(0));
//! # let issuer_account = doc_utils::create_secp256k1_test_account(Some(1));
//! # let issuer_dn = create_dn(&[(oids::CN, "Test Issuer")])?;
//!
//! // Create a distinguished name for the subject
//! let subject_dn = create_dn(&[(oids::CN, "Test Subject")])?;
//! // Get the subject public key info from the subject's account
//! let subject_public_key_info = SubjectPublicKeyInfo::try_from(&subject_account)?;
//! // Create a certificate with KYC attributes
//! let certificate = CertificateBuilder::for_end_entity()
//!     .with_subject_dn(subject_dn)
//!     .with_issuer_dn(issuer_dn)
//!     .with_serial_number(SerialNumber::from(12345u64))
//!     .with_validity_days(365)
//!     .with_subject_public_key(subject_public_key_info)
//!     .with_sensitive_attribute("fullName", b"John Doe".to_vec().into_secret())
//!     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
//!     .build(&subject_account.keypair, &issuer_account.keypair)?;
//!
//! // The certificate now contains both standard X.509 fields and KYC attributes
//! assert!(certificate.has_kyc_attributes());
//! assert_eq!(certificate.kyc_attribute_count(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Creating Different Certificate Types
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! # use keetanetwork_x509::utils::create_dn;
//! # use keetanetwork_asn1::SubjectPublicKeyInfo;
//! # use keetanetwork_x509::oids;
//! use keetanetwork_anchor::certificates::CertificateBuilder;
//! use keetanetwork_x509::SerialNumber;
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! # let dn = create_dn(&[(oids::CN, "Test")]).unwrap();
//! # let public_key_info = SubjectPublicKeyInfo::try_from(&account).unwrap();
//!
//! // End-entity certificate (default for user certificates)
//! let end_entity_cert = CertificateBuilder::for_end_entity()
//!     .with_subject_dn(dn.clone())
//!     .with_issuer_dn(dn.clone())
//!     .with_serial_number(SerialNumber::from(1u64))
//!     .with_validity_days(365)
//!     .with_subject_public_key(public_key_info.clone())
//!     .build(&account.keypair, &account.keypair)?;
//!
//! // CA certificate (for certificate authorities)
//! let ca_cert = CertificateBuilder::for_ca()
//!     .with_subject_dn(dn.clone())
//!     .with_issuer_dn(dn)
//!     .with_serial_number(SerialNumber::from(2u64))
//!     .with_validity_days(3650) // 10 years for CA
//!     .with_subject_public_key(public_key_info)
//!     .with_basic_constraints(true, Some(5)) // CA with path length 5
//!     .build(&account.keypair, &account.keypair)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Working with KYC Attributes
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::certificates::CertificateBuilder;
//! use keetanetwork_crypto::prelude::{IntoSecret, ExposeSecret};
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! # let certificate_builder = doc_utils::create_test_certificate_builder(&account);
//!
//! let certificate = certificate_builder
//!     // Plain text attributes for non-sensitive information
//!     .with_plain_attribute("postalCode", "12345")
//!     // Sensitive attributes for personally identifiable information
//!     .with_sensitive_attribute("dateOfBirth", b"1990-01-01".to_vec().into_secret())
//!     .with_sensitive_attribute("fullName", b"John Doe".to_vec().into_secret())
//!     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
//!     .with_sensitive_attribute("phoneNumber", b"+1-555-123-4567".to_vec().into_secret())
//!     .with_sensitive_attribute("address", b"123 Main St, City, State".to_vec().into_secret())
//!     .build(&account.keypair, &account.keypair)?;
//!
//! // Access plain text attributes directly
//! let postal_code = certificate.get_plain_kyc_attribute("postalCode")?;
//! assert_eq!(postal_code, b"12345");
//!
//! // Decrypt sensitive attributes using the subject's keypair
//! let email = certificate.decrypt_kyc_attribute("email", &account.keypair)?;
//! assert_eq!(email, b"john@example.com");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Advanced X.509 Features
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::certificates::CertificateBuilder;
//! use keetanetwork_x509::certificates::ExtensionBuilder;
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! # let certificate_builder = doc_utils::create_test_certificate_builder(&account);
//! let extension = ExtensionBuilder::new()
//!     .with_oid("2.5.29.37") // Extended Key Usage
//!     .with_value(vec![0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])
//!     .with_critical(false)
//!     .build()?;
//!
//! // Add custom X.509 extensions and constraints
//! let certificate = certificate_builder
//!     .with_key_usage(0x06) // Digital signature and key encipherment
//!     .with_basic_constraints(false, None) // Not a CA
//!     .with_extension(extension)
//!     .build(&account.keypair, &account.keypair)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Error Handling
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::certificates::{CertificateBuilder, CertificateError};
//! use keetanetwork_crypto::prelude::IntoSecret;
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! # let certificate_builder = doc_utils::create_test_certificate_builder(&account);
//!
//! // Invalid attribute names are collected and reported during build
//! let certificate_builder = certificate_builder
//!     .with_plain_attribute("invalidAttribute", "value")
//!     .with_sensitive_attribute("anotherInvalid", b"data".to_vec().into_secret());
//!
//! // Errors are reported during build
//! match certificate_builder.build(&account.keypair, &account.keypair) {
//!     Ok(_) => println!("Certificate built successfully"),
//!     Err(CertificateError::Asn1Error { .. }) => {
//!         println!("Invalid attribute name provided");
//!     }
//!     Err(e) => println!("Other error: {:?}", e),
//! }
//!
//! // Handle missing required fields during build
//! let incomplete_builder = CertificateBuilder::new(); // Missing required fields
//! match incomplete_builder.build(&account.keypair, &account.keypair) {
//!     Ok(_) => println!("Certificate built successfully"),
//!     Err(e) => println!("Build failed: {:?}", e),
//! }
//! ```

use std::collections::HashMap;

use keetanetwork_account::{Account, AccountError, Accountable, KeyPair};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::prelude::{CryptoSignerWithOptions, SecretBox, SignatureEncoding};
use keetanetwork_x509::certificates::{CertificateBuilder as X509CertificateBuilder, Extension, ExtensionBuilder};
use keetanetwork_x509::{DistinguishedName, SerialNumber};

use crate::asn1::oids;
use crate::certificates::{Certificate, CertificateError};
use crate::kyc_schema::builder::AttributeBuilderLike;
use crate::kyc_schema::{AttributeBuilder, KYCAttributes};
use crate::sensitive_attributes::{KycAttributeEntry, SensitiveAttributeBuilder};

/// Extended certificate builder that supports KYC attributes
///
/// This builder extends the standard X.509 certificate builder with support
/// for Keeta KYC attributes, both plain text and sensitive (encrypted). It
/// provides a fluent API for constructing certificates that can contain
/// personally identifiable information in a secure and standardized way.
///
/// # Security Model
///
/// - **Plain attributes** are stored unencrypted and should only be used for
///   non-sensitive information like names or non-private identifiers
/// - **Sensitive attributes** are encrypted using the subject's keypair and
///   should be used for personally identifiable information (PII)
///
/// # Examples
///
/// ## Basic End-Entity Certificate
///
/// ```rust
/// # use keetanetwork_anchor::doc_utils;
/// # use keetanetwork_x509::utils::create_dn;
/// # use keetanetwork_x509::oids;
/// # use keetanetwork_asn1::SubjectPublicKeyInfo;
/// use keetanetwork_anchor::certificates::CertificateBuilder;
/// use keetanetwork_crypto::prelude::IntoSecret;
/// use keetanetwork_x509::SerialNumber;
///
/// # let subject_account = doc_utils::create_secp256k1_test_account(Some(0));
/// # let issuer_account = doc_utils::create_secp256k1_test_account(Some(1));
/// # let subject_dn = create_dn(&[(oids::CN, "Test Subject")]).unwrap();
/// # let issuer_dn = create_dn(&[(oids::CN, "Test Issuer")]).unwrap();
/// # let subject_public_key_info = SubjectPublicKeyInfo::try_from(&subject_account).unwrap();
///
/// let certificate = CertificateBuilder::for_end_entity()
///     .with_subject_dn(subject_dn)
///     .with_issuer_dn(issuer_dn)
///     .with_serial_number(SerialNumber::from(12345u64))
///     .with_validity_days(365)
///     .with_subject_public_key(subject_public_key_info)
///     .with_plain_attribute("postalCode", "12345")
///     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
///     .build(&subject_account.keypair, &issuer_account.keypair)?;
///
/// assert!(certificate.has_kyc_attributes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## CA Certificate with Advanced Features
///
/// ```rust
/// # use keetanetwork_anchor::doc_utils;
/// # use keetanetwork_x509::utils::create_dn;
/// # use keetanetwork_x509::oids;
/// # use keetanetwork_asn1::SubjectPublicKeyInfo;
/// use keetanetwork_x509::SerialNumber;
/// use keetanetwork_anchor::certificates::CertificateBuilder;
///
/// # let ca_account = doc_utils::create_secp256k1_test_account(None);
/// # let ca_dn = create_dn(&[(oids::CN, "Test CA")]).unwrap();
/// # let ca_public_key_info = SubjectPublicKeyInfo::try_from(&ca_account).unwrap();
///
/// let ca_certificate = CertificateBuilder::for_ca()
///     .with_subject_dn(ca_dn.clone())
///     .with_issuer_dn(ca_dn) // Self-signed
///     .with_serial_number(SerialNumber::from(1u64))
///     .with_validity_days(3650) // 10 years
///     .with_subject_public_key(ca_public_key_info)
///     .with_basic_constraints(true, Some(3)) // CA with path length 3
///     .with_key_usage(0x06) // Certificate signing
///     .build(&ca_account.keypair, &ca_account.keypair)?;
///
/// assert!(ca_certificate.to_x509().is_ca());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default)]
pub struct CertificateBuilder {
	/// The underlying X.509 certificate builder
	inner: X509CertificateBuilder,
	/// KYC attributes to include in the certificate
	kyc_attributes: HashMap<String, KycAttributeEntry>,
	/// Collected errors from KYC attribute operations
	errors: Vec<CertificateError>,
}

impl CertificateBuilder {
	/// Create a new certificate builder
	///
	/// Creates a new builder with default settings. You'll need to configure
	/// all required certificate fields before calling [`build()`](Self::build).
	pub fn new() -> Self {
		Self::default()
	}

	/// Create a certificate builder for an end-entity certificate.
	///
	/// Creates a builder pre-configured for end-entity (leaf) certificates.
	/// These are typically used for individual users or devices and cannot
	/// be used to sign other certificates.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// let builder = CertificateBuilder::for_end_entity();
	/// // Add subject, issuer, and other required fields...
	/// ```
	pub fn for_end_entity() -> Self {
		Self { inner: X509CertificateBuilder::for_end_entity(), kyc_attributes: HashMap::new(), errors: Vec::new() }
	}

	/// Create a builder for a CA (Certificate Authority) certificate.
	///
	/// Creates a builder pre-configured for CA certificates. These certificates
	/// can be used to sign other certificates and establish a chain of trust.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// let builder = CertificateBuilder::for_ca();
	/// // Add required extensions...
	/// ```
	pub fn for_ca() -> Self {
		Self { inner: X509CertificateBuilder::for_ca(), kyc_attributes: HashMap::new(), errors: Vec::new() }
	}

	/// Set a KYC attribute to a given value.
	///
	/// This is the core method for adding KYC attributes to a certificate.
	/// It validates the attribute name against known KYC attribute OIDs and
	/// stores the attribute for inclusion in the certificate extension. If
	/// validation fails, the error is collected and will be reported
	/// during `build()`.
	///
	/// # Arguments
	///
	/// - `name` - The attribute name (e.g., "fullName", "email", "phoneNumber")
	/// - `entry` - The attribute entry containing either plain text or sensitive data
	///
	/// # Supported Attribute Names
	///
	/// The following attribute names are currently supported:
	/// - `"fullName"` - Person's full name
	/// - `"email"` - Email address
	/// - `"phoneNumber"` - Phone number
	/// - `"address"` - Physical address
	/// - `"dateOfBirth"` - Date of birth
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_anchor::sensitive_attributes::KycAttributeEntry;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	///
	/// let builder = CertificateBuilder::new()
	///     // Add plain text attribute
	///     .with_kyc_attribute(
	///         "fullName",
	///         KycAttributeEntry::PlainText(b"John Doe".to_vec())
	///     )
	///     // Add sensitive attribute
	///     .with_kyc_attribute(
	///         "email",
	///         KycAttributeEntry::Sensitive(b"john@example.com".to_vec().into_secret())
	///     );
	/// // Errors will be reported during build()
	/// ```
	pub fn with_kyc_attribute<N: AsRef<str>>(mut self, name: N, entry: KycAttributeEntry) -> Self {
		let name = name.as_ref();
		let oid = entry.to_oid(name);

		// Validate the attribute name
		match oid {
			Ok(_) => {
				self.kyc_attributes.insert(name.to_string(), entry);
			}
			Err(e) => {
				self.errors.push(e.into());
			}
		}

		self
	}

	/// Set a plain text KYC attribute
	///
	/// Convenience method for adding a plain text KYC attribute. Use this for
	/// non-sensitive information that can be stored unencrypted in the
	/// certificate. If the attribute name is invalid, the error is collected
	/// and will be reported during `build()`.
	///
	/// # Arguments
	///
	/// - `name` - The attribute name (see [`with_kyc_attribute`](Self::with_kyc_attribute) for supported names)
	/// - `value` - The attribute value as bytes or string
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_plain_attribute("postalCode", "12345");
	/// // Errors will be reported during build()
	/// ```
	pub fn with_plain_attribute<V: AsRef<[u8]>, N: AsRef<str>>(self, name: N, value: V) -> Self {
		let entry = KycAttributeEntry::PlainText(value.as_ref().to_vec());
		self.with_kyc_attribute(name, entry)
	}

	/// Set a sensitive (encrypted) KYC attribute.
	///
	/// Convenience method for adding a sensitive KYC attribute. Use this for
	/// personally identifiable information (PII) that should be encrypted for
	/// privacy protection. If the attribute name is invalid, the error is
	/// collected and will be reported during `build()`.
	///
	/// # Arguments
	///
	/// - `name` - The attribute name (see [`with_kyc_attribute`](Self::with_kyc_attribute) for supported names)
	/// - `value` - The attribute value wrapped in a `SecretBox`
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
	///     .with_sensitive_attribute("phoneNumber", b"+1-555-123-4567".to_vec().into_secret())
	///     .with_sensitive_attribute("address", b"123 Main St, City, State".to_vec().into_secret());
	/// ```
	pub fn with_sensitive_attribute<N: AsRef<str>>(self, name: N, value: SecretBox<Vec<u8>>) -> Self {
		let entry = KycAttributeEntry::Sensitive(value);
		self.with_kyc_attribute(name, entry)
	}

	/// Set the subject distinguished name.
	///
	/// Sets the distinguished name (DN) for the certificate subject (the
	/// entity the certificate is issued to).
	///
	/// # Arguments
	///
	/// - `subject_dn` - The distinguished name for the certificate subject
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_x509::oids;
	/// use keetanetwork_x509::utils::create_dn;
	///
	/// let subject_dn = create_dn(&[
	///     (oids::CN, "John Doe"),
	///     (oids::O, "Example Corp"),
	///     (oids::C, "US"),
	/// ])?;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_subject_dn(subject_dn);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_subject_dn(mut self, subject_dn: DistinguishedName) -> Self {
		self.inner = self.inner.with_subject_dn(subject_dn);
		self
	}

	/// Set the issuer distinguished name.
	///
	/// Sets the distinguished name (DN) for the certificate issuer (the entity
	/// that signs and issues the certificate). For self-signed certificates,
	/// this should be the same as the subject DN.
	///
	/// # Arguments
	///
	/// - `issuer_dn` - The distinguished name for the certificate issuer
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_x509::oids;
	/// use keetanetwork_x509::utils::create_dn;
	///
	/// let issuer_dn = create_dn(&[
	///     (oids::CN, "Example CA"),
	///     (oids::O, "Example Corp"),
	///     (oids::C, "US"),
	/// ])?;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_issuer_dn(issuer_dn);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_issuer_dn(mut self, issuer_dn: DistinguishedName) -> Self {
		self.inner = self.inner.with_issuer_dn(issuer_dn);
		self
	}

	/// Set the serial number.
	///
	/// Sets the certificate serial number, which must be unique for each
	/// certificate issued by the same CA. Serial numbers are used for
	/// certificate identification and revocation.
	///
	/// # Arguments
	///
	/// - `serial` - The certificate serial number
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_x509::SerialNumber;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_serial_number(SerialNumber::from(12345u64));
	/// ```
	pub fn with_serial_number(mut self, serial: SerialNumber) -> Self {
		self.inner = self.inner.with_serial_number(serial);
		self
	}

	/// Set the validity period in days from now
	///
	/// Sets how long the certificate will be valid, starting from the current
	/// time. Choose an appropriate validity period based on the certificate's
	/// intended use and security requirements.
	///
	/// # Arguments
	///
	/// - `days` - Number of days the certificate should be valid
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// // End-entity certificate valid for 1 year
	/// let user_cert_builder = CertificateBuilder::for_end_entity()
	///     .with_validity_days(365);
	///
	/// // CA certificate valid for 10 years
	/// let ca_cert_builder = CertificateBuilder::for_ca()
	///     .with_validity_days(3650);
	/// ```
	pub fn with_validity_days(mut self, days: u64) -> Self {
		self.inner = self.inner.with_validity_days(days);
		self
	}

	/// Set the subject public key
	///
	/// Sets the public key for the certificate subject. This is the public key
	/// that corresponds to the private key held by the certificate subject.
	///
	/// # Arguments
	///
	/// - `public_key` - The subject's public key information
	///
	/// # Examples
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_asn1::SubjectPublicKeyInfo;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// let public_key_info = SubjectPublicKeyInfo::try_from(&account)?;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_subject_public_key(public_key_info);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_subject_public_key(mut self, public_key: SubjectPublicKeyInfo) -> Self {
		self.inner = self.inner.with_subject_public_key(public_key);
		self
	}

	/// Set whether this is a CA certificate.
	///
	/// Marks the certificate as a Certificate Authority (CA) certificate,
	/// which can be used to issue and sign other certificates.
	///
	/// # Arguments
	///
	/// - `is_ca` - Whether this certificate should be marked as a CA
	///
	/// # Note
	///
	/// This is typically used in conjunction with [`with_basic_constraints`](Self::with_basic_constraints)
	/// for proper CA certificate configuration.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// // Create a CA certificate
	/// let ca_builder = CertificateBuilder::new()
	///     .with_is_ca(true);
	///
	/// // Create an end-entity certificate
	/// let user_builder = CertificateBuilder::new()
	///     .with_is_ca(false);
	/// ```
	pub fn with_is_ca(mut self, is_ca: bool) -> Self {
		self.inner = self.inner.with_is_ca(is_ca);
		self
	}

	/// Add a custom X.509 extension.
	///
	/// Adds a custom extension to the certificate. Extensions provide
	/// additional information and constraints for certificate usage.
	///
	/// # Arguments
	///
	/// - `extension` - The X.509 extension to add
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_x509::certificates::ExtensionBuilder;
	///
	/// let custom_extension = ExtensionBuilder::new()
	///     .with_oid("1.2.3.4.5") // Custom OID
	///     .with_value(b"custom value".to_vec())
	///     .with_critical(false)
	///     .build()?;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_extension(custom_extension);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_extension(mut self, extension: Extension) -> Self {
		self.inner = self.inner.with_extension(extension);
		self
	}

	/// Add basic constraints extension.
	///
	/// Adds the Basic Constraints extension, which indicates whether the
	/// certificate is a CA certificate and optionally sets the maximum
	/// path length for certificate chains.
	///
	/// # Arguments
	///
	/// - `is_ca` - Whether this certificate is a CA
	/// - `path_length` - Maximum number of intermediate CAs that may follow
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// // Root CA with unlimited path length
	/// let root_ca = CertificateBuilder::for_ca()
	///     .with_basic_constraints(true, None);
	///
	/// // Intermediate CA with maximum path length of 2
	/// let intermediate_ca = CertificateBuilder::for_ca()
	///     .with_basic_constraints(true, Some(2));
	///
	/// // End-entity certificate (not a CA)
	/// let end_entity = CertificateBuilder::for_end_entity()
	///     .with_basic_constraints(false, None);
	/// ```
	pub fn with_basic_constraints(mut self, is_ca: bool, path_length: Option<u8>) -> Self {
		self.inner = self.inner.with_basic_constraints(is_ca, path_length);
		self
	}

	/// Add key usage extension.
	///
	/// Adds the Key Usage extension, which restricts the purposes for which
	/// the certificate's public key may be used.
	///
	/// # Arguments
	///
	/// - `key_usage_bits` - Bit field indicating allowed key usage purposes
	///
	/// # Key Usage Bits
	///
	/// Common key usage values:
	/// - `0x01` - Digital signature
	/// - `0x02` - Non-repudiation
	/// - `0x04` - Key encipherment
	/// - `0x08` - Data encipherment
	/// - `0x10` - Key agreement
	/// - `0x20` - Certificate signing (for CAs)
	/// - `0x40` - CRL signing
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	///
	/// // CA certificate that can sign certificates and CRLs
	/// let ca_builder = CertificateBuilder::for_ca()
	///     .with_key_usage(0x20 | 0x40);
	///
	/// // End-entity certificate for digital signatures and key encipherment
	/// let user_builder = CertificateBuilder::for_end_entity()
	///     .with_key_usage(0x01 | 0x04);
	/// ```
	pub fn with_key_usage(mut self, key_usage_bits: u16) -> Self {
		self.inner = self.inner.with_key_usage(key_usage_bits);
		self
	}

	/// Build the certificate with KYC attributes.
	///
	/// Creates the final X.509 certificate with all configured standard fields
	/// and KYC attributes. If KYC attributes are present, they are encrypted
	/// (if sensitive) using the subject's keypair and embedded as a custom
	/// X.509 extension.
	///
	/// # Arguments
	///
	/// - `subject_keypair` - The keypair of the certificate subject
	/// - `signing_keypair` - The keypair used to sign the certificate
	///
	/// # Returns
	///
	/// - `Ok(_)` - Successfully created certificate with KYC attributes
	/// - `Err(_)` - If certificate creation fails
	///
	/// # Key Pair Requirements
	///
	/// - **Subject keypair**: Must match the public key set with [`with_subject_public_key`](Self::with_subject_public_key)
	/// - **Signing keypair**: Must belong to the issuer (can be the same as subject for self-signed certificates)
	///
	/// # Examples
	///
	/// ## Self-Signed Certificate
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// # use keetanetwork_x509::utils::create_dn;
	/// # use keetanetwork_asn1::SubjectPublicKeyInfo;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	/// use keetanetwork_x509::SerialNumber;
	/// use keetanetwork_x509::oids;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// # let dn = create_dn(&[(oids::CN, "Test User")])?;
	/// # let public_key_info = SubjectPublicKeyInfo::try_from(&account)?;
	///
	/// let certificate = CertificateBuilder::for_ca()
	///     .with_subject_dn(dn.clone())
	///     .with_issuer_dn(dn) // Same as subject for self-signed
	///     .with_serial_number(SerialNumber::from(1u64))
	///     .with_validity_days(365)
	///     .with_subject_public_key(public_key_info)
	///     .build(&account.keypair, &account.keypair)?;
	///
	/// assert!(!certificate.has_kyc_attributes());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	///
	/// ## CA-Signed Certificate
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// # use keetanetwork_x509::utils::create_dn;
	/// # use keetanetwork_x509::oids;
	/// # use keetanetwork_asn1::SubjectPublicKeyInfo;
	/// use keetanetwork_anchor::certificates::CertificateBuilder;
	/// use keetanetwork_crypto::prelude::IntoSecret;
	/// use keetanetwork_x509::SerialNumber;
	///
	/// # let subject_account = doc_utils::create_secp256k1_test_account(Some(0));
	/// # let ca_account = doc_utils::create_secp256k1_test_account(Some(1));
	/// # let subject_dn = create_dn(&[(oids::CN, "John Doe")])?;
	/// # let ca_dn = create_dn(&[(oids::CN, "Example CA")])?;
	/// # let subject_public_key_info = SubjectPublicKeyInfo::try_from(&subject_account)?;
	///
	/// let certificate = CertificateBuilder::for_end_entity()
	///     .with_subject_dn(subject_dn)
	///     .with_issuer_dn(ca_dn) // Different issuer
	///     .with_serial_number(SerialNumber::from(12345u64))
	///     .with_validity_days(365)
	///     .with_subject_public_key(subject_public_key_info)
	///     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
	///     .build(&subject_account.keypair, &ca_account.keypair);
	/// assert!(certificate.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn build<T, S>(mut self, subject_keypair: &T, signing_keypair: &T) -> Result<Certificate, CertificateError>
	where
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// Check for collected KYC attribute errors first
		if let Some(error) = self.errors.first() {
			return Err(error.clone());
		}

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
	///
	/// Creates an X.509 extension containing all KYC attributes. Sensitive
	/// attributes are encrypted using the subject's keypair before being
	/// embedded in the extension.
	///
	/// # Arguments
	///
	/// - `subject_keypair` - The keypair used to encrypt sensitive attributes
	///
	/// # Returns
	///
	/// - `Ok(_)` - X.509 extension containing the KYC attributes
	/// - `Err(_)` - If extension creation fails
	fn build_kyc_extension<T: KeyPair>(&self, subject_keypair: &T) -> Result<Extension, CertificateError>
	where
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	{
		let mut kyc_attributes = KYCAttributes::new();
		for (name, entry) in &self.kyc_attributes {
			let oid = entry.to_oid(name)?;
			let attribute_builder = AttributeBuilder::new().with_oid(oid);
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
			.with_oid(oids::keeta::KYC_ATTRIBUTES_EXTENSION.to_string())
			.with_value(rasn::der::encode(&kyc_attributes)?)
			.with_critical(false)
			.build()
			.map_err(Into::into)
	}
}

#[cfg(test)]
mod tests {
	use keetanetwork_account::KeyECDSASECP256K1;
	use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret};
	use keetanetwork_x509::certificates::ExtensionBuilder;
	use keetanetwork_x509::DistinguishedName;

	use super::*;
	use crate::testing::{create_account_from_seed, create_test_certificate_builder};

	const TEST_ATTRIBUTES: &[(&str, &str, bool)] = &[
		("fullName", "John Doe", true),           // Valid sensitive attribute
		("email", "john@example.com", true),      // Valid sensitive attribute
		("postalCode", "12345", false),           // Valid plain attribute
		("address", "123 Main St", true),         // Valid sensitive attribute
		("phoneNumber", "+1-555-123-4567", true), // Valid sensitive attribute
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
				builder.with_sensitive_attribute(name, value.as_bytes().to_vec().into_secret())
			} else {
				builder.with_plain_attribute(name, value)
			};
		}

		assert_eq!(builder.kyc_attributes.len(), TEST_ATTRIBUTES.len());
		assert!(builder.errors.is_empty());

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
		let subject_dn = DistinguishedName::default();
		let issuer_dn = DistinguishedName::default();
		let serial = SerialNumber::from(12345u64);

		// Create a test extension using ExtensionBuilder
		let test_extension = ExtensionBuilder::for_key_usage(0x01);
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
		let account = create_account_from_seed::<KeyECDSASECP256K1>(0);
		let invalid_names = ["invalidAttribute", "unknown", ""];
		for name in invalid_names {
			let builder = create_test_certificate_builder(&account).with_plain_attribute(name, "value");
			let result = builder.build(&account.keypair, &account.keypair);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), CertificateError::SensitiveAttributeError { .. }));
		}
	}

	/// Helper function to test conversion from KycAttributeEntry to SensitiveAttribute
	fn test_entry_to_sensitive_attribute<T, S>(account: &Account<T>, entry: KycAttributeEntry, expected_data: &[u8])
	where
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		let builder = SensitiveAttributeBuilder::from(entry);
		let sensitive_attr = builder.build(&account.keypair).unwrap();
		let decrypted_value = sensitive_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_value.expose_secret(), expected_data);
	}

	fn test_kyc_attribute_entry_plain_text_conversion<T, S>(account: Account<T>)
	where
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		const TEST_DATA: &[u8] = b"plain test value";
		let entry = KycAttributeEntry::PlainText(TEST_DATA.to_vec());
		test_entry_to_sensitive_attribute(&account, entry, TEST_DATA);
	}

	fn test_kyc_attribute_entry_sensitive_conversion<T, S>(account: Account<T>)
	where
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
		T: KeyPair + CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		const TEST_DATA: &[u8] = b"sensitive test value";
		let entry = KycAttributeEntry::Sensitive(TEST_DATA.to_vec().into_secret());
		test_entry_to_sensitive_attribute(&account, entry, TEST_DATA);
	}

	crate::test_all_key_types!(
		test_kyc_attribute_entry_plain_text_conversion_with_all_key_types,
		test_kyc_attribute_entry_plain_text_conversion
	);

	crate::test_all_key_types!(
		test_kyc_attribute_entry_sensitive_conversion_with_all_key_types,
		test_kyc_attribute_entry_sensitive_conversion
	);
}

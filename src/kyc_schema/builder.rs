//! KYC Schema Builder
//!
//! This module provides a fluent API for constructing individual attributes
//! and collections of attributes with proper validation and error handling.
//!
//! # Overview
//!
//! The module provides two main builders:
//! - [`AttributeBuilder`] - For creating individual KYC attributes
//! - [`KYCAttributesBuilder`] - For creating collections of KYC attributes
//!
//! # Basic Usage
//!
//! ```rust
//! use keetanetwork_anchor::asn1::oids;
//! use keetanetwork_anchor::kyc_schema::builder::{
//!     AttributeBuilder,
//!     KYCAttributesBuilder
//! };
//!
//! // Create a single attribute
//! let attribute = AttributeBuilder::new()
//!     .with_oid(oids::keeta::FULL_NAME)
//!     .with_value(b"John Doe")
//!     .as_sensitive()
//!     .build();
//! assert!(attribute.is_ok());
//!
//! // Create a collection of attributes
//! let kyc_attributes = KYCAttributesBuilder::new()
//!     .with_sensitive(oids::keeta::FULL_NAME, b"John Doe")
//!     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
//!     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
//!     .build();
//! assert!(kyc_attributes.is_ok());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use rasn::types::OctetString;

use super::error::KycSchemaError;
use crate::asn1::utils::parse_oid_string;
use crate::generated::{Attribute, AttributeValue, KYCAttributes};

/// Builder for creating KYC attributes.
///
/// This builder provides a fluent API for constructing individual KYC
/// attributes with proper validation and type safety. Attributes can be marked
/// as either plain text or sensitive (encrypted).
///
/// # Examples
///
/// ```rust
/// use keetanetwork_anchor::asn1::oids;
/// use keetanetwork_anchor::kyc_schema::builder::AttributeBuilder;
///
/// // Create a plain text attribute
/// let name_attr = AttributeBuilder::new()
///     .with_oid(oids::ADDRESS_POSTAL_CODE)
///     .with_value(b"12345")
///     .as_plain()
///     .build()?;
///
/// // Create a sensitive attribute
/// let email_attr = AttributeBuilder::new()
///     .with_oid(oids::keeta::EMAIL)
///     .with_value(b"john@example.com")
///     .as_sensitive()
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default, Clone)]
pub struct AttributeBuilder {
	name_oid: Option<String>,
	value: Option<Vec<u8>>,
	sensitive: bool,
}

impl AttributeBuilder {
	/// Create a new attribute builder
	///
	/// Returns a new builder instance with default values. All fields must be
	/// set before calling [`build()`](Self::build).
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the OID name for the attribute
	///
	/// # Arguments
	///
	/// - `oid` - Object Identifier string
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::builder::AttributeBuilder;
	///
	/// let builder = AttributeBuilder::new()
	///     .with_oid(oids::keeta::FULL_NAME);
	/// ```
	pub fn with_oid<S: ToString>(mut self, oid: S) -> Self {
		self.name_oid = Some(oid.to_string());
		self
	}

	/// Set the value for the attribute
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::AttributeBuilder;
	///
	/// let builder = AttributeBuilder::new()
	///     .with_value(b"John Doe")
	///     .with_value("Hello".as_bytes());
	/// ```
	pub fn with_value<V: AsRef<[u8]>>(mut self, value: V) -> Self {
		self.value = Some(value.as_ref().to_vec());
		self
	}

	/// Mark this attribute as sensitive (encrypted)
	///
	/// Sensitive attributes are encrypted for privacy protection and should
	/// be used for personally identifiable information (PII) such as email
	/// addresses, phone numbers, or other private data.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::AttributeBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let sensitive_attr = AttributeBuilder::new()
	///     .with_oid(oids::keeta::EMAIL)
	///     .with_value(b"john@example.com")
	///     .as_sensitive()
	///     .build();
	/// assert!(sensitive_attr.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn as_sensitive(mut self) -> Self {
		self.sensitive = true;
		self
	}

	/// Mark this attribute as plain text
	///
	/// Plain text attributes are stored unencrypted and should only be used
	/// for non-sensitive information.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::AttributeBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let plain_attr = AttributeBuilder::new()
	///     .with_oid(oids::ADDRESS_POSTAL_CODE)
	///     .with_value(b"12345")
	///     .as_plain()
	///     .build();
	/// assert!(plain_attr.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn as_plain(mut self) -> Self {
		self.sensitive = false;
		self
	}

	/// Build the attribute
	///
	/// Validates the builder state and constructs the final [`Attribute`].
	///
	/// # Returns
	///
	/// - `Ok(_)` - Successfully constructed attribute
	/// - `Err(_)` - If required fields are missing or invalid
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::AttributeBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let attribute = AttributeBuilder::new()
	///     .with_oid(oids::keeta::FULL_NAME)
	///     .with_value(b"John Doe")
	///     .as_sensitive()
	///     .build();
	/// assert!(attribute.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn build(self) -> Result<Attribute, KycSchemaError> {
		// Validate and extract OID and value
		let oid_str = self.name_oid.ok_or(KycSchemaError::MissingOid)?;
		let value_bytes = self.value.ok_or(KycSchemaError::MissingValue)?;
		let name = parse_oid_string(&oid_str)?;

		let octet_string = OctetString::from_slice(&value_bytes);
		let value = if self.sensitive {
			AttributeValue::sensitiveValue(octet_string)
		} else {
			AttributeValue::plainValue(octet_string)
		};

		Ok(Attribute { name, value })
	}
}

/// Builder for creating KYC attribute collections.
///
/// This builder provides a convenient way to construct collections of KYC
/// attributes with validation and helper methods for common operations.
/// Errors are collected during the building process and reported during `build()`.
///
/// # Examples
///
/// ```rust
/// use keetanetwork_anchor::kyc_schema::builder::KYCAttributesBuilder;
/// use keetanetwork_anchor::asn1::oids;
///
/// let kyc_attributes = KYCAttributesBuilder::new()
///     .with_sensitive(oids::keeta::FULL_NAME, b"John Doe")
///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
///     .with_sensitive(oids::keeta::PHONE_NUMBER, b"+1234567890")
///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
///     .build();
/// assert!(kyc_attributes.is_ok());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default, Clone)]
pub struct KYCAttributesBuilder {
	attributes: Vec<Attribute>,
	errors: Vec<KycSchemaError>,
}

impl KYCAttributesBuilder {
	/// Create a new KYC attributes builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Add an attribute to the collection
	///
	/// # Arguments
	///
	/// - `attribute` - A pre-built [`Attribute`] to add to the collection
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::{AttributeBuilder, KYCAttributesBuilder};
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let attribute = AttributeBuilder::new()
	///     .with_oid(oids::keeta::FULL_NAME)
	///     .with_value(b"John Doe")
	///     .as_plain()
	///     .build()?;
	///
	/// let kyc_attributes = KYCAttributesBuilder::new()
	///     .with_attribute(attribute)
	///     .build();
	/// assert!(kyc_attributes.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_attribute(mut self, attribute: Attribute) -> Self {
		self.attributes.push(attribute);
		self
	}

	/// Add a plain text attribute
	///
	/// Convenience method for adding a plain text attribute without manually
	/// creating an [`AttributeBuilder`]. If the attribute construction fails,
	/// the error is collected and will be reported during `build()`.
	///
	/// # Arguments
	///
	/// - `oid` - Object Identifier string in dotted decimal notation
	/// - `value` - The attribute value as bytes
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::KYCAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc_attributes = KYCAttributesBuilder::new()
	///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
	///     .build();
	/// assert!(kyc_attributes.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_plain<S: ToString, V: AsRef<[u8]>>(mut self, oid: S, value: V) -> Self {
		let result = AttributeBuilder::new()
			.with_oid(oid)
			.with_value(value)
			.as_plain()
			.build();

		match result {
			Ok(attribute) => {
				self.attributes.push(attribute);
			}
			Err(error) => {
				self.errors.push(error);
			}
		}

		self
	}

	/// Add a sensitive (encrypted) attribute
	///
	/// Convenience method for adding a sensitive attribute without manually
	/// creating an [`AttributeBuilder`]. If the attribute construction fails,
	/// the error is collected and will be reported during `build()`.
	///
	/// # Arguments
	///
	/// - `oid` - Object Identifier string in dotted decimal notation
	/// - `value` - The attribute value as bytes
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::KYCAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc_attributes = KYCAttributesBuilder::new()
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build();
	/// assert!(kyc_attributes.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_sensitive<S: ToString, V: AsRef<[u8]>>(mut self, oid: S, value: V) -> Self {
		let result = AttributeBuilder::new()
			.with_oid(oid)
			.with_value(value)
			.as_sensitive()
			.build();

		match result {
			Ok(attribute) => {
				self.attributes.push(attribute);
			}
			Err(error) => {
				self.errors.push(error);
			}
		}

		self
	}

	/// Build the KYC attributes collection
	///
	/// Validates all collected attributes and constructs the final [`KYCAttributes`]
	/// collection. If any errors were collected during the building process,
	/// returns the first error encountered.
	///
	/// # Returns
	///
	/// - `Ok(_)` - Successfully constructed [`KYCAttributes`] collection
	/// - `Err(_)` - If any validation errors occurred during building
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::KYCAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc_attributes = KYCAttributesBuilder::new()
	///     .with_plain(oids::keeta::FULL_NAME, b"John Doe")
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build()?;
	///
	/// assert_eq!(kyc_attributes.count(), 2);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn build(self) -> Result<KYCAttributes, KycSchemaError> {
		// Return the first error if any were collected
		if let Some(error) = self.errors.into_iter().next() {
			Err(error)
		} else {
			Ok(KYCAttributes::from_iter(self.attributes))
		}
	}
}

#[cfg(test)]
mod tests {
	use rasn::types::ObjectIdentifier;

	use super::*;
	use crate::asn1::oids;

	struct TestData {
		oid: ObjectIdentifier,
		value: &'static [u8],
		is_sensitive: bool,
	}

	const TEST_DATA: [TestData; 4] = [
		TestData { oid: oids::keeta::FULL_NAME, value: b"John Doe", is_sensitive: false },
		TestData { oid: oids::keeta::EMAIL, value: b"encrypted_data", is_sensitive: true },
		TestData { oid: oids::keeta::PHONE_NUMBER, value: b"test@example.com", is_sensitive: false },
		TestData { oid: oids::keeta::ADDRESS, value: b"123 Test St", is_sensitive: false },
	];

	/// Helper function to build test attributes.
	fn build_test_attribute(test_data: &TestData) -> Attribute {
		let builder = AttributeBuilder::new()
			.with_oid(test_data.oid.clone())
			.with_value(test_data.value);

		if test_data.is_sensitive {
			builder.as_sensitive().build()
		} else {
			builder.as_plain().build()
		}
		.unwrap()
	}

	/// Helper function to add test data to `KYCAttributesBuilder``.
	fn add_test_data_to_builder(builder: KYCAttributesBuilder, test_data: &TestData) -> KYCAttributesBuilder {
		if test_data.is_sensitive {
			builder.with_sensitive(test_data.oid.clone(), test_data.value)
		} else {
			builder.with_plain(test_data.oid.clone(), test_data.value)
		}
	}

	#[test]
	fn test_attribute_builder_errors() {
		// Missing OID
		let result = AttributeBuilder::new().with_value(b"test").build();
		assert!(result.is_err());

		// Missing value
		let result = AttributeBuilder::new().with_oid("1.2.3.4").build();
		assert!(result.is_err());

		// Invalid OID
		let result = AttributeBuilder::new()
			.with_oid("invalid.oid")
			.with_value(b"test")
			.build();
		assert!(result.is_err());
	}

	#[test]
	fn test_attribute_builder() {
		for test_case in &TEST_DATA {
			let attr = build_test_attribute(test_case);
			assert_eq!(attr.is_sensitive(), test_case.is_sensitive);
			assert_eq!(attr.as_ref(), test_case.value);
		}
	}

	#[test]
	fn test_kyc_attributes_builder() {
		let mut builder = KYCAttributesBuilder::new();
		for test_case in &TEST_DATA[0..2] {
			builder = add_test_data_to_builder(builder, test_case);
		}

		let attributes = builder.build().unwrap();
		assert_eq!(attributes.count(), 2);

		// Verify attributes match test data
		for test_case in &TEST_DATA[0..2] {
			let found = attributes.find_by_oid(test_case.oid.clone()).unwrap();
			assert_eq!(found.is_sensitive(), test_case.is_sensitive);
			assert_eq!(found.as_ref(), test_case.value);
		}
	}

	#[test]
	fn test_builder_with_manual_attributes() {
		let attrs: Vec<Attribute> = TEST_DATA[2..4].iter().map(build_test_attribute).collect();
		let mut builder = KYCAttributesBuilder::new();
		for attr in attrs {
			builder = builder.with_attribute(attr);
		}

		let attributes = builder.build().unwrap();
		assert_eq!(attributes.count(), 2);

		// Verify all attributes are present
		for test_case in &TEST_DATA[2..4] {
			let found = attributes.find_by_oid(test_case.oid.clone()).unwrap();
			assert_eq!(found.as_ref(), test_case.value);
		}
	}

	#[test]
	fn test_builder_error_collection() {
		// Test that errors are collected and reported on build
		let result = KYCAttributesBuilder::new()
			.with_plain("invalid.oid", b"test")
			.with_sensitive("1.2.3.4", b"valid")
			.build();

		assert!(result.is_err());
	}
}

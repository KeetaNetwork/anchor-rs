//! KYC Schema Builder
//!
//! This module provides a fluent API for constructing individual attributes
//! and collections of attributes with proper validation and error handling.
//!
//! # Overview
//!
//! The module provides two main builders:
//! - [`AttributeBuilder`] - For creating individual KYC attributes
//! - [`KycAttributesBuilder`] - For creating collections of KYC attributes
//!
//! # Basic Usage
//!
//! ```rust
//! use keetanetwork_anchor::iso20022::{ContactDetails, PhoneNumber};
//! use keetanetwork_anchor::kyc_schema::builder::{
//!     AttributeBuilder,
//!     KycAttributesBuilder,
//!     AttributeBuilderExtensions
//! };
//!
//! // Create attributes with compile-time helpers
//! let attribute_name = AttributeBuilder::for_full_name(b"John Doe");
//! let attribute_email = AttributeBuilder::for_email(b"john@example.com");
//! let attribute_contact = ContactDetails::new(
//!     None, None, None, None, None, None, None, None, None, None,
//!     Some(PhoneNumber("123-456-7890".to_string())),
//!     None,
//! );
//!
//! // Create a collection of attributes
//! let kyc_attributes = KycAttributesBuilder::new()
//!     .with_attribute(attribute_name)
//!     .with_attribute(attribute_email)
//!     .with_attribute(attribute_contact.try_into()?)
//!     .build();
//! assert!(kyc_attributes.is_ok());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Re-export generated extension
pub use crate::generated::builder_ext::AttributeBuilderExtensions;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rasn::types::OctetString;

use super::error::KycSchemaError;
use crate::asn1::utils::parse_oid_string;
use crate::generated::{Attribute, AttributeValue, KycAttributes};

pub trait AttributeBuilderLike: Default {
	/// Create a new attribute builder
	///
	/// Returns a new builder instance with default values. All fields must be
	/// set before calling [`build()`](Self::build).
	fn new() -> Self {
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
	/// use keetanetwork_anchor::kyc_schema::builder::{
	///     AttributeBuilder,
	///     AttributeBuilderLike
	/// };
	///
	/// let builder = AttributeBuilder::default()    
	///     .with_oid(oids::keeta::FULL_NAME);
	/// ```
	fn with_oid<S: ToString>(self, oid: S) -> Self;

	/// Set the value for the attribute
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::{
	///     AttributeBuilder,
	///     AttributeBuilderLike
	/// };
	///
	/// let builder = AttributeBuilder::default()    
	///     .with_value(b"John Doe")
	///     .with_value("Hello".as_bytes());
	/// ```
	fn with_value<V: AsRef<[u8]>>(self, value: V) -> Self;

	/// Mark this attribute as sensitive (encrypted)
	///
	/// Sensitive attributes are encrypted for privacy protection and should
	/// be used for personally identifiable information (PII) such as email
	/// addresses, phone numbers, or other private data.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::builder::{
	///     AttributeBuilder,
	///     AttributeBuilderLike
	/// };
	///
	/// let sensitive_attr = AttributeBuilder::default()    
	///     .with_oid(oids::keeta::EMAIL)
	///     .with_value(b"john@example.com")
	///     .as_sensitive()
	///     .build();
	/// assert!(sensitive_attr.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	#[allow(clippy::wrong_self_convention)]
	fn as_sensitive(self) -> Self;

	/// Mark this attribute as plain text
	///
	/// Plain text attributes are stored unencrypted and should only be used
	/// for non-sensitive information.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::builder::{
	///     AttributeBuilder,
	///     AttributeBuilderLike
	/// };
	///
	/// let plain_attr = AttributeBuilder::default()    
	///     .with_oid(oids::ADDRESS_POSTAL_CODE)
	///     .with_value(b"12345")
	///     .as_plain()
	///     .build();
	/// assert!(plain_attr.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	#[allow(clippy::wrong_self_convention)]
	fn as_plain(self) -> Self;

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
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::builder::{
	///     AttributeBuilder,
	///     AttributeBuilderLike
	/// };
	///
	/// let attribute = AttributeBuilder::default()    
	///     .with_oid(oids::keeta::FULL_NAME)
	///     .with_value(b"John Doe")
	///     .as_sensitive()
	///     .build();
	/// assert!(attribute.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	fn build(self) -> Result<Attribute, KycSchemaError>;
}

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
/// use keetanetwork_anchor::kyc_schema::builder::{
///     AttributeBuilder,
///     AttributeBuilderLike
/// };
///
/// // Create a plain text attribute
/// let name_attr = AttributeBuilder::default()    
///     .with_oid(oids::ADDRESS_POSTAL_CODE)
///     .with_value(b"12345")
///     .as_plain()
///     .build()?;
///
/// // Create a sensitive attribute
/// let email_attr = AttributeBuilder::default()    
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

impl AttributeBuilderLike for AttributeBuilder {
	fn with_oid<S: ToString>(mut self, oid: S) -> Self {
		self.name_oid = Some(oid.to_string());
		self
	}
	fn with_value<V: AsRef<[u8]>>(mut self, value: V) -> Self {
		self.value = Some(value.as_ref().to_vec());
		self
	}

	fn as_sensitive(mut self) -> Self {
		self.sensitive = true;
		self
	}

	fn as_plain(mut self) -> Self {
		self.sensitive = false;
		self
	}

	fn build(self) -> Result<Attribute, KycSchemaError> {
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
/// use keetanetwork_anchor::kyc_schema::builder::KycAttributesBuilder;
/// use keetanetwork_anchor::asn1::oids;
///
/// let kyc_attributes = KycAttributesBuilder::new()
///     .with_sensitive(oids::keeta::FULL_NAME, b"John Doe")
///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
///     .with_sensitive(oids::keeta::PHONE_NUMBER, b"+1234567890")
///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
///     .build();
/// assert!(kyc_attributes.is_ok());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default, Clone)]
pub struct KycAttributesBuilder {
	attributes: Vec<Attribute>,
	errors: Vec<KycSchemaError>,
}

impl KycAttributesBuilder {
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
	/// #[cfg(feature = "chrono")]
	/// use chrono::NaiveDate;
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::Attribute;
	/// use keetanetwork_anchor::kyc_schema::builder::{
	///     AttributeBuilder,
	///     AttributeBuilderExtensions,
	///     KycAttributesBuilder,
	/// };
	/// use keetanetwork_anchor::iso20022::{
	///     DateAndPlaceOfBirth,
	///     BirthDate,
	///     TownName,
	///     Country,
	///     CountrySubDivision
	/// };
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let attribute_name = AttributeBuilder::for_full_name(b"John Doe");
	/// let attribute_email = AttributeBuilder::for_email(b"john@example.com");
	///
	/// #[cfg(feature = "chrono")]
	/// let birth_info = DateAndPlaceOfBirth::new(
	///     BirthDate(NaiveDate::from_ymd_opt(1990, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc().into()),
	///     TownName("New York".to_string()),
	///     Country("US".to_string()),
	///     Some(CountrySubDivision("NY".to_string())),
	/// );
	///
	/// #[cfg(feature = "chrono")]
	/// let attribute_birth = Attribute::try_from(birth_info)?;
	/// let mut kyc_attributes_builder = KycAttributesBuilder::new()
	///     .with_attribute(attribute_name)
	///     .with_attribute(attribute_email);
	///
	/// #[cfg(feature = "chrono")] {
	///     kyc_attributes_builder = kyc_attributes_builder.with_attribute(attribute_birth);
	/// }
	///
	/// let kyc_attributes = kyc_attributes_builder.build();
	/// assert!(kyc_attributes.is_ok());
	/// #[cfg(feature = "chrono")]
	/// assert_eq!(kyc_attributes.unwrap().count(), 3);
	/// #[cfg(not(feature = "chrono"))]
	/// assert_eq!(kyc_attributes.unwrap().count(), 2);
	/// # Ok(())
	/// # }
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
	/// use keetanetwork_anchor::kyc_schema::builder::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc_attributes = KycAttributesBuilder::new()
	///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
	///     .build();
	/// assert!(kyc_attributes.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_plain<S: ToString, V: AsRef<[u8]>>(mut self, oid: S, value: V) -> Self {
		let result = AttributeBuilder::default()
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
	/// use keetanetwork_anchor::kyc_schema::builder::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc_attributes = KycAttributesBuilder::new()
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build();
	/// assert!(kyc_attributes.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_sensitive<S: ToString, V: AsRef<[u8]>>(mut self, oid: S, value: V) -> Self {
		let result = AttributeBuilder::default()
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
	/// Validates all collected attributes and constructs the final [`KycAttributes`]
	/// collection. If any errors were collected during the building process,
	/// returns the first error encountered.
	///
	/// # Returns
	///
	/// - `Ok(_)` - Successfully constructed [`KycAttributes`] collection
	/// - `Err(_)` - If any validation errors occurred during building
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::kyc_schema::builder::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc_attributes = KycAttributesBuilder::new()
	///     .with_plain(oids::keeta::FULL_NAME, b"John Doe")
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build()?;
	///
	/// assert_eq!(kyc_attributes.count(), 2);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn build(self) -> Result<KycAttributes, KycSchemaError> {
		// Return the first error if any were collected
		if let Some(error) = self.errors.into_iter().next() {
			Err(error)
		} else {
			Ok(KycAttributes::from_iter(self.attributes))
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
		let builder = AttributeBuilder::default()
			.with_oid(test_data.oid.clone())
			.with_value(test_data.value);

		if test_data.is_sensitive {
			builder.as_sensitive().build()
		} else {
			builder.as_plain().build()
		}
		.expect("build attribute")
	}

	/// Helper function to add test data to `KycAttributesBuilder``.
	fn add_test_data_to_builder(builder: KycAttributesBuilder, test_data: &TestData) -> KycAttributesBuilder {
		if test_data.is_sensitive {
			builder.with_sensitive(test_data.oid.clone(), test_data.value)
		} else {
			builder.with_plain(test_data.oid.clone(), test_data.value)
		}
	}

	#[test]
	fn test_attribute_builder_errors() {
		// Missing OID
		let result = AttributeBuilder::default().with_value(b"test").build();
		assert!(result.is_err());

		// Missing value
		let result = AttributeBuilder::default().with_oid("1.2.3.4").build();
		assert!(result.is_err());

		// Invalid OID
		let result = AttributeBuilder::default()
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
	fn test_kyc_attributes_builder() -> Result<(), Box<dyn std::error::Error>> {
		let mut builder = KycAttributesBuilder::new();
		for test_case in &TEST_DATA[0..2] {
			builder = add_test_data_to_builder(builder, test_case);
		}

		let attributes = builder.build()?;
		assert_eq!(attributes.count(), 2);

		// Verify attributes match test data
		for test_case in &TEST_DATA[0..2] {
			let found = attributes
				.find_by_oid(test_case.oid.clone())
				.ok_or("attribute not found")?;
			assert_eq!(found.is_sensitive(), test_case.is_sensitive);
			assert_eq!(found.as_ref(), test_case.value);
		}
		Ok(())
	}

	#[test]
	fn test_builder_with_manual_attributes() -> Result<(), Box<dyn std::error::Error>> {
		let attrs: Vec<Attribute> = TEST_DATA[2..4].iter().map(build_test_attribute).collect();
		let mut builder = KycAttributesBuilder::new();
		for attr in attrs {
			builder = builder.with_attribute(attr);
		}

		let attributes = builder.build()?;
		assert_eq!(attributes.count(), 2);

		// Verify all attributes are present
		for test_case in &TEST_DATA[2..4] {
			let found = attributes
				.find_by_oid(test_case.oid.clone())
				.ok_or("attribute not found")?;
			assert_eq!(found.as_ref(), test_case.value);
		}
		Ok(())
	}

	#[test]
	fn test_builder_error_collection() {
		// Test that errors are collected and reported on build
		let result = KycAttributesBuilder::new()
			.with_plain("invalid.oid", b"test")
			.with_sensitive("1.2.3.4", b"valid")
			.build();

		assert!(result.is_err());
	}
}

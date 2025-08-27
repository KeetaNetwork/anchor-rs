//! KYC Schema Module
//!
//! This module provides ergonomic interfaces for working with KYC attributes
//! and schemas. It includes builders for creating attributes, extension
//! methods for working with generated ASN.1 types, and utilities for managing
//! collections of KYC data.
//!
//! # Quick Start
//!
//! ```rust
//! use anchor_rs::kyc_schema::{AttributeBuilder, KYCAttributesBuilder};
//! use anchor_rs::asn1::oids;
//!
//! // Create individual attributes
//! let name_attr = AttributeBuilder::new()
//!     .with_oid(oids::keeta::FULL_NAME)
//!     .with_value(b"John Doe")
//!     .as_plain()
//!     .build()?;
//!
//! let email_attr = AttributeBuilder::new()
//!     .with_oid(oids::keeta::EMAIL)
//!     .with_value(b"john@example.com")
//!     .as_sensitive()
//!     .build()?;
//!
//! // Create a collection using the builder
//! let kyc_data = KYCAttributesBuilder::new()
//!     .with_attribute(name_attr)
//!     .with_attribute(email_attr)
//!     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
//!     .with_sensitive(oids::keeta::ADDRESS, b"123 Main St")
//!     .build()?;
//!
//! // Access attributes
//! if let Some(name) = kyc_data.find_by_oid(oids::keeta::FULL_NAME) {
//!     println!("Name: {:?}", std::str::from_utf8(name.as_ref()));
//!     println!("Is sensitive: {}", name.is_sensitive());
//! }
//!
//! // Iterate over all attributes
//! for attr in &kyc_data {
//!     println!("OID: {}, Sensitive: {}", attr.name.to_string(), attr.is_sensitive());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Working with Sensitive Data
//!
//! The module distinguishes between plain and sensitive attributes:
//!
//! ```rust
//! use anchor_rs::kyc_schema::KYCAttributesBuilder;
//! use anchor_rs::asn1::oids;
//!
//! let kyc_data = KYCAttributesBuilder::new()
//!     // Plain text - for non-sensitive information
//!     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
//!     // Sensitive - for personally identifiable information
//!     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
//!     .with_sensitive(oids::keeta::PHONE_NUMBER, b"+1234567890")
//!     .build()?;
//!
//! // Check which attributes are sensitive
//! for attr in &kyc_data {
//!     if attr.is_sensitive() {
//!         println!("Sensitive attribute: {}", attr.name.to_string());
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Serialization
//!
//! KYC attributes support ASN.1 DER encoding for storage and transmission:
//!
//! ```rust
//! use anchor_rs::kyc_schema::{
//!     KYCAttributes,
//!     KYCAttributesBuilder
//! };
//! use anchor_rs::asn1::oids;
//!
//! let kyc_attributes = KYCAttributesBuilder::new()
//!     .with_plain(oids::keeta::FULL_NAME, b"John Doe")
//!     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
//!     .build()?;
//!
//! // Encode to DER bytes
//! let der_bytes = kyc_attributes.to_der()?;
//! // Decode from DER bytes
//! let kyc_attributes = KYCAttributes::try_from(der_bytes)?;
//! let attribute = kyc_attributes.find_by_oid(&oids::keeta::FULL_NAME);
//! assert!(attribute.is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod builder;
pub mod error;

#[cfg(feature = "serde")]
pub mod serde;

// Re-exports
pub use crate::generated::{Attribute, AttributeValue, KYCAttributes};
pub use builder::{AttributeBuilder, KYCAttributesBuilder};
pub use error::KycSchemaError;

impl Attribute {
	/// Check if this attribute is sensitive (encrypted).
	///
	/// Returns `true` if the attribute contains sensitive data that should be
	/// encrypted, `false` if it's plain text.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::AttributeBuilder;
	/// use anchor_rs::asn1::oids;
	///
	/// let sensitive_attr = AttributeBuilder::new()
	///     .with_oid(oids::keeta::EMAIL)
	///     .with_value(b"john@example.com")
	///     .as_sensitive()
	///     .build()?;
	/// assert!(sensitive_attr.is_sensitive());
	///
	/// let plain_attr = AttributeBuilder::new()
	///     .with_oid(oids::ADDRESS_POSTAL_CODE)
	///     .with_value(b"12345")
	///     .as_plain()
	///     .build()?;
	/// assert!(!plain_attr.is_sensitive());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn is_sensitive(&self) -> bool {
		matches!(self.value, AttributeValue::sensitiveValue(_))
	}
}

impl AsRef<[u8]> for Attribute {
	fn as_ref(&self) -> &[u8] {
		match &self.value {
			AttributeValue::plainValue(octets) => octets.as_ref(),
			AttributeValue::sensitiveValue(octets) => octets.as_ref(),
		}
	}
}

impl KYCAttributes {
	/// Create a new empty collection of KYC attributes.
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a KYC attribute to the collection.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::{KYCAttributes, AttributeBuilder};
	/// use anchor_rs::asn1::oids;
	///
	/// let mut kyc = KYCAttributes::new();
	/// let attr = AttributeBuilder::new()
	///     .with_oid(oids::keeta::FULL_NAME)
	///     .with_value(b"John Doe")
	///     .as_plain()
	///     .build()?;
	///
	/// kyc.add_attribute(attr);
	/// assert_eq!(kyc.count(), 1);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn add_attribute(&mut self, attribute: Attribute) {
		self.0.push(attribute);
	}

	/// Find an attribute by OID string.
	///
	/// Searches for an attribute with the given Object Identifier (OID)
	/// represented as a string.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::KYCAttributesBuilder;
	/// use anchor_rs::asn1::oids;
	///
	/// let kyc = KYCAttributesBuilder::new()
	///     .with_plain(oids::keeta::FULL_NAME, b"John Doe")
	///     .build()?;
	///
	/// let attr = kyc.find_by_oid(oids::keeta::FULL_NAME.to_string());
	/// assert!(attr.is_some());
	///
	/// let missing = kyc.find_by_oid("1.2.3.4.5");
	/// assert!(missing.is_none());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn find_by_oid<T: ToString>(&self, oid: T) -> Option<&Attribute> {
		let oid_str = oid.to_string();
		self.0.iter().find(|attr| attr.name.to_string() == oid_str)
	}

	/// Get count of attributes.
	///
	/// Returns the number of attributes in this collection.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::KYCAttributesBuilder;
	/// use anchor_rs::asn1::oids;
	///
	/// let kyc = KYCAttributesBuilder::new()
	///     .with_sensitive(oids::keeta::FULL_NAME, b"John Doe")
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build()?;
	///
	/// assert_eq!(kyc.count(), 2);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn count(&self) -> usize {
		self.0.len()
	}

	/// Check if collection is empty.
	///
	/// # Returns
	///
	/// - `true` if the collection contains no attributes.
	/// - `false` if the collection contains one or more attributes.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::KYCAttributes;
	///
	/// let empty_kyc = KYCAttributes::new();
	/// assert!(empty_kyc.is_empty());
	/// ```
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Get an iterator over all attributes in this collection.
	///
	/// This provides a convenient way to iterate over all attributes without
	/// directly accessing the internal structure.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::KYCAttributesBuilder;
	/// use anchor_rs::asn1::oids;
	///
	/// let kyc = KYCAttributesBuilder::new()
	///     .with_sensitive(oids::keeta::FULL_NAME, b"John Doe")
	///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
	///     .build()?;
	///
	/// let count = kyc.iter().count();
	/// assert_eq!(count, 2);
	///
	/// // Check if any attributes are sensitive
	/// let has_sensitive = kyc.iter().any(|attr| attr.is_sensitive());
	/// assert!(has_sensitive);
	///
	/// // Check if any attributes are plain
	/// let has_plain = kyc.iter().any(|attr| !attr.is_sensitive());
	/// assert!(has_plain);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn iter(&self) -> impl Iterator<Item = &Attribute> {
		self.0.iter()
	}

	/// Filter attributes to only sensitive ones.
	///
	/// Returns an iterator over attributes that contain sensitive values.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::KYCAttributesBuilder;
	/// use anchor_rs::asn1::oids;
	///
	/// let kyc = KYCAttributesBuilder::new()
	///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build()?;
	///
	/// let sensitive_count = kyc.sensitive_attributes().count();
	/// assert_eq!(sensitive_count, 1);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn sensitive_attributes(&self) -> impl Iterator<Item = &Attribute> {
		self.0.iter().filter(|attr| attr.is_sensitive())
	}

	/// Filter attributes to only plain text ones.
	///
	/// Returns an iterator over attributes that contain plain text values.
	///
	/// # Examples
	///
	/// ```rust
	/// use anchor_rs::kyc_schema::KYCAttributesBuilder;
	/// use anchor_rs::asn1::oids;
	///
	/// let kyc = KYCAttributesBuilder::new()
	///     .with_plain(oids::ADDRESS_POSTAL_CODE, b"12345")
	///     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
	///     .build()?;
	///
	/// let plain_count = kyc.plain_attributes().count();
	/// assert_eq!(plain_count, 1);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn plain_attributes(&self) -> impl Iterator<Item = &Attribute> {
		self.0.iter().filter(|attr| !attr.is_sensitive())
	}

	/// Convert the KYCAttributes to DER-encoded bytes
	pub fn to_der(&self) -> Result<Vec<u8>, KycSchemaError> {
		self.try_into()
	}
}

// Default implementation for KYCAttributes. This is generated and does not
// have the `Default` derive.
#[allow(clippy::derivable_impls)]
impl Default for KYCAttributes {
	fn default() -> Self {
		Self(rasn::types::SequenceOf::new())
	}
}

impl IntoIterator for KYCAttributes {
	type Item = Attribute;
	type IntoIter = std::vec::IntoIter<Attribute>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a> IntoIterator for &'a KYCAttributes {
	type Item = &'a Attribute;
	type IntoIter = std::slice::Iter<'a, Attribute>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl FromIterator<Attribute> for KYCAttributes {
	fn from_iter<T: IntoIterator<Item = Attribute>>(iter: T) -> Self {
		Self(iter.into_iter().collect())
	}
}

impl TryFrom<&KYCAttributes> for Vec<u8> {
	type Error = KycSchemaError;

	fn try_from(attr: &KYCAttributes) -> std::result::Result<Self, Self::Error> {
		Ok(rasn::der::encode(attr)?)
	}
}

impl TryFrom<KYCAttributes> for Vec<u8> {
	type Error = KycSchemaError;

	fn try_from(attr: KYCAttributes) -> std::result::Result<Self, Self::Error> {
		(&attr).try_into()
	}
}

impl TryFrom<&[u8]> for KYCAttributes {
	type Error = KycSchemaError;

	fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
		Ok(rasn::der::decode(bytes)?)
	}
}

impl TryFrom<Vec<u8>> for KYCAttributes {
	type Error = KycSchemaError;

	fn try_from(bytes: Vec<u8>) -> std::result::Result<Self, Self::Error> {
		(&bytes[..]).try_into()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::oids::keeta;

	struct TestAttribute {
		oid: rasn::types::ObjectIdentifier,
		value: &'static [u8],
		is_sensitive: bool,
	}

	// Shared test data for all tests
	const TEST_ATTRIBUTES: [TestAttribute; 4] = [
		TestAttribute { oid: keeta::FULL_NAME, value: b"John Doe", is_sensitive: false },
		TestAttribute { oid: keeta::EMAIL, value: b"test@example.com", is_sensitive: true },
		TestAttribute { oid: keeta::PHONE_NUMBER, value: b"+1234567890", is_sensitive: false },
		TestAttribute { oid: keeta::ADDRESS, value: b"123 Main St", is_sensitive: true },
	];

	fn build_attribute(test_attr: &TestAttribute) -> Attribute {
		let builder = AttributeBuilder::new()
			.with_oid(test_attr.oid.clone())
			.with_value(test_attr.value);

		if test_attr.is_sensitive {
			builder.as_sensitive().build()
		} else {
			builder.as_plain().build()
		}
		.unwrap()
	}

	#[test]
	fn test_kyc_attribute_creation() {
		for case in &TEST_ATTRIBUTES {
			let attr = build_attribute(case);
			assert_eq!(attr.name.to_string(), case.oid.to_string());
			assert_eq!(attr.is_sensitive(), case.is_sensitive);
			assert_eq!(attr.as_ref(), case.value);
		}
	}

	#[test]
	fn test_kyc_attributes_collection() {
		let mut attributes = KYCAttributes::new();
		assert!(attributes.is_empty());
		assert_eq!(attributes.count(), 0);

		// Add all test attributes
		for (i, test_attr) in TEST_ATTRIBUTES.iter().enumerate() {
			let attr = build_attribute(test_attr);
			attributes.add_attribute(attr);
			assert_eq!(attributes.count(), i + 1);
			assert!(!attributes.is_empty());
		}

		// Test finding by OID for all attributes
		for test_attr in &TEST_ATTRIBUTES {
			let found = attributes.find_by_oid(test_attr.oid.to_string()).unwrap();
			assert_eq!(found.as_ref(), test_attr.value);
			assert_eq!(found.is_sensitive(), test_attr.is_sensitive);
		}

		// Test non-existent OID
		assert!(attributes.find_by_oid("1.2.3.4.5").is_none());
	}

	#[test]
	fn test_asn1_encoding_decoding() {
		let mut attributes = KYCAttributes::new();
		for test_attr in &TEST_ATTRIBUTES {
			let attr = build_attribute(test_attr);
			attributes.add_attribute(attr);
		}

		// Encode to DER
		let encoded = attributes.to_der().unwrap();
		assert!(!encoded.is_empty());

		// Decode back
		let decoded = KYCAttributes::try_from(encoded).unwrap();
		assert_eq!(decoded.count(), TEST_ATTRIBUTES.len());

		// Verify all attributes match
		for test_attr in &TEST_ATTRIBUTES {
			let found_attr = decoded.find_by_oid(test_attr.oid.to_string()).unwrap();
			assert_eq!(found_attr.as_ref(), test_attr.value);
			assert_eq!(found_attr.is_sensitive(), test_attr.is_sensitive);
		}
	}

	#[test]
	fn test_iterator_support() {
		// Build test attributes
		let mut attributes = KYCAttributes::new();
		for test_attr in &TEST_ATTRIBUTES {
			if !test_attr.is_sensitive {
				let attr = build_attribute(test_attr);
				attributes.add_attribute(attr);
			}
		}

		let expected_count = TEST_ATTRIBUTES
			.iter()
			.filter(|attr| !attr.is_sensitive)
			.count();

		// Test iter()
		let count = attributes.clone().into_iter().count();
		assert_eq!(count, expected_count);

		for attr in attributes.clone().into_iter() {
			assert!(!attr.is_sensitive());
		}

		// Test &KYCAttributes iteration
		let count = (&attributes).into_iter().count();
		assert_eq!(count, expected_count);

		for attr in &attributes {
			assert!(!attr.is_sensitive());
		}

		// Test into_iter()
		let count = attributes.into_iter().count();
		assert_eq!(count, expected_count);
	}

	#[test]
	fn test_from_iterator() {
		let attrs: Vec<Attribute> = TEST_ATTRIBUTES.iter().map(build_attribute).collect();
		let kyc_attrs: KYCAttributes = attrs.into_iter().collect();
		assert_eq!(kyc_attrs.count(), TEST_ATTRIBUTES.len());

		// Verify all attributes are present
		for test_attr in &TEST_ATTRIBUTES {
			let found = kyc_attrs.find_by_oid(test_attr.oid.to_string()).unwrap();
			assert_eq!(found.as_ref(), test_attr.value);
		}
	}
}

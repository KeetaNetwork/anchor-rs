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
//! use keetanetwork_anchor::asn1::oids;
//! use keetanetwork_anchor::kyc_schema::{
//!     AttributeBuilder,
//!     KycAttributesBuilder,
//!     AttributeBuilderLike
//! };
//!
//! // Create individual attributes
//! let name_attr = AttributeBuilder::default()    
//!     .with_oid(oids::keeta::FULL_NAME)
//!     .with_value(b"John Doe")
//!     .as_plain()
//!     .build()?;
//!
//! let email_attr = AttributeBuilder::default()    
//!     .with_oid(oids::keeta::EMAIL)
//!     .with_value(b"john@example.com")
//!     .as_sensitive()
//!     .build()?;
//!
//! // Create a collection using the builder
//! let kyc_data = KycAttributesBuilder::new()
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
//! use keetanetwork_anchor::kyc_schema::KycAttributesBuilder;
//! use keetanetwork_anchor::asn1::oids;
//!
//! let kyc_data = KycAttributesBuilder::new()
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
//! use keetanetwork_anchor::kyc_schema::{
//!     KycAttributes,
//!     KycAttributesBuilder
//! };
//! use keetanetwork_anchor::asn1::oids;
//!
//! let kyc_attributes = KycAttributesBuilder::new()
//!     .with_plain(oids::keeta::FULL_NAME, b"John Doe")
//!     .with_sensitive(oids::keeta::EMAIL, b"john@example.com")
//!     .build()?;
//!
//! // Encode to DER bytes
//! let der_bytes = kyc_attributes.to_der()?;
//! // Decode from DER bytes
//! let kyc_attributes = KycAttributes::try_from(der_bytes)?;
//! let attribute = kyc_attributes.find_by_oid(&oids::keeta::FULL_NAME);
//! assert!(attribute.is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod builder;
pub mod codec;
pub mod error;

#[cfg(feature = "serde")]
pub mod structured;
#[cfg(feature = "serde")]
pub mod serde;

use alloc::string::ToString;
use alloc::vec::Vec;

// Re-exports
pub use crate::generated::{Attribute, AttributeValue, KycAttributes};
pub use builder::{AttributeBuilder, AttributeBuilderLike, KycAttributesBuilder};
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
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::{
	///    AttributeBuilder,
	///    AttributeBuilderLike
	/// };
	///
	/// let sensitive_attr = AttributeBuilder::default()    
	///     .with_oid(oids::keeta::EMAIL)
	///     .with_value(b"john@example.com")
	///     .as_sensitive()
	///     .build()?;
	/// assert!(sensitive_attr.is_sensitive());
	///
	/// let plain_attr = AttributeBuilder::default()    
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

impl KycAttributes {
	/// Create a new empty collection of KYC attributes.
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a KYC attribute to the collection.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_anchor::asn1::oids;
	/// use keetanetwork_anchor::kyc_schema::{
	///    KycAttributes,
	///    AttributeBuilder,
	///    AttributeBuilderLike
	/// };
	///
	/// let mut kyc = KycAttributes::new();
	/// let attr = AttributeBuilder::default()    
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
	/// use keetanetwork_anchor::kyc_schema::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc = KycAttributesBuilder::new()
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
	/// use keetanetwork_anchor::kyc_schema::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc = KycAttributesBuilder::new()
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
	/// use keetanetwork_anchor::kyc_schema::KycAttributes;
	///
	/// let empty_kyc = KycAttributes::new();
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
	/// use keetanetwork_anchor::kyc_schema::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc = KycAttributesBuilder::new()
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
	/// use keetanetwork_anchor::kyc_schema::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc = KycAttributesBuilder::new()
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
	/// use keetanetwork_anchor::kyc_schema::KycAttributesBuilder;
	/// use keetanetwork_anchor::asn1::oids;
	///
	/// let kyc = KycAttributesBuilder::new()
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

	/// Convert the KycAttributes to DER-encoded bytes
	pub fn to_der(&self) -> Result<Vec<u8>, KycSchemaError> {
		self.try_into()
	}
}

// Default implementation for KycAttributes. This is generated and does not
// have the `Default` derive.
#[allow(clippy::derivable_impls)]
impl Default for KycAttributes {
	fn default() -> Self {
		Self(rasn::types::SequenceOf::new())
	}
}

impl IntoIterator for KycAttributes {
	type Item = Attribute;
	type IntoIter = alloc::vec::IntoIter<Attribute>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a> IntoIterator for &'a KycAttributes {
	type Item = &'a Attribute;
	type IntoIter = core::slice::Iter<'a, Attribute>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl FromIterator<Attribute> for KycAttributes {
	fn from_iter<T: IntoIterator<Item = Attribute>>(iter: T) -> Self {
		Self(iter.into_iter().collect())
	}
}

impl TryFrom<&KycAttributes> for Vec<u8> {
	type Error = KycSchemaError;

	fn try_from(attr: &KycAttributes) -> core::result::Result<Self, Self::Error> {
		Ok(rasn::der::encode(attr)?)
	}
}

impl TryFrom<KycAttributes> for Vec<u8> {
	type Error = KycSchemaError;

	fn try_from(attr: KycAttributes) -> core::result::Result<Self, Self::Error> {
		(&attr).try_into()
	}
}

impl TryFrom<&[u8]> for KycAttributes {
	type Error = KycSchemaError;

	fn try_from(bytes: &[u8]) -> core::result::Result<Self, Self::Error> {
		Ok(rasn::der::decode(bytes)?)
	}
}

impl TryFrom<Vec<u8>> for KycAttributes {
	type Error = KycSchemaError;

	fn try_from(bytes: Vec<u8>) -> core::result::Result<Self, Self::Error> {
		(&bytes[..]).try_into()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::{create_test_attribute, create_test_kyc_attributes, TEST_KYC_ATTRIBUTES};

	#[test]
	fn test_attribute_is_sensitive_plain() {
		let attr = create_test_attribute("1.2.3.4.1", b"test", false);
		assert!(!attr.is_sensitive());
	}

	#[test]
	fn test_attribute_is_sensitive_encrypted() {
		let attr = create_test_attribute("1.2.3.4.1", b"test", true);
		assert!(attr.is_sensitive());
	}

	#[test]
	fn test_kyc_attributes_new() {
		let kyc = KycAttributes::new();
		assert!(kyc.is_empty());
		assert_eq!(kyc.count(), 0);
	}

	#[test]
	fn test_kyc_attributes_add_attribute() {
		let mut kyc = KycAttributes::new();
		let attr = create_test_attribute("1.2.3.4.1", b"test", false);

		kyc.add_attribute(attr);
		assert_eq!(kyc.count(), 1);
		assert!(!kyc.is_empty());
	}

	#[test]
	fn test_kyc_attributes_count() {
		let kyc = create_test_kyc_attributes();
		assert_eq!(kyc.count(), TEST_KYC_ATTRIBUTES.len());
	}

	#[test]
	fn test_kyc_attributes_is_empty_false() {
		let kyc = create_test_kyc_attributes();
		assert!(!kyc.is_empty());
	}

	#[test]
	fn test_kyc_attributes_find_by_oid_exists() {
		let kyc = create_test_kyc_attributes();
		let (oid_str, _, _) = TEST_KYC_ATTRIBUTES[0];

		let found = kyc.find_by_oid(oid_str);
		assert!(found.is_some());
	}

	#[test]
	fn test_kyc_attributes_find_by_oid_missing() {
		let kyc = create_test_kyc_attributes();
		let found = kyc.find_by_oid("9.9.9.9.9");
		assert!(found.is_none());
	}

	#[test]
	fn test_kyc_attributes_to_der() {
		let kyc = create_test_kyc_attributes();
		let der_result = kyc.to_der();
		assert!(der_result.is_ok());
	}

	#[test]
	fn test_kyc_attributes_iter() {
		let kyc = create_test_kyc_attributes();
		let collected: Vec<_> = kyc.iter().collect();
		assert_eq!(collected.len(), TEST_KYC_ATTRIBUTES.len());
	}

	#[test]
	fn test_kyc_attributes_sensitive_attributes() {
		let kyc = create_test_kyc_attributes();
		let sensitive_count = kyc.sensitive_attributes().count();
		let expected_sensitive = TEST_KYC_ATTRIBUTES
			.iter()
			.filter(|(_, _, is_sensitive)| *is_sensitive)
			.count();
		assert_eq!(sensitive_count, expected_sensitive);
	}

	#[test]
	fn test_kyc_attributes_plain_attributes() {
		let kyc = create_test_kyc_attributes();
		let plain_count = kyc.plain_attributes().count();
		let expected_plain = TEST_KYC_ATTRIBUTES
			.iter()
			.filter(|(_, _, is_sensitive)| !*is_sensitive)
			.count();
		assert_eq!(plain_count, expected_plain);
	}

	#[test]
	fn test_iterator_traits_reference() {
		let kyc = create_test_kyc_attributes();
		let ref_iter_count = (&kyc).into_iter().count();
		assert_eq!(ref_iter_count, TEST_KYC_ATTRIBUTES.len());
	}

	#[test]
	fn test_iterator_traits_owned() {
		let kyc = create_test_kyc_attributes();
		let owned_iter_count = kyc.into_iter().count();
		assert_eq!(owned_iter_count, TEST_KYC_ATTRIBUTES.len());
	}

	#[test]
	fn test_from_iterator() {
		let attrs: Vec<Attribute> = TEST_KYC_ATTRIBUTES
			.iter()
			.map(|&(oid_str, value, is_sensitive)| create_test_attribute(oid_str, value, is_sensitive))
			.collect();

		let kyc: KycAttributes = attrs.into_iter().collect();
		assert_eq!(kyc.count(), TEST_KYC_ATTRIBUTES.len());
	}

	#[test]
	fn test_der_roundtrip() {
		let original = create_test_kyc_attributes();
		let der_bytes: Vec<u8> = original.clone().try_into().unwrap();
		let decoded: KycAttributes = der_bytes.try_into().unwrap();
		assert_eq!(decoded.count(), original.count());
	}
}

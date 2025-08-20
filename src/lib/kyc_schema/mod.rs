//! KYC Schema Module
//!
//! This module provides ergonomic interfaces for working with KYC
//! attributes and schemas.

pub mod builder;
pub mod error;

use rasn::types::{ObjectIdentifier, OctetString};

#[cfg(feature = "serde")]
use base64::Engine;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// Re-exports
pub use crate::generated::{Attribute, AttributeValue, KYCAttributes};
pub use builder::{AttributeBuilder, KYCAttributesBuilder};
pub use error::KycSchemaError;

/// Extension methods for the generated KYC attribute types.
///
/// These methods provide a more ergonomic interface for working with
/// the ASN.1 generated types.
impl Attribute {
	/// Check if this attribute is sensitive (encrypted)
	pub fn is_sensitive(&self) -> bool {
		matches!(self.value, AttributeValue::sensitiveValue(_))
	}

	/// Get the attribute OID as a string
	pub fn to_oid_string(&self) -> String {
		self.name.to_string()
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
	/// Create a new empty collection of KYC attributes
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a KYC attribute to the collection
	pub fn add_attribute(&mut self, attribute: Attribute) {
		self.0.push(attribute);
	}

	/// Find an attribute by OID string
	pub fn find_by_oid<T: AsRef<str>>(&self, oid: T) -> Option<&Attribute> {
		let oid_str = oid.as_ref();
		self.0.iter().find(|attr| attr.to_oid_string() == oid_str)
	}

	/// Find an attribute by ObjectIdentifier
	pub fn find_by_object_identifier(&self, oid: &ObjectIdentifier) -> Option<&Attribute> {
		self.0.iter().find(|attr| &attr.name == oid)
	}

	/// Get count of attributes
	pub fn count(&self) -> usize {
		self.0.len()
	}

	/// Check if collection is empty
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

/// Default implementation for KYCAttributes. This is generated and does not
/// have the `Default` derive.
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

#[cfg(feature = "serde")]
impl Serialize for KYCAttributes {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.serialize(serializer)
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for KYCAttributes {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Ok(Self(rasn::types::SequenceOf::deserialize(deserializer)?))
	}
}

#[cfg(feature = "serde")]
impl Serialize for Attribute {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		use serde::ser::SerializeStruct;

		let mut state = serializer.serialize_struct("Attribute", 2)?;
		state.serialize_field("name", &self.name.to_string())?;

		match &self.value {
			AttributeValue::plainValue(octets) => {
				state.serialize_field("value", &base64::prelude::BASE64_STANDARD.encode(octets.as_ref()))?;
				state.serialize_field("sensitive", &false)?;
			}
			AttributeValue::sensitiveValue(octets) => {
				state.serialize_field("value", &base64::prelude::BASE64_STANDARD.encode(octets.as_ref()))?;
				state.serialize_field("sensitive", &true)?;
			}
		}

		state.end()
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Attribute {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		use crate::asn1::utils::parse_oid_string;
		use serde::de;

		#[derive(Deserialize)]
		struct AttributeJson {
			name: String,
			value: String,
			sensitive: bool,
		}

		let attr_json = AttributeJson::deserialize(deserializer)?;
		let oid = parse_oid_string(&attr_json.name).map_err(de::Error::custom)?;
		let decoded = base64::prelude::BASE64_STANDARD
			.decode(&attr_json.value)
			.map_err(de::Error::custom)?;

		let octet_string = OctetString::from_slice(&decoded);

		let attr_value = if attr_json.sensitive {
			AttributeValue::sensitiveValue(octet_string)
		} else {
			AttributeValue::plainValue(octet_string)
		};

		Ok(Attribute { name: oid, value: attr_value })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1;

	struct TestAttribute {
		oid: ObjectIdentifier,
		value: &'static [u8],
		is_sensitive: bool,
	}

	// Shared test data for all tests
	const TEST_ATTRIBUTES: [TestAttribute; 4] = [
		TestAttribute { oid: asn1::FULL_NAME_OID, value: b"John Doe", is_sensitive: false },
		TestAttribute { oid: asn1::EMAIL_OID, value: b"test@example.com", is_sensitive: true },
		TestAttribute { oid: asn1::PHONE_NUMBER_OID, value: b"+1234567890", is_sensitive: false },
		TestAttribute { oid: asn1::ADDRESS_OID, value: b"123 Main St", is_sensitive: true },
	];

	fn build_attribute(test_attr: &TestAttribute) -> Attribute {
		let builder = AttributeBuilder::new()
			.with_oid(&test_attr.oid.to_string())
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
			assert_eq!(attr.to_oid_string(), case.oid.to_string());
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
		assert!(attributes.find_by_oid("1.2.3.4.5".to_string()).is_none());
	}

	#[test]
	fn test_asn1_encoding_decoding() {
		let mut attributes = KYCAttributes::new();

		// Add all test attributes
		for test_attr in &TEST_ATTRIBUTES {
			let attr = build_attribute(test_attr);
			attributes.add_attribute(attr);
		}

		// Encode to DER
		let encoded = rasn::der::encode(&attributes).unwrap();
		assert!(!encoded.is_empty());

		// Decode back
		let decoded: KYCAttributes = rasn::der::decode(&encoded).unwrap();
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
		// Build test attributes (only plain ones)
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
		let attrs: Vec<Attribute> = TEST_ATTRIBUTES
			.iter()
			.map(|test_attr| build_attribute(test_attr))
			.collect();

		let kyc_attrs: KYCAttributes = attrs.into_iter().collect();
		assert_eq!(kyc_attrs.count(), TEST_ATTRIBUTES.len());

		// Verify all attributes are present
		for test_attr in &TEST_ATTRIBUTES {
			let found = kyc_attrs.find_by_oid(test_attr.oid.to_string()).unwrap();
			assert_eq!(found.as_ref(), test_attr.value);
		}
	}

	#[cfg(feature = "serde")]
	#[test]
	fn test_json_serialization() {
		let mut attributes = KYCAttributes::new();

		// Add test attributes
		for test_attr in &TEST_ATTRIBUTES {
			let attr = build_attribute(test_attr);
			attributes.add_attribute(attr);
		}

		// Serialize to JSON
		let json = serde_json::to_string(&attributes).unwrap();
		assert!(!json.is_empty());

		// Deserialize from JSON
		let deserialized: KYCAttributes = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.count(), TEST_ATTRIBUTES.len());

		// Verify all attributes match
		for test_attr in &TEST_ATTRIBUTES {
			let attr = deserialized.find_by_oid(test_attr.oid.to_string()).unwrap();
			assert_eq!(attr.as_ref(), test_attr.value);
			assert_eq!(attr.is_sensitive(), test_attr.is_sensitive);
		}
	}
}

//! KYC Schema Builder
//!
//! This module provides a builder for creating KYC attributes and schemas.

use rasn::types::OctetString;

use super::error::KycSchemaError;
use crate::asn1::utils::parse_oid_string;
use crate::generated::{Attribute, AttributeValue, KYCAttributes};

/// Builder for creating KYC attributes.
#[derive(Debug, Default, Clone)]
pub struct AttributeBuilder {
	name_oid: Option<String>,
	value: Option<Vec<u8>>,
	sensitive: bool,
}

impl AttributeBuilder {
	/// Create a new attribute builder
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the OID name for the attribute
	pub fn with_oid<S: AsRef<str>>(mut self, oid: S) -> Self {
		self.name_oid = Some(oid.as_ref().to_string());
		self
	}

	/// Set the value for the attribute
	pub fn with_value<V: AsRef<[u8]>>(mut self, value: V) -> Self {
		self.value = Some(value.as_ref().to_vec());
		self
	}

	/// Mark this attribute as sensitive (encrypted)
	pub fn as_sensitive(mut self) -> Self {
		self.sensitive = true;
		self
	}

	/// Mark this attribute as plain text
	pub fn as_plain(mut self) -> Self {
		self.sensitive = false;
		self
	}

	/// Build the attribute
	pub fn build(self) -> Result<Attribute, KycSchemaError> {
		// Validate and extract OID and value
		let oid_str = self.name_oid.ok_or(KycSchemaError::MissingOid)?;
		let value_bytes = self.value.ok_or(KycSchemaError::MissingValue)?;
		// Parse OID string using utility function
		let oid = parse_oid_string(&oid_str)?;
		let octet_string = OctetString::from_slice(&value_bytes);

		let attr_value = if self.sensitive {
			AttributeValue::sensitiveValue(octet_string)
		} else {
			AttributeValue::plainValue(octet_string)
		};

		Ok(Attribute { name: oid, value: attr_value })
	}
}

/// Builder for creating KYC attribute collections
#[derive(Debug, Default, Clone)]
pub struct KYCAttributesBuilder {
	attributes: Vec<Attribute>,
}

impl KYCAttributesBuilder {
	/// Create a new KYC attributes builder
	pub fn new() -> Self {
		Self { attributes: Vec::new() }
	}

	/// Add an attribute to the collection
	pub fn with_attribute(mut self, attribute: Attribute) -> Self {
		self.attributes.push(attribute);
		self
	}

	/// Add a plain text attribute
	pub fn with_plain<S: AsRef<str>, V: AsRef<[u8]>>(self, oid: S, value: V) -> Result<Self, KycSchemaError> {
		let attribute = AttributeBuilder::new()
			.with_oid(oid)
			.with_value(value)
			.as_plain()
			.build()?;
		Ok(self.with_attribute(attribute))
	}

	/// Add a sensitive (encrypted) attribute
	pub fn with_sensitive<S: AsRef<str>, V: AsRef<[u8]>>(self, oid: S, value: V) -> Result<Self, KycSchemaError> {
		let attribute = AttributeBuilder::new()
			.with_oid(oid)
			.with_value(value)
			.as_sensitive()
			.build()?;
		Ok(self.with_attribute(attribute))
	}

	/// Build the KYC attributes collection
	pub fn build(self) -> KYCAttributes {
		KYCAttributes::from_iter(self.attributes)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct TestData {
		oid: &'static str,
		value: &'static [u8],
		is_sensitive: bool,
	}

	const TEST_DATA: [TestData; 4] = [
		TestData { oid: "1.3.6.1.4.1.62675.1.0", value: b"John Doe", is_sensitive: false },
		TestData { oid: "1.3.6.1.4.1.62675.1.3", value: b"encrypted_data", is_sensitive: true },
		TestData { oid: "1.3.6.1.4.1.62675.1.4", value: b"test@example.com", is_sensitive: false },
		TestData { oid: "1.3.6.1.4.1.62675.1.2", value: b"123 Test St", is_sensitive: false },
	];

	/// Helper function to build test attributes.
	fn build_test_attribute(test_data: &TestData) -> Attribute {
		let builder = AttributeBuilder::new()
			.with_oid(test_data.oid)
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
			builder
				.with_sensitive(test_data.oid, test_data.value)
				.unwrap()
		} else {
			builder.with_plain(test_data.oid, test_data.value).unwrap()
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

		let attributes = builder.build();
		assert_eq!(attributes.count(), 2);

		// Verify attributes match test data
		for test_case in &TEST_DATA[0..2] {
			let found = attributes.find_by_oid(test_case.oid).unwrap();
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

		let attributes = builder.build();
		assert_eq!(attributes.count(), 2);

		// Verify all attributes are present
		for test_case in &TEST_DATA[2..4] {
			let found = attributes.find_by_oid(test_case.oid).unwrap();
			assert_eq!(found.as_ref(), test_case.value);
		}
	}
}

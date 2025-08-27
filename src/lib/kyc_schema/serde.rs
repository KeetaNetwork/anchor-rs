//! Serde JSON encoding functionality.

use base64::Engine;
use rasn::types::{OctetString, SequenceOf};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

use crate::asn1::utils::parse_oid_string;
use crate::generated::{Attribute, AttributeValue, KYCAttributes};

impl Serialize for KYCAttributes {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for KYCAttributes {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Ok(Self(SequenceOf::deserialize(deserializer)?))
	}
}

impl Serialize for Attribute {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
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

impl<'de> Deserialize<'de> for Attribute {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		use serde::de::Error;

		#[derive(Deserialize)]
		struct AttributeJson {
			name: String,
			value: String,
			sensitive: bool,
		}

		let attr_json = AttributeJson::deserialize(deserializer)?;
		let oid = parse_oid_string(&attr_json.name).map_err(Error::custom)?;
		let decoded = base64::prelude::BASE64_STANDARD
			.decode(&attr_json.value)
			.map_err(Error::custom)?;

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
	use crate::asn1::oids;
	use crate::kyc_schema::{AttributeBuilder, KYCAttributes};

	struct TestAttribute {
		oid: rasn::types::ObjectIdentifier,
		value: &'static [u8],
		is_sensitive: bool,
	}

	// Shared test data for serde tests
	const TEST_ATTRIBUTES: [TestAttribute; 4] = [
		TestAttribute { oid: oids::keeta::FULL_NAME, value: b"John Doe", is_sensitive: false },
		TestAttribute { oid: oids::keeta::EMAIL, value: b"test@example.com", is_sensitive: true },
		TestAttribute { oid: oids::keeta::PHONE_NUMBER, value: b"+1234567890", is_sensitive: false },
		TestAttribute { oid: oids::keeta::ADDRESS, value: b"123 Main St", is_sensitive: true },
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

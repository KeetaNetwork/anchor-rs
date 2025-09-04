//! Generated trait extension for AttributeBuilderLike with typed methods
//!
//! This module provides a trait extension that adds `for_*` methods for all
//! available KYC attributes, making the builder API more ergonomic and type-safe.

use crate::asn1::oids;
use crate::generated::Attribute;
use crate::kyc_schema::builder::AttributeBuilderLike;

/// Extension trait for [`AttributeBuilderLike`] providing typed methods for KYC attributes.
///
/// This trait extends the basic [`AttributeBuilderLike`] functionality with convenience
/// methods for creating attributes with predefined OIDs. Each method is infallible
/// and will panic if the attribute cannot be created.
pub trait AttributeBuilderExtensions: AttributeBuilderLike + Sized {
	/// Create a dateOfBirth attribute (sensitive)
	///
	/// Creates a sensitive attribute for dateOfBirth with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_date_of_birth<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::DATE_OF_BIRTH)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build dateOfBirth attribute")
	}

	/// Create a email attribute (sensitive)
	///
	/// Creates a sensitive attribute for email with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_email<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::EMAIL)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build email attribute")
	}

	/// Create a fullName attribute (sensitive)
	///
	/// Creates a sensitive attribute for fullName with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_full_name<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::FULL_NAME)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build fullName attribute")
	}

	/// Create a id attribute (sensitive)
	///
	/// Creates a sensitive attribute for id with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_id<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::ID)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build id attribute")
	}

	/// Create a issuer attribute (sensitive)
	///
	/// Creates a sensitive attribute for issuer with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_issuer<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::ISSUER)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build issuer attribute")
	}

	/// Create a jobResponsibility attribute (sensitive)
	///
	/// Creates a sensitive attribute for jobResponsibility with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_job_responsibility<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::JOB_RESPONSIBILITY)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build jobResponsibility attribute")
	}

	/// Create a jobTitle attribute (sensitive)
	///
	/// Creates a sensitive attribute for jobTitle with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_job_title<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::JOB_TITLE)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build jobTitle attribute")
	}

	/// Create a phoneNumber attribute (sensitive)
	///
	/// Creates a sensitive attribute for phoneNumber with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_phone_number<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::keeta::PHONE_NUMBER)
			.with_value(value)
			.as_sensitive()
			.build()
			.expect("Failed to build phoneNumber attribute")
	}

	/// Create a postalCode attribute (plain)
	///
	/// Creates a plain attribute for postalCode with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn for_postal_code<V: AsRef<[u8]>>(value: V) -> Attribute {
		Self::default()
			.with_oid(oids::ADDRESS_POSTAL_CODE)
			.with_value(value)
			.as_plain()
			.build()
			.expect("Failed to build postalCode attribute")
	}
}

// Implement the extension trait for any type that implements AttributeBuilderLike
impl<T: AttributeBuilderLike> AttributeBuilderExtensions for T {}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::kyc_schema::builder::AttributeBuilder;

	struct AttributeTestData {
		method_name: &'static str,
		test_value: &'static [u8],
		expected_sensitivity: bool,
	}

	const ATTRIBUTE_TEST_DATA: &[AttributeTestData] = &[
		AttributeTestData {
			method_name: "for_date_of_birth",
			test_value: b"test_dateOfBirth_value",
			expected_sensitivity: true,
		},
		AttributeTestData { method_name: "for_email", test_value: b"test_email_value", expected_sensitivity: true },
		AttributeTestData {
			method_name: "for_full_name",
			test_value: b"test_fullName_value",
			expected_sensitivity: true,
		},
		AttributeTestData { method_name: "for_id", test_value: b"test_id_value", expected_sensitivity: true },
		AttributeTestData { method_name: "for_issuer", test_value: b"test_issuer_value", expected_sensitivity: true },
		AttributeTestData {
			method_name: "for_job_responsibility",
			test_value: b"test_jobResponsibility_value",
			expected_sensitivity: true,
		},
		AttributeTestData {
			method_name: "for_job_title",
			test_value: b"test_jobTitle_value",
			expected_sensitivity: true,
		},
		AttributeTestData {
			method_name: "for_phone_number",
			test_value: b"test_phoneNumber_value",
			expected_sensitivity: true,
		},
		AttributeTestData {
			method_name: "for_postal_code",
			test_value: b"test_postalCode_value",
			expected_sensitivity: false,
		},
	];

	#[test]
	fn test_all_attribute_builder_extensions() {
		for test_data in ATTRIBUTE_TEST_DATA {
			// Test that each method exists and works correctly
			let result = match test_data.method_name {
				"for_date_of_birth" => AttributeBuilder::for_date_of_birth(test_data.test_value),
				"for_email" => AttributeBuilder::for_email(test_data.test_value),
				"for_full_name" => AttributeBuilder::for_full_name(test_data.test_value),
				"for_id" => AttributeBuilder::for_id(test_data.test_value),
				"for_issuer" => AttributeBuilder::for_issuer(test_data.test_value),
				"for_job_responsibility" => AttributeBuilder::for_job_responsibility(test_data.test_value),
				"for_job_title" => AttributeBuilder::for_job_title(test_data.test_value),
				"for_phone_number" => AttributeBuilder::for_phone_number(test_data.test_value),
				"for_postal_code" => AttributeBuilder::for_postal_code(test_data.test_value),
				_ => panic!("Unknown method: {}", test_data.method_name),
			};

			// Verify the attribute was created correctly
			assert_eq!(
				result.is_sensitive(),
				test_data.expected_sensitivity,
				"Method {} should create {} attribute",
				test_data.method_name,
				if test_data.expected_sensitivity {
					"sensitive"
				} else {
					"plain"
				}
			);

			// Verify the value was set correctly
			let expected_value = test_data.test_value;
			let actual_value = result.as_ref();
			assert_eq!(actual_value, expected_value, "Method {} should set value correctly", test_data.method_name);
		}
	}

	#[test]
	fn test_method_count() {
		// Ensure we have the expected number of testable methods (simple types only)
		assert_eq!(ATTRIBUTE_TEST_DATA.len(), 9, "Expected 9 testable attribute methods");
	}
}

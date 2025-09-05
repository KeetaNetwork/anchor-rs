use std::fs;
use std::path::Path;

use keetanetwork_utils::build::{compile_asn1_directory_with_full_config, Asn1CompileConfig};
use serde_json::Value;

fn main() {
	// Generate ASN.1 code
	let config = Asn1CompileConfig::new("asn1", "src/generated")
		.with_generated_rs_path("src/generated.rs")
		.with_remove_module_wrappers(true)
		.with_public_modules(vec!["iso20022"]);

	if let Err(e) = compile_asn1_directory_with_full_config(&config) {
		panic!("ASN.1 compilation failed: {e}");
	}

	// Load OID data once for all generators
	let oids = load_oids_json();

	// Generate From implementations for wrapper types
	generate_attribute_from_impl(&oids);
	// Generate the builder trait extension
	generate_builder_trait_extension(&oids);
}

fn load_oids_json() -> Value {
	let oids = keetanetwork_asn1::utils::get_oid_json();
	serde_json::from_str(&oids).expect("Failed to parse OIDs JSON")
}

fn format_oid_comment(oid_array: &[Value]) -> String {
	let numbers: Vec<String> = oid_array
		.iter()
		.filter_map(|v| v.as_u64())
		.map(|n| n.to_string())
		.collect();
	numbers.join(".")
}

fn generate_attribute_from_impl(oids: &Value) {
	let dest_path = Path::new("src/generated").join("from_impls.rs");
	let mut generated_code = String::new();
	generated_code.push_str("use crate::oids;\n");
	generated_code.push_str("use crate::error::Asn1Error;\n");
	generated_code.push_str("use rasn::types::OctetString;\n\n");

	// Generate TryFrom implementations for structured types in sensitive attributes
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		for (name, info) in sensitive_attrs {
			if let (Some(token), Some(_oid_array), Some(attr_type)) =
				(info["token"].as_str(), info["oid"].as_array(), info["type"].as_str())
			{
				let const_name = format!("oids::keeta::{}", camel_to_snake_upper(name));

				match attr_type {
					"SEQUENCE" | "CHOICE" => {
						let type_name = if let Some(stripped) = token.strip_suffix("Attribute") {
							stripped.to_string()
						} else {
							token.to_string()
						};

						generated_code.push_str(&format!(
							r#"impl TryFrom<{type_name}> for Attribute {{
	type Error = Asn1Error;

	fn try_from(value: {type_name}) -> Result<Self, Self::Error> {{
		let name = {const_name};
		let encoded = rasn::der::encode(&value)?;
		let value = AttributeValue::sensitiveValue(OctetString::from_slice(&encoded));
		Ok(Attribute {{ name, value }})
	}}
}}

"#
						));
					}
					_ => {} // Skip primitive types as they're handled by builder extensions
				}
			}
		}
	}

	// Ensure the src/generated directory exists
	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create src/generated directory");
	}

	fs::write(&dest_path, generated_code).expect("Failed to write from_impls.rs");
	println!("Generated {}", dest_path.display());
}

fn generate_builder_trait_extension(oids: &Value) {
	let dest_path = Path::new("src/generated").join("builder_ext.rs");
	let mut generated_code = String::new();

	// Add module header and imports
	generated_code.push_str(
		r#"//! Generated trait extension for AttributeBuilderLike with typed methods
//!
//! This module provides a trait extension that adds `for_*` methods for all
//! available KYC attributes, making the builder API more ergonomic and type-safe.

use crate::kyc_schema::builder::AttributeBuilderLike;
use crate::generated::Attribute;
use crate::asn1::oids;

/// Extension trait for [`AttributeBuilderLike`] providing typed methods for KYC attributes.
///
/// This trait extends the basic [`AttributeBuilderLike`] functionality with convenience
/// methods for creating attributes with predefined OIDs. Each method is infallible
/// and will panic if the attribute cannot be created.
pub trait AttributeBuilderExtensions: AttributeBuilderLike + Sized {
"#,
	);

	// Collect all attributes from different sources
	let mut all_attributes = Vec::new();

	// Add plain attributes
	if let Some(plain_attrs) = oids["plain_attributes"].as_object() {
		for (name, info) in plain_attrs {
			if let Some(oid_array) = info["oid"].as_array() {
				let oid_comment = format_oid_comment(oid_array);
				let type_str = info["type"].as_str().unwrap_or("UTF8String");
				all_attributes.push((name.clone(), oid_comment, false, "plain", type_str.to_string()));
			}
		}
	}

	// Add sensitive attributes (all types)
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		for (name, info) in sensitive_attrs {
			if let Some(oid_array) = info["oid"].as_array() {
				let oid_comment = format_oid_comment(oid_array);
				let type_str = info["type"].as_str().unwrap_or("Unknown");
				all_attributes.push((name.clone(), oid_comment, true, "sensitive", type_str.to_string()));
			}
		}
	}

	// Sort attributes alphabetically for consistent output
	all_attributes.sort_by(|a, b| a.0.cmp(&b.0));

	// Generate methods for each attribute
	for (attr_name, _oid_comment, is_sensitive, source, attr_type) in &all_attributes {
		// Skip complex types since we now have TryFrom implementations for them
		if matches!(attr_type.as_str(), "SEQUENCE" | "CHOICE") {
			continue;
		}

		let method_name = format!("for_{}", camel_to_snake_case(attr_name));
		let sensitivity = if *is_sensitive {
			"sensitive"
		} else {
			"plain"
		};
		let const_name = if *source == "plain" {
			match attr_name.as_str() {
				"postalCode" => "oids::ADDRESS_POSTAL_CODE".to_string(),
				_ => format!("oids::ADDRESS_{}", attr_name.to_uppercase()),
			}
		} else {
			format!("oids::keeta::{}", camel_to_snake_upper(attr_name))
		};

		// Generate method signatures for simple types only
		generated_code.push_str(&format!(
			r#"	/// Create a {attr_name} attribute ({sensitivity})
	///
	/// Creates a {sensitivity} attribute for {attr_name} with the predefined OID.
	///
	/// # Arguments
	///
	/// - `value` - The attribute value as bytes
	fn {method_name}<V: AsRef<[u8]>>(value: V) -> Attribute {{
		Self::default()
			.with_oid({const_name})
			.with_value(value)
			.as_{sensitivity}()
			.build()
			.expect("Failed to build {attr_name} attribute")
	}}

"#
		));
	}

	// Close the trait
	generated_code.push_str("}\n\n");

	// Implement the trait for AttributeBuilder
	generated_code.push_str(
		r#"// Implement the extension trait for any type that implements AttributeBuilderLike
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
"#,
	);

	// Generate test data for each attribute
	let mut test_data_entries = Vec::new();
	for (attr_name, _oid_comment, is_sensitive, _source, attr_type) in &all_attributes {
		let method_name = format!("for_{}", camel_to_snake_case(attr_name));

		// Only generate tests for simple types that can be tested with byte values
		if matches!(attr_type.as_str(), "UTF8String" | "GeneralizedTime") {
			test_data_entries.push(format!(
				r#"		AttributeTestData {{
			method_name: "{method_name}",
			test_value: b"test_{attr_name}_value",
			expected_sensitivity: {is_sensitive},
		}}"#
			));
		}
	}

	generated_code.push_str(&test_data_entries.join(",\n"));
	generated_code.push_str(
		r#"
	];

	#[test]
	fn test_all_attribute_builder_extensions() {
		for test_data in ATTRIBUTE_TEST_DATA {
			// Test that each method exists and works correctly
			let result = match test_data.method_name {
"#,
	);

	// Generate match arms for each testable method (simple types only)
	for (attr_name, _oid_comment, _is_sensitive, _source, attr_type) in &all_attributes {
		if matches!(attr_type.as_str(), "UTF8String" | "GeneralizedTime") {
			let method_name = format!("for_{}", camel_to_snake_case(attr_name));
			generated_code.push_str(&format!(
				r#"				"{method_name}" => AttributeBuilder::{method_name}(test_data.test_value),
"#
			));
		}
	}

	generated_code.push_str(
		r#"				_ => panic!("Unknown method: {}", test_data.method_name),
			};

			// Verify the attribute was created correctly
			assert_eq!(result.is_sensitive(), test_data.expected_sensitivity, 
				"Method {} should create {} attribute", 
				test_data.method_name, 
				if test_data.expected_sensitivity { "sensitive" } else { "plain" }
			);

			// Verify the value was set correctly
			let expected_value = test_data.test_value;
			let actual_value = result.as_ref();
			assert_eq!(actual_value, expected_value,
				"Method {} should set value correctly", test_data.method_name
			);
		}
	}
"#,
	);

	// Generate the test method count
	let testable_count = all_attributes
		.iter()
		.filter(|(_, _, _, _, attr_type)| matches!(attr_type.as_str(), "UTF8String" | "GeneralizedTime"))
		.count();
	let test_count_section = format!(
		r#"
	#[test]
	fn test_method_count() {{
		// Ensure we have the expected number of testable methods (simple types only)
		assert_eq!(ATTRIBUTE_TEST_DATA.len(), {testable_count}, 
			"Expected {testable_count} testable attribute methods"); 
	}}
}}
"#
	);
	generated_code.push_str(&test_count_section);

	// Ensure the src/generated directory exists
	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create src/generated directory");
	}

	fs::write(&dest_path, generated_code).expect("Failed to write builder_ext.rs");
	println!("Generated {}", dest_path.display());

	// Generate builder trait extension and update generated.rs
	update_generated_rs_with_builder_trait();
}

fn update_generated_rs_with_builder_trait() {
	let generated_rs_path = Path::new("src/generated.rs");

	// Read the current generated.rs content
	let current_content = fs::read_to_string(generated_rs_path).expect("Failed to read generated.rs");

	// Check if builder_ext module is already included
	if current_content.contains("mod builder_ext;") {
		return; // Already updated
	}

	// Find the insertion point (after all module declarations but before re-exports)
	let lines: Vec<&str> = current_content.lines().collect();
	let mut updated_lines = Vec::new();
	let mut inserted = false;

	for line in lines {
		// Insert before the first re-export line (which starts with "// Re-export" or "pub use")
		if (line.starts_with("// Re-export") || line.starts_with("pub use")) && !inserted {
			updated_lines.push("#[path = \"generated/builder_ext.rs\"]".to_string());
			updated_lines.push("pub mod builder_ext;".to_string());
			updated_lines.push("".to_string()); // Add empty line before re-exports
			inserted = true;
		}

		updated_lines.push(line.to_string());
	}

	// If we didn't find re-exports, append at the end
	if !inserted {
		updated_lines.push("".to_string());
		updated_lines.push("#[path = \"generated/builder_ext.rs\"]".to_string());
		updated_lines.push("pub mod builder_ext;".to_string());
	}

	// Write the updated content back
	let updated_content = updated_lines.join("\n");
	fs::write(generated_rs_path, updated_content).expect("Failed to update generated.rs");

	println!("Updated generated.rs with builder_ext module");
}

fn camel_to_snake_case(s: &str) -> String {
	let mut result = String::new();
	let chars = s.chars().peekable();
	for c in chars {
		if c.is_uppercase() && !result.is_empty() {
			result.push('_');
		}
		result.push(c.to_lowercase().next().unwrap());
	}
	result
}

fn camel_to_snake_upper(s: &str) -> String {
	let mut result = String::new();
	let chars = s.chars().peekable();
	for c in chars {
		if c.is_uppercase() && !result.is_empty() {
			result.push('_');
		}
		result.push(c.to_uppercase().next().unwrap());
	}

	result
}

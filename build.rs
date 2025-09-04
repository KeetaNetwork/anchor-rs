use std::fs;
use std::path::Path;

use keetanetwork_utils::build::{compile_asn1_directory_with_full_config, Asn1CompileConfig};
use serde_json::Value;

fn main() {
	// Generate OID schema tokens
	generate_schema();
	// Generate OIDs from JSON
	generate_oids_from_json();

	// Generate ASN.1 code
	let config = Asn1CompileConfig::new("asn1", "src/generated")
		.with_generated_rs_path("src/generated.rs")
		.with_remove_module_wrappers(true)
		.with_public_modules(vec!["iso20022"]);

	if let Err(e) = compile_asn1_directory_with_full_config(&config) {
		panic!("ASN.1 compilation failed: {e}");
	}

	// Generate From implementations for wrapper types
	generate_from_implementations();
	// Generate the builder trait extension
	generate_builder_trait_extension();
}

fn generate_schema() {
	println!("cargo:rerun-if-changed=oids.json");

	let dest_path = Path::new("asn1").join("iso20022.asn");

	// Read and parse the JSON file
	let json_content = fs::read_to_string("oids.json").expect("Failed to read oids.json");
	let oids: Value = serde_json::from_str(&json_content).expect("Failed to parse oids.json");

	let mut schema_content = String::new();

	// Add ASN.1 module header
	schema_content.push_str(
		"Iso20022 DEFINITIONS AUTOMATIC TAGS ::= BEGIN

",
	);

	// Generate all type definitions
	generate_primitive_types(&oids, &mut schema_content);
	generate_sensitive_primitive_types(&oids, &mut schema_content);

	schema_content.push('\n');

	generate_choice_types(&oids, &mut schema_content);
	generate_sensitive_sequence_types(&oids, &mut schema_content);
	generate_iso20022_sequence_types(&oids, &mut schema_content);
	generate_sensitive_choice_types(&oids, &mut schema_content);
	generate_enumerated_types(&oids, &mut schema_content);

	// Add module footer
	schema_content.push_str("END\n");

	// Ensure the asn1 directory exists
	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create asn1 directory");
	}

	fs::write(&dest_path, schema_content).expect("Failed to write iso20022.asn");
	println!("Generated {}", dest_path.display());
}

fn generate_primitive_types(oids: &Value, schema_content: &mut String) {
	if let Some(primitives) = oids["iso20022_types"]["primitives"].as_object() {
		let mut primitive_items: Vec<_> = primitives.iter().collect();
		primitive_items.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (name, info) in primitive_items {
			if let (Some(oid_array), Some(type_str)) = (info["oid"].as_array(), info["type"].as_str()) {
				let oid_comment = format_oid_comment(oid_array);
				let padded_name = format!("{:<21}", format!("{} ::= {}", name, type_str));
				schema_content.push_str(&format!("    {padded_name} --{oid_comment}\n"));
			}
		}
	}
}

fn generate_sensitive_primitive_types(oids: &Value, schema_content: &mut String) {
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		let mut simple_attrs: Vec<_> = sensitive_attrs
			.iter()
			.filter(|(_, info)| matches!(info["type"].as_str(), Some("UTF8String") | Some("GeneralizedTime")))
			.collect();

		simple_attrs.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (_name, info) in simple_attrs {
			if let (Some(oid_array), Some(type_str), Some(token)) =
				(info["oid"].as_array(), info["type"].as_str(), info["token"].as_str())
			{
				let oid_comment = format_oid_comment(oid_array);
				let padded_name = format!("{:<21}", format!("{} ::= {}", token, type_str));
				schema_content.push_str(&format!("    {padded_name} --{oid_comment}\n"));
			}
		}
	}
}

fn generate_choice_types(oids: &Value, schema_content: &mut String) {
	if let Some(choices) = oids["iso20022_types"]["choices"].as_object() {
		let mut choice_items: Vec<_> = choices.iter().collect();
		choice_items.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (name, info) in choice_items {
			if let (Some(oid_array), Some(choices_obj)) = (info["oid"].as_array(), info["choices"].as_object()) {
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {name} ::= CHOICE {{ -- {oid_comment}\n"));

				let choice_entries: Vec<_> = choices_obj.iter().collect();
				for (i, (choice_name, choice_info)) in choice_entries.iter().enumerate() {
					if let Some(choice_type) = choice_info["type"].as_str() {
						let comma = if i == choice_entries.len() - 1 {
							""
						} else {
							","
						};

						schema_content
							.push_str(&format!("        {choice_name:<17} [{i}] IMPLICIT {choice_type}{comma}\n"));
					}
				}
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn generate_sensitive_sequence_types(oids: &Value, schema_content: &mut String) {
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		let mut sequence_attrs: Vec<_> = sensitive_attrs
			.iter()
			.filter(|(_, info)| info["type"].as_str() == Some("SEQUENCE"))
			.collect();

		sequence_attrs.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (_, info) in sequence_attrs {
			if let (Some(oid_array), Some(token), Some(fields)) =
				(info["oid"].as_array(), info["token"].as_str(), info["fields"].as_object())
			{
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {token} ::= SEQUENCE {{ --{oid_comment}\n"));

				for (field_name, field_info) in fields {
					if let (Some(field_type), Some(optional)) =
						(field_info["type"].as_str(), field_info["optional"].as_bool())
					{
						let optional_str = if optional {
							" OPTIONAL"
						} else {
							""
						};
						schema_content.push_str(&format!("        {field_name:<17} {field_type}{optional_str},\n"));
					}
				}
				// Remove the trailing comma and newline, add closing brace
				if schema_content.ends_with(",\n") {
					schema_content.truncate(schema_content.len() - 2);
					schema_content.push('\n');
				}
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn generate_iso20022_sequence_types(oids: &Value, schema_content: &mut String) {
	if let Some(sequences) = oids["iso20022_types"]["sequences"].as_object() {
		let mut sequence_items: Vec<_> = sequences.iter().collect();
		sequence_items.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (name, info) in sequence_items {
			if let (Some(oid_array), Some(fields)) = (info["oid"].as_array(), info["fields"].as_object()) {
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {name} ::= SEQUENCE {{ --{oid_comment}\n"));

				for (field_name, field_info) in fields {
					if let (Some(field_type), Some(optional)) =
						(field_info["type"].as_str(), field_info["optional"].as_bool())
					{
						let optional_str = if optional {
							" OPTIONAL"
						} else {
							""
						};
						schema_content.push_str(&format!("        {field_name:<17} {field_type}{optional_str},\n"));
					}
				}
				// Remove the trailing comma and newline, add closing brace
				if schema_content.ends_with(",\n") {
					schema_content.truncate(schema_content.len() - 2);
					schema_content.push('\n');
				}
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn generate_sensitive_choice_types(oids: &Value, schema_content: &mut String) {
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		let mut choice_attrs: Vec<_> = sensitive_attrs
			.iter()
			.filter(|(_, info)| info["type"].as_str() == Some("CHOICE"))
			.collect();

		choice_attrs.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (_, info) in choice_attrs {
			if let (Some(oid_array), Some(token), Some(choices_obj)) =
				(info["oid"].as_array(), info["token"].as_str(), info["choices"].as_object())
			{
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {token} ::= CHOICE {{ --{oid_comment}\n"));

				let choice_entries: Vec<_> = choices_obj.iter().collect();
				for (i, (choice_name, choice_info)) in choice_entries.iter().enumerate() {
					if let Some(choice_type) = choice_info["type"].as_str() {
						let comma = if i == choice_entries.len() - 1 {
							""
						} else {
							","
						};

						schema_content
							.push_str(&format!("        {choice_name:<17} [{i}] IMPLICIT {choice_type}{comma}\n"));
					}
				}
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn generate_enumerated_types(oids: &Value, schema_content: &mut String) {
	if let Some(enumerations) = oids["iso20022_types"]["enumerations"].as_object() {
		let mut enum_items: Vec<_> = enumerations.iter().collect();
		enum_items.sort_by_key(|(_, info)| {
			info["oid"]
				.as_array()
				.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
				.unwrap_or_default()
		});

		for (name, info) in enum_items {
			if let (Some(oid_array), Some(values)) = (info["oid"].as_array(), info["values"].as_array()) {
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {name} ::= ENUMERATED {{ --{oid_comment}\n"));

				let enum_values: Vec<String> = values
					.iter()
					.filter_map(|v| v.as_str())
					.map(|s| s.to_string())
					.collect();
				schema_content.push_str(&format!("        {}\n", enum_values.join(", ")));
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn format_oid_comment(oid_array: &[Value]) -> String {
	let numbers: Vec<String> = oid_array
		.iter()
		.filter_map(|v| v.as_u64())
		.map(|n| n.to_string())
		.collect();
	numbers.join(".")
}

fn generate_from_implementations() {
	println!("cargo:rerun-if-changed=oids.json");

	let dest_path = Path::new("src/generated").join("from_impls.rs");

	// Read and parse the JSON file
	let json_content = fs::read_to_string("oids.json").expect("Failed to read oids.json");
	let oids: Value = serde_json::from_str(&json_content).expect("Failed to parse oids.json");

	let mut generated_code = String::new();

	// Add header comment
	generated_code.push_str(
		r#"//! Generated From implementations for wrapper types
//!
//! This module provides convenient From implementations for all wrapper types
//! that delegate to primitive types like Utf8String and GeneralizedTime,
//! making them more ergonomic to use.

use super::*;

"#,
	);

	// Define supported type mappings with their From implementations
	let type_mappings = vec![
		TypeMapping {
			asn1_type: "UTF8String",
			implementations: vec![
				FromImpl { from_type: "String", conversion: "value.into()", feature_gate: None },
				FromImpl { from_type: "&str", conversion: "value.into()", feature_gate: None },
			],
		},
		TypeMapping {
			asn1_type: "GeneralizedTime",
			implementations: vec![
				FromImpl { from_type: "rasn::types::GeneralizedTime", conversion: "value", feature_gate: None },
				FromImpl {
					from_type: "std::time::SystemTime",
					conversion: "chrono::DateTime::<chrono::Utc>::from(value).into()",
					feature_gate: Some("chrono"),
				},
				FromImpl {
					from_type: "chrono::DateTime<chrono::Utc>",
					conversion: "value.into()",
					feature_gate: Some("chrono"),
				},
				FromImpl {
					from_type: "chrono::NaiveDate",
					conversion: "value.and_hms_opt(0, 0, 0).unwrap().and_utc().fixed_offset()",
					feature_gate: Some("chrono"),
				},
			],
		},
	];

	// Collect wrapper types by their underlying ASN.1 type
	let wrapper_types = collect_wrapper_types(&oids);

	// Generate From implementations for each type mapping
	for type_mapping in &type_mappings {
		if let Some(wrappers) = wrapper_types.get(type_mapping.asn1_type) {
			generate_from_impls_for_type(&mut generated_code, wrappers, type_mapping);
		}
	}

	// Generate From implementations for Attribute from structured types
	generate_attribute_from_impls(&mut generated_code, &oids);

	// Ensure the src/generated directory exists
	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create src/generated directory");
	}

	fs::write(&dest_path, generated_code).expect("Failed to write from_impls.rs");
	println!("Generated {}", dest_path.display());

	// Update generated.rs to include this module
	update_generated_rs_with_from_impls();
}

#[derive(Debug)]
struct TypeMapping {
	asn1_type: &'static str,
	implementations: Vec<FromImpl>,
}

#[derive(Debug)]
struct FromImpl {
	from_type: &'static str,
	conversion: &'static str,
	feature_gate: Option<&'static str>,
}

fn collect_wrapper_types(oids: &Value) -> std::collections::HashMap<String, Vec<String>> {
	let mut wrapper_types: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

	// Add primitive types
	if let Some(primitives) = oids["iso20022_types"]["primitives"].as_object() {
		for (name, info) in primitives {
			if let Some(asn1_type) = info["type"].as_str() {
				wrapper_types
					.entry(asn1_type.to_string())
					.or_default()
					.push(name.clone());
			}
		}
	}

	// Add sensitive attributes
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		for (_name, info) in sensitive_attrs {
			if let Some(token) = info["token"].as_str() {
				if let Some(asn1_type) = info["type"].as_str() {
					wrapper_types
						.entry(asn1_type.to_string())
						.or_default()
						.push(token.to_string());
				}
			}
		}
	}

	// Sort for consistent output
	for wrappers in wrapper_types.values_mut() {
		wrappers.sort();
	}

	wrapper_types
}

fn generate_from_impls_for_type(generated_code: &mut String, wrapper_types: &[String], type_mapping: &TypeMapping) {
	for wrapper_type in wrapper_types {
		for from_impl in &type_mapping.implementations {
			let impl_block = format!(
				r#"impl From<{from_type}> for {wrapper_type} {{
	fn from(value: {from_type}) -> Self {{
		Self({conversion})
	}}
}}

"#,
				from_type = from_impl.from_type,
				wrapper_type = wrapper_type,
				conversion = from_impl.conversion
			);

			if let Some(feature) = from_impl.feature_gate {
				generated_code.push_str(&format!("#[cfg(feature = \"{feature}\")]\n{impl_block}"));
			} else {
				generated_code.push_str(&impl_block);
			}
		}
	}
}

fn generate_attribute_from_impls(generated_code: &mut String, oids: &Value) {
	generated_code.push_str("// TryFrom implementations for Attribute from structured types\n\n");

	// Add necessary imports for Attribute creation
	generated_code.push_str("use crate::asn1::oids;\n");
	generated_code.push_str("use crate::kyc_schema::error::KycSchemaError;\n");
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
	type Error = KycSchemaError;

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

	// Generate Default implementations for types with all optional fields
	generate_default_impls(oids, generated_code);
}

fn generate_default_impls(oids: &Value, generated_code: &mut String) {
	generated_code.push_str("// Default implementations for types with defaultable fields\n\n");

	// Types that typically implement Default in rasn
	let default_types = [
		"String",
		"UTF8String",
		"Utf8String",
		"Vec",
		"SequenceOf",
		"BooleanType",
		"Integer",
		"BitString",
		"OctetString",
	];

	// Check sensitive_attributes for SEQUENCE types
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		for (name, attr_info) in sensitive_attrs {
			if attr_info["type"] == "SEQUENCE" {
				if let Some(fields) = attr_info["fields"].as_object() {
					let token = attr_info["token"].as_str().unwrap_or(name);

					// Check if we can generate Default for this type
					let mut can_default = true;
					let mut field_defaults = Vec::new();

					for (_field_name, field_info) in fields {
						let is_optional = field_info["optional"].as_bool().unwrap_or(false);
						let field_type = field_info["type"].as_str().unwrap_or("");

						if is_optional {
							field_defaults.push("None".to_string());
						} else {
							// Check if the required field type implements Default
							if default_types.iter().any(|&t| field_type.contains(t))
								|| field_type == "NamePrefixCode"
								|| field_type == "PreferredContactMethodCode"
							{
								field_defaults.push("Default::default()".to_string());
							} else {
								can_default = false;
								break;
							}
						}
					}

					if can_default {
						generated_code.push_str(&format!(
							r#"impl Default for {token} {{
	fn default() -> Self {{
		Self::new(
			{}
		)
	}}
}}

"#,
							field_defaults.join(",\n\t\t\t")
						));
					}
				}
			}
		}
	}

	// Check iso20022_types sequences
	if let Some(iso_types) = oids["iso20022_types"]["sequences"].as_object() {
		for (name, type_info) in iso_types {
			if let Some(fields) = type_info["fields"].as_object() {
				let mut can_default = true;
				let mut field_defaults = Vec::new();

				for (_field_name, field_info) in fields {
					let is_optional = field_info["optional"].as_bool().unwrap_or(false);
					let field_type = field_info["type"].as_str().unwrap_or("");

					if is_optional {
						field_defaults.push("None".to_string());
					} else {
						// Check if the required field type implements Default
						if default_types.iter().any(|&t| field_type.contains(t))
							|| field_type == "NamePrefixCode"
							|| field_type == "PreferredContactMethodCode"
						{
							field_defaults.push("Default::default()".to_string());
						} else {
							can_default = false;
							break;
						}
					}
				}

				if can_default {
					generated_code.push_str(&format!(
						r#"impl Default for {name} {{
	fn default() -> Self {{
		Self::new(
			{}
		)
	}}
}}

"#,
						field_defaults.join(",\n\t\t\t")
					));
				}
			}
		}
	}
}

fn update_generated_rs_with_from_impls() {
	let generated_rs_path = Path::new("src/generated.rs");

	// Read the current generated.rs content
	let current_content = fs::read_to_string(generated_rs_path).expect("Failed to read generated.rs");

	// Check if from_impls module is already included
	if current_content.contains("mod from_impls;") {
		return; // Already updated
	}

	// Find the insertion point (after all module declarations but before re-exports)
	let lines: Vec<&str> = current_content.lines().collect();
	let mut updated_lines = Vec::new();
	let mut inserted = false;

	for line in lines {
		// Insert before the first re-export line (which starts with "// Re-export" or "pub use")
		if (line.starts_with("// Re-export") || line.starts_with("pub use")) && !inserted {
			updated_lines.push("#[path = \"generated/from_impls.rs\"]".to_string());
			updated_lines.push("mod from_impls;".to_string());
			updated_lines.push("".to_string()); // Add empty line before re-exports
			inserted = true;
		}

		updated_lines.push(line.to_string());
	}

	// If we didn't find re-exports, append at the end
	if !inserted {
		updated_lines.push("".to_string());
		updated_lines.push("#[path = \"generated/from_impls.rs\"]".to_string());
		updated_lines.push("mod from_impls;".to_string());
	}

	// Write the updated content back
	let updated_content = updated_lines.join("\n");
	fs::write(generated_rs_path, updated_content).expect("Failed to update generated.rs");

	println!("Updated generated.rs with from_impls module");
}

fn generate_oids_from_json() {
	println!("cargo:rerun-if-changed=oids.json");

	let dest_path = Path::new("src/generated").join("oids.rs");

	// Read and parse the JSON file
	let json_content = fs::read_to_string("oids.json").expect("Failed to read oids.json");
	let oids: Value = serde_json::from_str(&json_content).expect("Failed to parse oids.json");

	let mut generated_code = String::new();

	// Add imports and header
	generated_code.push_str(
		r#"
use std::borrow::Cow;
use std::collections::HashMap;
use rasn::types::ObjectIdentifier;

"#,
	);

	// Generate algorithm constants
	if let Some(algorithms) = oids["algorithms"].as_object() {
		generated_code.push_str("// Algorithm OID constants\n");
		for (name, oid_array) in algorithms {
			let const_name = name.to_uppercase().replace('-', "_");
			let oid_values = format_oid_array(oid_array);
			generated_code.push_str(&format!(
				"pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
			));
		}
		generated_code.push('\n');
	}

	// Generate plain attribute constants
	if let Some(plain_attrs) = oids["plain_attributes"].as_object() {
		generated_code.push_str("// Plain attribute OID constants\n");
		for (name, attr_info) in plain_attrs {
			if let Some(oid_array) = attr_info["oid"].as_array() {
				let const_name = match name.as_str() {
					"postalCode" => "ADDRESS_POSTAL_CODE",
					_ => &format!("ADDRESS_{}", name.to_uppercase()),
				};
				let oid_values = format_oid_array(&Value::Array(oid_array.clone()));

				if let Some(description) = attr_info["description"].as_str() {
					generated_code.push_str(&format!("/// {description}\n"));
				}
				if let Some(reference) = attr_info["reference"].as_str() {
					generated_code.push_str(&format!("/// # References\n/// - [{reference}]({reference})\n"));
				}

				generated_code.push_str(&format!(
					"pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
				));
			}
		}
		generated_code.push('\n');
	}

	// Generate Keeta module
	generated_code.push_str("pub mod keeta {\n");
	generated_code.push_str("    use super::*;\n\n");

	// Generate extension constants
	if let Some(extensions) = oids["extensions"].as_object() {
		generated_code.push_str("    // Extension OID constants\n");
		for (name, ext_info) in extensions {
			if let Some(oid_array) = ext_info["oid"].as_array() {
				let const_name = match name.as_str() {
					"kycAttributes" => "KYC_ATTRIBUTES",
					_ => &name.to_uppercase(),
				};
				let oid_values = format_oid_array(&Value::Array(oid_array.clone()));
				generated_code.push_str(&format!(
					"    pub const {const_name}_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
				));
			}
		}
		generated_code.push('\n');
	}

	// Generate sensitive attribute constants
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		generated_code.push_str("    // Sensitive attribute OID constants\n");
		for (name, attr_info) in sensitive_attrs {
			if let Some(oid_array) = attr_info["oid"].as_array() {
				let const_name = camel_to_snake_upper(name);
				let oid_values = format_oid_array(&Value::Array(oid_array.clone()));

				if let Some(description) = attr_info["description"].as_str() {
					generated_code.push_str(&format!("    /// {description}\n"));
				}

				generated_code.push_str(&format!(
					"    pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
				));
			}
		}
		generated_code.push('\n');
	}

	// Generate sensitive attributes HashMap
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		generated_code.push_str("    lazy_static::lazy_static! {\n");
		generated_code.push_str("        /// OID database for sensitive certificate attributes.\n");
		generated_code
			.push_str("        pub static ref SENSITIVE_ATTRIBUTES: HashMap<&'static str, ObjectIdentifier> = {\n");
		generated_code.push_str("            [\n");
		for name in sensitive_attrs.keys() {
			let const_name = camel_to_snake_upper(name);
			generated_code.push_str(&format!("                (\"{name}\", {const_name}),\n"));
		}
		generated_code.push_str("            ]\n");
		generated_code.push_str("            .iter()\n");
		generated_code.push_str("            .cloned()\n");
		generated_code.push_str("            .collect()\n");
		generated_code.push_str("        };\n");
		generated_code.push_str("    }\n");
	}

	generated_code.push_str("}\n\n");

	// Generate algorithm attributes HashMap
	if let Some(algorithms) = oids["algorithms"].as_object() {
		generated_code.push_str("lazy_static::lazy_static! {\n");
		generated_code.push_str("    /// OID database for sensitive attribute algorithms.\n");
		generated_code
			.push_str("    pub static ref ALGORITHM_ATTRIBUTES: HashMap<&'static str, ObjectIdentifier> = {\n");
		generated_code.push_str("        [\n");
		for name in algorithms.keys() {
			let const_name = name.to_uppercase().replace('-', "_");
			generated_code.push_str(&format!("            (\"{name}\", {const_name}),\n"));
		}
		generated_code.push_str("        ]\n");
		generated_code.push_str("        .iter()\n");
		generated_code.push_str("        .cloned()\n");
		generated_code.push_str("        .collect()\n");
		generated_code.push_str("    };\n");
		generated_code.push_str("}\n\n");
	}

	// Generate plain attributes HashMap
	if let Some(plain_attrs) = oids["plain_attributes"].as_object() {
		generated_code.push_str("lazy_static::lazy_static! {\n");
		generated_code.push_str("    /// OID database for plain certificate attributes.\n");
		generated_code.push_str("    pub static ref PLAIN_ATTRIBUTES: HashMap<&'static str, ObjectIdentifier> = {\n");
		generated_code.push_str("        [\n");
		for name in plain_attrs.keys() {
			let const_name = match name.as_str() {
				"postalCode" => "ADDRESS_POSTAL_CODE",
				_ => &format!("ADDRESS_{}", name.to_uppercase()),
			};
			generated_code.push_str(&format!("            (\"{name}\", {const_name}),\n"));
		}
		generated_code.push_str("        ]\n");
		generated_code.push_str("        .iter()\n");
		generated_code.push_str("        .cloned()\n");
		generated_code.push_str("        .collect()\n");
		generated_code.push_str("    };\n");
		generated_code.push_str("}\n");
	}

	fs::write(&dest_path, generated_code).unwrap();
}

fn format_oid_array(value: &Value) -> String {
	if let Some(array) = value.as_array() {
		let numbers: Vec<String> = array
			.iter()
			.filter_map(|v| v.as_u64())
			.map(|n| n.to_string())
			.collect();
		format!("[{}]", numbers.join(", "))
	} else {
		"[0]".to_string()
	}
}

fn generate_builder_trait_extension() {
	println!("cargo:rerun-if-changed=oids.json");

	let dest_path = Path::new("src/generated").join("builder_ext.rs");

	// Read and parse the JSON file
	let json_content = fs::read_to_string("oids.json").expect("Failed to read oids.json");
	let oids: Value = serde_json::from_str(&json_content).expect("Failed to parse oids.json");

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

#[allow(dead_code)]
fn camel_to_pascal_case(s: &str) -> String {
	let mut result = String::new();
	let mut chars = s.chars();

	if let Some(first_char) = chars.next() {
		result.push(first_char.to_uppercase().next().unwrap());
		for c in chars {
			result.push(c);
		}
	}

	result
}

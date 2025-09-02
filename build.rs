use std::fs;
use std::path::Path;

use keetanetwork_utils::build::{compile_asn1_directory_with_full_config, Asn1CompileConfig};
use serde_json::Value;

fn main() {
	// Generate ASN.1 code
	let config = Asn1CompileConfig::new("asn1", "src/generated")
		.with_generated_rs_path("src/generated.rs")
		.with_remove_module_wrappers(true);

	if let Err(e) = compile_asn1_directory_with_full_config(&config) {
		panic!("ASN.1 compilation failed: {e}");
	}

	// Generate OIDs from JSON
	generate_oids_from_json();
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

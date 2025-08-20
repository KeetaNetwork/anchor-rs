use base64::Engine;

/// Macro to generate From implementations for error enums
///
/// This macro reduces boilerplate when implementing From trait for error types
/// that wrap other error types in enum variants.
///
/// # Example
/// ```rust
/// use anchor_rs::impl_source_error_from;
///
/// #[derive(Debug)]
/// enum MyError {
///     IoError { source: std::io::Error },
///     ParseError { source: std::num::ParseIntError },
/// }
///
/// impl_source_error_from!(MyError, {
///     std::io::Error => IoError,
///     std::num::ParseIntError => ParseError,
/// });
/// ```
#[macro_export]
macro_rules! impl_source_error_from {
	($target_error:ty, { $($source_type:ty => $variant:ident),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(source: $source_type) -> Self {
					Self::$variant { source: source.into() }
				}
			}
		)+
	};
}

/// Macro to generate From implementations for error enums with transitive
/// conversions (via pattern).
///
/// This macro handles cases where an error needs to be converted through an
/// intermediate type before being wrapped in the target error enum variant.
///
/// # Example
/// ```rust
/// use anchor_rs::impl_source_error_from_via;
///
/// #[derive(Debug)]
/// enum MyError {
///     Asn1Error { source: crate::asn1::error::Asn1Error },
/// }
///
/// impl_source_error_from_via!(MyError, {
///     rasn::error::EncodeError => Asn1Error via crate::asn1::error::Asn1Error,
///     rasn::error::DecodeError => Asn1Error via crate::asn1::error::Asn1Error,
/// });
/// ```
#[macro_export]
macro_rules! impl_source_error_from_via {
	($target_error:ty, { $($source_type:ty => $variant:ident via $intermediate_type:ty),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(error: $source_type) -> Self {
					Self::$variant { source: <$intermediate_type>::from(error) }
				}
			}
		)+
	};
}

/// Macro to generate From implementations for error enums with plain variants.
///
/// This macro reduces boilerplate when implementing From trait for error types
/// that map to simple enum variants without source fields.
///
/// # Example
/// ```rust
/// use anchor_rs::impl_variant_error_from;
///
/// #[derive(Debug)]
/// enum MyError {
///     InvalidUtf8,
///     InvalidFormat,
/// }
///
/// impl_variant_error_from!(MyError, {
///     std::string::FromUtf8Error => InvalidUtf8,
///     std::num::ParseIntError => InvalidFormat,
/// });
/// ```
#[macro_export]
macro_rules! impl_variant_error_from {
	($target_error:ty, { $($source_type:ty => $variant:ident),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(_: $source_type) -> Self {
					Self::$variant
				}
			}
		)+
	};
}

/// Base64 encode wrapper.
pub(crate) fn base64_encode(data: impl AsRef<[u8]>) -> String {
	base64::prelude::BASE64_STANDARD.encode(data)
}

/// Base64 decode wrapper.
pub(crate) fn base64_decode(data: impl AsRef<str>) -> Result<Vec<u8>, base64::DecodeError> {
	base64::prelude::BASE64_STANDARD.decode(data.as_ref().as_bytes())
}

/// Serde helper functions for JSON serialization/deserialization
#[cfg(feature = "serde")]
pub mod serde_helpers {
	use base64::Engine;
	use rasn::types::ObjectIdentifier;
	use serde::de::Error as DeError;
	use serde_json::Value;

	use crate::asn1::*;

	/// Create a JSON object with string fields
	macro_rules! json_object {
		($($key:expr => $value:expr),* $(,)?) => {{
			#[allow(unused_mut)]
			let mut map = serde_json::Map::new();
			$(
				map.insert($key.to_string(), serde_json::Value::String($value));
			)*
			serde_json::Value::Object(map)
		}};
	}

	pub(crate) use json_object;

	/// Extract a required string field from a JSON object
	pub(crate) fn extract_string<'a, E: DeError>(
		obj: &'a serde_json::Map<String, Value>,
		field: &str,
	) -> std::result::Result<&'a str, E> {
		obj.get(field)
			.and_then(|v| v.as_str())
			.ok_or_else(|| E::custom(format!("Missing or invalid {field}")))
	}

	/// Extract and decode a base64 field from a JSON object
	pub(crate) fn extract_base64<E: DeError>(
		obj: &serde_json::Map<String, Value>,
		field: &str,
	) -> std::result::Result<Vec<u8>, E> {
		let b64_str = extract_string(obj, field)?;
		base64::prelude::BASE64_STANDARD
			.decode(b64_str)
			.map_err(|_| E::custom(format!("Invalid base64 in {field}")))
	}

	/// Extract a required object field from a JSON object
	pub(crate) fn extract_object<'a, E: DeError>(
		obj: &'a serde_json::Map<String, Value>,
		field: &str,
	) -> std::result::Result<&'a serde_json::Map<String, Value>, E> {
		obj.get(field)
			.and_then(|v| v.as_object())
			.ok_or_else(|| E::custom(format!("Missing or invalid {field}")))
	}

	/// Convert algorithm name to OID
	pub(crate) fn algorithm_to_oid<E: DeError>(algorithm: &str) -> std::result::Result<ObjectIdentifier, E> {
		match algorithm {
			"aes-256-gcm" => Ok(AES_256_GCM_OID),
			"sha2-256" => Ok(SHA2_256_OID),
			_ => Err(E::custom(format!("Unknown algorithm: {algorithm}"))),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_base64_encode_decode_roundtrip() {
		let test_data = b"Hello, World!.";

		let encoded = base64_encode(test_data);
		assert!(!encoded.is_empty());

		// Verify roundtrip
		let decoded = base64_decode(&encoded);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), test_data);

		// Test decode with invalid base64
		let invalid_result = base64_decode("not_valid_base64!");
		assert!(invalid_result.is_err());
	}

	#[cfg(feature = "serde")]
	mod serde_tests {
		use base64::Engine;
		use rasn::types::ObjectIdentifier;
		use serde_json::{Map, Value};

		use crate::asn1::{AES_256_GCM_OID, SHA2_256_OID};
		use crate::utils::serde_helpers::*;

		#[test]
		fn test_extract_string() {
			let mut map = Map::new();
			map.insert("test_field".to_string(), Value::String("test_value".to_string()));

			// Test successful extraction
			let result: Result<&str, serde_json::Error> = extract_string(&map, "test_field");
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), "test_value");

			// Test missing field
			let missing_result: Result<&str, serde_json::Error> = extract_string(&map, "missing_field");
			assert!(missing_result.is_err());

			// Test wrong type
			map.insert("number_field".to_string(), Value::Number(42.into()));
			let wrong_type_result: Result<&str, serde_json::Error> = extract_string(&map, "number_field");
			assert!(wrong_type_result.is_err());
		}

		#[test]
		fn test_extract_base64() {
			let mut map = Map::new();
			let test_data = b"hello world";
			let encoded = base64::prelude::BASE64_STANDARD.encode(test_data);
			map.insert("b64_field".to_string(), Value::String(encoded));

			// Test successful extraction and decoding
			let result: Result<Vec<u8>, serde_json::Error> = extract_base64(&map, "b64_field");
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), test_data);

			// Test invalid base64
			map.insert("invalid_b64".to_string(), Value::String("not_valid_base64!".to_string()));
			let invalid_result: Result<Vec<u8>, serde_json::Error> = extract_base64(&map, "invalid_b64");
			assert!(invalid_result.is_err());

			// Test missing field
			let missing_result: Result<Vec<u8>, serde_json::Error> = extract_base64(&map, "missing");
			assert!(missing_result.is_err());
		}

		#[test]
		fn test_extract_object() {
			let mut map = Map::new();
			let mut nested_map = Map::new();
			nested_map.insert("nested_key".to_string(), Value::String("nested_value".to_string()));
			map.insert("object_field".to_string(), Value::Object(nested_map.clone()));

			// Test successful extraction
			let result: Result<&Map<String, Value>, serde_json::Error> = extract_object(&map, "object_field");
			assert!(result.is_ok());
			let extracted = result.unwrap();
			assert_eq!(extracted.get("nested_key").unwrap().as_str().unwrap(), "nested_value");

			// Test missing field
			let missing_result: Result<&Map<String, Value>, serde_json::Error> = extract_object(&map, "missing");
			assert!(missing_result.is_err());

			// Test wrong type
			map.insert("string_field".to_string(), Value::String("not_an_object".to_string()));
			let wrong_type_result: Result<&Map<String, Value>, serde_json::Error> =
				extract_object(&map, "string_field");
			assert!(wrong_type_result.is_err());
		}

		#[test]
		fn test_algorithm_to_oid() {
			// Test known algorithms
			let aes_result: Result<ObjectIdentifier, serde_json::Error> = algorithm_to_oid("aes-256-gcm");
			assert!(aes_result.is_ok());
			assert_eq!(aes_result.unwrap(), AES_256_GCM_OID);

			let sha_result: Result<ObjectIdentifier, serde_json::Error> = algorithm_to_oid("sha2-256");
			assert!(sha_result.is_ok());
			assert_eq!(sha_result.unwrap(), SHA2_256_OID);

			// Test unknown algorithm
			let unknown_result: Result<ObjectIdentifier, serde_json::Error> = algorithm_to_oid("unknown-algorithm");
			assert!(unknown_result.is_err());
		}

		#[test]
		fn test_json_object_macro() {
			// Test the json_object macro
			let obj = json_object! {
				"key1" => "value1".to_string(),
				"key2" => "value2".to_string()
			};

			let map = obj.as_object().expect("Should be a JSON object");
			assert_eq!(map.get("key1").unwrap().as_str().unwrap(), "value1");
			assert_eq!(map.get("key2").unwrap().as_str().unwrap(), "value2");

			// Test empty object
			let empty_obj = json_object! {};
			let empty_map = empty_obj.as_object().expect("Should be a JSON object");
			assert!(empty_map.is_empty());
		}
	}
}

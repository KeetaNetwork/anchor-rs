//! JSON Canonicalization Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)).

use alloc::borrow::Cow;
use core::cmp::Ordering;

use serde_json::Value;

use crate::signing::error::SigningError;
use crate::signing::signable::Signable;

/// Upper bound on the canonical byte length, matching the TypeScript guard.
const MAX_OUTPUT_BYTES: usize = 65536;
/// Upper bound on visited nodes, matching the TypeScript DoS guard.
const MAX_NODES: usize = 1000;
/// I-JSON safe integer magnitude (`2^53 - 1`).
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A pending unit of work for the iterative canonicalizing handler.
enum Frame<'a> {
	/// A literal fragment to append to the output verbatim.
	Emit(String),
	/// A value still to be expanded.
	Visit(&'a Value),
}

/// Canonicalize a structured `value` into a single-element signable payload (one
/// `UTF8String`), enforcing the same node and output-size guards as the
/// TypeScript `objectToSignable`.
pub fn object_to_signable(value: &Value) -> Result<Vec<Signable<'static>>, SigningError> {
	let canonical = canonicalize_into(value, Some(MAX_NODES))?;
	if canonical.len() > MAX_OUTPUT_BYTES {
		return Err(SigningError::OutputTooLarge);
	}

	Ok(vec![Signable::Text(Cow::Owned(canonical))])
}

fn canonicalize_into(value: &Value, max_nodes: Option<usize>) -> Result<String, SigningError> {
	let mut output = String::new();
	let mut stack: Vec<Frame<'_>> = vec![Frame::Visit(value)];
	let mut nodes = 0usize;

	while let Some(frame) = stack.pop() {
		let next = match frame {
			Frame::Emit(fragment) => {
				output.push_str(&fragment);
				continue;
			}
			Frame::Visit(node) => node,
		};

		nodes += 1;
		if max_nodes.is_some_and(|limit| nodes > limit) {
			return Err(SigningError::OutputTooLarge);
		}

		expand(next, &mut output, &mut stack)?;
	}

	Ok(output)
}

fn expand<'a>(value: &'a Value, output: &mut String, stack: &mut Vec<Frame<'a>>) -> Result<(), SigningError> {
	match value {
		Value::Null => output.push_str("null"),
		Value::Bool(true) => output.push_str("true"),
		Value::Bool(false) => output.push_str("false"),
		Value::Number(number) => write_number(number, output)?,
		Value::String(text) => escape_string(text, output),
		Value::Array(items) => push_array(items, stack),
		Value::Object(map) => push_object(map, stack),
	}

	Ok(())
}

fn push_array<'a>(items: &'a [Value], stack: &mut Vec<Frame<'a>>) {
	let mut frames: Vec<Frame<'a>> = Vec::with_capacity(items.len() * 2 + 1);
	frames.push(Frame::Emit("[".to_string()));

	for (index, item) in items.iter().enumerate() {
		if index > 0 {
			frames.push(Frame::Emit(",".to_string()));
		}

		frames.push(Frame::Visit(item));
	}

	frames.push(Frame::Emit("]".to_string()));

	for frame in frames.into_iter().rev() {
		stack.push(frame);
	}
}

fn push_object<'a>(map: &'a serde_json::Map<String, Value>, stack: &mut Vec<Frame<'a>>) {
	let mut entries: Vec<(&'a String, &'a Value)> = map.iter().collect();
	entries.sort_by(|(left, _), (right, _)| cmp_utf16(left, right));

	let mut frames: Vec<Frame<'a>> = Vec::with_capacity(entries.len() * 3 + 1);
	frames.push(Frame::Emit("{".to_string()));

	for (index, (key, child)) in entries.into_iter().enumerate() {
		if index > 0 {
			frames.push(Frame::Emit(",".to_string()));
		}

		let mut prefix = String::new();
		escape_string(key, &mut prefix);
		prefix.push(':');
		frames.push(Frame::Emit(prefix));
		frames.push(Frame::Visit(child));
	}

	frames.push(Frame::Emit("}".to_string()));

	for frame in frames.into_iter().rev() {
		stack.push(frame);
	}
}

/// Order two strings by their UTF-16 code units, as required by RFC 8785 §3.2.3.
fn cmp_utf16(left: &str, right: &str) -> Ordering {
	left.encode_utf16().cmp(right.encode_utf16())
}

fn write_number(number: &serde_json::Number, output: &mut String) -> Result<(), SigningError> {
	if let Some(value) = number.as_i64() {
		if value.unsigned_abs() > MAX_SAFE_INTEGER {
			return Err(SigningError::IntegerOutOfRange);
		}

		output.push_str(value.to_string().as_str());
		return Ok(());
	}

	if let Some(value) = number.as_u64() {
		if value > MAX_SAFE_INTEGER {
			return Err(SigningError::IntegerOutOfRange);
		}

		output.push_str(value.to_string().as_str());
		return Ok(());
	}

	match number.as_f64() {
		Some(value) if !value.is_finite() => Err(SigningError::NonFiniteNumber),
		_ => Err(SigningError::NonIntegerNumber),
	}
}

/// Append `value` as a JSON string literal using RFC 8785 §3.2.2.2 escaping
/// (mandatory escapes plus short forms for `\b \t \n \f \r`, `\u00xx`
/// otherwise; all other code points emitted as UTF-8).
fn escape_string(value: &str, output: &mut String) {
	output.push('"');
	for character in value.chars() {
		match character {
			'"' => output.push_str("\\\""),
			'\\' => output.push_str("\\\\"),
			'\u{0008}' => output.push_str("\\b"),
			'\u{0009}' => output.push_str("\\t"),
			'\u{000A}' => output.push_str("\\n"),
			'\u{000C}' => output.push_str("\\f"),
			'\u{000D}' => output.push_str("\\r"),
			control if (control as u32) < 0x20 => {
				output.push_str(&format!("\\u{:04x}", control as u32));
			}
			other => output.push(other),
		}
	}
	output.push('"');
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn canon(value: &Value) -> Result<String, SigningError> {
		canonicalize_into(value, None)
	}

	#[test]
	fn flat_object_sorts_keys_by_code_unit() {
		let value = json!({ "z": 1, "a": "first", "m": "middle" });
		assert_eq!(canon(&value).unwrap(), r#"{"a":"first","m":"middle","z":1}"#);
	}

	#[test]
	fn nested_object_preserves_structure() {
		let value = json!({ "outer": { "inner": "v" }, "top": "t" });
		assert_eq!(canon(&value).unwrap(), r#"{"outer":{"inner":"v"},"top":"t"}"#);
	}

	#[test]
	fn arrays_preserve_index_order() {
		let value = json!({ "items": ["a", "b", "c"] });
		assert_eq!(canon(&value).unwrap(), r#"{"items":["a","b","c"]}"#);
	}

	#[test]
	fn null_values_are_kept() {
		let value = json!({ "a": "kept", "c": null });
		assert_eq!(canon(&value).unwrap(), r#"{"a":"kept","c":null}"#);
	}

	#[test]
	fn booleans_serialize_as_json_literals() {
		let value = json!({ "yes": true, "no": false });
		assert_eq!(canon(&value).unwrap(), r#"{"no":false,"yes":true}"#);
	}

	#[test]
	fn top_level_scalar_emits_json_string_literal() {
		let value = json!("lonely");
		assert_eq!(canon(&value).unwrap(), r#""lonely""#);
	}

	#[test]
	fn top_level_array_preserves_order() {
		let value = json!(["x", "y"]);
		assert_eq!(canon(&value).unwrap(), r#"["x","y"]"#);
	}

	#[test]
	fn array_null_entries_serialize_as_json_null() {
		let value = json!(["x", null, null, "y"]);
		assert_eq!(canon(&value).unwrap(), r#"["x",null,null,"y"]"#);
	}

	#[test]
	fn marker_characters_as_keys_are_escaped() {
		let value = json!({ "a": "first", "m": "middle", "{": "a", "}": "{" });
		assert_eq!(canon(&value).unwrap(), r#"{"a":"first","m":"middle","{":"a","}":"{"}"#);
	}

	#[test]
	fn rfc8785_sort_vector_orders_keys_by_code_unit() {
		let value = json!({ "\u{20ac}": "Euro Sign", "\r": "Carriage Return", "1": "One" });
		assert_eq!(canon(&value).unwrap(), "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{20ac}\":\"Euro Sign\"}");
	}

	#[test]
	fn object_key_insertion_order_does_not_matter() {
		let first = canon(&json!({ "b": 2, "a": 1 })).unwrap();
		let second = canon(&json!({ "a": 1, "b": 2 })).unwrap();
		assert_eq!(first, second);
	}

	#[test]
	fn integer_above_safe_range_is_rejected() {
		let value = json!({ "x": 9_007_199_254_740_992_u64 });
		assert_eq!(canon(&value).unwrap_err(), SigningError::IntegerOutOfRange);
	}

	#[test]
	fn non_integer_number_is_rejected() {
		let value = json!({ "x": 1.5 });
		assert_eq!(canon(&value).unwrap_err(), SigningError::NonIntegerNumber);
	}

	#[test]
	fn object_to_signable_rejects_oversized_node_count() {
		let mut map = serde_json::Map::new();
		for index in 0..2000 {
			map.insert(format!("k{index}"), Value::String(format!("v{index}")));
		}

		assert_eq!(object_to_signable(&Value::Object(map)).unwrap_err(), SigningError::OutputTooLarge);
	}

	#[test]
	fn byte_limit_applies_to_object_to_signable_only() {
		let value = json!("x".repeat(MAX_OUTPUT_BYTES + 1));
		assert!(canon(&value).is_ok());
		assert_eq!(object_to_signable(&value).unwrap_err(), SigningError::OutputTooLarge);
	}

	#[test]
	fn equivalent_objects_canonicalize_identically() {
		let first = object_to_signable(&json!({ "a": 1, "b": { "c": "x", "d": "y" } })).unwrap();
		let second = object_to_signable(&json!({ "b": { "d": "y", "c": "x" }, "a": 1 })).unwrap();
		assert_eq!(first, second);
	}
}

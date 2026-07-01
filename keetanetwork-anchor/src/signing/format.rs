//! ASN.1 DER encoding of the verification payload.

use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use rasn::types::{Integer, OctetString, Utf8String};

use crate::signing::error::SigningError;
use crate::signing::signable::Signable;

/// DER tag for a constructed `SEQUENCE`.
const SEQUENCE_TAG: u8 = 0x30;
/// Marks the long-form length encoding.
const LONG_FORM_FLAG: u8 = 0x80;

/// Build the DER verification bytes for `data` signed by the account whose
/// `publicKeyAndType` bytes are `signer_public_key_and_type`.
pub(crate) fn format_data(
	signer_public_key_and_type: &[u8],
	nonce: &str,
	timestamp: &str,
	data: &[Signable<'_>],
) -> Result<Vec<u8>, SigningError> {
	let mut elements: Vec<Vec<u8>> = Vec::with_capacity(3 + data.len());
	elements.push(encode_utf8(nonce)?);
	elements.push(encode_utf8(timestamp)?);
	elements.push(encode_octet(signer_public_key_and_type)?);

	for part in data {
		elements.push(encode_part(part)?);
	}

	Ok(wrap_sequence(&elements))
}

fn encode_part(part: &Signable<'_>) -> Result<Vec<u8>, SigningError> {
	match part {
		Signable::Text(text) => encode_utf8(text),
		Signable::Integer(value) => encode_integer(*value),
		Signable::Account(bytes) => encode_octet(bytes),
	}
}

fn encode_utf8(value: &str) -> Result<Vec<u8>, SigningError> {
	let encoded: Utf8String = value.to_owned();
	Ok(rasn::der::encode(&encoded)?)
}

fn encode_octet(value: &[u8]) -> Result<Vec<u8>, SigningError> {
	let encoded = OctetString::from_slice(value);
	Ok(rasn::der::encode(&encoded)?)
}

fn encode_integer(value: i64) -> Result<Vec<u8>, SigningError> {
	let encoded = Integer::from(value);
	Ok(rasn::der::encode(&encoded)?)
}

fn wrap_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
	let body_length: usize = elements.iter().map(Vec::len).sum();
	let mut output = Vec::with_capacity(body_length + 4);
	output.push(SEQUENCE_TAG);
	encode_length(body_length, &mut output);
	for element in elements {
		output.extend_from_slice(element);
	}

	output
}

fn encode_length(length: usize, output: &mut Vec<u8>) {
	if length < 0x80 {
		output.push(length as u8);
		return;
	}

	let bytes = length.to_be_bytes();
	let leading_zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
	let significant = &bytes[leading_zeros..];
	output.push(LONG_FORM_FLAG | significant.len() as u8);
	output.extend_from_slice(significant);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn short_form_length_is_a_single_byte() {
		let mut output = Vec::new();
		encode_length(6, &mut output);
		assert_eq!(output, [0x06]);
	}

	#[test]
	fn long_form_length_uses_minimal_octets() {
		let mut output = Vec::new();
		encode_length(200, &mut output);
		assert_eq!(output, [0x81, 0xC8]);
	}

	#[test]
	fn long_form_length_spans_multiple_octets() {
		let mut output = Vec::new();
		encode_length(65536, &mut output);
		assert_eq!(output, [0x83, 0x01, 0x00, 0x00]);
	}

	#[test]
	fn empty_payload_encodes_three_empty_headers() -> Result<(), Box<dyn std::error::Error>> {
		let encoded = format_data(&[], "", "", &[])?;
		assert_eq!(encoded, [0x30, 0x06, 0x0C, 0x00, 0x0C, 0x00, 0x04, 0x00]);
		Ok(())
	}

	#[test]
	fn integer_part_encodes_as_der_integer() -> Result<(), Box<dyn std::error::Error>> {
		let encoded = format_data(&[], "", "", &[Signable::from(12345_i64)])?;
		let tail = &encoded[encoded.len() - 4..];
		assert_eq!(tail, [0x02, 0x02, 0x30, 0x39]);
		Ok(())
	}
}

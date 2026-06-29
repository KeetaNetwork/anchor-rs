//! Schema-aware KYC attribute value codec.

use alloc::string::ToString;
use alloc::vec::Vec;

use rasn::types::Utf8String;

use crate::asn1::error::AnchorAsn1Error;
use crate::generated::attribute_types::{attribute_value_type, AttributeValueType};

/// Encode a semantic attribute value into its schema ASN.1 DER.
pub fn encode_value<O: AsRef<str>>(oid: O, semantic: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	match attribute_value_type(oid.as_ref()) {
		Some(AttributeValueType::Utf8String) => Ok(rasn::der::encode(&Utf8String::from(as_utf8(semantic)?))?),
		#[cfg(feature = "chrono")]
		Some(AttributeValueType::GeneralizedTime) => encode_time(semantic),
		_ => Ok(semantic.to_vec()),
	}
}

/// Decode a schema ASN.1 DER attribute value back to its semantic form.
pub fn decode_value<O: AsRef<str>>(oid: O, der: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	let decoded = match attribute_value_type(oid.as_ref()) {
		Some(AttributeValueType::Utf8String) => decode_utf8(der),
		#[cfg(feature = "chrono")]
		Some(AttributeValueType::GeneralizedTime) => decode_time(der),
		#[cfg(feature = "serde")]
		Some(AttributeValueType::Structured(token)) => crate::kyc_schema::structured::decode_structured(token, der),
		_ => return Ok(der.to_vec()),
	};

	Ok(decoded.unwrap_or_else(|_| der.to_vec()))
}

/// Decode a DER `UTF8String` into its raw UTF-8 bytes.
fn decode_utf8(der: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	let text: Utf8String = rasn::der::decode(der)?;
	Ok(text.into_bytes())
}

/// Borrow attribute bytes as UTF-8, mapping invalid input to an encode error.
fn as_utf8(bytes: &[u8]) -> Result<&str, AnchorAsn1Error> {
	core::str::from_utf8(bytes).map_err(|error| AnchorAsn1Error::Asn1EncodeError { reason: error.to_string() })
}

/// Encode a date/time string as ASN.1 `GeneralizedTime`, the canonical KYC time
/// form. `UTCTime` is read on decode only, as backwards compatibility for
/// TypeScript-issued certificates.
#[cfg(feature = "chrono")]
fn encode_time(semantic: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	let text = as_utf8(semantic)?;
	let datetime =
		parse_datetime(text).ok_or_else(|| AnchorAsn1Error::Asn1EncodeError { reason: format!("invalid date/time: {text}") })?;

	let body = datetime.format("%Y%m%d%H%M%SZ").to_string();

	let mut der = Vec::with_capacity(2 + body.len());
	der.push(0x18);
	der.push(body.len() as u8);
	der.extend_from_slice(body.as_bytes());
	Ok(der)
}

/// Decode a DER `UTCTime`/`GeneralizedTime` into an ISO-8601 (`toISOString`) form.
#[cfg(feature = "chrono")]
fn decode_time(der: &[u8]) -> Result<Vec<u8>, AnchorAsn1Error> {
	use chrono::{TimeZone, Utc};

	let (tag, value) = read_tlv(der)?;
	let text = as_utf8(value)?.trim_end_matches('Z');

	let naive = match tag {
		0x17 => parse_utc_time(text),
		0x18 => parse_generalized_time(text),
		_ => None,
	}
	.ok_or_else(|| AnchorAsn1Error::Asn1DecodeError { reason: format!("invalid time value: {text}") })?;

	Ok(Utc
		.from_utc_datetime(&naive)
		.format("%Y-%m-%dT%H:%M:%S%.3fZ")
		.to_string()
		.into_bytes())
}

/// Read a single short/long-form DER TLV, returning its tag and value slice.
#[cfg(feature = "chrono")]
fn read_tlv(der: &[u8]) -> Result<(u8, &[u8]), AnchorAsn1Error> {
	let decode_error = || AnchorAsn1Error::Asn1DecodeError { reason: "truncated time value".to_string() };

	let tag = *der.first().ok_or_else(decode_error)?;
	let first_len = *der.get(1).ok_or_else(decode_error)? as usize;

	let (length, header) = if first_len < 0x80 {
		(first_len, 2)
	} else {
		// Reject the indefinite-length form (invalid for DER) and any width that
		// cannot fit a usize, then accumulate with checked arithmetic so untrusted
		// input cannot overflow into a wrapped, attacker-chosen length.
		let count = first_len & 0x7f;
		if count == 0 || count > core::mem::size_of::<usize>() {
			return Err(decode_error());
		}
		let bytes = der.get(2..2 + count).ok_or_else(decode_error)?;
		let length = bytes
			.iter()
			.try_fold(0usize, |acc, byte| acc.checked_mul(256)?.checked_add(usize::from(*byte)))
			.ok_or_else(decode_error)?;
		(length, 2 + count)
	};

	let end = header.checked_add(length).ok_or_else(decode_error)?;
	let value = der.get(header..end).ok_or_else(decode_error)?;
	Ok((tag, value))
}

/// Parse a `UTCTime` body (`YYMMDDHHMMSS`) using the RFC 5280 sliding window:
/// two-digit years below 50 are 21st century, the rest 20th century.
#[cfg(feature = "chrono")]
fn parse_utc_time(body: &str) -> Option<chrono::NaiveDateTime> {
	use chrono::NaiveDateTime;

	let two_digit_year: i32 = body.get(0..2)?.parse().ok()?;
	let century = if two_digit_year < 50 { 2000 } else { 1900 };
	let full = format!("{}{}", century + two_digit_year, body.get(2..)?);
	NaiveDateTime::parse_from_str(&full, "%Y%m%d%H%M%S").ok()
}

/// Parse a `GeneralizedTime` body (`YYYYMMDDHHMMSS` with optional fraction).
#[cfg(feature = "chrono")]
fn parse_generalized_time(body: &str) -> Option<chrono::NaiveDateTime> {
	use chrono::NaiveDateTime;

	NaiveDateTime::parse_from_str(body, "%Y%m%d%H%M%S%.f")
		.or_else(|_| NaiveDateTime::parse_from_str(body, "%Y%m%d%H%M%S"))
		.ok()
}

/// Parse the date/time forms a caller may supply (RFC-3339, ISO with `Z`, or a
/// bare calendar date) into a UTC datetime.
#[cfg(feature = "chrono")]
fn parse_datetime(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
	use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

	if let Ok(datetime) = DateTime::parse_from_rfc3339(text) {
		return Some(datetime.with_timezone(&Utc));
	}

	if let Ok(naive) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.fZ") {
		return Some(Utc.from_utc_datetime(&naive));
	}

	let date = NaiveDate::parse_from_str(text, "%Y-%m-%d").ok()?;
	Some(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::oids;

	#[test]
	fn utf8_attribute_round_trips_through_der() {
		let oid = oids::keeta::EMAIL.to_string();
		let encoded = encode_value(&oid, b"john@example.com").unwrap();
		assert_ne!(encoded, b"john@example.com");
		let decoded = decode_value(&oid, &encoded).unwrap();
		assert_eq!(decoded, b"john@example.com");
	}

	#[test]
	fn utf8_encoding_is_der_utf8string() {
		let oid = oids::ADDRESS_POSTAL_CODE.to_string();
		let encoded = encode_value(&oid, b"12345").unwrap();
		assert_eq!(encoded, [0x0c, 0x05, b'1', b'2', b'3', b'4', b'5']);
	}

	#[test]
	fn unknown_oid_passes_through() {
		let decoded = decode_value("1.2.3.4.5", b"raw").unwrap();
		assert_eq!(decoded, b"raw");
	}

	#[test]
	fn malformed_utf8_value_falls_back_to_raw() {
		let oid = oids::keeta::EMAIL.to_string();
		let decoded = decode_value(&oid, &[0xff, 0xfe]).unwrap();
		assert_eq!(decoded, [0xff, 0xfe]);
	}

	#[cfg(feature = "chrono")]
	#[test]
	fn pre_2050_date_encodes_as_generalized_time() {
		let oid = oids::keeta::DATE_OF_BIRTH.to_string();
		let encoded = encode_value(&oid, b"1990-01-01").unwrap();
		assert_eq!(encoded[0], 0x18);
		let decoded = decode_value(&oid, &encoded).unwrap();
		assert_eq!(decoded, b"1990-01-01T00:00:00.000Z");
	}

	#[cfg(feature = "chrono")]
	#[test]
	fn post_2050_date_encodes_as_generalized_time() {
		let oid = oids::keeta::DATE_OF_BIRTH.to_string();
		let encoded = encode_value(&oid, b"2080-06-15").unwrap();
		assert_eq!(encoded[0], 0x18);
		let decoded = decode_value(&oid, &encoded).unwrap();
		assert_eq!(decoded, b"2080-06-15T00:00:00.000Z");
	}

	#[cfg(feature = "chrono")]
	#[test]
	fn decodes_typescript_utc_time() {
		let oid = oids::keeta::DATE_OF_BIRTH.to_string();
		let body = b"800101000000Z";
		let mut der = alloc::vec![0x17u8, body.len() as u8];
		der.extend_from_slice(body);
		let decoded = decode_value(&oid, &der).unwrap();
		assert_eq!(decoded, b"1980-01-01T00:00:00.000Z");
	}
}

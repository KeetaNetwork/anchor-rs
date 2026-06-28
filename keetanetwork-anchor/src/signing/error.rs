//! Errors raised while canonicalizing, encoding, signing, or verifying.

use alloc::string::String;

use crate::impl_variant_error_from;
use keetanetwork_utils::impl_error_from_with_fields;
use snafu::Snafu;

/// A failure while building or producing a signature (the sign-time pipeline).
///
/// Distinct from [`VerifyError`]: a [`SigningError`] is a fault the caller must
/// fix (malformed payload, encoding failure), whereas a [`VerifyError`] is the
/// reason a signature was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub))]
pub enum SigningError {
	/// A number was not finite (RFC 8785 §3.2.2.3).
	#[snafu(display("non-finite number in canonical JSON"))]
	NonFiniteNumber,

	/// An integer fell outside the I-JSON safe range (RFC 8785 Appendix D).
	#[snafu(display("integer outside the safe range in canonical JSON"))]
	IntegerOutOfRange,

	/// A non-integer number was encountered; only integers participate in the
	/// signing subset shared with the TypeScript reference.
	#[snafu(display("non-integer number in canonical JSON"))]
	NonIntegerNumber,

	/// The canonical output exceeded the size or node-count (complexity) guard.
	#[snafu(display("canonical output exceeds the size or complexity limit"))]
	OutputTooLarge,

	/// The supplied signing timestamp was not a strict ISO 8601 instant with
	/// millisecond precision and a `Z` zone, so the resulting signature
	/// could never verify.
	#[snafu(display("signing timestamp is not a strict ISO 8601 instant with millisecond precision and a Z zone"))]
	NonCanonicalTimestamp,

	/// An ASN.1 DER encoding failure.
	#[snafu(display("ASN.1 encoding error: {reason}"))]
	Encode {
		/// The underlying encoder message.
		reason: String,
	},

	/// An account crypto failure (signing).
	#[snafu(display("account error: {reason}"))]
	Account {
		/// The underlying account message.
		reason: String,
	},
}

impl_error_from_with_fields!(SigningError, {
	rasn::error::EncodeError => Encode { reason: |error: &rasn::error::EncodeError| format!("{error}") },
	keetanetwork_account::AccountError => Account { reason: |error: keetanetwork_account::AccountError| format!("{error}") },
});

impl_variant_error_from!(SigningError, {
	chrono::ParseError => NonCanonicalTimestamp,
});

/// The reason a [`Signed`](crate::signing::Signed) envelope was rejected by
/// [`verify`](crate::signing::verify).
///
/// Unlike a boolean result, each variant tells the caller *why* verification
/// failed so they can react appropriately (retry on skew, reject on mismatch).
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub))]
pub enum VerifyError {
	/// The signature did not validate against the account and signed data.
	#[snafu(display("signature does not match the signed data"))]
	SignatureMismatch,

	/// The signed timestamp was further from the reference time than allowed.
	#[snafu(display("timestamp skew {skew_ms}ms exceeds the maximum {max_ms}ms"))]
	ClockSkew {
		/// The observed skew, in milliseconds.
		skew_ms: i64,
		/// The configured maximum, in milliseconds.
		max_ms: i64,
	},

	/// The timestamp was not a strict ISO 8601 instant with millisecond
	/// precision and a `Z` zone (the only form the reference produces).
	#[snafu(display("timestamp is not a strict ISO 8601 instant with millisecond precision and a Z zone"))]
	MalformedTimestamp,

	/// The signature field was not valid base64.
	#[snafu(display("signature is not valid base64: {reason}"))]
	MalformedSignature {
		/// The underlying decoder message.
		reason: String,
	},

	/// The verification bytes could not be encoded (an internal fault).
	#[snafu(display("could not encode verification data: {reason}"))]
	Encoding {
		/// The underlying signing-pipeline message.
		reason: String,
	},
}

impl_error_from_with_fields!(VerifyError, {
	base64::DecodeError => MalformedSignature { reason: |error: base64::DecodeError| format!("{error}") },
	SigningError => Encoding { reason: |error: SigningError| format!("{error}") },
});

impl_variant_error_from!(VerifyError, {
	chrono::ParseError => MalformedTimestamp,
});

/// The reason a signed HTTP request (URL- or body-bound) was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub))]
pub enum RequestError {
	/// The base URL already carried one of the `signed.*` parameters, so
	/// signing it again would overwrite an existing signature.
	#[snafu(display("URL already has signed field parameter: {name}"))]
	DuplicateParameter {
		/// The offending parameter name.
		name: &'static str,
	},

	/// Some but not all of `signed.nonce`, `signed.timestamp`, and
	/// `signed.signature` were present.
	#[snafu(display("incomplete signature fields in request"))]
	IncompleteSignature,

	/// The request carried neither an `account` nor any signature fields, so
	/// there was nothing to authenticate.
	#[snafu(display("authentication required: missing account and signature"))]
	MissingAuthentication,

	/// The `account` parameter was not a valid public-key string.
	#[snafu(display("account is malformed: {reason}"))]
	MalformedAccount {
		/// The underlying account-decoding message.
		reason: String,
	},

	/// The signature did not pass [`verify`](crate::signing::verify).
	#[snafu(display("request signature rejected: {source}"), context(false))]
	Verify {
		/// The underlying verification failure.
		source: VerifyError,
	},
}

impl_error_from_with_fields!(RequestError, {
	keetanetwork_account::AccountError => MalformedAccount { reason: |error: keetanetwork_account::AccountError| format!("{error}") },
});

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_utils::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(
		test_signing_from_conversions,
		SigningError,
		[
			rasn::error::EncodeError::length_exceeds_platform_size(rasn::Codec::Der),
			keetanetwork_account::AccountError::InvalidKeyType,
			chrono::DateTime::parse_from_rfc3339("not-a-timestamp").unwrap_err(),
		]
	);

	test_error_variants!(
		test_signing_error_variants,
		[
			SigningError::NonFiniteNumber,
			SigningError::IntegerOutOfRange,
			SigningError::NonIntegerNumber,
			SigningError::OutputTooLarge,
			SigningError::NonCanonicalTimestamp,
			SigningError::Encode { reason: "boom".to_string() },
			SigningError::Account { reason: "boom".to_string() },
		]
	);

	test_error_from_conversions!(
		test_verify_from_conversions,
		VerifyError,
		[
			base64::DecodeError::InvalidPadding,
			SigningError::Encode { reason: "boom".to_string() },
			chrono::DateTime::parse_from_rfc3339("not-a-timestamp").unwrap_err(),
		]
	);

	test_error_variants!(
		test_verify_error_variants,
		[
			VerifyError::SignatureMismatch,
			VerifyError::ClockSkew { skew_ms: 1, max_ms: 0 },
			VerifyError::MalformedTimestamp,
			VerifyError::MalformedSignature { reason: "boom".to_string() },
			VerifyError::Encoding { reason: "boom".to_string() },
		]
	);

	test_error_from_conversions!(
		test_request_from_conversions,
		RequestError,
		[keetanetwork_account::AccountError::InvalidKeyType, VerifyError::SignatureMismatch]
	);

	test_error_variants!(
		test_request_error_variants,
		[
			RequestError::DuplicateParameter { name: "signed.nonce" },
			RequestError::IncompleteSignature,
			RequestError::MissingAuthentication,
			RequestError::MalformedAccount { reason: "boom".to_string() },
			RequestError::Verify { source: VerifyError::SignatureMismatch },
		]
	);
}

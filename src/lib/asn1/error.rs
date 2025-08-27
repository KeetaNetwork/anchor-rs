use snafu::Snafu;
use utils::impl_error_from_with_fields;

/// Error type for ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub))]
pub enum AnchorAsn1Error {
	#[snafu(display("Invalid OID: {reason}"))]
	InvalidOid { reason: String },

	#[snafu(display("ASN.1 encoding error: {}", reason))]
	Asn1EncodeError { reason: String },

	#[snafu(display("ASN.1 decoding error: {}", reason))]
	Asn1DecodeError { reason: String },
}

impl_error_from_with_fields!(AnchorAsn1Error, {
	rasn::error::EncodeError => Asn1EncodeError { reason: |error: &rasn::error::EncodeError| format!("ASN.1 encoding error: {error}") },
	rasn::error::DecodeError => Asn1DecodeError { reason: |error: &rasn::error::DecodeError| format!("ASN.1 decoding error: {error}") },
});

#[cfg(test)]
mod tests {
	use super::*;
	use utils::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(
		test_from_conversions,
		AnchorAsn1Error,
		[
			rasn::error::EncodeError::length_exceeds_platform_size(rasn::Codec::Der),
			rasn::error::DecodeError::integer_overflow(100, rasn::Codec::Der),
		]
	);

	test_error_variants!(
		test_error_variants,
		[
			AnchorAsn1Error::InvalidOid { reason: "test.oid".to_string() },
			AnchorAsn1Error::Asn1EncodeError { reason: "test encode error".to_string() },
			AnchorAsn1Error::Asn1DecodeError { reason: "test decode error".to_string() },
		]
	);
}

use snafu::Snafu;

/// Error type for ASN.1.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum AnchorAsn1Error {
	#[snafu(display("Invalid OID: {message}"))]
	InvalidOid { message: String },

	#[snafu(display("ASN.1 encoding error: {}", source))]
	Asn1EncodeError { source: rasn::error::EncodeError },

	#[snafu(display("ASN.1 decoding error: {}", source))]
	Asn1DecodeError { source: rasn::error::DecodeError },
}

crate::impl_source_error_from!(AnchorAsn1Error, {
	rasn::error::EncodeError => Asn1EncodeError,
	rasn::error::DecodeError => Asn1DecodeError,
});

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{test_error_from_conversions, test_error_variants};

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
			AnchorAsn1Error::InvalidOid { message: "test.oid".to_string() },
			AnchorAsn1Error::Asn1EncodeError {
				source: rasn::error::EncodeError::length_exceeds_platform_size(rasn::Codec::Der)
			},
			AnchorAsn1Error::Asn1DecodeError {
				source: rasn::error::DecodeError::integer_overflow(100, rasn::Codec::Der)
			},
		]
	);
}

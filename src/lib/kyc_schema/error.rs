//! KYC Schema Error Types
//!
//! This module defines error types specific to KYC schema operations.

use snafu::Snafu;

use crate::asn1::error::AnchorAsn1Error;

/// Errors that can occur during KYC schema operations
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum KycSchemaError {
	/// ASN.1 error
	#[snafu(display("ASN.1 error: {source}"))]
	Asn1Error { source: AnchorAsn1Error },

	/// Serialization error
	#[snafu(display("Serialization error: {message}"))]
	Serialization { message: String },

	/// Missing OID
	#[snafu(display("Missing OID"))]
	MissingOid,

	/// Missing Value
	#[snafu(display("Missing Value"))]
	MissingValue,
}

crate::impl_source_error_from!(KycSchemaError, {
	AnchorAsn1Error => Asn1Error,
});

crate::impl_source_error_from_via!(KycSchemaError, {
	rasn::error::EncodeError => Asn1Error via AnchorAsn1Error,
	rasn::error::DecodeError => Asn1Error via AnchorAsn1Error,
});

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(
		test_from_conversions,
		KycSchemaError,
		[
			AnchorAsn1Error::InvalidOid { message: "test".to_string() },
			rasn::error::EncodeError::length_exceeds_platform_size(rasn::Codec::Der),
			rasn::error::DecodeError::length_exceeds_platform_width("test".to_string(), rasn::Codec::Der),
		]
	);

	test_error_variants!(
		test_error_variants,
		[
			KycSchemaError::Asn1Error { source: AnchorAsn1Error::InvalidOid { message: "test.oid".to_string() } },
			KycSchemaError::Serialization { message: "test serialization error".to_string() },
			KycSchemaError::MissingOid,
			KycSchemaError::MissingValue,
		]
	);
}

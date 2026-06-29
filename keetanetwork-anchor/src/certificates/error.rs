use alloc::string::String;

use snafu::Snafu;

use crate::asn1::error::AnchorAsn1Error;
use crate::kyc_schema::error::KycSchemaError;
use crate::sensitive_attributes::error::SensitiveAttributeError;

/// Error type for certificate operations
#[derive(Debug, Clone, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum KycCertificateError {
	#[snafu(display("Sensitive attribute error: {}", source))]
	SensitiveAttributeError { source: SensitiveAttributeError },

	#[snafu(display("X.509 certificate error: {}", source))]
	X509Error { source: keetanetwork_x509::error::CertificateError },

	#[snafu(display("ASN.1 error: {}", source))]
	Asn1Error { source: AnchorAsn1Error },

	#[snafu(display("KYC schema error: {}", source))]
	KycSchemaError { source: KycSchemaError },

	#[snafu(display("Attribute not found: {}", name))]
	AttributeNotFound { name: String },

	#[snafu(display("Invalid attribute value for {}: {}", name, reason))]
	InvalidAttributeValue { name: String, reason: String },

	#[snafu(display("Missing required field: {}", field))]
	MissingRequiredField { field: String },
}

crate::impl_source_error_from!(KycCertificateError, {
	SensitiveAttributeError => SensitiveAttributeError,
	keetanetwork_x509::error::CertificateError => X509Error,
	AnchorAsn1Error => Asn1Error,
	KycSchemaError => KycSchemaError,
	rasn::error::EncodeError => Asn1Error,
	rasn::error::DecodeError => Asn1Error,
});

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_utils::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(
		test_from_conversions,
		KycCertificateError,
		[SensitiveAttributeError::InvalidVersion, AnchorAsn1Error::InvalidOid { reason: "test".to_string() },]
	);
	test_error_variants!(
		test_error_variants,
		[
			KycCertificateError::SensitiveAttributeError { source: SensitiveAttributeError::MissingValue },
			KycCertificateError::Asn1Error { source: AnchorAsn1Error::InvalidOid { reason: "test".to_string() } },
			KycCertificateError::AttributeNotFound { name: "test".to_string() },
			KycCertificateError::InvalidAttributeValue { name: "test".to_string(), reason: "test".to_string() },
			KycCertificateError::MissingRequiredField { field: "test".to_string() },
		]
	);
}

use snafu::Snafu;

use crate::asn1::error::AnchorAsn1Error;
use crate::certificates::error::CertificateError;
use crate::impl_source_error_from;
use crate::sensitive_attributes::error::SensitiveAttributeError;

/// Error type for certificate operations
#[derive(Debug, Clone, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum AnchorError {
	#[snafu(display("ASN.1 error: {}", source))]
	Asn1Error { source: AnchorAsn1Error },

	#[snafu(display("Certificate error: {}", source))]
	CertificateError { source: CertificateError },

	#[snafu(display("Sensitive attribute error: {}", source))]
	SensitiveAttributeError { source: SensitiveAttributeError },
}

impl_source_error_from!(AnchorError, {
	AnchorAsn1Error => Asn1Error,
	CertificateError => CertificateError,
	SensitiveAttributeError => SensitiveAttributeError,
});

#[cfg(test)]
mod tests {
	use super::*;
	use utils::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(
		test_from_conversions,
		AnchorError,
		[
			AnchorAsn1Error::InvalidOid { reason: "test.oid".to_string() },
			CertificateError::SensitiveAttributeError { source: SensitiveAttributeError::InvalidVersion },
			SensitiveAttributeError::InvalidVersion,
		]
	);

	test_error_variants!(
		test_error_variants,
		[
			AnchorError::Asn1Error { source: AnchorAsn1Error::InvalidOid { reason: "test.oid".to_string() } },
			AnchorError::CertificateError {
				source: CertificateError::SensitiveAttributeError { source: SensitiveAttributeError::InvalidVersion }
			},
			AnchorError::SensitiveAttributeError { source: SensitiveAttributeError::MissingValue },
		]
	);
}

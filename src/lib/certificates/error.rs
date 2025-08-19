use snafu::Snafu;

use crate::sensitive_attributes::error::SensitiveAttributeError;

/// Error type for certificate operations
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum CertificateError {
	#[snafu(display("Sensitive attribute error: {}", source))]
	SensitiveAttributeError { source: SensitiveAttributeError },
}

crate::impl_source_error_from!(CertificateError, {
	SensitiveAttributeError => SensitiveAttributeError,
});

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(test_from_conversions, CertificateError, [SensitiveAttributeError::InvalidVersion,]);
	test_error_variants!(
		test_error_variants,
		[CertificateError::SensitiveAttributeError { source: SensitiveAttributeError::MissingValue },]
	);
}

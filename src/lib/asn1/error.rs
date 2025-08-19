use snafu::Snafu;

/// Error type for ASN.1.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Asn1Error {
	#[snafu(display("Invalid OID: {message}"))]
	InvalidOid { message: String },
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_error_variants;

	test_error_variants!(test_error_variants, [Asn1Error::InvalidOid { message: "test.oid".to_string() },]);
}

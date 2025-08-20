use snafu::Snafu;

/// Error type for certificate operations
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum SensitiveAttributeError {
	#[snafu(display("Value not set"))]
	MissingValue,

	#[snafu(display("Invalid OID: {message}"))]
	InvalidOid { message: String },

	#[snafu(display("Signing error: {message}"))]
	SigningError { message: String },

	#[snafu(display("Missing public key"))]
	MissingPublicKey,

	#[snafu(display("Unsupported key type for encryption"))]
	UnsupportedKeyType,

	#[snafu(display("Invalid version format"))]
	InvalidVersion,

	#[snafu(display("Unsupported version: {version}"))]
	UnsupportedVersion { version: u64 },

	#[snafu(display("Invalid proof format or content"))]
	InvalidProof,

	#[snafu(display("Invalid UTF-8 data in decrypted value"))]
	InvalidUtf8,

	#[snafu(display("Account error: {source}"))]
	AccountError { source: accounts::error::AccountError },

	#[snafu(display("Cryptographic error: {source}"))]
	CryptoError { source: crypto::error::CryptoError },

	#[snafu(display("ASN.1 error: {source}"))]
	Asn1Error { source: asn1::error::Asn1Error },
}

crate::impl_variant_error_from!(SensitiveAttributeError, {
	std::string::FromUtf8Error => InvalidUtf8,
});

crate::impl_source_error_from!(SensitiveAttributeError, {
	asn1::error::Asn1Error => Asn1Error,
	crypto::error::CryptoError => CryptoError,
	accounts::error::AccountError => AccountError,
	crypto::error::AeadError => CryptoError
});

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{test_error_from_conversions, test_error_variants};

	test_error_from_conversions!(
		test_from_conversions,
		SensitiveAttributeError,
		[
			std::string::String::from_utf8(vec![0, 159, 146, 150]).unwrap_err(),
			asn1::error::Asn1Error::InvalidOid { reason: "test".to_string() },
			crypto::error::CryptoError::InvalidKeyMaterial,
			accounts::error::AccountError::InvalidKeyType,
			crypto::error::AeadError,
		]
	);

	test_error_variants!(
		test_error_variants,
		[
			SensitiveAttributeError::MissingValue,
			SensitiveAttributeError::InvalidOid { message: "test.oid".to_string() },
			SensitiveAttributeError::SigningError { message: "test signing".to_string() },
			SensitiveAttributeError::UnsupportedKeyType,
			SensitiveAttributeError::InvalidVersion,
			SensitiveAttributeError::UnsupportedVersion { version: 42 },
			SensitiveAttributeError::InvalidProof,
			SensitiveAttributeError::InvalidUtf8,
		]
	);
}

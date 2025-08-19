use snafu::Snafu;

/// Error type for certificate operations
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum CertificateError {
	#[snafu(display("Value not set"))]
	MissingValue,

	#[snafu(display("Invalid OID: {message}"))]
	InvalidOid { message: String },

	#[snafu(display("Signing error: {message}"))]
	SigningError { message: String },

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

impl From<std::string::FromUtf8Error> for CertificateError {
	fn from(_: std::string::FromUtf8Error) -> Self {
		CertificateError::InvalidUtf8
	}
}

impl From<asn1::error::Asn1Error> for CertificateError {
	fn from(source: asn1::error::Asn1Error) -> Self {
		CertificateError::Asn1Error { source }
	}
}

impl From<crypto::error::CryptoError> for CertificateError {
	fn from(source: crypto::error::CryptoError) -> Self {
		CertificateError::CryptoError { source }
	}
}

impl From<accounts::error::AccountError> for CertificateError {
	fn from(source: accounts::error::AccountError) -> Self {
		CertificateError::AccountError { source }
	}
}

impl From<crypto::error::AeadError> for CertificateError {
	fn from(source: crypto::error::AeadError) -> Self {
		CertificateError::CryptoError { source: source.into() }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_from_conversions() {
		let test_cases: &[Box<dyn Fn() -> CertificateError>] = &[
			Box::new(|| {
				let utf8_error = std::string::String::from_utf8(vec![0, 159, 146, 150]).unwrap_err();
				utf8_error.into()
			}),
			Box::new(|| {
				let asn1_error = asn1::error::Asn1Error::InvalidOid { reason: "test".to_string() };
				asn1_error.into()
			}),
			Box::new(|| {
				let crypto_error = crypto::error::CryptoError::InvalidKeyMaterial;
				crypto_error.into()
			}),
			Box::new(|| {
				let account_error = accounts::error::AccountError::InvalidKeyType;
				account_error.into()
			}),
			Box::new(|| {
				let aead_error = crypto::error::AeadError;
				aead_error.into()
			}),
		];

		for error_fn in test_cases {
			let cert_error = error_fn();

			// Verify the conversion worked by checking the error can be formatted
			let display_str = format!("{}", cert_error);
			let debug_str = format!("{cert_error:?}");
			assert!(!display_str.is_empty());
			assert!(!debug_str.is_empty());
		}
	}

	#[test]
	fn test_error_variants() {
		let test_cases = [
			CertificateError::MissingValue,
			CertificateError::InvalidOid { message: "test.oid".to_string() },
			CertificateError::SigningError { message: "test signing".to_string() },
			CertificateError::UnsupportedKeyType,
			CertificateError::InvalidVersion,
			CertificateError::UnsupportedVersion { version: 42 },
			CertificateError::InvalidProof,
			CertificateError::InvalidUtf8,
		];

		for error in test_cases {
			let display_str = format!("{}", error);
			let debug_str = format!("{error:?}");
			assert!(!display_str.is_empty());
			assert!(!debug_str.is_empty());
		}
	}
}

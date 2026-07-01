use snafu::Snafu;

use crate::asn1::error::AnchorAsn1Error;

/// Result type for [`EncryptedContainer`](crate::encrypted_container::EncryptedContainer)
/// operations.
pub type Result<T> = core::result::Result<T, EncryptedContainerError>;

/// A failure encoding, decoding, or managing access to an encrypted container.
#[derive(Debug, Clone, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum EncryptedContainerError {
	#[snafu(display("Unsupported container version: {version}"))]
	UnsupportedVersion { version: u64 },

	#[snafu(display("Unsupported cipher algorithm"))]
	UnsupportedCipherAlgorithm,

	#[snafu(display("Unsupported digest algorithm"))]
	UnsupportedDigestAlgorithm,

	#[snafu(display("Unsupported signature algorithm"))]
	UnsupportedSignatureAlgorithm,

	/// A principal in the container or signer carries a key type that cannot
	/// participate in the operation requested.
	#[snafu(display("Unsupported key type"))]
	UnsupportedKeyType,

	#[snafu(display("No keys were provided to decrypt an encrypted container"))]
	NoKeysProvided,

	/// None of the supplied principals matched a key-store entry, so the
	/// symmetric key cannot be unwrapped.
	#[snafu(display("No supplied key can decrypt the container"))]
	NoMatchingKey,

	/// A matched principal failed to unwrap the symmetric key, or the body
	/// cipher rejected the ciphertext (wrong key or corrupt data).
	#[snafu(display("Decryption failed"))]
	DecryptionFailed,

	#[snafu(display("Decompression failed"))]
	DecompressionFailed,

	#[snafu(display("Signer account must hold a private key"))]
	SignerRequiresPrivateKey,

	#[snafu(display("Container is not signed"))]
	NotSigned,

	#[snafu(display("No plaintext is available"))]
	NoPlaintextAvailable,

	#[snafu(display("No encoded data is available"))]
	NoEncodedDataAvailable,

	#[snafu(display("Plaintext access is disabled for this container"))]
	PlaintextDisabled,

	/// Encrypted bytes were found, or encryption was requested, without a set
	/// of principals to gate access.
	#[snafu(display("Encryption requires a non-empty set of principals"))]
	EncryptionRequired,

	#[snafu(display("Invalid principal set for the requested operation"))]
	InvalidPrincipals,

	#[snafu(display("Access management is not allowed on a plaintext container"))]
	AccessManagementNotAllowed,

	#[snafu(display("Account error: {source}"))]
	AccountError { source: keetanetwork_account::error::AccountError },

	#[snafu(display("Cryptographic error: {source}"))]
	CryptoError { source: keetanetwork_crypto::error::CryptoError },

	#[snafu(display("ASN.1 error: {source}"))]
	Asn1Error { source: AnchorAsn1Error },
}

crate::impl_source_error_from!(EncryptedContainerError, {
	keetanetwork_account::error::AccountError => AccountError,
	keetanetwork_crypto::error::CryptoError => CryptoError,
	crate::asn1::error::AnchorAsn1Error => Asn1Error,
});

crate::impl_source_error_from_via!(EncryptedContainerError, {
	rasn::error::EncodeError => Asn1Error via AnchorAsn1Error,
	rasn::error::DecodeError => Asn1Error via AnchorAsn1Error,
});

/// Collapses any source error from a decryption step into
/// [`EncryptedContainerError::DecryptionFailed`].
pub(crate) trait OrDecryptionFailed<T> {
	fn or_decryption_failed(self) -> Result<T>;
}

impl<T, E> OrDecryptionFailed<T> for core::result::Result<T, E> {
	fn or_decryption_failed(self) -> Result<T> {
		self.map_err(|_| EncryptedContainerError::DecryptionFailed)
	}
}

#[cfg(test)]
mod tests {
	use keetanetwork_utils::{test_error_from_conversions, test_error_variants};

	use super::*;

	test_error_from_conversions!(
		test_from_conversions,
		EncryptedContainerError,
		[
			keetanetwork_account::error::AccountError::InvalidKeyType,
			keetanetwork_crypto::error::CryptoError::InvalidKeyMaterial,
			crate::asn1::error::AnchorAsn1Error::InvalidOid { reason: "test".to_string() },
		]
	);

	test_error_variants!(
		test_error_variants,
		[
			EncryptedContainerError::UnsupportedVersion { version: 2 },
			EncryptedContainerError::UnsupportedCipherAlgorithm,
			EncryptedContainerError::UnsupportedDigestAlgorithm,
			EncryptedContainerError::UnsupportedSignatureAlgorithm,
			EncryptedContainerError::UnsupportedKeyType,
			EncryptedContainerError::NoKeysProvided,
			EncryptedContainerError::NoMatchingKey,
			EncryptedContainerError::DecryptionFailed,
			EncryptedContainerError::DecompressionFailed,
			EncryptedContainerError::SignerRequiresPrivateKey,
			EncryptedContainerError::NotSigned,
			EncryptedContainerError::NoPlaintextAvailable,
			EncryptedContainerError::NoEncodedDataAvailable,
			EncryptedContainerError::PlaintextDisabled,
			EncryptedContainerError::EncryptionRequired,
			EncryptedContainerError::InvalidPrincipals,
			EncryptedContainerError::AccessManagementNotAllowed,
		]
	);
}

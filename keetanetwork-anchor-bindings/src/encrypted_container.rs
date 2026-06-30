//! Encrypted container binding ops over the core [`EncryptedContainer`].
//!
//! Accounts cross every binding boundary erased and shared as
//! [`Arc<GenericAccount>`], so principal sets and signers are passed by shared
//! reference and never cloned by value.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::account::AccountPublicKey;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::encrypted_container::{EncryptedContainer, EncryptedContainerError, FromPlaintextOptions};

use crate::error::CodedError;

/// Code for an unsupported container version.
pub const UNSUPPORTED_VERSION: &str = "UNSUPPORTED_VERSION";
/// Code for an unsupported body cipher.
pub const UNSUPPORTED_CIPHER: &str = "UNSUPPORTED_CIPHER";
/// Code for an unsupported signature digest.
pub const UNSUPPORTED_DIGEST: &str = "UNSUPPORTED_DIGEST";
/// Code for an unsupported signature algorithm.
pub const UNSUPPORTED_SIGNATURE: &str = "UNSUPPORTED_SIGNATURE";
/// Code for a key type that cannot participate in the operation.
pub const UNSUPPORTED_KEY_TYPE: &str = "UNSUPPORTED_KEY_TYPE";
/// Code for a decrypt attempt with no principals.
pub const NO_KEYS_PROVIDED: &str = "NO_KEYS_PROVIDED";
/// Code for a principal set that cannot unwrap the body key.
pub const NO_MATCHING_KEY: &str = "NO_MATCHING_KEY";
/// Code for a failed decryption (wrong key or corrupt body).
pub const DECRYPTION_FAILED: &str = "DECRYPTION_FAILED";
/// Code for a body that is not valid zlib.
pub const DECOMPRESSION_FAILED: &str = "DECOMPRESSION_FAILED";
/// Code for a signer supplied without its private key.
pub const SIGNER_REQUIRES_PRIVATE_KEY: &str = "SIGNER_REQUIRES_PRIVATE_KEY";
/// Code for a signature operation on an unsigned container.
pub const NOT_SIGNED: &str = "NOT_SIGNED";
/// Code for a missing plaintext payload.
pub const NO_PLAINTEXT: &str = "NO_PLAINTEXT";
/// Code for a missing encoded payload.
pub const NO_ENCODED_DATA: &str = "NO_ENCODED_DATA";
/// Code for plaintext access disabled on the instance.
pub const PLAINTEXT_DISABLED: &str = "PLAINTEXT_DISABLED";
/// Code for encryption requested without a principal set.
pub const ENCRYPTION_REQUIRED: &str = "ENCRYPTION_REQUIRED";
/// Code for a principal set invalid for the requested operation.
pub const INVALID_PRINCIPALS: &str = "INVALID_PRINCIPALS";
/// Code for access management on a plaintext container.
pub const ACCESS_MANAGEMENT_NOT_ALLOWED: &str = "ACCESS_MANAGEMENT_NOT_ALLOWED";
/// Code for an account-layer failure.
pub const ACCOUNT_ERROR: &str = "ACCOUNT_ERROR";
/// Code for a cryptographic failure.
pub const CRYPTO_ERROR: &str = "CRYPTO_ERROR";
/// Code for an ASN.1 failure.
pub const ASN1_ERROR: &str = "ASN1_ERROR";

/// Build a container from plaintext, optionally sealing it to `principals` and
/// attaching `signer`'s detached signature. `locked` overrides the default
/// plaintext-access policy.
pub fn from_plaintext(
	data: impl Into<Vec<u8>>,
	principals: Option<&[Arc<GenericAccount>]>,
	locked: Option<bool>,
	signer: Option<&Arc<GenericAccount>>,
) -> EncryptedContainer {
	let principals = principals.map(<[Arc<GenericAccount>]>::to_vec);
	let options = FromPlaintextOptions { locked, signer: signer.cloned() };
	EncryptedContainer::from_plaintext(data, principals, options)
}

/// Build a container from an encoded blob that may be plaintext or encrypted.
pub fn from_encoded(
	data: impl AsRef<[u8]>,
	principals: Option<&[Arc<GenericAccount>]>,
) -> Result<EncryptedContainer, CodedError> {
	EncryptedContainer::from_encoded(data, principals.map(<[Arc<GenericAccount>]>::to_vec)).map_err(coded)
}

/// Build a container from a blob that must be encrypted.
pub fn from_encrypted(
	data: impl AsRef<[u8]>,
	principals: &[Arc<GenericAccount>],
) -> Result<EncryptedContainer, CodedError> {
	EncryptedContainer::from_encrypted(data, principals.iter().cloned()).map_err(coded)
}

/// The decrypted, decompressed plaintext.
pub fn get_plaintext(container: &mut EncryptedContainer) -> Result<Vec<u8>, CodedError> {
	container.get_plaintext().map_err(coded)
}

/// The DER-encoded container.
pub fn get_encoded(container: &mut EncryptedContainer) -> Result<Vec<u8>, CodedError> {
	container.get_encoded().map_err(coded)
}

/// Whether the container is sealed to a principal set.
pub fn is_encrypted(container: &EncryptedContainer) -> bool {
	container.is_encrypted()
}

/// Whether a signer is attached or a signature is present.
pub fn is_signed(container: &EncryptedContainer) -> bool {
	container.is_signed()
}

/// The type-prefixed public keys of the accounts that can open the container.
pub fn principals(container: &EncryptedContainer) -> Result<Vec<Vec<u8>>, CodedError> {
	let principals = container.principals().map_err(coded)?;
	Ok(principals
		.iter()
		.map(|account| account.to_public_key_with_type())
		.collect())
}

/// Grant `accounts` access, invalidating the cached encoded form.
pub fn grant_access(container: &mut EncryptedContainer, accounts: &[Arc<GenericAccount>]) -> Result<(), CodedError> {
	container
		.grant_access(accounts.iter().cloned())
		.map_err(coded)?;
	Ok(())
}

/// Revoke the account identified by its type-prefixed public key.
pub fn revoke_access(container: &mut EncryptedContainer, public_key: impl AsRef<[u8]>) -> Result<(), CodedError> {
	container.revoke_access(public_key).map_err(coded)?;
	Ok(())
}

/// Verify the detached signature over the compressed payload.
pub fn verify_signature(container: &mut EncryptedContainer) -> Result<bool, CodedError> {
	container.verify_signature().map_err(coded)
}

/// The type-prefixed public key of the signing account, if the container is
/// signed.
pub fn signing_account(container: &EncryptedContainer) -> Result<Option<Vec<u8>>, CodedError> {
	let account = container.signing_account().map_err(coded)?;
	Ok(account.map(|account| account.to_public_key_with_type()))
}

/// Reduce a container error to a stable boundary code.
fn coded(error: EncryptedContainerError) -> CodedError {
	let message = error.to_string();
	let code = match error {
		EncryptedContainerError::UnsupportedVersion { .. } => UNSUPPORTED_VERSION,
		EncryptedContainerError::UnsupportedCipherAlgorithm => UNSUPPORTED_CIPHER,
		EncryptedContainerError::UnsupportedDigestAlgorithm => UNSUPPORTED_DIGEST,
		EncryptedContainerError::UnsupportedSignatureAlgorithm => UNSUPPORTED_SIGNATURE,
		EncryptedContainerError::UnsupportedKeyType => UNSUPPORTED_KEY_TYPE,
		EncryptedContainerError::NoKeysProvided => NO_KEYS_PROVIDED,
		EncryptedContainerError::NoMatchingKey => NO_MATCHING_KEY,
		EncryptedContainerError::DecryptionFailed => DECRYPTION_FAILED,
		EncryptedContainerError::DecompressionFailed => DECOMPRESSION_FAILED,
		EncryptedContainerError::SignerRequiresPrivateKey => SIGNER_REQUIRES_PRIVATE_KEY,
		EncryptedContainerError::NotSigned => NOT_SIGNED,
		EncryptedContainerError::NoPlaintextAvailable => NO_PLAINTEXT,
		EncryptedContainerError::NoEncodedDataAvailable => NO_ENCODED_DATA,
		EncryptedContainerError::PlaintextDisabled => PLAINTEXT_DISABLED,
		EncryptedContainerError::EncryptionRequired => ENCRYPTION_REQUIRED,
		EncryptedContainerError::InvalidPrincipals => INVALID_PRINCIPALS,
		EncryptedContainerError::AccessManagementNotAllowed => ACCESS_MANAGEMENT_NOT_ALLOWED,
		EncryptedContainerError::AccountError { .. } => ACCOUNT_ERROR,
		EncryptedContainerError::CryptoError { .. } => CRYPTO_ERROR,
		EncryptedContainerError::Asn1Error { .. } => ASN1_ERROR,
	};
	CodedError::new(code, message)
}

#[cfg(test)]
mod tests {
	use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;

	use super::*;

	/// A private-keyed secp256k1 principal derived from the doc seed at `index`,
	/// reproducible across calls for sealing and reopening.
	fn principal(index: u32) -> Arc<GenericAccount> {
		Arc::new(create_secp256k1_generic_account(Some(index)))
	}

	#[test]
	fn plaintext_round_trips_through_encoded() -> Result<(), CodedError> {
		let mut container = from_plaintext(b"payload".to_vec(), None, None, None);
		let encoded = get_encoded(&mut container)?;

		let mut restored = from_encoded(&encoded, None)?;
		assert_eq!(get_plaintext(&mut restored)?, b"payload");
		assert!(!is_encrypted(&restored));
		Ok(())
	}

	#[test]
	fn encrypted_round_trips_for_a_principal() -> Result<(), CodedError> {
		let owner = principal(0);
		let mut container = from_plaintext(b"secret".to_vec(), Some(&[owner]), Some(false), None);
		let encoded = get_encoded(&mut container)?;

		let mut opened = from_encrypted(&encoded, &[principal(0)])?;
		assert_eq!(get_plaintext(&mut opened)?, b"secret");
		assert!(is_encrypted(&opened));
		Ok(())
	}

	#[test]
	fn a_signed_container_verifies_and_recovers_its_signer() -> Result<(), CodedError> {
		let signer = principal(0);
		let mut container = from_plaintext(b"authentic".to_vec(), None, Some(false), Some(&signer));
		let encoded = get_encoded(&mut container)?;

		let mut restored = from_encoded(&encoded, None)?;
		assert!(is_signed(&restored));
		assert!(verify_signature(&mut restored)?);
		assert_eq!(signing_account(&restored)?, Some(signer.to_public_key_with_type()));
		Ok(())
	}

	#[test]
	fn granting_then_revoking_keeps_the_principal_count() -> Result<(), CodedError> {
		let mut container = from_plaintext(b"shared".to_vec(), Some(&[principal(0)]), Some(false), None);
		grant_access(&mut container, &[principal(1)])?;
		assert_eq!(principals(&container)?.len(), 2);

		revoke_access(&mut container, principal(1).to_public_key_with_type())?;
		assert_eq!(principals(&container)?.len(), 1);
		Ok(())
	}

	#[test]
	fn an_encrypted_blob_without_principals_is_rejected() -> Result<(), CodedError> {
		let mut container = from_plaintext(b"secret".to_vec(), Some(&[principal(0)]), Some(false), None);
		let encoded = get_encoded(&mut container)?;

		let error = from_encoded(&encoded, None)
			.err()
			.ok_or_else(|| CodedError::new("TEST", "expected a rejection"))?;
		assert_eq!(error.code, INVALID_PRINCIPALS);
		Ok(())
	}

	#[test]
	fn principals_are_rejected_on_a_plaintext_container() -> Result<(), CodedError> {
		let container = from_plaintext(b"x".to_vec(), None, None, None);
		let error = principals(&container)
			.err()
			.ok_or_else(|| CodedError::new("TEST", "expected a rejection"))?;
		assert_eq!(error.code, ACCESS_MANAGEMENT_NOT_ALLOWED);
		Ok(())
	}
}

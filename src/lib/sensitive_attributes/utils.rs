use accounts::KeyPair;
use crypto::algorithms::aes_gcm::Aes256Gcm;
use crypto::operations::encryption::NonceGeneration;
use rasn::prelude::*;

use crate::generated::SensitiveAttributeCipher;
use crate::sensitive_attributes::error::SensitiveAttributeError;

/// Result type for sensitive attribute operations
type Result<T> = std::result::Result<T, SensitiveAttributeError>;

/// Set up cipher for decryption using keypair and cipher info.
pub fn setup_cipher_for_decryption<T>(
	keypair: &T,
	cipher_info: &SensitiveAttributeCipher,
) -> Result<(Aes256Gcm, <Aes256Gcm as NonceGeneration>::Nonce)>
where
	T: KeyPair,
{
	// Decrypt the symmetric key with the keypair
	let decrypted_symmetric_key = keypair.decrypt(&cipher_info.key)?;
	// Extract nonce and set up cipher
	let nonce_bytes = cipher_info.iv_or_nonce.as_ref();
	let nonce = <Aes256Gcm as NonceGeneration>::Nonce::from_slice(nonce_bytes);
	let cipher = Aes256Gcm::new(&decrypted_symmetric_key)?;

	Ok((cipher, *nonce))
}

/// Create hash input for proof validation.
pub fn create_hash_input(
	salt: impl AsRef<[u8]>,
	public_key: impl AsRef<[u8]>,
	encrypted_value: impl AsRef<[u8]>,
	plaintext_value: impl AsRef<[u8]>,
) -> Vec<u8> {
	let mut hash_input = Vec::new();

	hash_input.extend_from_slice(salt.as_ref());
	hash_input.extend_from_slice(public_key.as_ref());
	hash_input.extend_from_slice(encrypted_value.as_ref());
	hash_input.extend_from_slice(plaintext_value.as_ref());

	hash_input
}

/// Validate version (currently only supports version 0).
pub fn validate_version(version: &Integer) -> Result<u64> {
	let version: u64 = version
		.clone()
		.try_into()
		.map_err(|_| SensitiveAttributeError::InvalidVersion)?;

	if version != 0 {
		return Err(SensitiveAttributeError::UnsupportedVersion { version });
	}

	Ok(version)
}

#[cfg(test)]
mod tests {
	use core::convert::TryFrom;

	use accounts::{Account, Accountable, IntoSecret, KeyECDSASECP256K1, Keyable, Seed};
	use crypto::algorithms::aes_gcm::Aes256Gcm;
	use crypto::generate_random_seed;
	use crypto::operations::encryption::{Aead, NonceGeneration};
	use crypto::prelude::ExposeSecret;
	use rasn::prelude::*;

	use super::*;

	/// Test seed for consistent test results
	const TEST_SEED: &str = "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D";

	/// Helper function to create a test seed array
	fn create_test_seed_array() -> Seed {
		let seed_bytes = hex::decode(TEST_SEED).unwrap();
		let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();

		seed_array.into_secret()
	}

	/// Helper function to create an account from seed
	fn create_test_account() -> Account<KeyECDSASECP256K1> {
		let seed_array = create_test_seed_array();
		let seed = Keyable::Seed((seed_array, 0));
		let accountable = Accountable::KeyAndType(seed, KeyECDSASECP256K1::KEY_PAIR_TYPE);

		Account::<KeyECDSASECP256K1>::try_from(accountable).unwrap()
	}

	#[test]
	fn test_setup_cipher_for_decryption() {
		let account = create_test_account();

		// Generate a symmetric key and encrypt it
		let symmetric_key = generate_random_seed().unwrap();
		let symmetric_key_bytes = symmetric_key.expose_secret();
		let encrypted_key = account.keypair.encrypt(symmetric_key_bytes).unwrap();

		// Generate a nonce
		let nonce = Aes256Gcm::generate_nonce();
		// Create cipher info
		let cipher_info =
			SensitiveAttributeCipher::new(crate::asn1::AES_256_GCM_OID, nonce.to_vec().into(), encrypted_key.into());

		let result = setup_cipher_for_decryption(&account.keypair, &cipher_info);
		assert!(result.is_ok());

		let (cipher, decrypted_nonce) = result.unwrap();
		assert_eq!(nonce, decrypted_nonce);

		// Verify the cipher works by encrypting/decrypting test data
		let test_data = b"test encryption data";
		let encrypted = cipher.encrypt(&nonce, test_data.as_ref()).unwrap();
		let decrypted = cipher.decrypt(&nonce, encrypted.as_ref()).unwrap();
		assert_eq!(test_data.as_ref(), decrypted.as_slice());
	}

	#[test]
	fn test_create_hash_input() {
		let salt = b"test_salt_32_bytes_long_for_test";
		let public_key = b"test_public_key";
		let encrypted_value = b"encrypted_test_value";
		let plaintext_value = b"plaintext_test_value";

		let hash_input = create_hash_input(salt, public_key, encrypted_value, plaintext_value);

		// Verify the hash input contains all components in the correct order
		let mut expected = Vec::new();
		expected.extend_from_slice(salt);
		expected.extend_from_slice(public_key);
		expected.extend_from_slice(encrypted_value);
		expected.extend_from_slice(plaintext_value);
		assert_eq!(hash_input, expected);
		assert_eq!(hash_input.len(), salt.len() + public_key.len() + encrypted_value.len() + plaintext_value.len());

		// Test with different input types (Vec, &[u8], String, etc.)
		let salt_vec = salt.to_vec();
		let public_key_str = String::from_utf8(public_key.to_vec()).unwrap();
		let hash_input2 = create_hash_input(&salt_vec, public_key_str.as_bytes(), encrypted_value, plaintext_value);
		assert_eq!(hash_input, hash_input2);
	}

	#[test]
	fn test_validate_version() {
		// Test valid version 0
		let version_zero: Integer = 0u64.into();
		let result = validate_version(&version_zero);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), 0);

		// Test invalid version 1
		let version_one: Integer = 1u64.into();
		let result = validate_version(&version_one);
		assert!(result.is_err());

		let error = result.unwrap_err();
		assert!(matches!(error, SensitiveAttributeError::UnsupportedVersion { version: 1 }));
	}
}

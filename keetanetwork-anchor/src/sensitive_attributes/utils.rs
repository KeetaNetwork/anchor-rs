use alloc::string::ToString;
use alloc::vec::Vec;

use keetanetwork_account::KeyPair;
use keetanetwork_crypto::algorithms::aes_gcm::Aes256Gcm;
use keetanetwork_crypto::operations::encryption::NonceGeneration;
use rasn::prelude::*;

use crate::generated::SensitiveAttributeCipher;
use crate::sensitive_attributes::error::SensitiveAttributeError;

/// Result type for sensitive attribute operations
type Result<T> = core::result::Result<T, SensitiveAttributeError>;

/// Set up cipher for decryption using keypair and cipher info.
pub(crate) fn setup_cipher_for_decryption<T>(
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
pub(crate) fn create_hash_input(
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
pub(crate) fn assert_valid_version(version: &Integer) -> Result<u64> {
	let version: u64 = version
		.clone()
		.try_into()
		.map_err(|_| SensitiveAttributeError::InvalidVersion)?;
	if version != 0 {
		return Err(SensitiveAttributeError::UnsupportedVersion { version });
	}

	Ok(version)
}

/// Private helper function to validate attribute sensitivity
fn validate_attribute_sensitivity(
	attribute: &crate::kyc_schema::Attribute,
	name: impl AsRef<str>,
	expected_sensitive: bool,
) -> Result<()> {
	let is_sensitive = attribute.is_sensitive();
	if is_sensitive != expected_sensitive {
		let name = name.as_ref().to_string();
		return if expected_sensitive {
			Err(SensitiveAttributeError::InvalidAttributeIsPlain { name })
		} else {
			Err(SensitiveAttributeError::InvalidAttributeIsSensitive { name })
		};
	}

	Ok(())
}

/// Assert that an attribute is sensitive (encrypted).
///
/// # Parameters
/// - `attribute` - The attribute to check
/// - `name` - The name of the attribute (for error messages)
///
/// # Returns
/// - `Ok(_)` if the attribute is sensitive
/// - `Err(_)` if the attribute is not sensitive
pub fn assert_attribute_is_sensitive(attribute: &crate::kyc_schema::Attribute, name: impl AsRef<str>) -> Result<()> {
	validate_attribute_sensitivity(attribute, name, true)
}

/// Assert that an attribute is plain text (not encrypted).
///
/// # Parameters
/// - `attribute` - The attribute to check
/// - `name` - The name of the attribute (for error messages)
///
/// # Returns
/// - `Ok(_)` if the attribute is plain text
/// - `Err(_)` if the attribute is sensitive
pub fn assert_attribute_is_plain(attribute: &crate::kyc_schema::Attribute, name: impl AsRef<str>) -> Result<()> {
	validate_attribute_sensitivity(attribute, name, false)
}

#[cfg(test)]
mod tests {
	use keetanetwork_account::KeyECDSASECP256K1;
	use keetanetwork_crypto::algorithms::aes_gcm::Aes256Gcm;
	use keetanetwork_crypto::operations::encryption::{Aead, NonceGeneration};
	use keetanetwork_crypto::prelude::ExposeSecret;
	use keetanetwork_crypto::utils::generate_random_seed;
	use rasn::prelude::*;

	use super::*;
	use crate::asn1::oids;
	use crate::kyc_schema::builder::AttributeBuilderLike;
	use crate::testing::create_account_from_seed;

	/// Helper function to create a test attribute for assertion testing
	fn create_test_attribute(is_sensitive: bool) -> crate::kyc_schema::Attribute {
		use crate::kyc_schema::AttributeBuilder;

		let builder = AttributeBuilder::new()
			.with_oid("1.3.6.1.4.1.62675.1.0")
			.with_value(b"test value");

		if is_sensitive {
			builder.as_sensitive().build().unwrap()
		} else {
			builder.as_plain().build().unwrap()
		}
	}

	#[test]
	fn test_setup_cipher_for_decryption() {
		let account = create_account_from_seed::<KeyECDSASECP256K1>(0);

		// Generate a symmetric key and encrypt it
		let symmetric_key = generate_random_seed().unwrap();
		let symmetric_key_bytes = symmetric_key.expose_secret();
		let encrypted_key = account.keypair.encrypt(symmetric_key_bytes).unwrap();

		// Generate a nonce
		let nonce = Aes256Gcm::generate_nonce();
		// Create cipher info
		let cipher_info = SensitiveAttributeCipher::new(oids::AES_256_GCM, nonce.to_vec().into(), encrypted_key.into());

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
		let result = assert_valid_version(&version_zero);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), 0);

		// Test invalid version 1
		let version_one: Integer = 1u64.into();
		let result = assert_valid_version(&version_one);
		assert!(result.is_err());

		let error = result.unwrap_err();
		assert!(matches!(error, SensitiveAttributeError::UnsupportedVersion { version: 1 }));
	}

	/// Macro to test assertion functions with both success and failure cases
	macro_rules! test_attribute_assertion {
		($test_name:ident, $assert_fn:ident, $success_case:expr, $failure_case:expr, $expected_error:pat) => {
			#[test]
			fn $test_name() {
				// Should succeed with correct attribute type
				let success_attr = create_test_attribute($success_case);
				assert!($assert_fn(&success_attr, "testAttr").is_ok());

				// Should fail with incorrect attribute type
				let failure_attr = create_test_attribute($failure_case);
				let result = $assert_fn(&failure_attr, "testAttr");
				assert!(result.is_err());
				assert!(matches!(result.unwrap_err(), $expected_error));
			}
		};
	}

	test_attribute_assertion!(
		test_assert_attribute_is_sensitive,
		assert_attribute_is_sensitive,
		true,
		false,
		SensitiveAttributeError::InvalidAttributeIsPlain { .. }
	);

	test_attribute_assertion!(
		test_assert_attribute_is_plain,
		assert_attribute_is_plain,
		false,
		true,
		SensitiveAttributeError::InvalidAttributeIsSensitive { .. }
	);
}

use accounts::KeyPair;
use crypto::algorithms::aes_gcm::Aes256Gcm;
use crypto::generate_random_seed;
use crypto::operations::encryption::{Aead, NonceGeneration};
use crypto::prelude::{ExposeSecret, HashAlgorithm};
use rasn::prelude::*;

use crate::asn1::*;
use crate::generated::{SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue};
use crate::sensitive_attributes::error::SensitiveAttributeError;
use crate::sensitive_attributes::utils::create_hash_input;

/// Result type for certificate operations
pub type Result<T> = std::result::Result<T, SensitiveAttributeError>;

/// Builder for creating SensitiveAttribute instances
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SensitiveAttributeBuilder {
	value: Option<Vec<u8>>,
}

impl SensitiveAttributeBuilder {
	/// Create a new builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the value for the builder.
	pub fn with_value(mut self, value: impl Into<Vec<u8>>) -> Self {
		self.value = Some(value.into());
		self
	}

	/// Build the SensitiveAttribute using the provided keypair.
	pub fn build<T>(&self, keypair: &T) -> Result<SensitiveAttribute>
	where
		T: KeyPair,
	{
		let value = self
			.value
			.as_ref()
			.ok_or(SensitiveAttributeError::MissingValue)?;

		// Check if the keypair supports encryption
		if !keypair.supports_encryption() {
			return Err(SensitiveAttributeError::UnsupportedKeyType);
		}

		// Generate salt (32 bytes)
		let salt = generate_random_seed()?;
		let salt = salt.expose_secret();

		// Get public key
		let public_key_bytes = if let Some(public_key) = keypair.to_public_key() {
			public_key.to_bytes()
		} else {
			return Err(SensitiveAttributeError::MissingPublicKey);
		};

		// Generate a symmetric encryption key
		let symmetric_key = generate_random_seed()?;
		let symmetric_key = symmetric_key.expose_secret();

		// Generate nonce (12 bytes for GCM)
		let nonce = Aes256Gcm::generate_nonce();
		// Encrypt the symmetric key with the keypair
		let encrypted_key = keypair.encrypt(symmetric_key)?;
		// Set up AES-256-GCM cipher
		let cipher = Aes256Gcm::new(symmetric_key)?;
		// Encrypt the value
		let encrypted_value = cipher.encrypt(&nonce, value.as_ref())?;
		// Encrypt the salt
		let encrypted_salt = cipher.encrypt(&nonce, salt.as_ref())?;
		// Create hash using utility function
		let hash_input = create_hash_input(salt.as_slice(), &public_key_bytes, &encrypted_value, value);

		let version: Integer = 0u64.into(); // version 0
		let hashed_and_salted_value: OctetString = HashAlgorithm::Sha2_256.hash(&hash_input).into();
		let encrypted_salt: OctetString = encrypted_salt.into();
		let hashed_value = SensitiveAttributeHashedValue::new(encrypted_salt, SHA2_256_OID, hashed_and_salted_value);
		let nonce = nonce.to_vec();
		let cipher = SensitiveAttributeCipher::new(AES_256_GCM_OID, nonce.into(), encrypted_key.into());
		let encrypted_value: OctetString = encrypted_value.into();

		// Build ASN.1 structure
		let sensitive_attribute = SensitiveAttribute::new(version, cipher, hashed_value, encrypted_value);
		Ok(sensitive_attribute)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_all_key_types;

	test_all_key_types!(test_sensitive_attribute_builder_with_real_keypair, |account: accounts::Account<_>| {
		let builder = SensitiveAttributeBuilder::new().with_value(b"test value");
		let result = builder.build(&account.keypair);
		assert!(result.is_ok());
	});

	test_all_key_types!(test_sensitive_attribute_builder_missing_value, |account: accounts::Account<_>| {
		let builder = SensitiveAttributeBuilder::new();
		let result = builder.build(&account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SensitiveAttributeError::MissingValue));
	});

	#[test]
	fn test_sensitive_attribute_builder_unsupported_key_type() {
		let network_account = accounts::Account::<accounts::KeyNETWORK>::generate_network_address(1).unwrap();
		let builder = SensitiveAttributeBuilder::new().with_value(b"test value");
		let result = builder.build(&network_account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SensitiveAttributeError::UnsupportedKeyType));
	}
}

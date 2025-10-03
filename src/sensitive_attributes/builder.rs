//! Sensitive Attribute Builder
//!
//! This module provides the `SensitiveAttributeBuilder` for creating encrypted
//! sensitive attributes that can be embedded in KYC certificates.
//!
//! # Example
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_anchor::sensitive_attributes::SensitiveAttributeBuilder;
//! use keetanetwork_crypto::prelude::ExposeSecret;
//!
//! // Create a test account
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! // Create a sensitive attribute with personal data
//! let sensitive_attr = SensitiveAttributeBuilder::new()
//!     .with_value(b"john.doe@example.com")
//!     .build(&account.keypair)?;
//!
//! // The attribute is now encrypted and can be stored safely
//! let der_encoded = sensitive_attr.to_der()?;
//! println!("Encrypted attribute size: {} bytes", der_encoded.len());
//!
//! // Later, decrypt the attribute using the same keypair
//! let decrypted_data = sensitive_attr.decrypt(&account.keypair)?;
//! let decrypted_string = String::from_utf8(decrypted_data.expose_secret().clone())?;
//!
//! assert_eq!(decrypted_string, "john.doe@example.com");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use keetanetwork_account::KeyPair;
use keetanetwork_crypto::algorithms::aes_gcm::Aes256Gcm;
use keetanetwork_crypto::operations::encryption::{Aead, NonceGeneration};
use keetanetwork_crypto::prelude::{ExposeSecret, HashAlgorithm};
use keetanetwork_crypto::utils::generate_random_seed;
use rasn::prelude::*;

use crate::asn1::oids;
use crate::generated::{SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue};
use crate::sensitive_attributes::error::SensitiveAttributeError;
use crate::sensitive_attributes::utils::create_hash_input;

/// Result type for certificate operations
pub type Result<T> = std::result::Result<T, SensitiveAttributeError>;

/// Builder for creating encrypted SensitiveAttribute instances.
///
/// # Example
///
/// ```rust
/// # use keetanetwork_anchor::doc_utils;
/// use keetanetwork_anchor::sensitive_attributes::SensitiveAttributeBuilder;
///
/// # let account = doc_utils::create_secp256k1_test_account(None);
///
/// // Create a sensitive attribute containing personal data
/// let sensitive_attr = SensitiveAttributeBuilder::new()
///     .with_value(b"Social Security Number: 123-45-6789")
///     .build(&account.keypair)?;
///
/// // The attribute is now encrypted and can be safely stored
/// println!("Sensitive attribute created successfully");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SensitiveAttributeBuilder {
	value: Option<Vec<u8>>,
}

impl SensitiveAttributeBuilder {
	/// Creates a new empty builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Sets the raw byte value to be encrypted and stored it.
	///
	/// # Arguments
	///
	/// - `value` - The data to encrypt and store
	///
	/// # Example
	///
	/// ```rust
	/// use keetanetwork_anchor::sensitive_attributes::SensitiveAttributeBuilder;
	///
	/// // With byte slice
	/// let builder1 = SensitiveAttributeBuilder::new()
	///     .with_value(b"sensitive data");
	///
	/// // With string
	/// let builder2 = SensitiveAttributeBuilder::new()
	///     .with_value("personal information".as_bytes());
	///
	/// // With vector
	/// let data = vec![1, 2, 3, 4, 5];
	/// let builder3 = SensitiveAttributeBuilder::new()
	///     .with_value(data);
	/// ```
	pub fn with_value(mut self, value: impl Into<Vec<u8>>) -> Self {
		self.value = Some(value.into());
		self
	}

	/// Builds the encrypted SensitiveAttribute using the provided keypair.
	///
	/// # Arguments
	///
	/// - `keypair` - A keypair that supports encryption operations
	///
	/// # Returns
	///
	/// - `Ok(_)` on success
	/// - `Err(_)` if any of the steps fail
	///
	/// # Example
	///
	/// ```rust
	/// # use keetanetwork_anchor::doc_utils;
	/// use keetanetwork_anchor::sensitive_attributes::SensitiveAttributeBuilder;
	///
	/// let account = doc_utils::create_secp256k1_test_account(None);
	///
	/// let result = SensitiveAttributeBuilder::new()
	///     .with_value("confidential data")
	///     .build(&account.keypair);
	///
	/// assert!(result.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
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
		let public_key = keypair.to_public_key();
		let public_key_bytes = public_key.as_ref();
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
		let hash_input = create_hash_input(salt.as_slice(), public_key_bytes, &encrypted_value, value);

		let version: Integer = 0u64.into(); // version 0
		let hashed_and_salted_value: OctetString = HashAlgorithm::Sha3_256.hash(&hash_input).into();
		let encrypted_salt: OctetString = encrypted_salt.into();
		let hashed_value = SensitiveAttributeHashedValue::new(encrypted_salt, oids::SHA3_256, hashed_and_salted_value);
		let nonce = nonce.to_vec();
		let cipher = SensitiveAttributeCipher::new(oids::AES_256_GCM, nonce.into(), encrypted_key.into());
		let encrypted_value: OctetString = encrypted_value.into();

		// Build ASN.1 structure
		let sensitive_attribute = SensitiveAttribute::new(version, cipher, hashed_value, encrypted_value);
		Ok(sensitive_attribute)
	}
}

#[cfg(test)]
mod tests {
	use keetanetwork_account::{Account, KeyNETWORK};

	use super::*;
	use crate::test_all_key_types;

	test_all_key_types!(test_sensitive_attribute_builder_with_real_keypair, |account: Account<_>| {
		let builder = SensitiveAttributeBuilder::new().with_value(b"test value");
		let result = builder.build(&account.keypair);
		assert!(result.is_ok());
	});

	test_all_key_types!(test_sensitive_attribute_builder_missing_value, |account: Account<_>| {
		let builder = SensitiveAttributeBuilder::new();
		let result = builder.build(&account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SensitiveAttributeError::MissingValue));
	});

	#[test]
	fn test_sensitive_attribute_builder_unsupported_key_type() {
		let network_account = Account::<KeyNETWORK>::generate_network_address(1).unwrap();
		let builder = SensitiveAttributeBuilder::new().with_value(b"test value");
		let result = builder.build(&network_account.keypair);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SensitiveAttributeError::UnsupportedKeyType));
	}
}

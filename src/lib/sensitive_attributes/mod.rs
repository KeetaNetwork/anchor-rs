//! Sensitive Attributes Module
//!
//! This module provides functionality for creating, encrypting, and managing
//! sensitive attributes that can be embedded in KYC certificates. It uses
//! hybrid encryption combining symmetric encryption with asymmetric key
//! encryption for security.
//!
//! # Overview
//!
//! Sensitive attributes allow you to:
//! - Encrypt personal data using hybrid cryptography
//! - Generate proofs for attribute validation without exposing private keys
//! - Serialize attributes to DER format for storage and transmission
//! - Validate attribute proofs to ensure data integrity
//!
//! # Basic Usage
//!
//! ```rust
//! # use anchor_rs::doc_utils;
//! use anchor_rs::sensitive_attributes::{
//!     SensitiveAttribute,
//!     SensitiveAttributeBuilder
//! };
//! use crypto::prelude::ExposeSecret;
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//!
//! // Create an encrypted sensitive attribute
//! let personal_email = b"john.doe@example.com";
//! let sensitive_attr = SensitiveAttributeBuilder::new()
//!     .with_value(personal_email)
//!     .build(&account.keypair)?;
//!
//! // Later, decrypt the attribute
//! let decrypted = sensitive_attr.decrypt(&account.keypair)?;
//! assert_eq!(decrypted.expose_secret(), personal_email);
//!
//! // Generate a proof for validation
//! let proof = sensitive_attr.to_proof(&account.keypair)?;
//! assert!(sensitive_attr.validate_proof(&account.keypair, proof)?);
//!
//! // Convert to DER format for storage
//! let der_bytes = sensitive_attr.to_der()?;
//! // Convert from DER
//! let sensitive_attr = SensitiveAttribute::try_from(der_bytes.as_ref())?;
//! let decrypted = sensitive_attr.decrypt(&account.keypair)?;
//! assert_eq!(decrypted.expose_secret(), personal_email);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Proof-Based Validation
//!
//! ```rust
//! # use anchor_rs::doc_utils;
//! use anchor_rs::sensitive_attributes::SensitiveAttributeBuilder;
//!
//! # let account = doc_utils::create_secp256k1_test_account(None);
//! let ssn = b"123-45-6789";
//!
//! // Create encrypted attribute
//! let sensitive_attr = SensitiveAttributeBuilder::new()
//!     .with_value(ssn)
//!     .build(&account.keypair)?;
//!
//! // Entity A generates a proof
//! let proof = sensitive_attr.to_proof(&account.keypair)?;
//! // Entity B can validate the proof without needing the original data
//! let is_valid = sensitive_attr.validate_proof(&account.keypair, proof)?;
//! assert!(is_valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod builder;
pub mod error;
pub mod utils;

#[cfg(feature = "serde")]
pub mod serde;

use std::hash::Hash;

use accounts::KeyPair;
use crypto::operations::encryption::Aead;
use crypto::prelude::{ExposeSecret, HashAlgorithm, IntoSecret, SecretBox};
use rasn::prelude::*;
use strum::AsRefStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::asn1::error::AnchorAsn1Error;
use crate::asn1::*;
use crate::sensitive_attributes::error::SensitiveAttributeError;
use crate::sensitive_attributes::utils::{assert_valid_version, create_hash_input, setup_cipher_for_decryption};
use crate::utils::{base64_decode, base64_encode};

/// Result type for certificate operations
pub type Result<T> = std::result::Result<T, SensitiveAttributeError>;
/// Sensitive attribute value type
pub type SensitiveAttributeValue = SecretBox<Vec<u8>>;
pub type SensitiveAttributeProofValue = SecretBox<String>;

// Re-export sensitive attribute types
pub use crate::generated::{SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue};
pub use builder::SensitiveAttributeBuilder;

/// Certificate attribute names
///
/// Predefined attribute names for common KYC data types, each mapped to a
/// specific Object Identifier (OID). ,These provide standardized ways to
/// identify different types of sensitive personal information.
///
/// # Example
///
/// ```rust
/// use anchor_rs::sensitive_attributes::SensitiveAttributeName;
/// use rasn::types::ObjectIdentifier;
///
/// // Convert attribute names to OIDs
/// let email_oid = ObjectIdentifier::from(SensitiveAttributeName::Email);
/// let name_oid = ObjectIdentifier::from(SensitiveAttributeName::FullName);
///
/// // Use in attribute identification
/// println!("Email OID: {}", email_oid);
/// println!("Full Name OID: {}", name_oid);
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, AsRefStr)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[strum(serialize_all = "camelCase")]
pub enum SensitiveAttributeName {
	FullName,
	DateOfBirth,
	Address,
	Email,
	PhoneNumber,
}

impl From<SensitiveAttributeName> for ObjectIdentifier {
	fn from(attr: SensitiveAttributeName) -> Self {
		match attr {
			SensitiveAttributeName::FullName => oids::keeta::FULL_NAME,
			SensitiveAttributeName::DateOfBirth => oids::keeta::DATE_OF_BIRTH,
			SensitiveAttributeName::Address => oids::keeta::ADDRESS,
			SensitiveAttributeName::Email => oids::keeta::EMAIL,
			SensitiveAttributeName::PhoneNumber => oids::keeta::PHONE_NUMBER,
		}
	}
}

/// Hash structure for sensitive attribute proof.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SensitiveAttributeProofHash {
	pub salt: String,
}

impl From<&[u8]> for SensitiveAttributeProofHash {
	fn from(salt_bytes: &[u8]) -> Self {
		Self { salt: base64_encode(salt_bytes) }
	}
}

impl From<Vec<u8>> for SensitiveAttributeProofHash {
	fn from(salt_bytes: Vec<u8>) -> Self {
		salt_bytes.as_slice().into()
	}
}

/// Proof structure for sensitive attribute validation.
#[derive(Debug)]
pub struct SensitiveAttributeProof {
	pub value: SensitiveAttributeProofValue,
	pub hash: SensitiveAttributeProofHash,
}

impl PartialEq for SensitiveAttributeProof {
	fn eq(&self, other: &Self) -> bool {
		// Two proofs are equal if both their hash and value match
		self.hash == other.hash && self.value.expose_secret() == other.value.expose_secret()
	}
}

// Note: You cannot derive this
impl Eq for SensitiveAttributeProof {}

impl SensitiveAttribute {
	/// Decrypt the sensitive attribute value using the provided keypair
	///
	/// # Arguments
	///
	/// - `keypair` - A keypair that supports encryption operations
	///
	/// # Returns
	///
	/// - `Ok(_)` containing the decrypted data
	/// - `Err(_)` if decryption fails
	///
	/// # Security
	///
	/// The decrypted value is wrapped in a `SecretBox` to prevent accidental
	/// exposure in logs or debug output. Use `expose_secret()` only when
	/// necessary and ensure the exposed data is properly handled.
	///
	/// # Example
	///
	/// ```rust
	/// # use anchor_rs::doc_utils;
	/// use anchor_rs::sensitive_attributes::SensitiveAttributeBuilder;
	/// use crypto::prelude::ExposeSecret;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// // Create an encrypted sensitive attribute
	/// let original_data = b"john.doe@example.com";
	/// let sensitive_attr = SensitiveAttributeBuilder::new()
	///     .with_value(original_data)
	///     .build(&account.keypair)?;
	///
	/// // Decrypt the attribute
	/// let decrypted = sensitive_attr.decrypt(&account.keypair)?;
	/// assert_eq!(decrypted.expose_secret(), original_data);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn decrypt<T>(&self, keypair: &T) -> Result<SensitiveAttributeValue>
	where
		T: KeyPair,
	{
		// Validate version and keypair capabilities
		assert_valid_version(&self.version)?;

		if !keypair.supports_encryption() {
			return Err(SensitiveAttributeError::UnsupportedKeyType);
		}

		// Set up cipher for decryption
		let (cipher, nonce) = setup_cipher_for_decryption(keypair, &self.cipher)?;

		// Decrypt the value
		let decrypted_value = cipher.decrypt(&nonce, self.encrypted_value.as_ref())?;
		Ok(decrypted_value.into_secret())
	}

	/// Decrypt the sensitive attribute value and return it as a UTF-8 string.
	///
	/// # Arguments
	///
	/// - `keypair` - A keypair that supports encryption operations
	///
	/// # Returns
	///
	/// - `Ok(_)` containing the decrypted data as a UTF-8 string
	/// - `Err(_)` if decryption fails or the data is not valid UTF-8
	///
	/// # Example
	///
	/// ```rust
	/// # use anchor_rs::doc_utils;
	/// use anchor_rs::sensitive_attributes::SensitiveAttributeBuilder;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// // Create an encrypted sensitive attribute with UTF-8 text
	/// let message = "Hello, secure world! 🔐";
	/// let sensitive_attr = SensitiveAttributeBuilder::new()
	///     .with_value(message.as_bytes())
	///     .build(&account.keypair)?;
	///
	/// // Decrypt as string
	/// let decrypted_string = sensitive_attr.decrypt_as_string(&account.keypair)?;
	/// assert_eq!(decrypted_string, message);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn decrypt_as_string<T>(&self, keypair: &T) -> Result<String>
	where
		T: KeyPair,
	{
		let decrypted_value = self.decrypt(keypair)?;
		let bytes = decrypted_value.expose_secret();
		Ok(String::from_utf8(bytes.clone())?)
	}

	/// TODO: I am not sure this approach makes sense. - TW
	/// Generate a proof that is used to validate the sensitive attribute value.
	///
	/// # Arguments
	///
	/// - `keypair` - The keypair used to decrypt the attribute for proof generation
	///
	/// # Returns
	///
	/// - `Ok(_)` containing the generated proof
	/// - `Err(_)` if proof generation fails
	///
	/// # Security Considerations
	///
	/// The proof contains the actual decrypted value in base64 format, so it
	/// should be handled with the same security considerations as the original
	/// plaintext data.
	///
	/// # Example
	///
	/// ```rust
	/// # use anchor_rs::doc_utils;
	/// use anchor_rs::sensitive_attributes::SensitiveAttributeBuilder;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// // Create an encrypted sensitive attribute
	/// let email = b"user@example.com";
	/// let sensitive_attr = SensitiveAttributeBuilder::new()
	///     .with_value(email)
	///     .build(&account.keypair)?;
	///
	/// // Generate a proof for the attribute
	/// let proof = sensitive_attr.to_proof(&account.keypair);
	/// assert!(proof.is_ok());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn to_proof<T>(&self, keypair: &T) -> Result<SensitiveAttributeProof>
	where
		T: KeyPair,
	{
		// Decrypt the value
		let decrypted_value = self.decrypt(keypair)?;
		// Set up cipher for decrypting salt
		let (cipher, nonce) = setup_cipher_for_decryption(keypair, &self.cipher)?;
		let decrypted_salt = cipher.decrypt(&nonce, self.hashed_value.encrypted_salt.as_ref())?;
		let base64_value = base64_encode(decrypted_value.expose_secret());

		Ok(SensitiveAttributeProof {
			value: base64_value.into_secret(),
			hash: SensitiveAttributeProofHash::from(decrypted_salt),
		})
	}

	/// Validate a proof against this sensitive attribute.
	///
	/// # Arguments
	///
	/// - `keypair` - The keypair used for validation
	/// - `proof` - The proof to validate against this attribute
	///
	/// # Returns
	///
	/// - `Ok(true)` if the proof is valid for this attribute
	/// - `Ok(false)` if the proof is invalid
	/// - `Err(_)` if validation cannot be performed
	///
	/// # Example
	///
	/// ```rust
	/// # use anchor_rs::doc_utils;
	/// use anchor_rs::sensitive_attributes::{
	///     SensitiveAttributeBuilder,
	///     SensitiveAttributeProof,
	///     SensitiveAttributeProofHash
	/// };
	/// use crypto::prelude::IntoSecret;
	///
	/// # let account = doc_utils::create_secp256k1_test_account(None);
	/// // Create an encrypted sensitive attribute
	/// let data = b"confidential-information";
	/// let sensitive_attr = SensitiveAttributeBuilder::new()
	///     .with_value(data)
	///     .build(&account.keypair)?;
	///
	/// // Generate a proof
	/// let valid_proof = sensitive_attr.to_proof(&account.keypair)?;
	/// # let hash = valid_proof.hash.clone();
	/// // Validate the proof
	/// let result = sensitive_attr.validate_proof(&account.keypair, valid_proof)?;
	/// assert!(result);
	///
	/// // Create an invalid proof with wrong data
	/// let invalid_proof = SensitiveAttributeProof {
	///     value: "wrong-data".to_string().into_secret(),
	///     hash,
	/// };
	/// // Invalid proof should fail validation
	/// let result = sensitive_attr.validate_proof(&account.keypair, invalid_proof);
	/// assert!(result.is_err());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn validate_proof<T>(&self, keypair: &T, proof: SensitiveAttributeProof) -> Result<bool>
	where
		T: KeyPair,
	{
		// Decode the proof values
		let base64_value = proof.value.expose_secret();
		let plaintext_value = base64_decode(base64_value).map_err(|_| SensitiveAttributeError::InvalidProof)?;
		let proof_salt = base64_decode(&proof.hash.salt).map_err(|_| SensitiveAttributeError::InvalidProof)?;
		// Get the public key bytes
		let public_key = keypair.to_public_key();
		let public_key_bytes = public_key.as_ref();
		// Create hash input using utility function
		let hash_input = create_hash_input(&proof_salt, public_key_bytes, &self.encrypted_value, &plaintext_value);

		// Hash the concatenated data and compare
		let computed_hash = HashAlgorithm::Sha2_256.hash(&hash_input);
		Ok(computed_hash.as_slice() == self.hashed_value.value.as_ref())
	}

	/// Convert the sensitive attribute to DER format.
	///
	/// This is a convenience method for encoding the attribute.
	///
	/// # Returns
	///
	/// - `Ok(_)` with the DER-encoded bytes of this sensitive attribute
	/// - `Err(_)` if encoding fails
	///
	/// # Example
	///
	/// ```rust
	/// # use anchor_rs::doc_utils;
	/// use anchor_rs::sensitive_attributes::{
	///     SensitiveAttribute,
	///     SensitiveAttributeBuilder
	/// };
	/// use crypto::prelude::ExposeSecret;
	///
	/// let account = doc_utils::create_secp256k1_test_account(None);
	/// let data = b"data-to-be-serialized";
	///
	/// // Create an encrypted sensitive attribute
	/// let sensitive_attr = SensitiveAttributeBuilder::new()
	///     .with_value(data)
	///     .build(&account.keypair)?;
	///
	/// // Convert to DER format for storage or transmission
	/// let der_bytes = sensitive_attr.to_der()?;
	/// // The DER bytes can be stored and later decoded
	/// let decoded_attr = SensitiveAttribute::try_from(der_bytes)?;
	///
	/// // Verify the round-trip worked
	/// let decrypted = decoded_attr.decrypt(&account.keypair)?;
	/// assert_eq!(decrypted.expose_secret(), data);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn to_der(&self) -> Result<Vec<u8>> {
		self.try_into()
	}
}

impl TryFrom<&SensitiveAttribute> for Vec<u8> {
	type Error = SensitiveAttributeError;

	fn try_from(attr: &SensitiveAttribute) -> std::result::Result<Self, Self::Error> {
		Ok(rasn::der::encode(attr)?)
	}
}

impl TryFrom<SensitiveAttribute> for Vec<u8> {
	type Error = SensitiveAttributeError;

	fn try_from(attr: SensitiveAttribute) -> std::result::Result<Self, Self::Error> {
		(&attr).try_into()
	}
}

impl TryFrom<&[u8]> for SensitiveAttribute {
	type Error = SensitiveAttributeError;

	fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
		Ok(rasn::der::decode(bytes)?)
	}
}

impl TryFrom<Vec<u8>> for SensitiveAttribute {
	type Error = SensitiveAttributeError;

	fn try_from(bytes: Vec<u8>) -> std::result::Result<Self, Self::Error> {
		(&bytes[..]).try_into()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::oids;
	use crate::test_all_key_types;
	use crate::testing::{create_test_sensitive_attribute, create_test_sensitive_attribute_with_proof};

	#[test]
	fn test_certificate_attribute_name_oid() {
		let full_name_oid: ObjectIdentifier = SensitiveAttributeName::FullName.into();
		let email_oid: ObjectIdentifier = SensitiveAttributeName::Email.into();
		assert_eq!(full_name_oid, rasn::oid!("1.3.6.1.4.1.62675.1.0"));
		assert_eq!(email_oid, rasn::oid!("1.3.6.1.4.1.62675.1.3"));
	}

	#[test]
	fn test_certificate_attribute_name_conversion() {
		let test_cases = [
			(SensitiveAttributeName::FullName, oids::keeta::FULL_NAME),
			(SensitiveAttributeName::DateOfBirth, oids::keeta::DATE_OF_BIRTH),
			(SensitiveAttributeName::Address, oids::keeta::ADDRESS),
			(SensitiveAttributeName::Email, oids::keeta::EMAIL),
			(SensitiveAttributeName::PhoneNumber, oids::keeta::PHONE_NUMBER),
		];

		for (attr_name, expected_oid) in test_cases {
			let oid = ObjectIdentifier::from(attr_name);
			assert_eq!(oid, expected_oid);
			let oid2: ObjectIdentifier = attr_name.into();
			assert_eq!(oid2, expected_oid);
		}
	}

	test_all_key_types!(test_sensitive_attribute_decrypt, |account: accounts::Account<_>| {
		let test_value = b"test value for decryption";
		let sensitive_attr = create_test_sensitive_attribute(&account, test_value);
		let decrypted = sensitive_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted.expose_secret(), test_value);
	});

	test_all_key_types!(test_sensitive_attribute_decrypt_string, |account: accounts::Account<_>| {
		let test_string = "Hello, world! 🦀";
		let sensitive_attr = create_test_sensitive_attribute(&account, test_string.as_bytes());
		let decrypted_string = sensitive_attr.decrypt_as_string(&account.keypair).unwrap();
		assert_eq!(decrypted_string, test_string);
	});

	test_all_key_types!(test_sensitive_attribute_prove, |account: accounts::Account<_>| {
		let test_value = b"test value for proof";
		let (_, proof) = create_test_sensitive_attribute_with_proof(&account, test_value);
		assert!(!proof.value.expose_secret().is_empty());
		assert!(!proof.hash.salt.is_empty());

		let decoded_value = base64_decode(proof.value.expose_secret()).unwrap();
		assert_eq!(decoded_value, test_value);
	});

	test_all_key_types!(test_sensitive_attribute_validate_proof, |account: accounts::Account<_>| {
		let test_value = b"test value for validation";
		let (sensitive_attr, proof) = create_test_sensitive_attribute_with_proof(&account, test_value);
		let salt = proof.hash.salt.clone();

		// Validate the valid proof
		assert!(sensitive_attr
			.validate_proof(&account.keypair, proof)
			.unwrap());

		// Test with invalid proof (wrong value)
		let invalid_proof = SensitiveAttributeProof {
			value: base64_encode(b"wrong value").into_secret(),
			hash: SensitiveAttributeProofHash { salt },
		};
		assert!(!sensitive_attr
			.validate_proof(&account.keypair, invalid_proof)
			.unwrap());

		// Test with invalid proof (wrong salt)
		let invalid_proof_salt = SensitiveAttributeProof {
			value: base64_encode(b"wrong value").into_secret(),
			hash: SensitiveAttributeProofHash::from(b"wrong salt that is 32 bytes long!!".to_vec()),
		};
		assert!(!sensitive_attr
			.validate_proof(&account.keypair, invalid_proof_salt)
			.unwrap());
	});

	test_all_key_types!(test_sensitive_attribute_proof_partial_eq, |account: accounts::Account<_>| {
		let test_value = b"test value for equality";
		let sensitive_attr = create_test_sensitive_attribute(&account, test_value);

		// Test PartialEq trait - proofs should be equal based on hash field only
		let proof1 = sensitive_attr.to_proof(&account.keypair).unwrap();
		let proof2 = sensitive_attr.to_proof(&account.keypair).unwrap();
		assert_eq!(proof1, proof2);
		assert_eq!(proof1.hash, proof2.hash);

		// Create a different sensitive attribute with different value
		// Different sensitive attributes should produce different proofs
		let sensitive_attr2 = create_test_sensitive_attribute(&account, b"different value");
		let proof3 = sensitive_attr2.to_proof(&account.keypair).unwrap();
		assert_ne!(proof1, proof3);
		assert_ne!(proof1.hash, proof3.hash);
	});

	test_all_key_types!(test_sensitive_attribute_to_der, |account: accounts::Account<_>| {
		let test_value = b"test value for DER encoding";
		let sensitive_attr = create_test_sensitive_attribute(&account, test_value);

		// Test object to vec
		let der_bytes = Vec::<u8>::try_from(sensitive_attr.clone());
		assert!(der_bytes.is_ok());
		assert!(!der_bytes.unwrap().is_empty());

		// Test to_der method
		let der_bytes = sensitive_attr.to_der().unwrap();
		assert!(!der_bytes.is_empty());

		// DER encoding should be deterministic
		let der_bytes2 = sensitive_attr.to_der().unwrap();
		assert_eq!(der_bytes, der_bytes2);

		// Test round-trip: decode the DER bytes back to SensitiveAttribute
		let decoded_attr = SensitiveAttribute::try_from(der_bytes).unwrap();
		// Verify the decoded attribute has the same functionality
		let decrypted_original = sensitive_attr.decrypt(&account.keypair).unwrap();
		let decrypted_roundtrip = decoded_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_original.expose_secret(), decrypted_roundtrip.expose_secret());
		assert_eq!(decrypted_roundtrip.expose_secret(), test_value);
	});
}

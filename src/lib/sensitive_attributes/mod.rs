pub mod error;
pub mod utils;

use accounts::KeyPair;
use crypto::algorithms::aes_gcm::Aes256Gcm;
use crypto::generate_random_seed;
use crypto::operations::encryption::{Aead, NonceGeneration};
use crypto::prelude::{ExposeSecret, HashAlgorithm, SecretBox};
use rasn::prelude::*;
use strum::AsRefStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_json::Value;

use crate::asn1::*;
use crate::generated::{SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue};
use crate::sensitive_attributes::error::SensitiveAttributeError;
use crate::sensitive_attributes::utils::{create_hash_input, setup_cipher_for_decryption, validate_version};
use crate::utils::{base64_decode, base64_encode};

#[cfg(feature = "serde")]
use crate::asn1::utils::get_algorithm_by_oid;
#[cfg(feature = "serde")]
use crate::utils::serde_helpers;

/// Result type for certificate operations
pub type Result<T> = std::result::Result<T, SensitiveAttributeError>;
/// Sensitive attribute value type
pub type SensitiveAttributeValue = SecretBox<Vec<u8>>;

/// Certificate attribute names
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
			SensitiveAttributeName::FullName => FULL_NAME_OID,
			SensitiveAttributeName::DateOfBirth => DATE_OF_BIRTH_OID,
			SensitiveAttributeName::Address => ADDRESS_OID,
			SensitiveAttributeName::Email => EMAIL_OID,
			SensitiveAttributeName::PhoneNumber => PHONE_NUMBER_OID,
		}
	}
}

/// Hash structure for sensitive attribute proof.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SensitiveAttributeProof {
	pub value: String,
	pub hash: SensitiveAttributeProofHash,
}

impl SensitiveAttribute {
	/// Decrypt the sensitive attribute value using the provided keypair
	pub fn decrypt<T>(&self, keypair: &T) -> Result<SensitiveAttributeValue>
	where
		T: KeyPair,
	{
		// Validate version and keypair capabilities
		validate_version(&self.version)?;

		if !keypair.supports_encryption() {
			return Err(SensitiveAttributeError::UnsupportedKeyType);
		}

		// Set up cipher for decryption
		let (cipher, nonce) = setup_cipher_for_decryption(keypair, &self.cipher)?;

		// Decrypt the value
		let decrypted_value = cipher.decrypt(&nonce, self.encrypted_value.as_ref())?;
		Ok(SecretBox::new(Box::new(decrypted_value)))
	}

	/// Decrypt the sensitive attribute value and return it as a UTF-8 string.
	pub fn decrypt_as_string<T>(&self, keypair: &T) -> Result<String>
	where
		T: KeyPair,
	{
		let decrypted_value = self.decrypt(keypair)?;
		let bytes = decrypted_value.expose_secret();

		Ok(String::from_utf8(bytes.clone())?)
	}

	/// Generate a proof that can be used to validate the sensitive attribute value
	pub fn to_proof<T>(&self, keypair: &T) -> Result<SensitiveAttributeProof>
	where
		T: KeyPair,
	{
		// Decrypt the value
		let decrypted_value = self.decrypt(keypair)?;
		// Set up cipher for decrypting salt
		let (cipher, nonce) = setup_cipher_for_decryption(keypair, &self.cipher)?;
		let decrypted_salt = cipher.decrypt(&nonce, self.hashed_value.encrypted_salt.as_ref())?;

		Ok(SensitiveAttributeProof {
			value: base64_encode(decrypted_value.expose_secret()),
			hash: SensitiveAttributeProofHash::from(decrypted_salt),
		})
	}

	/// Validate a proof against this sensitive attribute
	/// Returns true if the proof is valid, false otherwise
	pub fn validate_proof<T>(&self, keypair: &T, proof: &SensitiveAttributeProof) -> Result<bool>
	where
		T: KeyPair,
	{
		// Decode the proof values
		let plaintext_value = base64_decode(&proof.value).map_err(|_| SensitiveAttributeError::InvalidProof)?;
		let proof_salt = base64_decode(&proof.hash.salt).map_err(|_| SensitiveAttributeError::InvalidProof)?;
		// Get the public key bytes
		let public_key = keypair.to_public_key_string().into_bytes();
		// Create hash input using utility function
		let hash_input = create_hash_input(&proof_salt, &public_key, &self.encrypted_value, &plaintext_value);

		// Hash the concatenated data and compare
		let computed_hash = HashAlgorithm::Sha2_256.hash(&hash_input);
		Ok(computed_hash.as_slice() == self.hashed_value.value.as_ref())
	}
}

#[cfg(feature = "serde")]
impl Serialize for SensitiveAttribute {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::{Error, SerializeStruct};

		// Convert version from Integer to u64
		let version: u64 = self
			.version
			.clone()
			.try_into()
			.map_err(|_| S::Error::custom("Invalid version"))?;

		// Lookup algorithm names from OIDs
		let cipher_algorithm = get_algorithm_by_oid(&self.cipher.algorithm)
			.map(|s| s.to_string())
			.unwrap_or_else(|_| self.cipher.algorithm.to_string());
		let hash_algorithm = get_algorithm_by_oid(&self.hashed_value.algorithm)
			.map(|s| s.to_string())
			.unwrap_or_else(|_| self.hashed_value.algorithm.to_string());

		let mut state = serializer.serialize_struct("SensitiveAttribute", 4)?;
		state.serialize_field("version", &version)?;

		// Serialize cipher using helper macro
		let cipher_obj = serde_helpers::json_object! {
			"algorithm" => cipher_algorithm,
			"iv" => base64_encode(&self.cipher.iv_or_nonce),
			"key" => base64_encode(&self.cipher.key)
		};
		state.serialize_field("cipher", &cipher_obj)?;

		// Serialize hashedValue using helper macro
		let hashed_value_obj = serde_helpers::json_object! {
			"encryptedSalt" => base64_encode(&self.hashed_value.encrypted_salt),
			"algorithm" => hash_algorithm,
			"value" => base64_encode(&self.hashed_value.value)
		};

		state.serialize_field("hashedValue", &hashed_value_obj)?;
		state.serialize_field("encryptedValue", &base64_encode(&self.encrypted_value))?;

		state.end()
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SensitiveAttribute {
	fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;

		let value: Value = Value::deserialize(deserializer)?;
		let obj = value
			.as_object()
			.ok_or_else(|| D::Error::custom("Expected object"))?;

		// Extract version
		let version_u64 = obj
			.get("version")
			.and_then(|v| v.as_u64())
			.ok_or_else(|| D::Error::custom("Missing or invalid version"))?;
		let version: Integer = version_u64.into();

		// Extract cipher
		let cipher_obj = serde_helpers::extract_object(obj, "cipher")?;
		let cipher_algorithm_name = serde_helpers::extract_string(cipher_obj, "algorithm")?;
		let cipher_algorithm = serde_helpers::algorithm_to_oid(cipher_algorithm_name)?;
		let iv_bytes = serde_helpers::extract_base64(cipher_obj, "iv")?;
		let key_bytes = serde_helpers::extract_base64(cipher_obj, "key")?;
		let cipher = SensitiveAttributeCipher::new(cipher_algorithm, iv_bytes.into(), key_bytes.into());

		// Extract hashedValue
		let hashed_value_obj = serde_helpers::extract_object(obj, "hashedValue")?;
		let hash_algorithm_name = serde_helpers::extract_string(hashed_value_obj, "algorithm")?;
		let hash_algorithm = serde_helpers::algorithm_to_oid(hash_algorithm_name)?;
		let encrypted_salt_bytes = serde_helpers::extract_base64(hashed_value_obj, "encryptedSalt")?;
		let hash_value_bytes = serde_helpers::extract_base64(hashed_value_obj, "value")?;
		let hashed_value =
			SensitiveAttributeHashedValue::new(encrypted_salt_bytes.into(), hash_algorithm, hash_value_bytes.into());

		// Extract encryptedValue
		let encrypted_value_bytes = serde_helpers::extract_base64(obj, "encryptedValue")?;

		// Construct the SensitiveAttribute
		Ok(SensitiveAttribute::new(version, cipher, hashed_value, encrypted_value_bytes.into()))
	}
}

/// Builder for creating SensitiveAttribute instances
#[derive(Default)]
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
		let public_key = keypair.to_public_key_string().into_bytes();

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
		let hash_input = create_hash_input(salt.as_slice(), &public_key, &encrypted_value, value);

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
	use crate::testing::*;

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
			(SensitiveAttributeName::FullName, FULL_NAME_OID),
			(SensitiveAttributeName::DateOfBirth, DATE_OF_BIRTH_OID),
			(SensitiveAttributeName::Address, ADDRESS_OID),
			(SensitiveAttributeName::Email, EMAIL_OID),
			(SensitiveAttributeName::PhoneNumber, PHONE_NUMBER_OID),
		];

		for (attr_name, expected_oid) in test_cases {
			let oid = ObjectIdentifier::from(attr_name);
			assert_eq!(oid, expected_oid);
			let oid2: ObjectIdentifier = attr_name.into();
			assert_eq!(oid2, expected_oid);
		}
	}

	#[test]
	fn test_sensitive_attribute_builder_with_real_keypair() {
		// Create a real account using the test data
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let builder = SensitiveAttributeBuilder::new().with_value(b"test value");

		// This should now work and return a SensitiveAttribute - pass the keypair, not the account
		let result = builder.build(&account.keypair);
		assert!(result.is_ok());
	}

	#[test]
	fn test_builder_missing_value() {
		let builder = SensitiveAttributeBuilder::new();
		assert!(builder.value.is_none());
	}

	#[test]
	fn test_sensitive_attribute_decrypt() {
		// Create a real account using the test data
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for decryption";

		// Build the sensitive attribute
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let sensitive_attr = builder.build(&account.keypair).unwrap();

		// Decrypt and verify
		let decrypted = sensitive_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted.expose_secret(), test_value);
	}

	#[test]
	fn test_sensitive_attribute_decrypt_string() {
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		// Create a test string with special characters
		let test_string = "Hello, world! 🦀";

		// Build the sensitive attribute with a UTF-8 string
		let builder = SensitiveAttributeBuilder::new().with_value(test_string.as_bytes());
		let sensitive_attr = builder.build(&account.keypair).unwrap();

		// Decrypt as string and verify
		let decrypted_string = sensitive_attr.decrypt_as_string(&account.keypair).unwrap();
		assert_eq!(decrypted_string, test_string);
	}

	#[test]
	fn test_sensitive_attribute_prove() {
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for proof";

		// Build the sensitive attribute
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let sensitive_attr = builder.build(&account.keypair).unwrap();

		// Generate proof
		// Verify proof contains base64 encoded data
		let proof = sensitive_attr.to_proof(&account.keypair).unwrap();
		assert!(!proof.value.is_empty());
		assert!(!proof.hash.salt.is_empty());

		// Decode and verify the value matches
		let decoded_value = base64_decode(&proof.value).unwrap();
		assert_eq!(decoded_value, test_value);
	}

	#[test]
	fn test_sensitive_attribute_validate_proof() {
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for validation";

		// Build the sensitive attribute
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let sensitive_attr = builder.build(&account.keypair).unwrap();

		// Generate a valid proof
		let proof = sensitive_attr.to_proof(&account.keypair).unwrap();

		// Validate the proof
		let is_valid = sensitive_attr.validate_proof(&account.keypair, &proof);
		assert!(is_valid.unwrap());

		// Test with invalid proof (wrong value)
		let invalid_proof = SensitiveAttributeProof {
			value: base64_encode(b"wrong value"),
			hash: SensitiveAttributeProofHash { salt: proof.hash.salt.clone() },
		};
		let is_invalid = sensitive_attr.validate_proof(&account.keypair, &invalid_proof);
		assert!(!is_invalid.unwrap());

		// Test with invalid proof (wrong salt)
		let invalid_proof_salt = SensitiveAttributeProof {
			value: proof.value.clone(),
			hash: SensitiveAttributeProofHash::from(b"wrong salt that is 32 bytes long!!".to_vec()),
		};
		let is_invalid_salt = sensitive_attr.validate_proof(&account.keypair, &invalid_proof_salt);
		assert!(!is_invalid_salt.unwrap());
	}

	#[test]
	#[cfg(feature = "serde")]
	fn test_sensitive_attribute_serialize() {
		// Create a real account using the test data
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for serialization";

		// Build the sensitive attribute
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let sensitive_attr = builder.build(&account.keypair).unwrap();

		// Serialize to JSON
		let json_result = serde_json::to_string_pretty(&sensitive_attr);
		assert!(json_result.is_ok());

		// Verify it contains expected fields
		let json_str = json_result.unwrap();
		assert!(json_str.contains("version"));
		assert!(json_str.contains("cipher"));
		assert!(json_str.contains("hashedValue"));
		assert!(json_str.contains("encryptedValue"));
	}

	#[test]
	#[cfg(feature = "serde")]
	fn test_sensitive_attribute_roundtrip() {
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for roundtrip";

		// Build the original sensitive attribute
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let original_attr = builder.build(&account.keypair).unwrap();

		// Serialize to JSON
		let json_str = serde_json::to_string(&original_attr).unwrap();
		// Deserialize back
		let deserialized_attr: SensitiveAttribute = serde_json::from_str(&json_str).unwrap();

		// Verify the deserialized version can decrypt the same value
		let decrypted_original = original_attr.decrypt(&account.keypair).unwrap();
		let decrypted_deserialized = deserialized_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_original.expose_secret(), decrypted_deserialized.expose_secret());
		assert_eq!(decrypted_original.expose_secret(), test_value);

		// Verify they produce the same proof
		let proof_original = original_attr.to_proof(&account.keypair).unwrap();
		let proof_deserialized = deserialized_attr.to_proof(&account.keypair).unwrap();
		assert_eq!(proof_original.value, proof_deserialized.value);
		assert_eq!(proof_original.hash.salt, proof_deserialized.hash.salt);
	}
}

pub mod builder;
pub mod error;
pub mod utils;

#[cfg(feature = "serde")]
pub mod serde;

use std::hash::{Hash, Hasher};

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
use crate::sensitive_attributes::utils::{create_hash_input, setup_cipher_for_decryption, validate_version};
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

impl Clone for SensitiveAttributeProof {
	fn clone(&self) -> Self {
		let value = self.value.expose_secret().to_string().into_secret();
		let hash = self.hash.clone();

		SensitiveAttributeProof { value, hash }
	}
}

impl Hash for SensitiveAttributeProof {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.hash.hash(state);
	}
}

impl PartialEq for SensitiveAttributeProof {
	fn eq(&self, other: &Self) -> bool {
		self.hash == other.hash
	}
}

// Note: You cannot derive this
impl Eq for SensitiveAttributeProof {}

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
		Ok(decrypted_value.into_secret())
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
		let base64_value = base64_encode(decrypted_value.expose_secret());

		Ok(SensitiveAttributeProof {
			value: base64_value.into_secret(),
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

	/// Convert the sensitive attribute to DER format
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

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use super::*;
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

		// Validate the valid proof
		assert!(sensitive_attr
			.validate_proof(&account.keypair, &proof)
			.unwrap());

		// Test with invalid proof (wrong value)
		let invalid_proof = SensitiveAttributeProof {
			value: base64_encode(b"wrong value").into_secret(),
			hash: SensitiveAttributeProofHash { salt: proof.hash.salt.clone() },
		};
		assert!(!sensitive_attr
			.validate_proof(&account.keypair, &invalid_proof)
			.unwrap());

		// Test with invalid proof (wrong salt)
		let invalid_proof_salt = SensitiveAttributeProof {
			value: base64_encode(b"wrong value").into_secret(),
			hash: SensitiveAttributeProofHash::from(b"wrong salt that is 32 bytes long!!".to_vec()),
		};
		assert!(!sensitive_attr
			.validate_proof(&account.keypair, &invalid_proof_salt)
			.unwrap());
	});

	test_all_key_types!(test_sensitive_attribute_proof_hash, |account: accounts::Account<_>| {
		let test_value = b"test value for hash";
		let sensitive_attr = create_test_sensitive_attribute(&account, test_value);

		let proof1 = sensitive_attr.to_proof(&account.keypair).unwrap();
		let proof2 = sensitive_attr.to_proof(&account.keypair).unwrap();

		// Both proofs should have the same hash since they have the same salt
		let mut map = HashMap::new();
		map.insert(proof1.clone(), "first");
		map.insert(proof2.clone(), "second");

		// Since the salts are the same, the hash should be the same
		assert_eq!(map.len(), 1);
		assert!(map.contains_key(&proof1));
		assert!(map.contains_key(&proof2));
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

	test_all_key_types!(test_sensitive_attribute_proof_clone, |account: accounts::Account<_>| {
		let test_value = b"test value for clone";
		let (sensitive_attr, original_proof) = create_test_sensitive_attribute_with_proof(&account, test_value);

		// Verify cloned proof is equal
		let cloned_proof = original_proof.clone();
		assert_eq!(original_proof, cloned_proof);
		assert_eq!(original_proof.value.expose_secret(), cloned_proof.value.expose_secret());
		assert_eq!(original_proof.hash, cloned_proof.hash);

		// Both proofs should validate
		assert!(sensitive_attr
			.validate_proof(&account.keypair, &original_proof)
			.unwrap());
		assert!(sensitive_attr
			.validate_proof(&account.keypair, &cloned_proof)
			.unwrap());
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
		let decoded_attr: SensitiveAttribute = rasn::der::decode(&der_bytes).unwrap();
		// Verify the decoded attribute has the same functionality
		let decrypted_original = sensitive_attr.decrypt(&account.keypair).unwrap();
		let decrypted_roundtrip = decoded_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_original.expose_secret(), decrypted_roundtrip.expose_secret());
		assert_eq!(decrypted_roundtrip.expose_secret(), test_value);
	});
}

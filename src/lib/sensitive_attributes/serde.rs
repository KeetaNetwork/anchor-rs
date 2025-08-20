//! Serde JSON encoding functionality.

pub(crate) use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub(crate) use serde_json::Value;

use accounts::IntoSecret;
use crypto::ExposeSecret;
use rasn::types::Integer;
use serde::ser::SerializeStruct;

use crate::asn1::utils::get_algorithm_by_oid;
use crate::sensitive_attributes::{
	SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue, SensitiveAttributeProof,
	SensitiveAttributeProofHash,
};
use crate::utils::{base64_encode, serde_helpers};

impl Serialize for SensitiveAttributeProof {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let mut state = serializer.serialize_struct("SensitiveAttributeProof", 2)?;
		state.serialize_field("value", self.value.expose_secret())?;
		state.serialize_field("hash", &self.hash)?;

		state.end()
	}
}

impl<'de> Deserialize<'de> for SensitiveAttributeProof {
	fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct SensitiveAttributeProofHelper {
			value: String,
			hash: SensitiveAttributeProofHash,
		}

		let helper = SensitiveAttributeProofHelper::deserialize(deserializer)?;
		let value = helper.value.into_secret();
		let hash = helper.hash;

		Ok(SensitiveAttributeProof { value, hash })
	}
}

impl Serialize for SensitiveAttribute {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;

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
		let algorithm = serde_helpers::algorithm_to_oid(hash_algorithm_name)?;
		let salt_bytes = serde_helpers::extract_base64(hashed_value_obj, "encryptedSalt")?;
		let hash_bytes = serde_helpers::extract_base64(hashed_value_obj, "value")?;
		let hashed_value = SensitiveAttributeHashedValue::new(salt_bytes.into(), algorithm, hash_bytes.into());
		// Extract encryptedValue
		let value_bytes = serde_helpers::extract_base64(obj, "encryptedValue")?;

		// Construct the SensitiveAttribute
		Ok(SensitiveAttribute::new(version, cipher, hashed_value, value_bytes.into()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sensitive_attributes::SensitiveAttributeBuilder;
	use crate::test_all_key_types;
	use crate::testing::{create_account_from_seed, create_test_sensitive_attribute};

	#[test]
	fn test_sensitive_attribute_serialize() {
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for serialization";
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let sensitive_attr = builder.build(&account.keypair).unwrap();

		let json_result = serde_json::to_string_pretty(&sensitive_attr);
		assert!(json_result.is_ok());

		let json_str = json_result.unwrap();
		assert!(json_str.contains("version"));
		assert!(json_str.contains("cipher"));
		assert!(json_str.contains("hashedValue"));
		assert!(json_str.contains("encryptedValue"));
	}

	#[test]
	fn test_sensitive_attribute_proof_serde() {
		let account = create_account_from_seed::<accounts::KeyECDSASECP256K1>(0);
		let test_value = b"test value for proof serde";
		let builder = SensitiveAttributeBuilder::new().with_value(test_value);
		let sensitive_attr = builder.build(&account.keypair).unwrap();
		let original_proof = sensitive_attr.to_proof(&account.keypair).unwrap();

		// Test serialization
		let json_str = serde_json::to_string(&original_proof).unwrap();
		assert!(json_str.contains("value"));
		assert!(json_str.contains("hash"));
		assert!(json_str.contains("salt"));
		assert!(json_str.contains(&base64_encode(test_value)));

		// Test deserialization
		let deserialized_proof: SensitiveAttributeProof = serde_json::from_str(&json_str).unwrap();

		// Test roundtrip equivalence
		assert_eq!(original_proof.value.expose_secret(), deserialized_proof.value.expose_secret());
		assert_eq!(original_proof.hash, deserialized_proof.hash);
		assert_eq!(original_proof, deserialized_proof);

		// Both proofs should validate
		assert!(sensitive_attr
			.validate_proof(&account.keypair, &original_proof)
			.unwrap());
		assert!(sensitive_attr
			.validate_proof(&account.keypair, &deserialized_proof)
			.unwrap());

		// Serialize the deserialized proof again - should be identical
		let json_str2 = serde_json::to_string(&deserialized_proof).unwrap();
		assert_eq!(json_str, json_str2);
	}

	test_all_key_types!(test_sensitive_attribute_roundtrip, |account: accounts::Account<_>| {
		let test_value = b"test value for roundtrip";
		let original_attr = create_test_sensitive_attribute(&account, test_value);

		// Serialize and deserialize
		let json_str = serde_json::to_string(&original_attr).unwrap();
		let deserialized_attr: SensitiveAttribute = serde_json::from_str(&json_str).unwrap();

		// Verify decryption equivalence
		let decrypted_original = original_attr.decrypt(&account.keypair).unwrap();
		let decrypted_deserialized = deserialized_attr.decrypt(&account.keypair).unwrap();
		assert_eq!(decrypted_original.expose_secret(), decrypted_deserialized.expose_secret());
		assert_eq!(decrypted_original.expose_secret(), test_value);

		// Verify proof equivalence
		let proof_original = original_attr.to_proof(&account.keypair).unwrap();
		let proof_deserialized = deserialized_attr.to_proof(&account.keypair).unwrap();
		assert_eq!(proof_original.value.expose_secret(), proof_deserialized.value.expose_secret());
		assert_eq!(proof_original.hash.salt, proof_deserialized.hash.salt);
	});
}

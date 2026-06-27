use base64::Engine;
use keetanetwork_account::{
	Account, AccountError, Accountable, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair,
};
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret};

use keetanetwork_anchor::generated::SensitiveAttribute;
use keetanetwork_anchor::sensitive_attributes::{
	SensitiveAttributeBuilder, SensitiveAttributeProof, SensitiveAttributeProofHash,
};
use keetanetwork_anchor::testing::*;

mod common;
use common::TestAccounts;

const TEST_VALUE: &str = "Test Value";
const EXPECTED_BYTES: &[u8] = &[0x54, 0x65, 0x73, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65];

/// Simplified test scenario using common test helpers
struct SensitiveAttributeTestScenario<T: KeyPair>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	accounts: TestAccounts<T>,
	sensitive_attr: SensitiveAttribute,
	valid_proof: SensitiveAttributeProof,
	test_value: String,
	expected_bytes: Vec<u8>,
}

impl<T: KeyPair> SensitiveAttributeTestScenario<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	/// Create a test scenario using standard test data
	fn new() -> Self {
		Self::with_value(TEST_VALUE)
	}

	/// Create a test scenario with custom test value
	fn with_value<S: Into<String>>(value: S) -> Self {
		let test_value = value.into();
		let expected_bytes = test_value.as_bytes().to_vec();
		let accounts = TestAccounts::new();

		let builder = SensitiveAttributeBuilder::new().with_value(expected_bytes.clone());
		let sensitive_attr = builder.build(&accounts.subject.keypair).unwrap();
		let valid_proof = sensitive_attr.to_proof(&accounts.subject.keypair).unwrap();

		Self { accounts, sensitive_attr, valid_proof, test_value, expected_bytes }
	}

	/// Create a test scenario with custom seeds
	fn with_seeds(primary_seed: u32, wrong_seed: u32) -> Self {
		let test_value = TEST_VALUE.to_string();
		let expected_bytes = test_value.as_bytes().to_vec();
		let accounts = TestAccounts::with_seeds(primary_seed, wrong_seed);

		let builder = SensitiveAttributeBuilder::new().with_value(expected_bytes.clone());
		let sensitive_attr = builder.build(&accounts.subject.keypair).unwrap();
		let valid_proof = sensitive_attr.to_proof(&accounts.subject.keypair).unwrap();

		Self { accounts, sensitive_attr, valid_proof, test_value, expected_bytes }
	}

	/// Create a test scenario with specific account
	fn with_account(account: Account<T>) -> Self {
		let test_value = TEST_VALUE.to_string();
		let expected_bytes = test_value.as_bytes().to_vec();

		// Create accounts using the provided account as subject
		let wrong_account = create_account_from_seed::<T>(999);
		let subject_public_only = create_public_key_only_account::<T>(&account);
		let accounts = TestAccounts {
			issuer: create_account_from_seed::<T>(0),
			subject: account,
			subject_public_only,
			wrong_account,
		};

		let builder = SensitiveAttributeBuilder::new().with_value(expected_bytes.clone());
		let sensitive_attr = builder.build(&accounts.subject.keypair).unwrap();
		let valid_proof = sensitive_attr.to_proof(&accounts.subject.keypair).unwrap();

		Self { accounts, sensitive_attr, valid_proof, test_value, expected_bytes }
	}

	/// Generate a new proof (since we can't clone the existing one)
	fn generate_proof(&self) -> SensitiveAttributeProof {
		self.sensitive_attr
			.to_proof(&self.accounts.subject.keypair)
			.unwrap()
	}

	/// Create an invalid proof with wrong value
	fn create_invalid_value_proof(&self) -> SensitiveAttributeProof {
		let base64_value = base64::prelude::BASE64_STANDARD.encode("Wrong Value");
		SensitiveAttributeProof { value: base64_value.into_secret(), hash: self.valid_proof.hash.clone() }
	}

	/// Create an invalid proof with wrong salt
	fn create_invalid_salt_proof(&self) -> SensitiveAttributeProof {
		let proof = self.generate_proof();
		SensitiveAttributeProof {
			value: proof.value,
			hash: SensitiveAttributeProofHash::from(b"wrong_salt_32_bytes_long_for_test".to_vec()),
		}
	}
}

fn test_basic_functionality<T: KeyPair>(
	scenario: &SensitiveAttributeTestScenario<T>,
) -> Result<(), Box<dyn std::error::Error>>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Test decryption with correct key
	let decrypted_value = scenario
		.sensitive_attr
		.decrypt(&scenario.accounts.subject.keypair)?;
	assert_eq!(decrypted_value.expose_secret(), &scenario.expected_bytes);

	// Test string decryption
	let decrypted_string = scenario
		.sensitive_attr
		.decrypt_as_string(&scenario.accounts.subject.keypair)?;
	assert_eq!(decrypted_string, scenario.test_value);

	// Verify proof contains expected base64 encoded value
	let proof_value = scenario.valid_proof.value.expose_secret();
	let decoded_proof_value = base64::prelude::BASE64_STANDARD.decode(proof_value)?;
	assert_eq!(decoded_proof_value, scenario.expected_bytes);

	// Verify salt length
	let decoded_salt = base64::prelude::BASE64_STANDARD.decode(&scenario.valid_proof.hash.salt)?;
	assert_eq!(decoded_salt.len(), 32, "Salt should be 32 bytes");

	Ok(())
}

fn test_proof_validation<T: KeyPair>(
	scenario: SensitiveAttributeTestScenario<T>,
) -> Result<(), Box<dyn std::error::Error>>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Valid proof should pass
	let validation_result = scenario
		.sensitive_attr
		.validate_proof(&scenario.accounts.subject.keypair, scenario.valid_proof)?;
	assert!(validation_result, "Valid proof should pass validation");

	Ok(())
}

fn test_failure_scenarios<T: KeyPair>(
	scenario: &SensitiveAttributeTestScenario<T>,
) -> Result<(), Box<dyn std::error::Error>>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Wrong private key for decryption
	let wrong_decrypt_result = scenario
		.sensitive_attr
		.decrypt(&scenario.accounts.wrong_account.keypair);
	assert!(wrong_decrypt_result.is_err(), "Wrong key should fail decryption");

	// Wrong private key for proof generation
	let wrong_proof_result = scenario
		.sensitive_attr
		.to_proof(&scenario.accounts.wrong_account.keypair);
	assert!(wrong_proof_result.is_err(), "Wrong key should fail proof generation");

	// Public key only account cannot decrypt or generate proofs
	let public_decrypt_result = scenario
		.sensitive_attr
		.decrypt(&scenario.accounts.subject_public_only.keypair);
	assert!(public_decrypt_result.is_err(), "Public key only account should not decrypt");

	let public_proof_result = scenario
		.sensitive_attr
		.to_proof(&scenario.accounts.subject_public_only.keypair);
	assert!(public_proof_result.is_err(), "Public key only account should not generate proofs");

	Ok(())
}

fn test_invalid_proofs<T: KeyPair>(
	scenario: &SensitiveAttributeTestScenario<T>,
) -> Result<(), Box<dyn std::error::Error>>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Invalid proof value
	let invalid_proof = scenario.create_invalid_value_proof();
	let invalid_validation = scenario
		.sensitive_attr
		.validate_proof(&scenario.accounts.subject.keypair, invalid_proof)?;
	assert!(!invalid_validation, "Invalid proof should fail validation");

	// Invalid proof salt
	let invalid_salt_proof = scenario.create_invalid_salt_proof();
	let invalid_salt_validation = scenario
		.sensitive_attr
		.validate_proof(&scenario.accounts.subject.keypair, invalid_salt_proof)?;
	assert!(!invalid_salt_validation, "Invalid salt should fail validation");

	// Wrong public key validation
	let valid_proof = scenario.generate_proof();
	let wrong_key_validation = scenario
		.sensitive_attr
		.validate_proof(&scenario.accounts.wrong_account.keypair, valid_proof)?;
	assert!(!wrong_key_validation, "Wrong public key should fail validation");

	Ok(())
}

fn test_basic_sensitive_attribute_functionality<T: KeyPair>(account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	let scenario = SensitiveAttributeTestScenario::with_account(account);
	assert!(test_basic_functionality(&scenario).is_ok());
	assert!(test_proof_validation(scenario).is_ok());

	let new_scenario = SensitiveAttributeTestScenario::<T>::new();
	assert!(test_failure_scenarios(&new_scenario).is_ok());
	assert!(test_invalid_proofs(&new_scenario).is_ok());
}

// Test basic sensitive attribute functionality across all key types
keetanetwork_anchor::test_all_key_types!(test_sensitive_attributes, test_basic_sensitive_attribute_functionality);

fn test_custom_values_functionality<T: KeyPair>(account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	let scenario_original = SensitiveAttributeTestScenario::with_account(account);
	assert!(test_basic_functionality(&scenario_original).is_ok());
	assert!(test_proof_validation(scenario_original).is_ok());

	// Verify the original test value produces expected bytes - create new scenario with same setup
	let scenario_verification = SensitiveAttributeTestScenario::<T>::new();
	let decrypted_value = scenario_verification
		.sensitive_attr
		.decrypt(&scenario_verification.accounts.subject.keypair)
		.expect("Decryption should succeed");
	assert_eq!(decrypted_value.expose_secret(), EXPECTED_BYTES);
	assert_eq!(scenario_verification.test_value, TEST_VALUE);

	// Test with custom value
	let scenario = SensitiveAttributeTestScenario::<T>::with_value("Custom Test Data");
	assert!(test_basic_functionality(&scenario).is_ok());
	assert!(test_proof_validation(scenario).is_ok());

	// Test with custom seeds
	let scenario_seeds = SensitiveAttributeTestScenario::<T>::with_seeds(42, 84);
	assert!(test_basic_functionality(&scenario_seeds).is_ok());
	assert!(test_proof_validation(scenario_seeds).is_ok());

	// Test failure scenarios with a standard scenario
	let scenario_failures = SensitiveAttributeTestScenario::<T>::new();
	assert!(test_failure_scenarios(&scenario_failures).is_ok());
}

// Test custom values and builder patterns across all key types
keetanetwork_anchor::test_all_key_types!(test_custom_values, test_custom_values_functionality);

// Macro to test builder flexibility across multiple key types
macro_rules! test_builder_across_key_types {
	($test_name:ident, $($key_type:ty => $value:expr, $primary_seed:expr, $wrong_seed:expr),+ $(,)?) => {
		#[test]
		fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			$(
				let scenario = SensitiveAttributeTestScenario::<$key_type>::with_value($value);
				assert!(test_basic_functionality(&scenario).is_ok());
				assert!(test_proof_validation(scenario).is_ok());

				let scenario_seeds = SensitiveAttributeTestScenario::<$key_type>::with_seeds($primary_seed, $wrong_seed);
				assert!(test_basic_functionality(&scenario_seeds).is_ok());
				assert!(test_proof_validation(scenario_seeds).is_ok());
			)+
			Ok(())
		}
	};
}

// Use the macro to test builder flexibility across key types
test_builder_across_key_types!(
	test_builder_flexibility_across_key_types,
	KeyECDSASECP256K1 => "SECP256K1 Custom Value", 10, 20,
	KeyECDSASECP256R1 => "SECP256R1 Custom Value", 30, 40,
	KeyED25519 => "ED25519 Custom Value", 50, 60,
	KeyECDSASECP256K1 => "Comprehensive SECP256K1", 100, 101,
	KeyECDSASECP256R1 => "Comprehensive SECP256R1", 102, 103,
);

#[cfg(feature = "serde")]
fn test_serialization_functionality<T: KeyPair>(account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	const TEST_VALUE: &str = "Test Value For Serialization";

	// Build a sensitive attribute
	let builder = SensitiveAttributeBuilder::new().with_value(TEST_VALUE.as_bytes());
	let original_attr = builder
		.build(&account.keypair)
		.expect("Failed to build sensitive attribute");

	// Serialize to JSON
	let json_str = serde_json::to_string(&original_attr).expect("Failed to serialize original attribute");
	assert!(!json_str.is_empty());

	// Parse JSON to validate structure
	let json_value: serde_json::Value = serde_json::from_str(&json_str).expect("Failed to parse JSON");
	// Verify all expected fields are present
	let obj = json_value.as_object().expect("JSON should be an object");
	assert!(obj.contains_key("version"), "JSON should contain 'version' field");
	assert!(obj.contains_key("cipher"), "JSON should contain 'cipher' field");
	assert!(obj.contains_key("hashedValue"), "JSON should contain 'hashedValue' field");
	assert!(obj.contains_key("encryptedValue"), "JSON should contain 'encryptedValue' field");

	// Note: TypeScript includes 'publicKey' field which we don't have in Rust
	// implementation. This is expected because the Rust SensitiveAttribute is
	// a pure ASN.1 structure without state of the original keypair, while
	// TypeScript stores the account reference
	assert!(!obj.contains_key("publicKey"), "Rust implementation should not include 'publicKey' field");

	// Verify JSON contains expected fields
	assert!(json_str.contains("version"));
	assert!(json_str.contains("cipher"));
	assert!(json_str.contains("hashedValue"));
	assert!(json_str.contains("encryptedValue"));

	// Deserialize back
	let deserialized_attr: SensitiveAttribute = serde_json::from_str(&json_str).expect("Failed to deserialize JSON");
	// Verify the deserialized version works the same
	let original_decrypted = original_attr
		.decrypt(&account.keypair)
		.expect("Failed to decrypt original attribute");
	let deserialized_decrypted = deserialized_attr
		.decrypt(&account.keypair)
		.expect("Failed to decrypt deserialized attribute");
	assert_eq!(original_decrypted.expose_secret(), deserialized_decrypted.expose_secret());

	// Verify they produce the same proof
	let original_proof = original_attr
		.to_proof(&account.keypair)
		.expect("Failed to create proof for original attribute");
	let deserialized_proof = deserialized_attr
		.to_proof(&account.keypair)
		.expect("Failed to create proof for deserialized attribute");
	assert_eq!(original_proof.value.expose_secret(), deserialized_proof.value.expose_secret());
	assert_eq!(original_proof.hash.salt, deserialized_proof.hash.salt);

	// Validate proof value can be decoded from base64
	let decoded_proof_value = base64::prelude::BASE64_STANDARD
		.decode(original_proof.value.expose_secret())
		.expect("Failed to decode proof value from base64");
	let proof_string = String::from_utf8(decoded_proof_value).expect("Failed to convert proof value to string");
	assert_eq!(proof_string, TEST_VALUE, "Proof value should match original when base64 decoded");
}

// Test serialization/deserialization if serde feature is enabled
#[cfg(feature = "serde")]
keetanetwork_anchor::test_all_key_types!(test_sensitive_attribute_serialization, test_serialization_functionality);

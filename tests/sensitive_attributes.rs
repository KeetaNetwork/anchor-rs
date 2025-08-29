use accounts::{Account, AccountError, Accountable, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair};
use base64::Engine;
use crypto::prelude::{ExposeSecret, IntoSecret};

use anchor_rs::generated::SensitiveAttribute;
use anchor_rs::sensitive_attributes::{
	SensitiveAttributeBuilder, SensitiveAttributeProof, SensitiveAttributeProofHash,
};
use anchor_rs::testing::*;

const TEST_VALUE: &str = "Test Value";
const EXPECTED_BYTES: &[u8] = &[0x54, 0x65, 0x73, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65];

// Test scenarios helper
struct TestScenario<T: KeyPair>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	primary_account: Account<T>,
	wrong_account: Account<T>,
	public_only_account: Account<T>,
	sensitive_attr: SensitiveAttribute,
	valid_proof: SensitiveAttributeProof,
	test_value: String,
	expected_bytes: Vec<u8>,
}

/// Builder for creating customized test scenarios
struct TestScenarioBuilder<T: KeyPair>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	primary_account: Option<Account<T>>,
	wrong_account: Option<Account<T>>,
	public_only_account: Option<Account<T>>,
	test_value: Option<String>,
	primary_seed: u32,
	wrong_seed: u32,
}

impl<T: KeyPair> TestScenarioBuilder<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	fn new() -> Self {
		Self {
			primary_account: None,
			wrong_account: None,
			public_only_account: None,
			test_value: None,
			primary_seed: 0,
			wrong_seed: 1,
		}
	}

	/// Set a custom primary account for testing
	fn with_primary_account(mut self, account: Account<T>) -> Self {
		self.primary_account = Some(account);
		self
	}

	/// Set a custom wrong account for negative testing
	fn with_wrong_account(mut self, account: Account<T>) -> Self {
		self.wrong_account = Some(account);
		self
	}

	/// Set custom test value to encrypt/decrypt
	fn with_test_value<S: Into<String>>(mut self, value: S) -> Self {
		self.test_value = Some(value.into());
		self
	}

	/// Set custom seed for primary account generation (default: 0)
	fn with_primary_seed(mut self, seed: u32) -> Self {
		self.primary_seed = seed;
		self
	}

	/// Set custom seed for wrong account generation (default: 1)
	fn with_wrong_seed(mut self, seed: u32) -> Self {
		self.wrong_seed = seed;
		self
	}

	/// Build the test scenario with the configured options
	fn build(self) -> TestScenario<T> {
		let test_value = self.test_value.unwrap_or_else(|| TEST_VALUE.to_string());
		let expected_bytes = test_value.as_bytes().to_vec();

		let primary_account = self
			.primary_account
			.unwrap_or_else(|| create_account_from_seed::<T>(self.primary_seed));
		let wrong_account = self
			.wrong_account
			.unwrap_or_else(|| create_account_from_seed::<T>(self.wrong_seed));
		let public_only_account = self
			.public_only_account
			.unwrap_or_else(|| create_public_key_only_account::<T>(&primary_account));

		let builder = SensitiveAttributeBuilder::new().with_value(expected_bytes.clone());
		let sensitive_attr = builder.build(&primary_account.keypair).unwrap();
		let valid_proof = sensitive_attr.to_proof(&primary_account.keypair).unwrap();

		TestScenario {
			primary_account,
			wrong_account,
			public_only_account,
			sensitive_attr,
			valid_proof,
			test_value,
			expected_bytes,
		}
	}
}

impl<T: KeyPair> TestScenario<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	/// Create a builder for customizing the test scenario
	fn builder() -> TestScenarioBuilder<T> {
		TestScenarioBuilder::new()
	}

	/// Create a test scenario with a custom test value
	fn with_value<S: Into<String>>(value: S) -> Self {
		TestScenarioBuilder::new().with_test_value(value).build()
	}

	/// Create a test scenario with custom seeds for account generation
	fn with_seeds(primary_seed: u32, wrong_seed: u32) -> Self {
		TestScenarioBuilder::new()
			.with_primary_seed(primary_seed)
			.with_wrong_seed(wrong_seed)
			.build()
	}

	/// Create a test scenario with a custom primary account
	fn with_account(account: Account<T>) -> Self {
		TestScenarioBuilder::new()
			.with_primary_account(account)
			.build()
	}

	/// Generate a new proof (since we can't clone the existing one)
	fn generate_proof(&self) -> SensitiveAttributeProof {
		self.sensitive_attr
			.to_proof(&self.primary_account.keypair)
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

// Test functions that use TestScenario as a data provider

fn test_basic_functionality<T: KeyPair>(scenario: &TestScenario<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Test decryption with correct key
	let decrypted_value = scenario
		.sensitive_attr
		.decrypt(&scenario.primary_account.keypair)
		.unwrap();
	assert_eq!(decrypted_value.expose_secret(), &scenario.expected_bytes);

	// Test string decryption
	let decrypted_string = scenario
		.sensitive_attr
		.decrypt_as_string(&scenario.primary_account.keypair)
		.unwrap();
	assert_eq!(decrypted_string, scenario.test_value);

	// Verify proof contains expected base64 encoded value
	let proof_value = scenario.valid_proof.value.expose_secret();
	let decoded_proof_value = base64::prelude::BASE64_STANDARD
		.decode(proof_value)
		.unwrap();
	assert_eq!(decoded_proof_value, scenario.expected_bytes);

	// Verify salt length
	let decoded_salt = base64::prelude::BASE64_STANDARD
		.decode(&scenario.valid_proof.hash.salt)
		.unwrap();
	assert_eq!(decoded_salt.len(), 32, "Salt should be 32 bytes");
}

fn test_proof_validation<T: KeyPair>(scenario: TestScenario<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Valid proof should pass
	let validation_result = scenario
		.sensitive_attr
		.validate_proof(&scenario.primary_account.keypair, scenario.valid_proof)
		.unwrap();
	assert!(validation_result, "Valid proof should pass validation");
}

fn test_failure_scenarios<T: KeyPair>(scenario: &TestScenario<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Wrong private key for decryption
	let wrong_decrypt_result = scenario
		.sensitive_attr
		.decrypt(&scenario.wrong_account.keypair);
	assert!(wrong_decrypt_result.is_err(), "Wrong key should fail decryption");

	// Wrong private key for proof generation
	let wrong_proof_result = scenario
		.sensitive_attr
		.to_proof(&scenario.wrong_account.keypair);
	assert!(wrong_proof_result.is_err(), "Wrong key should fail proof generation");

	// Public key only account cannot decrypt or generate proofs
	let public_decrypt_result = scenario
		.sensitive_attr
		.decrypt(&scenario.public_only_account.keypair);
	assert!(public_decrypt_result.is_err(), "Public key only account should not decrypt");

	let public_proof_result = scenario
		.sensitive_attr
		.to_proof(&scenario.public_only_account.keypair);
	assert!(public_proof_result.is_err(), "Public key only account should not generate proofs");
}

fn test_invalid_proofs<T: KeyPair>(scenario: &TestScenario<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Invalid proof value
	let invalid_proof = scenario.create_invalid_value_proof();
	let invalid_validation = scenario
		.sensitive_attr
		.validate_proof(&scenario.primary_account.keypair, invalid_proof)
		.unwrap();
	assert!(!invalid_validation, "Invalid proof should fail validation");

	// Invalid proof salt
	let invalid_salt_proof = scenario.create_invalid_salt_proof();
	let invalid_salt_validation = scenario
		.sensitive_attr
		.validate_proof(&scenario.primary_account.keypair, invalid_salt_proof)
		.unwrap();
	assert!(!invalid_salt_validation, "Invalid salt should fail validation");

	// Wrong public key validation
	let valid_proof = scenario.generate_proof();
	let wrong_key_validation = scenario
		.sensitive_attr
		.validate_proof(&scenario.wrong_account.keypair, valid_proof)
		.unwrap();
	assert!(!wrong_key_validation, "Wrong public key should fail validation");
}

fn test_basic_sensitive_attribute_functionality<T: KeyPair>(account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	let scenario = TestScenario::with_account(account);
	test_basic_functionality(&scenario);
	test_proof_validation(scenario);

	let new_account = create_account_from_seed::<T>(0);
	let scenario = TestScenario::with_account(new_account);
	test_failure_scenarios(&scenario);
	test_invalid_proofs(&scenario);
}

// Test basic sensitive attribute functionality across all key types
anchor_rs::test_all_key_types!(test_sensitive_attributes, test_basic_sensitive_attribute_functionality);

fn test_custom_values_functionality<T: KeyPair>(account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	let scenario_original = TestScenario::with_account(account);
	test_basic_functionality(&scenario_original);
	test_proof_validation(scenario_original);

	// Verify the original test value produces expected bytes - create new account with same seed
	let verification_account = create_account_from_seed::<T>(0);
	let scenario_original = TestScenario::with_account(verification_account);
	let decrypted_value = scenario_original
		.sensitive_attr
		.decrypt(&scenario_original.primary_account.keypair)
		.unwrap();
	assert_eq!(decrypted_value.expose_secret(), EXPECTED_BYTES);
	assert_eq!(scenario_original.test_value, TEST_VALUE);

	// Test with custom value
	let scenario = TestScenario::<T>::with_value("Custom Test Data");
	test_basic_functionality(&scenario);
	test_proof_validation(scenario);

	// Test with custom seeds
	let scenario_seeds = TestScenario::<T>::with_seeds(42, 84);
	test_basic_functionality(&scenario_seeds);
	test_proof_validation(scenario_seeds);

	// Test with builder pattern for maximum flexibility
	let wrong_account = create_account_from_seed::<T>(200);
	let scenario_builder = TestScenario::builder()
		.with_primary_account(create_account_from_seed::<T>(100))
		.with_wrong_account(wrong_account)
		.with_test_value("Advanced Custom Value")
		.build();
	test_basic_functionality(&scenario_builder);
	test_proof_validation(scenario_builder);

	let scenario_builder = TestScenario::builder()
		.with_primary_account(create_account_from_seed::<T>(100))
		.with_wrong_account(create_account_from_seed::<T>(200))
		.with_test_value("Advanced Custom Value")
		.build();
	test_failure_scenarios(&scenario_builder);
}

// Test custom values and builder patterns across all key types
anchor_rs::test_all_key_types!(test_custom_values, test_custom_values_functionality);

// Macro to test builder flexibility across multiple key types
macro_rules! test_builder_across_key_types {
	($test_name:ident, $($key_type:ty => $value:expr, $primary_seed:expr, $wrong_seed:expr),+ $(,)?) => {
		#[test]
		fn $test_name() {
			$(
				let scenario = TestScenario::<$key_type>::builder()
					.with_test_value($value)
					.with_primary_seed($primary_seed)
					.with_wrong_seed($wrong_seed)
					.build();
				test_basic_functionality(&scenario);
				test_proof_validation(scenario);
			)+
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
	let original_attr = builder.build(&account.keypair).unwrap();

	// Serialize to JSON
	let json_str = serde_json::to_string(&original_attr).unwrap();
	assert!(!json_str.is_empty());

	// Parse JSON to validate structure
	let json_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();
	// Verify all expected fields are present
	let obj = json_value.as_object().unwrap();
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
	let deserialized_attr: SensitiveAttribute = serde_json::from_str(&json_str).unwrap();
	// Verify the deserialized version works the same
	let original_decrypted = original_attr.decrypt(&account.keypair).unwrap();
	let deserialized_decrypted = deserialized_attr.decrypt(&account.keypair).unwrap();
	assert_eq!(original_decrypted.expose_secret(), deserialized_decrypted.expose_secret());

	// Verify they produce the same proof
	let original_proof = original_attr.to_proof(&account.keypair).unwrap();
	let deserialized_proof = deserialized_attr.to_proof(&account.keypair).unwrap();
	assert_eq!(original_proof.value.expose_secret(), deserialized_proof.value.expose_secret());
	assert_eq!(original_proof.hash.salt, deserialized_proof.hash.salt);

	// Validate proof value can be decoded from base64
	let decoded_proof_value = base64::prelude::BASE64_STANDARD
		.decode(original_proof.value.expose_secret())
		.unwrap();
	let proof_string = String::from_utf8(decoded_proof_value).unwrap();
	assert_eq!(proof_string, TEST_VALUE, "Proof value should match original when base64 decoded");
}

// Test serialization/deserialization if serde feature is enabled
#[cfg(feature = "serde")]
anchor_rs::test_all_key_types!(test_sensitive_attribute_serialization, test_serialization_functionality);

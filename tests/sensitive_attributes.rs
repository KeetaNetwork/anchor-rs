mod common;

use crate::common::*;

use accounts::{Account, AccountError, Accountable, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair};
use anchor_rs::certificates::{SensitiveAttributeBuilder, SensitiveAttributeProof};
use anchor_rs::SensitiveAttribute;
use base64::Engine;
use crypto::prelude::ExposeSecret;
use rasn;

const TEST_VALUE: &str = "Test Value";

// Helper functions for tests
fn assert_valid_proof(proof: &SensitiveAttributeProof, expected_value: &str) {
	// Decode and verify the proof content
	let decoded_value = base64::prelude::BASE64_STANDARD
		.decode(&proof.value)
		.expect("Failed to decode proof value");
	let value_string = String::from_utf8(decoded_value).expect("Invalid UTF-8 in proof value");
	assert_eq!(value_string, expected_value, "Proof value doesn't match expected");

	// Verify the salt is base64 encoded and has the expected length
	let decoded_salt = base64::prelude::BASE64_STANDARD
		.decode(&proof.hash.salt)
		.expect("Failed to decode proof salt");
	assert_eq!(decoded_salt.len(), 32, "Salt should be 32 bytes");
}

fn assert_wrong_account_fails<T: KeyPair>(sensitive_attr: &SensitiveAttribute, wrong_account: &Account<T>) {
	// Test that the wrong account can't decrypt
	let decrypt_result = sensitive_attr.decrypt(&wrong_account.keypair);
	assert!(decrypt_result.is_err(), "Wrong account should not be able to decrypt");

	// Test that the wrong account can't generate a valid proof
	let proof_result = sensitive_attr.to_proof(&wrong_account.keypair);
	assert!(proof_result.is_err(), "Wrong account should not be able to generate proof");
}

fn test_with_key_type<T: KeyPair>(key_type: &str)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Create accounts using the same seed but different indices
	let test_account1 = create_account_from_seed::<T>(0);
	let test_account2 = create_account_from_seed::<T>(1);

	// Build a sensitive attribute
	let builder = SensitiveAttributeBuilder::new().with_value(TEST_VALUE.as_bytes());
	let sensitive_attr = builder.build(&test_account1.keypair).unwrap();

	// Test decryption
	let decrypted_value = sensitive_attr.decrypt(&test_account1.keypair).unwrap();
	let decrypted_string = String::from_utf8(decrypted_value.expose_secret().clone()).unwrap();
	assert_eq!(decrypted_string, TEST_VALUE, "Decryption failed for key type: {}", key_type);

	// Test proof generation and validation
	// Validate proof structure
	let proof = sensitive_attr.to_proof(&test_account1.keypair).unwrap();
	assert_valid_proof(&proof, TEST_VALUE);

	// Test that the proof validates correctly
	let is_valid = sensitive_attr
		.validate_proof(&test_account1.keypair, &proof)
		.unwrap();
	assert!(is_valid, "Valid proof should pass validation for key type: {}", key_type);

	// Test that wrong account fails
	assert_wrong_account_fails(&sensitive_attr, &test_account2);

	// Verify salt format and length
	let decoded_salt = base64::prelude::BASE64_STANDARD
		.decode(&proof.hash.salt)
		.expect("Failed to decode salt");
	assert_eq!(decoded_salt.len(), 32, "Salt length mismatch for key type: {}", key_type);
}

#[test]
fn test_sensitive_attributes() {
	// Create accounts using the same seed and indices
	let test_account1 = create_account_from_seed::<KeyECDSASECP256K1>(0);
	let test_account2 = create_account_from_seed::<KeyECDSASECP256K1>(1);

	// Build a sensitive attribute with the test value
	let builder = SensitiveAttributeBuilder::new().with_value(TEST_VALUE.as_bytes());
	let sensitive_attr = builder.build(&test_account1.keypair).unwrap();

	// Test decryption and verify we get the same value back
	let decrypted_value = sensitive_attr.decrypt(&test_account1.keypair).unwrap();
	let decrypted_string = String::from_utf8(decrypted_value.expose_secret().clone()).unwrap();
	assert_eq!(decrypted_string, TEST_VALUE);

	// Verify the decrypted bytes match
	let expected_bytes = vec![0x54, 0x65, 0x73, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65];
	assert_eq!(decrypted_value.expose_secret(), &expected_bytes);

	// Test proof generation and validation
	let proof = sensitive_attr.to_proof(&test_account1.keypair).unwrap();
	assert_valid_proof(&proof, TEST_VALUE);

	// Validate the proof with the same account
	let is_valid = sensitive_attr
		.validate_proof(&test_account1.keypair, &proof)
		.unwrap();
	assert!(is_valid, "Valid proof should pass validation");

	// Test that wrong account cannot access the sensitive attribute
	assert_wrong_account_fails(&sensitive_attr, &test_account2);

	// Test validation with wrong value (matches TS validateProof with wrong value)
	let invalid_proof = SensitiveAttributeProof {
		value: base64::prelude::BASE64_STANDARD.encode(b"Something"),
		hash: anchor_rs::certificates::SensitiveAttributeProofHash { salt: proof.hash.salt.clone() },
	};
	let is_invalid = sensitive_attr
		.validate_proof(&test_account1.keypair, &invalid_proof)
		.unwrap();
	assert!(!is_invalid, "Invalid proof should fail validation");

	// Test validation with wrong keypair
	let is_invalid_key = sensitive_attr
		.validate_proof(&test_account2.keypair, &proof)
		.unwrap();
	assert!(!is_invalid_key, "Proof validation with wrong keypair should fail");

	// Test with public key only account
	let test_account1_no_private = create_public_key_only_account(&test_account1);
	// Public key only account should be able to validate proofs
	let is_valid_public_only = sensitive_attr
		.validate_proof(&test_account1_no_private.keypair, &proof)
		.unwrap();
	assert!(is_valid_public_only, "Public key only account should be able to validate valid proofs");

	// Public key only account should NOT be able to decrypt or generate proofs
	let decrypt_result_public = sensitive_attr.decrypt(&test_account1_no_private.keypair);
	assert!(decrypt_result_public.is_err(), "Public key only account should not be able to decrypt");

	let proof_result_public = sensitive_attr.to_proof(&test_account1_no_private.keypair);
	assert!(proof_result_public.is_err(), "Public key only account should not be able to generate proofs");

	// Test tampered attribute validation
	let mut sensitive_attr_bytes = rasn::der::encode(&sensitive_attr).unwrap();
	// Tamper with the last few bytes
	let tamper_index = sensitive_attr_bytes.len().saturating_sub(3);
	sensitive_attr_bytes[tamper_index] = 0x00;

	// Decode the tampered attribute
	let tampered_attr = rasn::der::decode::<anchor_rs::SensitiveAttribute>(&sensitive_attr_bytes)
		.expect("Tampered attribute should decode (even if invalid) for this test scenario");

	// Validation should fail for tampered attribute
	let tampered_validation = tampered_attr
		.validate_proof(&test_account1_no_private.keypair, &proof)
		.unwrap_or(false);
	assert!(!tampered_validation, "Tampered attribute should fail proof validation");
}

#[test]
fn test_all_key_types() {
	// Test with KeyECDSASECP256K1
	test_with_key_type::<KeyECDSASECP256K1>("KeyECDSASECP256K1");
	// Test with KeyECDSASECP256R1
	test_with_key_type::<KeyECDSASECP256R1>("KeyECDSASECP256R1");
	// Test with KeyED25519
	test_with_key_type::<KeyED25519>("KeyED25519");
}

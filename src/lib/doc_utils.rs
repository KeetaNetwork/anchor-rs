//! Documentation utilities for anchor-rs examples.
//!
//! This module provides helper functions that are only available during
//! documentation generation. These helpers reduce code duplication in
//! documentation examples and provide consistent test data for KYC
//! certificate and sensitive attribute operations.

use accounts::{Account, Accountable, KeyECDSASECP256K1, KeyED25519, KeyNETWORK, KeyPair, Keyable};
use asn1::SubjectPublicKeyInfo;
use crypto::prelude::IntoSecret;
use x509::utils::create_dn;
use x509::{certificates::Certificate as X509Certificate, SerialNumber};

use crate::{
	certificates::CertificateBuilder,
	sensitive_attributes::{SensitiveAttribute, SensitiveAttributeBuilder},
};

/// Standard test seed for consistent documentation examples.
pub const DOC_TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

/// Standard test data for KYC attributes in documentation examples.
pub struct TestKycData {
	pub full_name: &'static str,
	pub email: &'static str,
	pub phone_number: &'static str,
	pub address: &'static str,
	pub date_of_birth: &'static str,
}

impl Default for TestKycData {
	fn default() -> Self {
		Self {
			full_name: "John Doe",
			email: "john.doe@example.com",
			phone_number: "+1-555-123-4567",
			address: "123 Main Street, Any Town, ST 12345",
			date_of_birth: "1990-01-01",
		}
	}
}

/// Create a secp256k1 account for documentation examples.
pub fn create_secp256k1_test_account(index: Option<u32>) -> Account<KeyECDSASECP256K1> {
	let keyable = Keyable::HexSeed((DOC_TEST_SEED.to_string().into_secret(), index.unwrap_or(0)));
	let accountable = Accountable::KeyAndType(keyable, KeyECDSASECP256K1::KEY_PAIR_TYPE);
	Account::<KeyECDSASECP256K1>::try_from(accountable).expect("Failed to create secp256k1 test account")
}

/// Create an Ed25519 account for documentation examples.
pub fn create_ed25519_test_account(index: Option<u32>) -> Account<KeyED25519> {
	let keyable = Keyable::HexSeed((DOC_TEST_SEED.to_string().into_secret(), index.unwrap_or(0)));
	let accountable = Accountable::KeyAndType(keyable, KeyED25519::KEY_PAIR_TYPE);
	Account::<KeyED25519>::try_from(accountable).expect("Failed to create Ed25519 test account")
}

/// Create a network identifier account for documentation examples.
pub fn create_network_test_account(network_id: Option<u64>) -> Account<KeyNETWORK> {
	let id = network_id.unwrap_or(12345);
	Account::<KeyNETWORK>::generate_network_address(id).expect("Failed to generate network address")
}

/// Create a test certificate builder with standard configuration.
pub fn create_test_certificate_builder<T>(account: &Account<T>) -> CertificateBuilder
where
	T: accounts::KeyPair,
{
	let subject_dn = create_dn(&[(x509::oids::CN, "Test Subject")]).expect("Failed to create test subject DN");
	let issuer_dn = create_dn(&[(x509::oids::CN, "Test Issuer")]).expect("Failed to create test issuer DN");
	let public_key_info = SubjectPublicKeyInfo::try_from(account).expect("Failed to create SubjectPublicKeyInfo");

	CertificateBuilder::for_end_entity()
		.with_subject_dn(subject_dn.clone())
		.with_issuer_dn(issuer_dn)
		.with_serial_number(SerialNumber::from(12345u64))
		.with_validity_days(365)
		.with_subject_public_key(public_key_info)
}

/// Create a test sensitive attribute with standard data.
pub fn create_test_sensitive_attribute<T>(account: &Account<T>, data: Option<&[u8]>) -> SensitiveAttribute
where
	T: accounts::KeyPair,
{
	let test_data = data.unwrap_or(TestKycData::default().email.as_bytes());
	SensitiveAttributeBuilder::new()
		.with_value(test_data)
		.build(&account.keypair)
		.expect("Failed to create test sensitive attribute")
}

/// Get test KYC data for documentation examples.
pub fn get_test_kyc_data() -> TestKycData {
	TestKycData::default()
}

/// Create a test hex seed for examples that need custom seeds.
pub fn create_test_hex_seed(suffix: Option<&str>) -> String {
	let base = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E";
	let suffix = suffix.unwrap_or("01");
	format!("{base}{suffix}")
}

/// Create a simple test X.509 certificate for documentation examples.
pub fn create_test_x509_cert() -> X509Certificate {
	let account = create_secp256k1_test_account(None);
	let subject_dn = create_dn(&[(x509::oids::CN, "Test")]).expect("Failed to create test DN");
	let public_key = account.keypair.to_public_key();

	x509::certificates::CertificateBuilder::new()
		.with_subject_dn(subject_dn.clone())
		.with_issuer_dn(subject_dn)
		.with_subject_public_key(public_key.into())
		.with_serial_number(SerialNumber::from(1u64))
		.with_validity_days(365)
		.build(&account.keypair)
		.expect("Failed to create test X.509 certificate")
}

#[cfg(test)]
mod tests {
	use super::*;
	use accounts::KeyPair;

	#[test]
	fn test_create_secp256k1_test_account() {
		let account = create_secp256k1_test_account(None);
		assert_eq!(account.keypair.to_keypair_type(), KeyECDSASECP256K1::KEY_PAIR_TYPE);
	}

	#[test]
	fn test_create_ed25519_test_account() {
		let account = create_ed25519_test_account(None);
		assert_eq!(account.keypair.to_keypair_type(), KeyED25519::KEY_PAIR_TYPE);
	}

	#[test]
	fn test_create_network_test_account() {
		let account = create_network_test_account(Some(999));
		assert_eq!(account.keypair.to_keypair_type(), KeyNETWORK::KEY_PAIR_TYPE);
	}

	#[test]
	fn test_create_test_certificate_builder() {
		let account = create_secp256k1_test_account(None);
		let builder = create_test_certificate_builder(&account);

		// Test that we can add attributes to the builder
		let result = builder.with_plain_attribute("fullName", b"Test Name");
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_test_sensitive_attribute() {
		let account = create_secp256k1_test_account(None);
		let sensitive_attr = create_test_sensitive_attribute(&account, None);

		// Test that we can decrypt it
		let decrypted = sensitive_attr.decrypt(&account.keypair);
		assert!(decrypted.is_ok());
	}

	#[test]
	fn test_get_test_kyc_data() {
		let kyc_data = get_test_kyc_data();
		assert_eq!(kyc_data.full_name, "John Doe");
		assert!(kyc_data.email.contains("@"));
		assert!(!kyc_data.phone_number.is_empty());
	}

	#[test]
	fn test_create_test_hex_seed() {
		let seed1 = create_test_hex_seed(None);
		let seed2 = create_test_hex_seed(Some("FF"));
		assert_eq!(seed1.len(), 64); // 32 bytes * 2 hex chars
		assert_eq!(seed2.len(), 64);
		assert_ne!(seed1, seed2);
		assert!(seed2.ends_with("FF"));
	}

	#[test]
	fn test_different_account_indices() {
		let account1 = create_secp256k1_test_account(Some(0));
		let account2 = create_secp256k1_test_account(Some(1));
		assert_ne!(account1.keypair.to_public_key_string(), account2.keypair.to_public_key_string());
	}
}

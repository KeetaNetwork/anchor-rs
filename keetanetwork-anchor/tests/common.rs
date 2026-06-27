//! Common test data and utilities for integration tests
//!
//! This module provides shared test data and helper functions that mirror
//! the TypeScript test suite, ensuring consistency across test environments.
#![allow(dead_code)]

use keetanetwork_account::{Account, AccountError, Accountable, KeyECDSASECP256K1, KeyPair};
use keetanetwork_crypto::prelude::{CryptoSignerWithOptions, SignatureEncoding};

use keetanetwork_anchor::certificates::Certificate;
use keetanetwork_anchor::generated::KYCAttributes;
use keetanetwork_anchor::kyc_schema::{Attribute, AttributeBuilder, AttributeBuilderLike, KYCAttributesBuilder};
use keetanetwork_anchor::testing::{create_account_from_seed, create_public_key_only_account};

/// Test seed used in TypeScript tests for deterministic account generation
pub const TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

/// Standard test data
pub struct TestData {
	pub full_name: &'static str,
	pub email: &'static str,
	pub phone_number: &'static str,
	pub address: &'static str,
	pub date_of_birth: &'static str,
	pub postal_code: &'static str,
}

impl TestData {
	/// Get the standard test data used across all tests
	pub const fn standard() -> Self {
		Self {
			full_name: "Test User",
			email: "user@example.com",
			phone_number: "+1 555 911 3808",
			// cspell:disable-next-line
			address: "100 Belgrave Street, Oldsmar, FL 34677",
			date_of_birth: "1980-01-01",
			postal_code: "12345",
		}
	}

	/// Get test data for sensitive attribute tests
	pub const fn sensitive_attribute() -> Self {
		Self {
			full_name: "Test Value",
			email: "test@example.com",
			phone_number: "+1234567890",
			address: "123 Test St",
			date_of_birth: "1990-01-01",
			postal_code: "54321",
		}
	}
}

/// Test account manager for creating deterministic accounts
pub struct TestAccounts<T: KeyPair>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	pub issuer: Account<T>,
	pub subject: Account<T>,
	pub subject_public_only: Account<T>,
	pub wrong_account: Account<T>,
}

impl<T: KeyPair> Default for TestAccounts<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	fn default() -> Self {
		Self::new()
	}
}

impl<T: KeyPair> TestAccounts<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	/// Create test accounts with standard seeds
	pub fn new() -> Self {
		let issuer = create_account_from_seed::<T>(0);
		let subject = create_account_from_seed::<T>(1);
		let subject_public_only = create_public_key_only_account::<T>(&subject);
		let wrong_account = create_account_from_seed::<T>(2);

		Self { issuer, subject, subject_public_only, wrong_account }
	}

	/// Create test accounts with custom seeds
	pub fn with_seeds(issuer_seed: u32, subject_seed: u32) -> Self {
		let issuer = create_account_from_seed::<T>(issuer_seed);
		let subject = create_account_from_seed::<T>(subject_seed);
		let subject_public_only = create_public_key_only_account::<T>(&subject);
		let wrong_account = create_account_from_seed::<T>(subject_seed + 100);

		Self { issuer, subject, subject_public_only, wrong_account }
	}
}

/// Create a KYC with the specified plain and sensitive attributes
///
/// # Arguments
/// * `plain_attrs` - Slice of (OID, value) tuples for plain attributes
/// * `sensitive_attrs` - Slice of (OID, value) tuples for sensitive attributes
pub fn create_kyc_with_attributes<T: ToString>(
	plain_attrs: &[(T, &[u8])],
	sensitive_attrs: &[(T, &[u8])],
) -> KYCAttributes {
	let mut builder = KYCAttributesBuilder::new();

	for (oid, value) in plain_attrs {
		builder = builder.with_plain(oid.to_string(), *value);
	}

	for (oid, value) in sensitive_attrs {
		builder = builder.with_sensitive(oid.to_string(), *value);
	}

	builder.build().expect("KYC should build successfully")
}

/// Create a plain attribute using AttributeBuilder
pub fn create_plain_attribute<T: ToString>(oid: T, value: &[u8]) -> Attribute {
	AttributeBuilder::default()
		.with_oid(oid.to_string())
		.with_value(value)
		.as_plain()
		.build()
		.expect("Failed to create plain attribute")
}

/// Create a sensitive attribute using AttributeBuilder
pub fn create_sensitive_attribute<T: ToString>(oid: T, value: &[u8]) -> Attribute {
	AttributeBuilder::default()
		.with_oid(oid.to_string())
		.with_value(value)
		.as_sensitive()
		.build()
		.expect("Failed to create sensitive attribute")
}

/// Create a KYC with specific attributes using KYCAttributesBuilder
pub fn create_kyc_from_attributes(attributes: Vec<Attribute>) -> KYCAttributes {
	let mut builder = KYCAttributesBuilder::new();
	for attr in attributes {
		builder = builder.with_attribute(attr);
	}

	builder.build().expect("Failed to create KYCAttributes")
}

/// Assert basic KYC properties and counts
pub fn test_kyc_count(kyc: &KYCAttributes, expected_count: usize) -> Result<(), Box<dyn std::error::Error>> {
	assert_eq!(kyc.0.len(), expected_count);
	Ok(())
}

/// Assert mixed attribute counts (plain + sensitive)
pub fn test_mixed_attribute_counts(
	kyc: &KYCAttributes,
	expected_plain: usize,
	expected_sensitive: usize,
) -> Result<(), Box<dyn std::error::Error>> {
	let plain_count = kyc.plain_attributes().count();
	let sensitive_count = kyc.sensitive_attributes().count();
	let total_count = kyc.iter().count();
	assert_eq!(plain_count, expected_plain);
	assert_eq!(sensitive_count, expected_sensitive);
	assert_eq!(plain_count + sensitive_count, total_count);
	assert_eq!(total_count, expected_plain + expected_sensitive);

	Ok(())
}

/// Assert that specific OIDs exist in the KYC
pub fn test_oids_exist<T: ToString>(kyc: &KYCAttributes, oids: &[T]) -> Result<(), Box<dyn std::error::Error>> {
	for oid in oids {
		assert!(kyc.find_by_oid(oid.to_string()).is_some(), "OID {} should exist", oid.to_string());
	}

	Ok(())
}

/// Assert that specific OIDs do not exist in the KYC
pub fn test_oids_not_exist<T: ToString>(kyc: &KYCAttributes, oids: &[T]) -> Result<(), Box<dyn std::error::Error>> {
	for oid in oids {
		assert!(kyc.find_by_oid(oid.to_string()).is_none(), "OID {} should not exist", oid.to_string());
	}

	Ok(())
}

/// Verify attribute properties (sensitivity and value)
pub fn test_attribute_properties(
	attr: &keetanetwork_anchor::generated::Attribute,
	expected_value: &[u8],
	should_be_sensitive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
	assert_eq!(attr.is_sensitive(), should_be_sensitive);
	assert_eq!(attr.as_ref(), expected_value);
	Ok(())
}

/// Test certificate attribute access patterns
pub fn test_certificate_attributes<T, S>(
	certificate: &Certificate,
	accounts: &TestAccounts<T>,
	test_data: &TestData,
) -> Result<(), Box<dyn std::error::Error>>
where
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	// Verify certificate has KYC attributes
	assert!(certificate.has_kyc_attributes(), "Certificate should have KYC attributes");

	// Test attribute access patterns
	if let Some(_full_name_attr) = certificate.get_kyc_attribute("fullName") {
		// Test decryption with correct private key
		let decrypted_name = certificate.decrypt_kyc_attribute("fullName", &accounts.subject.keypair)?;
		assert_eq!(decrypted_name, test_data.full_name.as_bytes());

		// Test that decryption fails with wrong private key
		let wrong_decrypt_result = certificate.decrypt_kyc_attribute("fullName", &accounts.wrong_account.keypair);
		assert!(wrong_decrypt_result.is_err(), "Decryption should fail with wrong key");
	}

	// Test email attribute
	if let Some(_email_attr) = certificate.get_kyc_attribute("email") {
		let decrypted_email = certificate.decrypt_kyc_attribute("email", &accounts.subject.keypair)?;
		assert_eq!(decrypted_email, test_data.email.as_bytes());
	}

	Ok(())
}

/// Test plain text attribute access
pub fn test_plain_attributes(
	certificate: &Certificate,
	test_data: &TestData,
) -> Result<(), Box<dyn std::error::Error>> {
	// Test postal code if present
	if certificate.get_kyc_attribute("postalCode").is_some() {
		let postal_code = certificate.get_plain_kyc_attribute("postalCode")?;
		assert_eq!(postal_code, test_data.postal_code.as_bytes());
	}

	// Test that attempting to decrypt a plain attribute fails
	if certificate.get_kyc_attribute("postalCode").is_some() {
		let fake_account = create_account_from_seed::<KeyECDSASECP256K1>(99);
		let decrypt_result = certificate.decrypt_kyc_attribute("postalCode", &fake_account.keypair);
		assert!(decrypt_result.is_err(), "Should not be able to decrypt plain text attribute");
	}

	Ok(())
}

/// Helper to assert certificate KYC attribute properties
pub fn test_has_kyc_attributes(
	cert: &Certificate,
	expected_count: usize,
	message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
	if expected_count == 0 {
		assert!(!cert.has_kyc_attributes(), "{message} should not have KYC attributes");
	} else {
		assert!(cert.has_kyc_attributes(), "{message} should have KYC attributes");
	}
	assert_eq!(cert.kyc_attribute_count(), expected_count, "{message} should have {expected_count} KYC attributes");

	Ok(())
}

/// Helper to get KYC attribute value, handling both plain and sensitive attributes
pub fn test_get_kyc_attribute_value<T>(
	cert: &Certificate,
	attr_name: &str,
	keypair: Option<&T>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
	T: KeyPair,
{
	// First check if the attribute exists
	cert.get_kyc_attribute(attr_name)
		.ok_or_else(|| format!("Attribute '{attr_name}' not found"))?;

	// Try to get as plain text first
	if let Ok(plain_value) = cert.get_plain_kyc_attribute(attr_name) {
		return Ok(plain_value);
	}

	// If plain failed, try to decrypt as sensitive attribute
	if let Some(key) = keypair {
		let decrypted_value = cert.decrypt_kyc_attribute(attr_name, key)?;
		return Ok(decrypted_value);
	}

	Err(format!("Attribute '{attr_name}' appears to be sensitive but no keypair provided for decryption").into())
}

/// Helper to verify certificate trust chain
pub fn test_certificate_issued_by(
	user_cert: &Certificate,
	ca_cert: &Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
	if user_cert.to_x509().is_issued_by(ca_cert.to_x509()) {
		Ok(())
	} else {
		Err("User certificate is not issued by the CA certificate".into())
	}
}

/// Load a PEM fixture from the tests/fixtures directory
pub fn load_pem_fixture(name: &str) -> String {
	let path = format!("tests/fixtures/{name}.pem");
	std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to load fixture: {path}"))
}

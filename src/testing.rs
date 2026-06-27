//! Common testing utilities shared between unit and integration tests.
#![allow(dead_code)]

use std::convert::TryFrom;

use keetanetwork_account::{Account, AccountError, Accountable, KeyPair, Keyable};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::prelude::IntoSecret;
use keetanetwork_x509::SerialNumber;

use crate::certificates::CertificateBuilder;
use crate::kyc_schema::builder::AttributeBuilderLike;
use crate::kyc_schema::{Attribute, AttributeBuilder, KYCAttributes, KYCAttributesBuilder};
use crate::sensitive_attributes::{SensitiveAttribute, SensitiveAttributeBuilder, SensitiveAttributeProof};

/// Test data from TypeScript test
pub const TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

/// Test data for KYC attributes - (oid, value, is_sensitive)
pub const TEST_KYC_ATTRIBUTES: &[(&str, &[u8], bool)] = &[
	("1.2.3.4.1", b"John Doe", false),        // Plain name
	("1.2.3.4.2", b"john@example.com", true), // Sensitive email
	("1.2.3.4.3", b"12345", false),           // Plain postal code
	("1.2.3.4.4", b"+1234567890", true),      // Sensitive phone
];

/// Macro to test functionality across all supported key types
#[macro_export]
macro_rules! test_all_key_types {
	($test_name:ident, $test_body:expr) => {
		#[test]
		fn $test_name() {
			use keetanetwork_account::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
			use $crate::testing::create_account_from_seed;

			// Test with ECDSA SECP256K1
			let account = create_account_from_seed::<KeyECDSASECP256K1>(0);
			$test_body(account);

			// Test with ECDSA SECP256R1
			let account = create_account_from_seed::<KeyECDSASECP256R1>(0);
			$test_body(account);

			// Test with ED25519
			let account = create_account_from_seed::<KeyED25519>(0);
			$test_body(account);
		}
	};
}

/// Helper function to create an account from a hex seed string for different key types.
pub fn create_account_from_seed_hex<T>(hex_seed: &str, index: u32) -> Account<T>
where
	T: KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	let seed_bytes = hex::decode(hex_seed).expect("Invalid hex seed");
	let seed_array: [u8; 32] = seed_bytes.try_into().expect("Seed must be 32 bytes");
	let seed = Keyable::Seed((seed_array.into_secret(), index));
	let accountable = Accountable::KeyAndType(seed, T::KEY_PAIR_TYPE);
	Account::<T>::try_from(accountable).expect("Failed to create account from seed")
}

/// Helper function to create an account from `TEST_SEED` for different key types.
pub fn create_account_from_seed<T>(index: u32) -> Account<T>
where
	T: KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	create_account_from_seed_hex(TEST_SEED, index)
}

/// Helper function to create a public key only account (no private key).
pub fn create_public_key_only_account<T>(full_account: &Account<T>) -> Account<T>
where
	T: KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	let public_key_string = full_account.keypair.to_public_key_string();
	let keyable = Keyable::PublicKeyString(public_key_string);
	let accountable = Accountable::KeyAndType(keyable, T::KEY_PAIR_TYPE);
	Account::<T>::try_from(accountable).unwrap()
}

/// Helper function to create a sensitive attribute and proof for testing.
pub fn create_test_sensitive_attribute_with_proof<T: KeyPair>(
	account: &Account<T>,
	test_value: &[u8],
) -> (SensitiveAttribute, SensitiveAttributeProof) {
	let builder = SensitiveAttributeBuilder::new().with_value(test_value);
	let sensitive_attr = builder.build(&account.keypair).unwrap();
	let proof = sensitive_attr.to_proof(&account.keypair).unwrap();
	(sensitive_attr, proof)
}

/// Helper function to create just a sensitive attribute for testing.
pub fn create_test_sensitive_attribute<T: KeyPair>(account: &Account<T>, test_value: &[u8]) -> SensitiveAttribute {
	let builder = SensitiveAttributeBuilder::new().with_value(test_value);
	builder.build(&account.keypair).unwrap()
}

/// Helper function to create a CertificateBuilder with default test data.
pub fn create_test_certificate_builder<T: KeyPair>(account: &Account<T>) -> CertificateBuilder {
	let subject_dn = keetanetwork_x509::utils::create_dn(&[(keetanetwork_x509::oids::CN, "Test Subject")]).unwrap();
	let subject_public_key_info = SubjectPublicKeyInfo::try_from(account).unwrap();

	CertificateBuilder::for_end_entity()
		.with_subject_dn(subject_dn.clone())
		.with_issuer_dn(subject_dn)
		.with_serial_number(SerialNumber::from(12345u64))
		.with_validity_days(365)
		.with_subject_public_key(subject_public_key_info)
}

/// Helper to create a KYCAttributes collection from test data
pub fn create_test_kyc_attributes() -> KYCAttributes {
	let mut builder = KYCAttributesBuilder::new();

	for &(oid_str, value, is_sensitive) in TEST_KYC_ATTRIBUTES {
		if is_sensitive {
			builder = builder.with_sensitive(oid_str, value);
		} else {
			builder = builder.with_plain(oid_str, value);
		}
	}

	builder.build().unwrap()
}

/// Helper to create individual test attributes
pub fn create_test_attribute(oid_str: &str, value: &[u8], is_sensitive: bool) -> Attribute {
	let mut builder = AttributeBuilder::new().with_oid(oid_str).with_value(value);

	if is_sensitive {
		builder = builder.as_sensitive();
	} else {
		builder = builder.as_plain();
	}

	builder.build().unwrap()
}

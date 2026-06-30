//! Common testing utilities shared between unit and integration tests.
#![allow(dead_code)]

use std::convert::TryFrom;
use std::str::FromStr;

use keetanetwork_account::{Account, AccountError, Accountable, KeyECDSASECP256K1, KeyPair, Keyable};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::prelude::IntoSecret;
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use keetanetwork_x509::utils::create_dn;
use keetanetwork_x509::SerialNumber;

use crate::certificates::{KycCertificate, KycCertificateBuilder};
use crate::kyc_schema::builder::AttributeBuilderLike;
use crate::kyc_schema::{Attribute, AttributeBuilder, KycAttributes, KycAttributesBuilder};
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
	let public_key_string = full_account
		.keypair
		.to_public_key_string()
		.expect("Failed to get public key string");
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

/// Helper function to create a KycCertificateBuilder with default test data.
pub fn create_test_certificate_builder<T: KeyPair>(account: &Account<T>) -> KycCertificateBuilder {
	let subject_dn = keetanetwork_x509::utils::create_dn(&[(keetanetwork_x509::oids::CN, "Test Subject")]).unwrap();
	let subject_public_key_info = SubjectPublicKeyInfo::try_from(account).unwrap();

	KycCertificateBuilder::for_end_entity()
		.with_subject_dn(subject_dn.clone())
		.with_issuer_dn(subject_dn)
		.with_serial_number(SerialNumber::from(12345u64))
		.with_validity_days(365)
		.with_subject_public_key(subject_public_key_info)
}

/// Helper to create a KycAttributes collection from test data
pub fn create_test_kyc_attributes() -> KycAttributes {
	let mut builder = KycAttributesBuilder::new();

	for &(oid_str, value, is_sensitive) in TEST_KYC_ATTRIBUTES {
		if is_sensitive {
			builder = builder.with_sensitive(oid_str, value);
		} else {
			builder = builder.with_plain(oid_str, value);
		}
	}

	builder.build().unwrap()
}

/// Issue a self-signed CA and an end-entity leaf for `subject_seed_hex`, encoding
/// each `(name, semantic, sensitive)` attribute through the production codec and
/// encrypting the sensitive ones to the subject.
pub fn issue_leaf_pem(subject_seed_hex: &str, attributes: &[(&str, &[u8], bool)]) -> (String, String) {
	let subject = create_account_from_seed_hex::<KeyECDSASECP256K1>(subject_seed_hex, 0);
	let issuer = create_account_from_seed::<KeyECDSASECP256K1>(1);

	let ca_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test CA Root")]).expect("CA distinguished name");
	let ca = KycCertificateBuilder::for_ca()
		.with_subject_dn(ca_dn.clone())
		.with_issuer_dn(ca_dn.clone())
		.with_serial_number(SerialNumber::from(1u64))
		.with_validity_days(3650)
		.with_subject_public_key(SubjectPublicKeyInfo::try_from(&issuer).expect("CA public key info"))
		.with_basic_constraints(true, Some(5))
		.build(&issuer.keypair, &issuer.keypair)
		.expect("CA certificate");

	let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Subject")]).expect("subject DN");
	let mut builder = KycCertificateBuilder::for_end_entity()
		.with_subject_dn(subject_dn)
		.with_issuer_dn(ca_dn)
		.with_serial_number(SerialNumber::from(4u64))
		.with_validity_days(365)
		.with_subject_public_key(SubjectPublicKeyInfo::try_from(&subject).expect("subject public key info"));

	for (name, value, sensitive) in attributes {
		builder = if *sensitive {
			builder.with_sensitive_attribute(*name, value.to_vec().into_secret())
		} else {
			builder.with_plain_attribute(*name, value)
		};
	}

	let leaf = builder
		.build(&subject.keypair, &issuer.keypair)
		.expect("leaf certificate");

	let leaf_pem = leaf.to_x509().to_pem().expect("leaf PEM");
	let ca_pem = ca.to_x509().to_pem().expect("CA PEM");
	(leaf_pem, ca_pem)
}

/// Parse a leaf PEM and decrypt the sensitive attribute `name` with the key for
/// `subject_seed_hex`, returning the decoded semantic bytes. The inverse of
/// [`issue_leaf_pem`] for reading an externally issued leaf through the core.
pub fn read_sensitive_attribute(leaf_pem: &str, subject_seed_hex: &str, name: &str) -> Vec<u8> {
	let subject = create_account_from_seed_hex::<KeyECDSASECP256K1>(subject_seed_hex, 0);
	let x509 = X509Certificate::from_str(leaf_pem).expect("leaf PEM parses");
	let certificate = KycCertificate::new(x509);
	certificate
		.decrypt_kyc_attribute(name, &subject.keypair)
		.expect("sensitive attribute decrypts")
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

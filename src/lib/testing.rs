//! Common testing utilities shared between unit and integration tests.
#![allow(dead_code)]

use std::convert::TryFrom;

use accounts::{Account, Accountable, IntoSecret, KeyPair, Keyable, Seed};
use crypto::bigint::U256;

use crate::{
	certificates::CertificateBuilder,
	generated::SensitiveAttribute,
	sensitive_attributes::{SensitiveAttributeBuilder, SensitiveAttributeProof},
};

/// Test data from TypeScript test
pub const TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

/// Macro to generate tests for From conversions on error types.
#[macro_export]
macro_rules! test_error_from_conversions {
	($test_name:ident, $error_type:ty, [$($source_expr:expr),+ $(,)?]) => {
		#[test]
		fn $test_name() {
			let test_cases: &[Box<dyn Fn() -> $error_type>] = &[
				$(Box::new(|| {
					let source_error = $source_expr;
					source_error.into()
				}),)+
			];

			for error_fn in test_cases {
				let error = error_fn();

				// Verify the conversion worked by checking the error can be formatted
				let display_str = format!("{}", error);
				let debug_str = format!("{error:?}");
				assert!(!display_str.is_empty());
				assert!(!debug_str.is_empty());
			}
		}
	};
}

/// Macro to generate tests for error variants (Display and Debug formatting).
#[macro_export]
macro_rules! test_error_variants {
	($test_name:ident, [$($variant:expr),+ $(,)?]) => {
		#[test]
		fn $test_name() {
			let test_cases = [$($variant),+];

			for error in test_cases {
				let display_str = format!("{}", error);
				let debug_str = format!("{error:?}");
				assert!(!display_str.is_empty());
				assert!(!debug_str.is_empty());
			}
		}
	};
}

/// Macro to test functionality across all supported key types
#[macro_export]
macro_rules! test_all_key_types {
	($test_name:ident, $test_body:expr) => {
		#[test]
		fn $test_name() {
			use accounts::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
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

/// Helper function to create a test seed array.
pub fn create_test_seed_array() -> Seed {
	let seed_bytes = hex::decode(TEST_SEED).unwrap();
	let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();
	seed_array.into_secret()
}

/// Helper function to create an account from seed for different key types.
pub fn create_account_from_seed<T>(index: u32) -> Account<T>
where
	T: accounts::KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = accounts::AccountError>,
{
	let seed_array = create_test_seed_array();
	let seed = Keyable::Seed((seed_array, index));
	let accountable = Accountable::KeyAndType(seed, T::KEY_PAIR_TYPE);

	Account::<T>::try_from(accountable).unwrap()
}

/// Helper function to create a public key only account (no private key).
pub fn create_public_key_only_account<T>(full_account: &Account<T>) -> Account<T>
where
	T: accounts::KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = accounts::AccountError>,
{
	let public_key_string = full_account.keypair.to_public_key_string().unwrap();
	let keyable = Keyable::PublicKeyString(public_key_string);
	let accountable = Accountable::KeyAndType(keyable, T::KEY_PAIR_TYPE);

	Account::<T>::try_from(accountable).unwrap()
}

/// Helper function to create a sensitive attribute and proof for testing.
pub fn create_test_sensitive_attribute_with_proof<T: KeyPair>(
	account: &accounts::Account<T>,
	test_value: &[u8],
) -> (SensitiveAttribute, SensitiveAttributeProof) {
	let builder = SensitiveAttributeBuilder::new().with_value(test_value);
	let sensitive_attr = builder.build(&account.keypair).unwrap();
	let proof = sensitive_attr.to_proof(&account.keypair).unwrap();
	(sensitive_attr, proof)
}

/// Helper function to create just a sensitive attribute for testing.
pub fn create_test_sensitive_attribute<T: KeyPair>(
	account: &accounts::Account<T>,
	test_value: &[u8],
) -> SensitiveAttribute {
	let builder = SensitiveAttributeBuilder::new().with_value(test_value);
	builder.build(&account.keypair).unwrap()
}

/// Helper function to create a CertificateBuilder with default test data.
pub fn create_test_certificate_builder<T: KeyPair>(account: &Account<T>) -> CertificateBuilder {
	let subject_dn = x509::utils::create_dn(&[(x509::oids::CN, "Test Subject")]).unwrap();
	let public_key = account.keypair.to_public_key().unwrap();

	CertificateBuilder::for_end_entity()
		.with_subject_dn(subject_dn.clone())
		.with_issuer_dn(subject_dn)
		.with_serial_number(U256::from(12345u64))
		.with_validity_days(365)
		.with_subject_public_key(public_key.into())
}

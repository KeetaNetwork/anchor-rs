//! TypeScript Interoperability Tests
//!
//! This module tests that Rust can parse and process certificates generated
//! by the TypeScript implementation, ensuring cross-platform compatibility.

mod common;

use core::str::FromStr;

use keetanetwork_account::KeyECDSASECP256K1;
use keetanetwork_anchor::certificates::Certificate;
use keetanetwork_anchor::testing::create_account_from_seed_hex;
use keetanetwork_x509::certificates::Certificate as X509Certificate;

use common::load_pem_fixture;

/// Test case for TypeScript certificate interoperability
struct InteropTestCase {
	name: &'static str,
	pem_fixture: &'static str,
	seed: &'static str,
	expected_attributes: &'static [&'static str],
}

/// Test cases from the TypeScript test suite (certificates.test.ts)
///
/// Note: The expected_attributes list contains attributes that MUST be present.
/// Both old and new format certificates are expected to have these core attributes.
const TEST_CASES: &[InteropTestCase] = &[
	InteropTestCase {
		name: "old format (no context tags)",
		pem_fixture: "old_format",
		seed: "38D8765C39247A2ED61C8C277DEB9E1E82D93DF2BB7C642EF86C63F5FE07F83D",
		// Core attributes that must be present in old format certificates
		expected_attributes: &["entityType", "fullName", "email", "dateOfBirth", "documentDriversLicense"],
	},
	InteropTestCase {
		name: "new format (with context tags)",
		pem_fixture: "new_format",
		seed: "657340915c5dd7d4610feaf281f6f4658b5689d414710ce080eb8f8b0b2e03a9",
		// Core attributes that must be present in new format certificates
		expected_attributes: &["entityType", "fullName", "email", "dateOfBirth", "documentDriversLicense"],
	},
];

/// Parse a certificate from PEM fixture and wrap it in our Certificate type
fn parse_certificate_from_fixture(fixture_name: &str) -> Certificate {
	let pem_content = load_pem_fixture(fixture_name);
	let x509_cert = X509Certificate::from_str(&pem_content).expect("Failed to parse PEM certificate");
	Certificate::new(x509_cert)
}

#[test]
fn test_typescript_certificate_parsing() {
	for test_case in TEST_CASES {
		let certificate = parse_certificate_from_fixture(test_case.pem_fixture);
		assert!(certificate.has_kyc_attributes(), "{}: Certificate should have KYC attributes", test_case.name);
		assert!(
			certificate.kyc_attribute_count() >= test_case.expected_attributes.len(),
			"{}: Certificate should have at least {} KYC attributes, found {}",
			test_case.name,
			test_case.expected_attributes.len(),
			certificate.kyc_attribute_count()
		);
	}
}

#[test]
fn test_typescript_certificate_attribute_decryption() {
	for test_case in TEST_CASES {
		let certificate = parse_certificate_from_fixture(test_case.pem_fixture);
		let account = create_account_from_seed_hex::<KeyECDSASECP256K1>(test_case.seed, 0);

		// Try to decrypt each expected sensitive attribute
		for attr_name in test_case.expected_attributes {
			let attr = certificate
				.get_kyc_attribute(attr_name)
				.unwrap_or_else(|| panic!("{}: Attribute '{}' should exist", test_case.name, attr_name));

			if attr.is_sensitive() {
				let result = certificate.decrypt_kyc_attribute(attr_name, &account.keypair);
				assert!(
					result.is_ok(),
					"{}: Failed to decrypt sensitive attribute '{}': {:?}",
					test_case.name,
					attr_name,
					result.err()
				);

				let decrypted = result.expect("Decryption should succeed");
				assert!(
					!decrypted.is_empty(),
					"{}: Decrypted attribute '{}' should not be empty",
					test_case.name,
					attr_name
				);
			}
		}
	}
}

#[test]
fn test_typescript_certificate_wrong_key_fails() {
	for test_case in TEST_CASES {
		let certificate = parse_certificate_from_fixture(test_case.pem_fixture);
		// Create account with wrong seed (index 99 instead of 0)
		let wrong_account = create_account_from_seed_hex::<KeyECDSASECP256K1>(test_case.seed, 99);

		// Find a sensitive attribute to test with
		for attr_name in test_case.expected_attributes {
			let attr = certificate.get_kyc_attribute(attr_name);
			if let Some(attr) = attr {
				if attr.is_sensitive() {
					let result = certificate.decrypt_kyc_attribute(attr_name, &wrong_account.keypair);
					assert!(
						result.is_err(),
						"{}: Decryption with wrong key should fail for attribute '{}'",
						test_case.name,
						attr_name
					);
				}
			}
		}
	}
}

#[test]
fn test_typescript_certificate_subject_contains_keeta() {
	for test_case in TEST_CASES {
		let certificate = parse_certificate_from_fixture(test_case.pem_fixture);
		let x509 = certificate.to_x509();

		// Get subject DN as string
		let subject = x509.tbs_certificate.subject.to_string();
		assert!(
			subject.to_lowercase().contains("keeta_"),
			"{}: Certificate subject should contain 'keeta_', got: {}",
			test_case.name,
			subject
		);
	}
}

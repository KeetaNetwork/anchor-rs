//! KYC certificate binding ops, layered on the shared base certificate
//! primitive from `keetanetwork-bindings`.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use keetanetwork_account::{GenericAccount, KeyPair};
use keetanetwork_anchor::certificates::{KycCertificate, KycCertificateError};
use keetanetwork_anchor::trust::{evaluate_certificate_chain, CertificateChainStatus, CertificateRecord};
use keetanetwork_bindings::x509::{
	certificate_der, certificate_from_der, certificate_from_pem, certificate_pem, certificate_valid_at,
};
use keetanetwork_x509::certificates::Certificate;

use crate::error::CodedError;

/// Code for a sensitive-attribute failure (wrong type, decode, or decrypt).
pub const SENSITIVE_ATTRIBUTE: &str = "SENSITIVE_ATTRIBUTE";
/// Code for an ASN.1 failure decoding a KYC attribute.
pub const ASN1_ERROR: &str = "ASN1_ERROR";
/// Code for a KYC schema failure.
pub const KYC_SCHEMA: &str = "KYC_SCHEMA";
/// Code for a requested attribute that is absent.
pub const ATTRIBUTE_NOT_FOUND: &str = "ATTRIBUTE_NOT_FOUND";
/// Code for an attribute carrying an invalid value.
pub const INVALID_ATTRIBUTE_VALUE: &str = "INVALID_ATTRIBUTE_VALUE";
/// Code for a missing required certificate field.
pub const MISSING_REQUIRED_FIELD: &str = "MISSING_REQUIRED_FIELD";
/// Code for a timestamp outside the representable range.
pub const INVALID_DATE: &str = "INVALID_DATE";
/// Code for a subject whose key type cannot decrypt sensitive attributes.
pub const UNSUPPORTED_KEY_TYPE: &str = "UNSUPPORTED_KEY_TYPE";

/// Parse a PEM-encoded KYC certificate, reusing the base certificate codec.
pub fn from_pem(certificate: &str) -> Result<KycCertificate, CodedError> {
	Ok(KycCertificate::new(certificate_from_pem(certificate)?))
}

/// Parse a DER-encoded KYC certificate, reusing the base certificate codec.
pub fn from_der(certificate: &[u8]) -> Result<KycCertificate, CodedError> {
	Ok(KycCertificate::new(certificate_from_der(certificate)?))
}

/// The PEM encoding of `certificate`.
pub fn pem(certificate: &KycCertificate) -> Result<String, CodedError> {
	certificate_pem(certificate.to_x509())
}

/// The DER encoding of `certificate`.
pub fn der(certificate: &KycCertificate) -> Result<Vec<u8>, CodedError> {
	certificate_der(certificate.to_x509())
}

/// Whether `certificate` is within its validity window at `unix_millis`.
pub fn valid_at(certificate: &KycCertificate, unix_millis: i64) -> Result<bool, CodedError> {
	certificate_valid_at(certificate.to_x509(), unix_millis)
}

/// Whether `certificate` carries any KYC attributes.
pub fn has_attributes(certificate: &KycCertificate) -> bool {
	certificate.has_kyc_attributes()
}

/// The number of KYC attributes, plain and sensitive.
pub fn attribute_count(certificate: &KycCertificate) -> usize {
	certificate.kyc_attribute_count()
}

/// The KYC attributes the certificate carries, each as its OID `name` paired
/// with whether its value is `sensitive` (encrypted) rather than plain.
pub fn attributes(certificate: &KycCertificate) -> Vec<(String, bool)> {
	certificate
		.kyc_attributes()
		.iter()
		.map(|attribute| (attribute.name.to_string(), attribute.is_sensitive()))
		.collect()
}

/// The plain-text value of the non-sensitive attribute `name`.
pub fn plain_attribute<N: AsRef<str>>(certificate: &KycCertificate, name: N) -> Result<Vec<u8>, CodedError> {
	certificate.get_plain_kyc_attribute(name).map_err(coded)
}

/// Whether `certificate` chains to one of `trusted_roots` at `unix_millis`,
/// using `intermediates` to bridge the chain. The roots are the only trust
/// anchors; the intermediates only help build the path.
pub fn verify(
	certificate: &KycCertificate,
	trusted_roots: &[Certificate],
	intermediates: &[Certificate],
	unix_millis: i64,
) -> Result<bool, CodedError> {
	let moment = DateTime::<Utc>::from_timestamp_millis(unix_millis)
		.ok_or_else(|| CodedError::new(INVALID_DATE, "unix milliseconds out of range"))?;
	let record =
		CertificateRecord { certificate: certificate.to_x509().clone(), intermediates: intermediates.to_vec() };

	let status = evaluate_certificate_chain(&[record], trusted_roots, moment);
	Ok(matches!(status, CertificateChainStatus::Trusted))
}

/// Decrypt the sensitive attribute `name` with the subject's `keypair`.
pub fn decrypt_attribute<K, N>(certificate: &KycCertificate, name: N, keypair: &K) -> Result<Vec<u8>, CodedError>
where
	K: KeyPair,
	N: AsRef<str>,
{
	certificate
		.decrypt_kyc_attribute(name, keypair)
		.map_err(coded)
}

/// Decrypt a sensitive attribute for an erased account, dispatching on the
/// account's signing algorithm. The binding ABIs hold accounts erased over their
/// key type, so this bridges that erased handle to the typed [`decrypt_attribute`].
pub fn decrypt_attribute_with_account<N>(
	certificate: &KycCertificate,
	name: N,
	account: &Arc<GenericAccount>,
) -> Result<Vec<u8>, CodedError>
where
	N: AsRef<str>,
{
	match account.as_ref() {
		GenericAccount::Ed25519(inner) => decrypt_attribute(certificate, name, &inner.keypair),
		GenericAccount::EcdsaSecp256k1(inner) => decrypt_attribute(certificate, name, &inner.keypair),
		GenericAccount::EcdsaSecp256r1(inner) => decrypt_attribute(certificate, name, &inner.keypair),
		_ => Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "attribute decryption requires a signing account")),
	}
}

/// Reduce a KYC certificate error to a stable boundary code, deferring the
/// X.509 case to the base certificate mapping so granular codes survive.
fn coded(error: KycCertificateError) -> CodedError {
	let message = error.to_string();
	match error {
		KycCertificateError::X509Error { source } => CodedError::from(source),
		KycCertificateError::SensitiveAttributeError { .. } => CodedError::new(SENSITIVE_ATTRIBUTE, message),
		KycCertificateError::Asn1Error { .. } => CodedError::new(ASN1_ERROR, message),
		KycCertificateError::KycSchemaError { .. } => CodedError::new(KYC_SCHEMA, message),
		KycCertificateError::AttributeNotFound { .. } => CodedError::new(ATTRIBUTE_NOT_FOUND, message),
		KycCertificateError::InvalidAttributeValue { .. } => CodedError::new(INVALID_ATTRIBUTE_VALUE, message),
		KycCertificateError::MissingRequiredField { .. } => CodedError::new(MISSING_REQUIRED_FIELD, message),
	}
}

#[cfg(test)]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use keetanetwork_account::{Account, KeyECDSASECP256K1};
	use keetanetwork_anchor::doc_utils::{create_secp256k1_test_account, create_test_certificate_builder};
	use keetanetwork_crypto::prelude::IntoSecret;

	use super::*;

	/// Plain attributes embedded in the fixture certificate.
	const PLAIN: &[(&str, &[u8])] = &[("postalCode", b"12345")];
	/// Sensitive attributes embedded in the fixture certificate.
	const SENSITIVE: &[(&str, &[u8])] = &[("email", b"john@example.com"), ("fullName", b"John Doe")];

	/// A fixture KYC certificate and the subject account able to decrypt it.
	fn fixture() -> (KycCertificate, Account<KeyECDSASECP256K1>) {
		let subject = create_secp256k1_test_account(Some(0));
		let issuer = create_secp256k1_test_account(Some(1));

		let mut builder = create_test_certificate_builder(&subject);
		for &(name, value) in PLAIN {
			builder = builder.with_plain_attribute(name, value);
		}
		for &(name, value) in SENSITIVE {
			builder = builder.with_sensitive_attribute(name, value.to_vec().into_secret());
		}

		let certificate = builder.build(&subject.keypair, &issuer.keypair).unwrap();
		(certificate, subject)
	}

	fn now_millis() -> i64 {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_millis() as i64
	}

	#[test]
	fn reports_attribute_presence_and_count() {
		let (certificate, _) = fixture();
		assert!(has_attributes(&certificate));
		assert_eq!(attribute_count(&certificate), PLAIN.len() + SENSITIVE.len());
	}

	#[test]
	fn reads_every_plain_attribute() {
		let (certificate, _) = fixture();
		for &(name, value) in PLAIN {
			assert_eq!(plain_attribute(&certificate, name).unwrap(), value.to_vec());
		}
	}

	#[test]
	fn decrypts_every_sensitive_attribute() {
		let (certificate, subject) = fixture();
		for &(name, value) in SENSITIVE {
			assert_eq!(decrypt_attribute(&certificate, name, &subject.keypair).unwrap(), value.to_vec());
		}
	}

	#[test]
	fn decrypts_every_sensitive_attribute_for_an_erased_subject() {
		let (certificate, subject) = fixture();
		let account = Arc::new(GenericAccount::EcdsaSecp256k1(subject));
		for &(name, value) in SENSITIVE {
			assert_eq!(decrypt_attribute_with_account(&certificate, name, &account).unwrap(), value.to_vec());
		}
	}

	#[test]
	fn round_trips_through_pem_preserving_attributes() {
		let (certificate, subject) = fixture();
		let encoded = pem(&certificate).unwrap();
		let parsed = from_pem(&encoded).unwrap();

		assert_eq!(attribute_count(&parsed), attribute_count(&certificate));
		for &(name, value) in SENSITIVE {
			assert_eq!(decrypt_attribute(&parsed, name, &subject.keypair).unwrap(), value.to_vec());
		}
	}

	#[test]
	fn round_trips_through_der_preserving_attributes() {
		let (certificate, _) = fixture();
		let encoded = der(&certificate).unwrap();
		let parsed = from_der(&encoded).unwrap();
		assert_eq!(attribute_count(&parsed), attribute_count(&certificate));
	}

	#[test]
	fn a_fresh_certificate_is_valid_now() {
		let (certificate, _) = fixture();
		assert!(valid_at(&certificate, now_millis()).unwrap());
	}

	#[test]
	fn a_missing_attribute_is_rejected_with_a_stable_code() {
		let (certificate, _) = fixture();
		let error = plain_attribute(&certificate, "doesNotExist").unwrap_err();
		assert_eq!(error.code, ATTRIBUTE_NOT_FOUND);
	}

	#[test]
	fn reading_a_sensitive_attribute_as_plain_is_rejected() {
		let (certificate, _) = fixture();
		let error = plain_attribute(&certificate, "email").unwrap_err();
		assert_eq!(error.code, SENSITIVE_ATTRIBUTE);
	}

	#[test]
	fn garbage_pem_is_rejected() {
		let error = from_pem("not a certificate").unwrap_err();
		assert!(!error.code.is_empty());
	}

	#[test]
	fn lists_every_attribute_with_its_sensitivity() {
		let (certificate, _) = fixture();
		let listed = attributes(&certificate);
		assert_eq!(listed.len(), PLAIN.len() + SENSITIVE.len());

		let sensitive = listed.iter().filter(|(_, sensitive)| *sensitive).count();
		assert_eq!(sensitive, SENSITIVE.len());
	}

	#[test]
	fn verifies_against_a_trusting_root() {
		let (certificate, _) = fixture();
		let root = certificate.to_x509().clone();
		assert!(verify(&certificate, &[root], &[], now_millis()).unwrap());
	}

	#[test]
	fn rejects_an_empty_trust_set() {
		let (certificate, _) = fixture();
		assert!(!verify(&certificate, &[], &[], now_millis()).unwrap());
	}

	#[test]
	fn rejects_a_foreign_root() {
		let (certificate, _) = fixture();
		let foreign = keetanetwork_anchor::doc_utils::create_test_x509_cert();
		assert!(!verify(&certificate, &[foreign], &[], now_millis()).unwrap());
	}

	#[test]
	fn an_out_of_range_timestamp_is_rejected() {
		let (certificate, _) = fixture();
		let root = certificate.to_x509().clone();
		let error = verify(&certificate, &[root], &[], i64::MAX).unwrap_err();
		assert_eq!(error.code, INVALID_DATE);
	}
}

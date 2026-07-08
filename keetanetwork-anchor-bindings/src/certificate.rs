//! KYC certificate binding ops, layered on the shared base certificate
//! primitive from `keetanetwork-bindings`.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use keetanetwork_account::{Account, AccountError, Accountable, GenericAccount, KeyPair};
use keetanetwork_anchor::certificates::{KycCertificate, KycCertificateBuilder, KycCertificateError};
use keetanetwork_anchor::sensitive_attributes::{SensitiveAttributeProof, SensitiveAttributeProofHash};
use keetanetwork_anchor::trust::{evaluate_certificate_chain, CertificateChainStatus, CertificateRecord};
use keetanetwork_bindings::x509::{
	certificate_der, certificate_from_der, certificate_from_pem, certificate_pem, certificate_valid_at,
	subject_public_key,
};
use keetanetwork_crypto::prelude::{CryptoSignerWithOptions, ExposeSecret, IntoSecret, SignatureEncoding};
use keetanetwork_x509::certificates::Certificate;
use keetanetwork_x509::utils::create_dn;
use keetanetwork_x509::{oids, SerialNumber};

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
pub fn from_pem(certificate: impl AsRef<str>) -> Result<KycCertificate, CodedError> {
	Ok(KycCertificate::new(certificate_from_pem(certificate.as_ref())?))
}

/// Parse a DER-encoded KYC certificate, reusing the base certificate codec.
pub fn from_der(certificate: impl AsRef<[u8]>) -> Result<KycCertificate, CodedError> {
	Ok(KycCertificate::new(certificate_from_der(certificate.as_ref())?))
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
	certificate.has_attributes()
}

/// The number of KYC attributes, plain and sensitive.
pub fn attribute_count(certificate: &KycCertificate) -> usize {
	certificate.attribute_count()
}

/// The KYC attributes the certificate carries, each as its OID `name` paired
/// with whether its value is `sensitive` (encrypted) rather than plain.
pub fn attributes(certificate: &KycCertificate) -> Vec<(String, bool)> {
	certificate
		.attributes()
		.iter()
		.map(|attribute| (attribute.name.to_string(), attribute.is_sensitive()))
		.collect()
}

/// The plain-text value of the non-sensitive attribute `name`.
pub fn plain_attribute<N: AsRef<str>>(certificate: &KycCertificate, name: N) -> Result<Vec<u8>, CodedError> {
	certificate.get_plain_attribute(name).map_err(coded)
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
	certificate.decrypt_attribute(name, keypair).map_err(coded)
}

/// One discovered external blob reference, flattened for boundary transport:
/// the carrying `attribute` name, the uppercase-hex digest `id`, and the
/// reference's location and algorithm fields as strings.
pub struct ExternalReferenceRecord {
	/// The attribute name carrying the reference.
	pub attribute: String,
	/// The uppercase-hex digest id keying the reference.
	pub id: String,
	/// The URL serving the stored blob.
	pub url: String,
	/// The MIME type of the blob plaintext.
	pub content_type: String,
	/// The digest algorithm's symbolic name.
	pub digest_algorithm: String,
	/// The encryption algorithm's symbolic name.
	pub encryption_algorithm: String,
}

/// The external blob references carried by the named attributes, discovered
/// with the erased `subject` account and flattened to one record per reference.
pub fn external_references_with_account(
	certificate: &KycCertificate,
	subject: &Arc<GenericAccount>,
	names: &[String],
) -> Result<Vec<ExternalReferenceRecord>, CodedError> {
	let discovered = certificate
		.external_references(subject.as_ref(), names)
		.map_err(coded)?;

	let records = discovered
		.into_iter()
		.flat_map(|(attribute, references)| {
			references
				.into_iter()
				.map(move |reference| ExternalReferenceRecord {
					attribute: attribute.clone(),
					id: reference.id(),
					url: reference.external.url,
					content_type: reference.external.content_type,
					digest_algorithm: reference.digest.algorithm_name(),
					encryption_algorithm: reference.encryption.to_string(),
				})
		})
		.collect();

	Ok(records)
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

/// A proof attesting to a sensitive attribute's committed value, validated
/// against the certificate with only the subject's public key. `value` is the
/// base64 attribute value the proof reveals.
pub struct AttributeProof {
	pub value: String,
	pub salt: String,
}

impl From<SensitiveAttributeProof> for AttributeProof {
	fn from(proof: SensitiveAttributeProof) -> Self {
		Self { value: proof.value.expose_secret().clone(), salt: proof.hash.salt }
	}
}

impl From<AttributeProof> for SensitiveAttributeProof {
	fn from(proof: AttributeProof) -> Self {
		Self { value: proof.value.into_secret(), hash: SensitiveAttributeProofHash { salt: proof.salt } }
	}
}

/// Prove the sensitive attribute `name`, decrypting it with the subject's
/// `keypair`. The proof validates against this certificate without the private
/// key, so it can be shared for selective disclosure.
pub fn prove_attribute<K, N>(certificate: &KycCertificate, name: N, keypair: &K) -> Result<AttributeProof, CodedError>
where
	K: KeyPair,
	N: AsRef<str>,
{
	certificate
		.prove_attribute(name, keypair)
		.map(AttributeProof::from)
		.map_err(coded)
}

/// Prove a sensitive attribute for an erased account, dispatching on its signing
/// algorithm.
pub fn prove_attribute_with_account<N>(
	certificate: &KycCertificate,
	name: N,
	account: &Arc<GenericAccount>,
) -> Result<AttributeProof, CodedError>
where
	N: AsRef<str>,
{
	match account.as_ref() {
		GenericAccount::Ed25519(inner) => prove_attribute(certificate, name, &inner.keypair),
		GenericAccount::EcdsaSecp256k1(inner) => prove_attribute(certificate, name, &inner.keypair),
		GenericAccount::EcdsaSecp256r1(inner) => prove_attribute(certificate, name, &inner.keypair),
		_ => Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "attribute proof requires a signing account")),
	}
}

/// Validate a `proof` for the sensitive attribute `name` against this
/// certificate, using `keypair`'s public key.
pub fn validate_attribute_proof<K, N>(
	certificate: &KycCertificate,
	name: N,
	keypair: &K,
	proof: AttributeProof,
) -> Result<bool, CodedError>
where
	K: KeyPair,
	N: AsRef<str>,
{
	certificate
		.validate_attribute_proof(name, keypair, proof.into())
		.map_err(coded)
}

/// Validate an attribute `proof` for an erased account, dispatching on its
/// signing algorithm.
pub fn validate_attribute_proof_with_account<N>(
	certificate: &KycCertificate,
	name: N,
	account: &Arc<GenericAccount>,
	proof: AttributeProof,
) -> Result<bool, CodedError>
where
	N: AsRef<str>,
{
	match account.as_ref() {
		GenericAccount::Ed25519(inner) => validate_attribute_proof(certificate, name, &inner.keypair, proof),
		GenericAccount::EcdsaSecp256k1(inner) => validate_attribute_proof(certificate, name, &inner.keypair, proof),
		GenericAccount::EcdsaSecp256r1(inner) => validate_attribute_proof(certificate, name, &inner.keypair, proof),
		_ => Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "attribute proof requires a signing account")),
	}
}

/// One attribute to embed at issuance: its OID `name`, whether its value is
/// `sensitive` (encrypted to the subject) rather than plain, and the semantic
/// `value` bytes the KYC codec encodes.
pub struct IssueAttribute {
	pub name: String,
	pub sensitive: bool,
	pub value: Vec<u8>,
}

/// Issue a KYC leaf signed by `issuer` for `subject`, embedding `attributes`
/// (sensitive ones encrypted to the subject). `subject` and `issuer` may use
/// different signing algorithms. Validity bounds are Unix seconds; the caller
/// supplies them since a component has no clock.
#[allow(clippy::too_many_arguments)]
pub fn issue(
	subject: &GenericAccount,
	issuer: &GenericAccount,
	subject_dn: impl AsRef<str>,
	issuer_dn: impl AsRef<str>,
	serial: u64,
	not_before_secs: i64,
	not_after_secs: i64,
	is_ca: bool,
	attributes: &[IssueAttribute],
) -> Result<KycCertificate, CodedError> {
	let not_before = timestamp(not_before_secs)?;
	let not_after = timestamp(not_after_secs)?;
	let builder =
		configure(subject, subject_dn.as_ref(), issuer_dn.as_ref(), serial, not_before, not_after, is_ca, attributes)?;

	dispatch_build(builder, subject, issuer)
}

/// A Unix-second timestamp as a UTC moment, or a stable code when out of range.
fn timestamp(seconds: i64) -> Result<DateTime<Utc>, CodedError> {
	DateTime::<Utc>::from_timestamp(seconds, 0)
		.ok_or_else(|| CodedError::new(INVALID_DATE, "unix seconds out of range"))
}

/// Configure the leaf builder with names, serial, validity, subject key, and
/// attributes; the caller signs it through [`dispatch_build`].
#[allow(clippy::too_many_arguments)]
fn configure(
	subject: &GenericAccount,
	subject_dn: &str,
	issuer_dn: &str,
	serial: u64,
	not_before: DateTime<Utc>,
	not_after: DateTime<Utc>,
	is_ca: bool,
	attributes: &[IssueAttribute],
) -> Result<KycCertificateBuilder, CodedError> {
	let public_key = subject_public_key(subject)?;
	let subject_name = create_dn(&[(oids::CN, subject_dn)])?;
	let issuer_name = create_dn(&[(oids::CN, issuer_dn)])?;
	let base = if is_ca {
		KycCertificateBuilder::for_ca()
	} else {
		KycCertificateBuilder::for_end_entity()
	};
	let mut builder = base
		.with_subject_dn(subject_name)
		.with_issuer_dn(issuer_name)
		.with_serial_number(SerialNumber::from(serial))
		.with_validity(not_before, not_after)
		.with_subject_public_key(public_key);

	for attribute in attributes {
		builder = if attribute.sensitive {
			builder.with_sensitive_attribute(&attribute.name, attribute.value.clone().into_secret())
		} else {
			builder.with_plain_attribute(&attribute.name, &attribute.value)
		};
	}

	Ok(builder)
}

/// Resolve the erased subject and issuer to their concrete key types, then
/// build: the subject key encrypts sensitive attributes, the issuer key signs.
fn dispatch_build(
	builder: KycCertificateBuilder,
	subject: &GenericAccount,
	issuer: &GenericAccount,
) -> Result<KycCertificate, CodedError> {
	match (subject, issuer) {
		(GenericAccount::Ed25519(sub), GenericAccount::Ed25519(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::Ed25519(sub), GenericAccount::EcdsaSecp256k1(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::Ed25519(sub), GenericAccount::EcdsaSecp256r1(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::EcdsaSecp256k1(sub), GenericAccount::Ed25519(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::EcdsaSecp256k1(sub), GenericAccount::EcdsaSecp256k1(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::EcdsaSecp256k1(sub), GenericAccount::EcdsaSecp256r1(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::EcdsaSecp256r1(sub), GenericAccount::Ed25519(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::EcdsaSecp256r1(sub), GenericAccount::EcdsaSecp256k1(iss)) => build_typed(builder, sub, iss),
		(GenericAccount::EcdsaSecp256r1(sub), GenericAccount::EcdsaSecp256r1(iss)) => build_typed(builder, sub, iss),
		_ => Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "issuance requires signing accounts for subject and issuer")),
	}
}

/// Build the leaf with a typed subject (encryption) and issuer (signature).
fn build_typed<TSubject, TSigning, S>(
	builder: KycCertificateBuilder,
	subject: &Account<TSubject>,
	signer: &Account<TSigning>,
) -> Result<KycCertificate, CodedError>
where
	Account<TSubject>: TryFrom<Accountable<TSubject>, Error = AccountError>,
	Account<TSigning>: TryFrom<Accountable<TSigning>, Error = AccountError>,
	TSubject: KeyPair,
	TSigning: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	builder
		.build(&subject.keypair, &signer.keypair)
		.map_err(coded)
}

/// Reduce a KYC certificate error to a stable boundary code, deferring the
/// X.509 case to the base certificate mapping so granular codes survive.
pub fn coded(error: KycCertificateError) -> CodedError {
	let message = error.to_string();
	match error {
		KycCertificateError::X509Error { source } => CodedError::from(source),
		KycCertificateError::SensitiveAttributeError { .. } => CodedError::new(SENSITIVE_ATTRIBUTE, message),
		KycCertificateError::Asn1Error { .. } => CodedError::new(ASN1_ERROR, message),
		KycCertificateError::KycSchemaError { .. } => CodedError::new(KYC_SCHEMA, message),
		KycCertificateError::AttributeNotFound { .. } => CodedError::new(ATTRIBUTE_NOT_FOUND, message),
		KycCertificateError::InvalidAttributeValue { .. } => CodedError::new(INVALID_ATTRIBUTE_VALUE, message),
		KycCertificateError::MissingRequiredField { .. } => CodedError::new(MISSING_REQUIRED_FIELD, message),
		KycCertificateError::UnsupportedSubjectKey => CodedError::new(UNSUPPORTED_KEY_TYPE, message),
	}
}

#[cfg(test)]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use keetanetwork_account::{Account, KeyECDSASECP256K1};
	use keetanetwork_anchor::doc_utils::{
		create_ed25519_test_account, create_secp256k1_test_account, create_test_certificate_builder,
	};
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

		let certificate = builder
			.build(&subject.keypair, &issuer.keypair)
			.expect("fixture certificate builds");
		(certificate, subject)
	}

	fn now_millis() -> i64 {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("system time is after the unix epoch")
			.as_millis() as i64
	}

	#[test]
	fn reports_attribute_presence_and_count() {
		let (certificate, _) = fixture();
		assert!(has_attributes(&certificate));
		assert_eq!(attribute_count(&certificate), PLAIN.len() + SENSITIVE.len());
	}

	#[test]
	fn reads_every_plain_attribute() -> Result<(), CodedError> {
		let (certificate, _) = fixture();
		for &(name, value) in PLAIN {
			assert_eq!(plain_attribute(&certificate, name)?, value.to_vec());
		}
		Ok(())
	}

	#[test]
	fn decrypts_every_sensitive_attribute() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		for &(name, value) in SENSITIVE {
			assert_eq!(decrypt_attribute(&certificate, name, &subject.keypair)?, value.to_vec());
		}
		Ok(())
	}

	#[test]
	fn decrypts_every_sensitive_attribute_for_an_erased_subject() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let account = Arc::new(GenericAccount::EcdsaSecp256k1(subject));
		for &(name, value) in SENSITIVE {
			assert_eq!(decrypt_attribute_with_account(&certificate, name, &account)?, value.to_vec());
		}
		Ok(())
	}

	#[test]
	fn round_trips_through_pem_preserving_attributes() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let encoded = pem(&certificate)?;
		let parsed = from_pem(&encoded)?;

		assert_eq!(attribute_count(&parsed), attribute_count(&certificate));
		for &(name, value) in SENSITIVE {
			assert_eq!(decrypt_attribute(&parsed, name, &subject.keypair)?, value.to_vec());
		}
		Ok(())
	}

	#[test]
	fn round_trips_through_der_preserving_attributes() -> Result<(), CodedError> {
		let (certificate, _) = fixture();
		let encoded = der(&certificate)?;
		let parsed = from_der(&encoded)?;
		assert_eq!(attribute_count(&parsed), attribute_count(&certificate));
		Ok(())
	}

	#[test]
	fn a_fresh_certificate_is_valid_now() -> Result<(), CodedError> {
		let (certificate, _) = fixture();
		assert!(valid_at(&certificate, now_millis())?);
		Ok(())
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
	fn verifies_against_a_trusting_root() -> Result<(), CodedError> {
		let (certificate, _) = fixture();
		let root = certificate.to_x509().clone();
		assert!(verify(&certificate, &[root], &[], now_millis())?);
		Ok(())
	}

	#[test]
	fn rejects_an_empty_trust_set() -> Result<(), CodedError> {
		let (certificate, _) = fixture();
		assert!(!verify(&certificate, &[], &[], now_millis())?);
		Ok(())
	}

	#[test]
	fn rejects_a_foreign_root() -> Result<(), CodedError> {
		let (certificate, _) = fixture();
		let foreign = keetanetwork_anchor::doc_utils::create_test_x509_cert();
		assert!(!verify(&certificate, &[foreign], &[], now_millis())?);
		Ok(())
	}

	#[test]
	fn an_out_of_range_timestamp_is_rejected() {
		let (certificate, _) = fixture();
		let root = certificate.to_x509().clone();
		let error = verify(&certificate, &[root], &[], i64::MAX).unwrap_err();
		assert_eq!(error.code, INVALID_DATE);
	}

	#[test]
	fn issues_across_algorithms_and_reads_back() -> Result<(), CodedError> {
		let subject = Arc::new(GenericAccount::Ed25519(create_ed25519_test_account(Some(0))));
		let issuer = Arc::new(GenericAccount::EcdsaSecp256k1(create_secp256k1_test_account(Some(1))));
		let attributes = [
			IssueAttribute { name: "postalCode".to_string(), sensitive: false, value: b"12345".to_vec() },
			IssueAttribute { name: "email".to_string(), sensitive: true, value: b"john@example.com".to_vec() },
		];
		let not_before = now_millis() / 1000;
		let not_after = not_before + 31_536_000;

		let certificate = issue(
			subject.as_ref(),
			issuer.as_ref(),
			"Subject",
			"Issuer",
			7,
			not_before,
			not_after,
			false,
			&attributes,
		)?;

		assert_eq!(plain_attribute(&certificate, "postalCode")?, b"12345".to_vec());
		assert_eq!(decrypt_attribute_with_account(&certificate, "email", &subject)?, b"john@example.com".to_vec());
		Ok(())
	}

	#[test]
	fn proves_and_validates_every_sensitive_attribute() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		for &(name, _) in SENSITIVE {
			let proof = prove_attribute(&certificate, name, &subject.keypair)?;
			assert!(validate_attribute_proof(&certificate, name, &subject.keypair, proof)?);
		}
		Ok(())
	}

	#[test]
	fn proves_and_validates_for_an_erased_subject() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let account = Arc::new(GenericAccount::EcdsaSecp256k1(subject));
		for &(name, _) in SENSITIVE {
			let proof = prove_attribute_with_account(&certificate, name, &account)?;
			assert!(validate_attribute_proof_with_account(&certificate, name, &account, proof)?);
		}
		Ok(())
	}

	#[test]
	fn a_proof_does_not_validate_against_a_different_attribute() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let proof = prove_attribute(&certificate, "fullName", &subject.keypair)?;
		assert!(!validate_attribute_proof(&certificate, "email", &subject.keypair, proof)?);
		Ok(())
	}

	#[test]
	fn proving_a_plain_attribute_is_rejected() {
		let (certificate, subject) = fixture();
		let code = prove_attribute(&certificate, "postalCode", &subject.keypair)
			.err()
			.map(|error| error.code);
		assert_eq!(code, Some(SENSITIVE_ATTRIBUTE.to_string()));
	}

	#[test]
	fn issuing_with_an_out_of_range_validity_is_rejected() {
		let subject = Arc::new(GenericAccount::EcdsaSecp256k1(create_secp256k1_test_account(Some(0))));
		let issuer = Arc::new(GenericAccount::EcdsaSecp256k1(create_secp256k1_test_account(Some(1))));

		let error = issue(subject.as_ref(), issuer.as_ref(), "Subject", "Issuer", 1, i64::MAX, i64::MAX, false, &[])
			.unwrap_err();
		assert_eq!(error.code, INVALID_DATE);
	}
}

//! Sharable certificate attribute binding ops over the core
//! [`SharableCertificateAttributes`].
//!
//! A sharable bundle seals a selected subset of a certificate's attributes for
//! a chosen recipient set. Accounts cross every binding boundary erased and
//! shared as [`Arc<GenericAccount>`], so principal sets and the proving subject
//! are passed by shared reference.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::account::AccountPublicKey;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::certificates::KycCertificate;
use keetanetwork_anchor::sharable_attributes::error::SharableAttributesError;
use keetanetwork_anchor::sharable_attributes::SharableCertificateAttributes;
use keetanetwork_x509::certificates::Certificate as X509Certificate;

use crate::error::CodedError;
use crate::{certificate as cert_ops, encrypted_container as ec_ops};

/// Code for an X.509 certificate failure inside a sharable bundle.
pub const X509_ERROR: &str = "X509_ERROR";
/// Code for an account-layer failure reconstructing the subject.
pub const ACCOUNT_ERROR: &str = "ACCOUNT_ERROR";
/// Code for an ASN.1 failure decoding a disclosed value.
pub const ASN1_ERROR: &str = "ASN1_ERROR";
/// Code for a disclosed attribute absent from the certificate.
pub const ATTRIBUTE_NOT_FOUND: &str = "ATTRIBUTE_NOT_FOUND";
/// Code for a disclosed attribute whose sensitivity disagrees with the source.
pub const SENSITIVITY_MISMATCH: &str = "SENSITIVITY_MISMATCH";
/// Code for a plain disclosed value that disagrees with the source.
pub const VALUE_MISMATCH: &str = "VALUE_MISMATCH";
/// Code for a sensitive-attribute proof that fails validation.
pub const PROOF_VALIDATION_FAILED: &str = "PROOF_VALIDATION_FAILED";
/// Code for a subject public key that cannot be reconstructed for validation.
pub const UNSUPPORTED_SUBJECT_KEY: &str = "UNSUPPORTED_SUBJECT_KEY";
/// Code for an export with no authorized recipients.
pub const NO_PRINCIPALS: &str = "NO_PRINCIPALS";
/// Code for a malformed PEM envelope.
pub const INVALID_PEM: &str = "INVALID_PEM";
/// Code for malformed JSON contents.
pub const INVALID_JSON: &str = "INVALID_JSON";
/// Code for a malformed base64 value.
pub const INVALID_BASE64: &str = "INVALID_BASE64";

/// Build a sharable bundle from `certificate`, proving or copying each named
/// attribute with the `subject` account and sealing the result. Grant access to
/// a recipient before exporting.
pub fn from_certificate(
	certificate: &KycCertificate,
	subject: &Arc<GenericAccount>,
	intermediates: &[X509Certificate],
	names: &[String],
) -> Result<SharableCertificateAttributes, CodedError> {
	SharableCertificateAttributes::from_certificate(certificate, subject.as_ref(), intermediates, names).map_err(coded)
}

/// Open a sharable bundle from its encoded container bytes with `principals`.
pub fn from_encoded(
	data: impl AsRef<[u8]>,
	principals: &[Arc<GenericAccount>],
) -> Result<SharableCertificateAttributes, CodedError> {
	SharableCertificateAttributes::from_encoded(data, principals.iter().cloned()).map_err(coded)
}

/// Open a sharable bundle from its PEM envelope with `principals`.
pub fn from_pem(
	pem: impl AsRef<str>,
	principals: &[Arc<GenericAccount>],
) -> Result<SharableCertificateAttributes, CodedError> {
	SharableCertificateAttributes::from_pem(pem, principals.iter().cloned()).map_err(coded)
}

/// Grant `accounts` access to the sealed contents.
pub fn grant_access(
	sharable: &mut SharableCertificateAttributes,
	accounts: &[Arc<GenericAccount>],
) -> Result<(), CodedError> {
	sharable
		.grant_access(accounts.iter().cloned())
		.map_err(coded)?;
	Ok(())
}

/// Revoke the account identified by its type-prefixed public key.
pub fn revoke_access(
	sharable: &mut SharableCertificateAttributes,
	public_key: impl AsRef<[u8]>,
) -> Result<(), CodedError> {
	sharable.revoke_access(public_key).map_err(coded)?;
	Ok(())
}

/// The type-prefixed public keys of the accounts authorized to open the bundle.
pub fn principals(sharable: &SharableCertificateAttributes) -> Result<Vec<Vec<u8>>, CodedError> {
	let principals = sharable.principals().map_err(coded)?;
	Ok(principals
		.iter()
		.map(|account| account.to_public_key_with_type())
		.collect())
}

/// The DER-encoded container bytes, requiring at least one granted recipient.
pub fn export(sharable: &mut SharableCertificateAttributes) -> Result<Vec<u8>, CodedError> {
	sharable.export().map_err(coded)
}

/// The container exported as a PEM envelope.
pub fn to_pem(sharable: &mut SharableCertificateAttributes) -> Result<String, CodedError> {
	sharable.to_pem().map_err(coded)
}

/// The embedded leaf certificate.
pub fn certificate(sharable: &mut SharableCertificateAttributes) -> Result<KycCertificate, CodedError> {
	sharable.certificate().map_err(coded)
}

/// The embedded intermediate certificate chain.
pub fn intermediates(sharable: &mut SharableCertificateAttributes) -> Result<Vec<X509Certificate>, CodedError> {
	sharable.intermediates().map_err(coded)
}

/// The names of the disclosed attributes.
pub fn attribute_names(sharable: &mut SharableCertificateAttributes) -> Result<Vec<String>, CodedError> {
	sharable.attribute_names().map_err(coded)
}

/// The validated raw disclosed value for `name`, if present.
pub fn attribute_buffer(
	sharable: &mut SharableCertificateAttributes,
	name: impl AsRef<str>,
) -> Result<Option<Vec<u8>>, CodedError> {
	sharable.attribute_buffer(name).map_err(coded)
}

/// The schema-decoded semantic value for `name`, if present.
pub fn attribute_value(
	sharable: &mut SharableCertificateAttributes,
	name: impl AsRef<str>,
) -> Result<Option<Vec<u8>>, CodedError> {
	sharable.attribute_value(name).map_err(coded)
}

/// Reduce a sharable-attributes error to a stable boundary code, deferring the
/// container and certificate cases to their own mappings so granular codes
/// survive.
pub fn coded(error: SharableAttributesError) -> CodedError {
	let message = error.to_string();
	match error {
		SharableAttributesError::Container { source } => ec_ops::coded(source),
		SharableAttributesError::Certificate { source } => cert_ops::coded(source),
		SharableAttributesError::X509 { .. } => CodedError::new(X509_ERROR, message),
		SharableAttributesError::Account { .. } => CodedError::new(ACCOUNT_ERROR, message),
		SharableAttributesError::Asn1 { .. } => CodedError::new(ASN1_ERROR, message),
		SharableAttributesError::AttributeNotFound { .. } => CodedError::new(ATTRIBUTE_NOT_FOUND, message),
		SharableAttributesError::SensitivityMismatch { .. } => CodedError::new(SENSITIVITY_MISMATCH, message),
		SharableAttributesError::ValueMismatch { .. } => CodedError::new(VALUE_MISMATCH, message),
		SharableAttributesError::ProofValidationFailed { .. } => CodedError::new(PROOF_VALIDATION_FAILED, message),
		SharableAttributesError::UnsupportedSubjectKey => CodedError::new(UNSUPPORTED_SUBJECT_KEY, message),
		SharableAttributesError::NoPrincipals => CodedError::new(NO_PRINCIPALS, message),
		SharableAttributesError::InvalidPem => CodedError::new(INVALID_PEM, message),
		SharableAttributesError::InvalidJson => CodedError::new(INVALID_JSON, message),
		SharableAttributesError::InvalidBase64 => CodedError::new(INVALID_BASE64, message),
	}
}

#[cfg(test)]
mod tests {
	use keetanetwork_anchor::doc_utils::{
		create_secp256k1_generic_account, create_secp256k1_test_account, create_test_certificate_builder,
	};
	use keetanetwork_crypto::prelude::IntoSecret;

	use super::*;

	/// The plain attribute embedded in the fixture certificate.
	const PLAIN: (&str, &[u8]) = ("postalCode", b"12345");
	/// The sensitive attribute embedded in the fixture certificate.
	const SENSITIVE: (&str, &[u8]) = ("email", b"john@example.com");

	/// A fixture leaf certificate and the subject account able to prove it.
	fn fixture() -> (KycCertificate, Arc<GenericAccount>) {
		let subject = create_secp256k1_test_account(Some(0));
		let issuer = create_secp256k1_test_account(Some(1));
		let certificate = create_test_certificate_builder(&subject)
			.with_plain_attribute(PLAIN.0, PLAIN.1)
			.with_sensitive_attribute(SENSITIVE.0, SENSITIVE.1.to_vec().into_secret())
			.build(&subject.keypair, &issuer.keypair)
			.expect("fixture certificate builds");

		(certificate, Arc::new(GenericAccount::EcdsaSecp256k1(subject)))
	}

	/// A recipient account derived from the doc seed at `index`.
	fn recipient(index: u32) -> Arc<GenericAccount> {
		Arc::new(create_secp256k1_generic_account(Some(index)))
	}

	#[test]
	fn round_trips_through_pem_disclosing_every_attribute() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let names = [PLAIN.0.to_string(), SENSITIVE.0.to_string()];
		let mut sharable = from_certificate(&certificate, &subject, &[], &names)?;

		grant_access(&mut sharable, &[recipient(2)])?;

		let pem = to_pem(&mut sharable)?;
		let mut opened = from_pem(&pem, &[recipient(2)])?;
		assert_eq!(attribute_value(&mut opened, PLAIN.0)?, Some(PLAIN.1.to_vec()));
		assert_eq!(attribute_value(&mut opened, SENSITIVE.0)?, Some(SENSITIVE.1.to_vec()));
		Ok(())
	}

	#[test]
	fn lists_the_disclosed_attribute_names() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let names = [SENSITIVE.0.to_string()];
		let mut sharable = from_certificate(&certificate, &subject, &[], &names)?;

		grant_access(&mut sharable, &[recipient(2)])?;

		assert_eq!(attribute_names(&mut sharable)?, names.to_vec());
		Ok(())
	}

	#[test]
	fn export_without_a_recipient_is_rejected() {
		let (certificate, subject) = fixture();
		let names = [SENSITIVE.0.to_string()];
		let build = from_certificate(&certificate, &subject, &[], &names);
		let code = build
			.and_then(|mut sharable| export(&mut sharable))
			.err()
			.map(|error| error.code);
		assert_eq!(code, Some(NO_PRINCIPALS.to_string()));
	}

	#[test]
	fn a_missing_attribute_discloses_nothing() -> Result<(), CodedError> {
		let (certificate, subject) = fixture();
		let names = [SENSITIVE.0.to_string()];
		let mut sharable = from_certificate(&certificate, &subject, &[], &names)?;

		grant_access(&mut sharable, &[recipient(2)])?;

		let pem = to_pem(&mut sharable)?;
		let mut opened = from_pem(&pem, &[recipient(2)])?;
		assert_eq!(attribute_buffer(&mut opened, "doesNotExist")?, None);
		Ok(())
	}
}

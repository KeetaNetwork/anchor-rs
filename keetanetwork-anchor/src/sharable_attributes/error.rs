use alloc::string::String;

use snafu::Snafu;

use crate::asn1::error::AnchorAsn1Error;
use crate::certificates::KycCertificateError;
use crate::encrypted_container::EncryptedContainerError;
use crate::kyc_schema::KycSchemaError;

/// Result type for
/// [`SharableCertificateAttributes`](super::SharableCertificateAttributes)
/// operations.
pub type Result<T> = core::result::Result<T, SharableAttributesError>;

/// A failure building, opening, validating, or exporting sharable certificate
/// attributes.
#[derive(Debug, Clone, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum SharableAttributesError {
	#[snafu(display("Encrypted container error: {source}"))]
	Container { source: EncryptedContainerError },

	#[snafu(display("Certificate error: {source}"))]
	Certificate { source: KycCertificateError },

	#[snafu(display("X.509 certificate error: {source}"))]
	X509 { source: keetanetwork_x509::error::CertificateError },

	#[snafu(display("Account error: {source}"))]
	Account { source: keetanetwork_account::error::AccountError },

	#[snafu(display("ASN.1 error: {source}"))]
	Asn1 { source: AnchorAsn1Error },

	#[snafu(display("Attribute not found: {name}"))]
	AttributeNotFound { name: String },

	#[snafu(display("Attribute sensitivity mismatch with certificate: {name}"))]
	SensitivityMismatch { name: String },

	#[snafu(display("Attribute value mismatch with certificate: {name}"))]
	ValueMismatch { name: String },

	#[snafu(display("Attribute proof validation failed: {name}"))]
	ProofValidationFailed { name: String },

	/// The subject public key in the certificate uses a key type that cannot be
	/// reconstructed for proof validation.
	#[snafu(display("Unsupported subject public key type"))]
	UnsupportedSubjectKey,

	#[snafu(display("Container has no authorized principals to export to"))]
	NoPrincipals,

	#[snafu(display("Malformed PEM envelope"))]
	InvalidPem,

	#[snafu(display("Malformed JSON contents"))]
	InvalidJson,

	#[snafu(display("Malformed base64 value"))]
	InvalidBase64,

	/// A supplied or inlined reference blob does not hash to its digest
	#[snafu(display("Reference digest mismatch for {name}/{id}"))]
	ReferenceDigestMismatch { name: String, id: String },

	/// A supplied reference blob is not a container the subject can open
	#[snafu(display("Reference decrypt failed for {name}/{id}: {source}"))]
	ReferenceDecrypt { name: String, id: String, source: EncryptedContainerError },
}

crate::impl_source_error_from!(SharableAttributesError, {
	EncryptedContainerError => Container,
	KycCertificateError => Certificate,
	keetanetwork_x509::error::CertificateError => X509,
	keetanetwork_account::error::AccountError => Account,
	AnchorAsn1Error => Asn1,
});

crate::impl_source_error_from_via!(SharableAttributesError, {
	rasn::error::DecodeError => Asn1 via AnchorAsn1Error,
	rasn::error::EncodeError => Asn1 via AnchorAsn1Error,
	KycSchemaError => Certificate via KycCertificateError,
});

crate::impl_variant_error_from!(SharableAttributesError, {
	serde_json::Error => InvalidJson,
	base64::DecodeError => InvalidBase64,
});

#[cfg(test)]
mod tests {
	use keetanetwork_utils::{test_error_from_conversions, test_error_variants};

	use super::*;

	test_error_from_conversions!(
		test_from_conversions,
		SharableAttributesError,
		[
			EncryptedContainerError::NoMatchingKey,
			KycCertificateError::AttributeNotFound { name: "email".to_string() },
			keetanetwork_account::error::AccountError::InvalidKeyType,
			AnchorAsn1Error::InvalidOid { reason: "test".to_string() },
		]
	);

	test_error_variants!(
		test_error_variants,
		[
			SharableAttributesError::AttributeNotFound { name: "email".to_string() },
			SharableAttributesError::SensitivityMismatch { name: "email".to_string() },
			SharableAttributesError::ValueMismatch { name: "email".to_string() },
			SharableAttributesError::ProofValidationFailed { name: "email".to_string() },
			SharableAttributesError::UnsupportedSubjectKey,
			SharableAttributesError::NoPrincipals,
			SharableAttributesError::InvalidPem,
			SharableAttributesError::InvalidJson,
			SharableAttributesError::InvalidBase64,
			SharableAttributesError::ReferenceDigestMismatch {
				name: "documentDriversLicense".to_string(),
				id: "AB".to_string()
			},
			SharableAttributesError::ReferenceDecrypt {
				name: "documentDriversLicense".to_string(),
				id: "AB".to_string(),
				source: EncryptedContainerError::NoMatchingKey,
			},
		]
	);
}

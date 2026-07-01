//! Selectively disclosed, sharable certificate attributes.
//!
//! A [`SharableCertificateAttributes`] composes a [`KycCertificate`] and an
//! [`EncryptedContainer`] to share a chosen subset of a certificate's attributes
//! with a chosen set of recipients. The leaf certificate, optional intermediate
//! chain, sensitive-attribute proofs, and plain-attribute values are serialized
//! to JSON (matching the TypeScript `SharableCertificateAttributes` schema),
//! sealed in an encrypted container, and exported as a PEM envelope.
//!
//! # Examples
//!
//! ```rust
//! # use keetanetwork_anchor::doc_utils;
//! use keetanetwork_account::GenericAccount;
//! use keetanetwork_anchor::certificates::KycCertificateBuilder;
//! use keetanetwork_anchor::sharable_attributes::SharableCertificateAttributes;
//! use keetanetwork_asn1::SubjectPublicKeyInfo;
//! use keetanetwork_crypto::prelude::IntoSecret;
//! use keetanetwork_x509::utils::create_dn;
//! use keetanetwork_x509::SerialNumber;
//!
//! # let subject = doc_utils::create_secp256k1_test_account(Some(0));
//! # let issuer = doc_utils::create_secp256k1_test_account(Some(1));
//! # let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Subject")])?;
//! # let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Issuer")])?;
//! # let reader = doc_utils::create_secp256k1_generic_account(Some(2));
//! # let reader_again = doc_utils::create_secp256k1_generic_account(Some(2));
//! let certificate = KycCertificateBuilder::for_end_entity()
//!     .with_subject_dn(subject_dn)
//!     .with_issuer_dn(issuer_dn)
//!     .with_serial_number(SerialNumber::from(7u64))
//!     .with_validity_days(365)
//!     .with_subject_public_key(SubjectPublicKeyInfo::try_from(&subject)?)
//!     .with_sensitive_attribute("email", b"john@example.com".to_vec().into_secret())
//!     .build(&subject.keypair, &issuer.keypair)?;
//!
//! let subject_account = GenericAccount::EcdsaSecp256k1(subject);
//!
//! let mut sharable =
//!     SharableCertificateAttributes::from_certificate(&certificate, &subject_account, &[], ["email"])?;
//! sharable.grant_access([reader])?;
//! let pem = sharable.to_pem()?;
//!
//! let mut opened = SharableCertificateAttributes::from_pem(&pem, [reader_again])?;
//! // Sensitive values are disclosed as their DER-encoded proof value.
//! assert_eq!(opened.attribute_names()?, vec!["email".to_string()]);
//! assert!(opened.attribute_buffer("email")?.is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod contents;
pub mod error;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_account::{
	Account, AccountPublicKey, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair,
	KeyPairType, Keyable,
};
use keetanetwork_asn1::{BitStringExt, SubjectPublicKeyInfo};
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret};
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use rasn::types::ObjectIdentifier;

use crate::asn1::oids;
use crate::certificates::KycCertificate;
use crate::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
use crate::kyc_schema::codec::decode_value;
use crate::sensitive_attributes::{SensitiveAttributeProof, SensitiveAttributeProofHash};
use crate::sharable_attributes::contents::{
	AttributeEntry, AttributeValueJson, ContentsJson, ProofHashJson, ProofJson,
};
use crate::sharable_attributes::error::{Result, SharableAttributesError};
use crate::utils::{base64_decode, base64_encode};

pub use crate::sharable_attributes::error::SharableAttributesError as Error;

const PEM_BEGIN: &str = "-----BEGIN KYC CERTIFICATE PROOF-----";
const PEM_END: &str = "-----END KYC CERTIFICATE PROOF-----";
const PEM_LINE_LENGTH: usize = 64;
const ZLIB_MAGIC: u8 = 0x78;

/// A disclosed attribute decoded from a sharable container, validated against
/// the embedded certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct DisclosedAttribute {
	/// Whether the source certificate attribute is sensitive (encrypted).
	pub sensitive: bool,
	/// The disclosed plaintext: the decrypted value for sensitive attributes,
	/// or the raw certificate value for plain attributes.
	pub value: Vec<u8>,
	/// External blob references preserved from the source. Resolution of the
	/// referenced blobs is the caller's concern.
	pub references: BTreeMap<String, String>,
}

/// The certificate, intermediate chain, and validated attributes recovered from
/// a sharable container.
#[derive(Debug)]
struct Populated {
	certificate: KycCertificate,
	intermediates: Vec<X509Certificate>,
	attributes: BTreeMap<String, DisclosedAttribute>,
}

/// A certificate with a selectively disclosed subset of its attributes, sealed
/// in an [`EncryptedContainer`] for sharing.
///
/// Disclosed values are validated lazily on first access and cached. Granting or
/// revoking access does not change the disclosed contents.
#[derive(Debug)]
pub struct SharableCertificateAttributes {
	container: EncryptedContainer,
	populated: Option<Populated>,
}

impl SharableCertificateAttributes {
	/// Build a sharable bundle from a certificate, proving or copying each named
	/// attribute and sealing the result.Grant access to one or more recipients
	/// before exporting.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::UnsupportedSubjectKey`] -- `subject` is not a signing account.
	/// - [`SharableAttributesError::Certificate`] -- proving a sensitive attribute failed.
	/// - [`SharableAttributesError::Account`] -- the transient principal could not be generated.
	pub fn from_certificate(
		kyc_certificate: &KycCertificate,
		subject: &GenericAccount,
		intermediates_certs: &[X509Certificate],
		names: impl IntoIterator<Item = impl AsRef<str>>,
	) -> Result<Self> {
		let attributes = Self::collect_attributes(kyc_certificate, subject, names)?;
		let intermediates = Self::encode_intermediates(intermediates_certs)?;
		let certificate: String = kyc_certificate.to_x509().to_pem()?;
		let payload = ContentsJson { certificate, intermediates, attributes };
		let json = serde_json::to_vec(&payload)?;

		let container = Self::seal_with_transient_principal(json)?;
		Ok(Self { container, populated: None })
	}

	/// Import a sharable bundle from its encoded container bytes, using
	/// `principals` to open the encrypted contents.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::Container`] -- the bytes are not a valid encrypted container.
	pub fn from_encoded(
		data: impl AsRef<[u8]>,
		principals: impl IntoIterator<Item = impl Into<Arc<GenericAccount>>>,
	) -> Result<Self> {
		let principals: Vec<Arc<GenericAccount>> = principals.into_iter().map(Into::into).collect();
		let container = EncryptedContainer::from_encoded(data, Some(principals))?;
		Ok(Self { container, populated: None })
	}

	/// Import a sharable bundle from its PEM envelope, using `principals` to open
	/// the encrypted contents.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::InvalidPem`] -- the envelope has no body.
	/// - [`SharableAttributesError::InvalidBase64`] -- the body is not valid base64.
	/// - As [`from_encoded`](Self::from_encoded).
	pub fn from_pem(
		pem: impl AsRef<str>,
		principals: impl IntoIterator<Item = impl Into<Arc<GenericAccount>>>,
	) -> Result<Self> {
		let encoded = decode_pem(pem.as_ref())?;
		Self::from_encoded(encoded, principals)
	}

	/// Grant the given accounts access to the sealed contents.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::Container`] -- access management failed.
	pub fn grant_access(
		&mut self,
		accounts: impl IntoIterator<Item = impl Into<Arc<GenericAccount>>>,
	) -> Result<&mut Self> {
		self.container.grant_access(accounts)?;
		Ok(self)
	}

	/// Revoke the account identified by its type-prefixed public key.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::Container`] -- access management failed.
	pub fn revoke_access(&mut self, public_key_and_type: impl AsRef<[u8]>) -> Result<&mut Self> {
		self.container.revoke_access(public_key_and_type)?;
		Ok(self)
	}

	/// The accounts authorized to open the sealed contents.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::Container`] -- the container is plaintext.
	pub fn principals(&self) -> Result<&[Arc<GenericAccount>]> {
		Ok(self.container.principals()?)
	}

	/// The DER-encoded container bytes.
	///
	/// # Errors
	///
	/// - [`SharableAttributesError::NoPrincipals`] -- no recipient has been granted access.
	/// - [`SharableAttributesError::Container`] -- encoding failed.
	pub fn export(&mut self) -> Result<Vec<u8>> {
		let principal_count = self.container.principals().map(<[_]>::len).unwrap_or(0);
		if principal_count == 0 {
			return Err(SharableAttributesError::NoPrincipals);
		}

		Ok(self.container.get_encoded()?)
	}

	/// The container exported as a PEM envelope.
	///
	/// # Errors
	///
	/// - As [`export`](Self::export).
	pub fn to_pem(&mut self) -> Result<String> {
		let encoded = self.export()?;
		Ok(encode_pem(&encoded))
	}

	/// The embedded leaf certificate.
	///
	/// # Errors
	///
	/// - Any error from opening and validating the contents.
	pub fn certificate(&mut self) -> Result<KycCertificate> {
		Ok(self.populated()?.certificate.clone())
	}

	/// The embedded intermediate certificate chain.
	///
	/// # Errors
	///
	/// - Any error from opening and validating the contents.
	pub fn intermediates(&mut self) -> Result<Vec<X509Certificate>> {
		Ok(self.populated()?.intermediates.clone())
	}

	/// The names of the disclosed attributes.
	///
	/// # Errors
	///
	/// - Any error from opening and validating the contents.
	pub fn attribute_names(&mut self) -> Result<Vec<String>> {
		Ok(self.populated()?.attributes.keys().cloned().collect())
	}

	/// The validated plaintext for a disclosed attribute, if present.
	///
	/// # Errors
	///
	/// - Any error from opening and validating the contents.
	pub fn attribute_buffer(&mut self, name: impl AsRef<str>) -> Result<Option<Vec<u8>>> {
		let value = self
			.populated()?
			.attributes
			.get(name.as_ref())
			.map(|attribute| attribute.value.clone());
		Ok(value)
	}

	/// A disclosed attribute with its metadata, if present.
	///
	/// # Errors
	///
	/// - Any error from opening and validating the contents.
	pub fn attribute(&mut self, name: impl AsRef<str>) -> Result<Option<DisclosedAttribute>> {
		Ok(self.populated()?.attributes.get(name.as_ref()).cloned())
	}

	/// The decoded semantic value for a disclosed attribute, if present.
	///
	/// Where [`attribute_buffer`](Self::attribute_buffer) returns the raw DER of
	/// the disclosed value, this decodes it through the KYC schema codec into its
	/// semantic form: UTF-8 text for scalars, an ISO-8601 timestamp for dates,
	/// and JSON for structured attributes, matching the reference reader's
	/// decoded value.
	///
	/// # Errors
	///
	/// - Any error from opening and validating the contents.
	/// - [`SharableAttributesError::Asn1`] -- the disclosed value is malformed for its schema.
	pub fn attribute_value(&mut self, name: impl AsRef<str>) -> Result<Option<Vec<u8>>> {
		let name = name.as_ref();
		let populated = self.populated()?;
		let Some(disclosed) = populated.attributes.get(name) else {
			return Ok(None);
		};
		let Some(cert_attribute) = populated.certificate.get_kyc_attribute(name) else {
			return Ok(None);
		};

		let oid = cert_attribute.name.to_string();
		let decoded = decode_value(oid, &disclosed.value)?;
		Ok(Some(decoded))
	}

	fn collect_attributes(
		certificate: &KycCertificate,
		subject: &GenericAccount,
		names: impl IntoIterator<Item = impl AsRef<str>>,
	) -> Result<BTreeMap<String, AttributeEntry>> {
		let mut attributes = BTreeMap::new();
		for name in names {
			let name = name.as_ref();
			let Some(cert_attribute) = certificate.get_kyc_attribute(name) else {
				continue;
			};

			let entry = if cert_attribute.is_sensitive() {
				let proof = prove_attribute(certificate, name, subject)?;
				AttributeEntry {
					sensitive: true,
					value: AttributeValueJson::Proof(ProofJson {
						value: proof.value.expose_secret().clone(),
						hash: ProofHashJson { salt: proof.hash.salt },
					}),
					references: BTreeMap::new(),
				}
			} else {
				let encoded = base64_encode(cert_attribute.as_ref());
				AttributeEntry {
					sensitive: false,
					value: AttributeValueJson::Plain(encoded),
					references: BTreeMap::new(),
				}
			};

			attributes.insert(name.to_string(), entry);
		}

		Ok(attributes)
	}

	fn encode_intermediates(intermediates: &[X509Certificate]) -> Result<Option<Vec<String>>> {
		if intermediates.is_empty() {
			return Ok(None);
		}

		let mut pem_certs = Vec::with_capacity(intermediates.len());
		for intermediate in intermediates {
			pem_certs.push(intermediate.to_pem()?);
		}

		Ok(Some(pem_certs))
	}

	fn seal_with_transient_principal(data: Vec<u8>) -> Result<EncryptedContainer> {
		let account = generate_transient_account()?;
		let transient = Arc::new(account);
		let principals = Some(vec![transient.clone()]);
		let options = FromPlaintextOptions { locked: Some(true), signer: None };
		let mut sealing = EncryptedContainer::from_plaintext(data, principals, options);
		let encoded = sealing.get_encoded()?;

		let recipients = vec![transient.clone()];
		let mut container = EncryptedContainer::from_encrypted(&encoded, recipients)?;
		let public_key = transient.to_public_key_with_type();

		container.revoke_access(public_key)?;

		Ok(container)
	}

	fn populated(&mut self) -> Result<&Populated> {
		if self.populated.is_none() {
			let populated = Self::compute_populated(&mut self.container)?;
			self.populated = Some(populated);
		}

		match &self.populated {
			Some(populated) => Ok(populated),
			None => Err(SharableAttributesError::InvalidJson),
		}
	}

	fn compute_populated(container: &mut EncryptedContainer) -> Result<Populated> {
		let plaintext = container.get_plaintext()?;
		let json = maybe_inflate(plaintext);
		let payload: ContentsJson = serde_json::from_slice(&json)?;

		let x509_certificate = X509Certificate::from_str(&payload.certificate)?;
		let certificate = KycCertificate::new(x509_certificate);
		let mut intermediates = Vec::new();
		for intermediate_pem in payload.intermediates.iter().flatten() {
			let intermediate = X509Certificate::from_str(intermediate_pem)?;
			intermediates.push(intermediate);
		}

		let subject = subject_account(&certificate)?;
		let mut attributes = BTreeMap::new();
		for (name, entry) in &payload.attributes {
			let value = disclose_attribute(&certificate, &subject, name, entry)?;
			attributes.insert(name.clone(), value);
		}

		Ok(Populated { certificate, intermediates, attributes })
	}
}

/// Validate a single contents entry against the certificate and decode its
/// disclosed value.
fn disclose_attribute(
	certificate: &KycCertificate,
	subject: &GenericAccount,
	name: &str,
	entry: &AttributeEntry,
) -> Result<DisclosedAttribute> {
	let cert_attribute = certificate
		.get_kyc_attribute(name)
		.ok_or_else(|| SharableAttributesError::AttributeNotFound { name: name.to_string() })?;

	if cert_attribute.is_sensitive() != entry.sensitive {
		return Err(SharableAttributesError::SensitivityMismatch { name: name.to_string() });
	}

	let value = match &entry.value {
		AttributeValueJson::Plain(encoded) => {
			let decoded = base64_decode(encoded)?;
			if decoded.as_slice() != cert_attribute.as_ref() {
				return Err(SharableAttributesError::ValueMismatch { name: name.to_string() });
			}

			decoded
		}
		AttributeValueJson::Proof(proof_json) => {
			let plaintext_value = base64_decode(&proof_json.value)?;
			let proof = SensitiveAttributeProof {
				value: proof_json.value.clone().into_secret(),
				hash: SensitiveAttributeProofHash { salt: proof_json.hash.salt.clone() },
			};
			if !validate_proof(certificate, name, subject, proof)? {
				return Err(SharableAttributesError::ProofValidationFailed { name: name.to_string() });
			}

			plaintext_value
		}
	};

	Ok(DisclosedAttribute { sensitive: entry.sensitive, value, references: entry.references.clone() })
}

/// Prove a sensitive attribute with the subject account, dispatching on its key
/// type.
fn prove_attribute(
	certificate: &KycCertificate,
	name: &str,
	subject: &GenericAccount,
) -> Result<SensitiveAttributeProof> {
	let proof = match subject {
		GenericAccount::Ed25519(account) => certificate.prove_kyc_attribute(name, &account.keypair)?,
		GenericAccount::EcdsaSecp256k1(account) => certificate.prove_kyc_attribute(name, &account.keypair)?,
		GenericAccount::EcdsaSecp256r1(account) => certificate.prove_kyc_attribute(name, &account.keypair)?,
		_ => return Err(SharableAttributesError::UnsupportedSubjectKey),
	};

	Ok(proof)
}

/// Validate a sensitive attribute proof with the subject public account,
/// dispatching on its key type.
fn validate_proof(
	certificate: &KycCertificate,
	name: &str,
	subject: &GenericAccount,
	proof: SensitiveAttributeProof,
) -> Result<bool> {
	let valid = match subject {
		GenericAccount::Ed25519(account) => certificate.validate_kyc_attribute_proof(name, &account.keypair, proof)?,
		GenericAccount::EcdsaSecp256k1(account) => {
			certificate.validate_kyc_attribute_proof(name, &account.keypair, proof)?
		}
		GenericAccount::EcdsaSecp256r1(account) => {
			certificate.validate_kyc_attribute_proof(name, &account.keypair, proof)?
		}
		_ => return Err(SharableAttributesError::UnsupportedSubjectKey),
	};

	Ok(valid)
}

/// Reconstruct the certificate subject as a public-only account so proofs can be
/// validated without the recipient supplying the subject identity.
fn subject_account(certificate: &KycCertificate) -> Result<GenericAccount> {
	let spki = certificate.to_x509().to_subject_public_key()?;
	let raw_key = spki.subject_public_key.raw_bytes().to_vec();
	let account = match subject_key_type(&spki)? {
		KeyPairType::ED25519 => {
			let keyable = Keyable::PublicKey(raw_key);
			let accountable = Accountable::KeyAndType(keyable, KeyPairType::ED25519);
			let account = Account::<KeyED25519>::try_from(accountable)?;
			GenericAccount::Ed25519(account)
		}
		KeyPairType::ECDSASECP256K1 => {
			let keyable = Keyable::PublicKey(raw_key);
			let accountable = Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256K1);
			let account = Account::<KeyECDSASECP256K1>::try_from(accountable)?;
			GenericAccount::EcdsaSecp256k1(account)
		}
		KeyPairType::ECDSASECP256R1 => {
			let keyable = Keyable::PublicKey(raw_key);
			let accountable = Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256R1);
			let account = Account::<KeyECDSASECP256R1>::try_from(accountable)?;
			GenericAccount::EcdsaSecp256r1(account)
		}
		_ => return Err(SharableAttributesError::UnsupportedSubjectKey),
	};

	Ok(account)
}

/// Map a certificate subject public key info to its account key type, reading
/// the curve OID from the EC parameters where required.
fn subject_key_type(spki: &SubjectPublicKeyInfo) -> Result<KeyPairType> {
	let algorithm = &spki.algorithm.algorithm;
	if *algorithm == oids::typed::ED25519.clone() {
		return Ok(KeyPairType::ED25519);
	}

	if *algorithm == oids::typed::EC_PUBLIC_KEY.clone() {
		let parameters = spki
			.algorithm
			.parameters
			.as_ref()
			.ok_or(SharableAttributesError::UnsupportedSubjectKey)?;

		let bytes = parameters.as_bytes();
		let curve: ObjectIdentifier = rasn::der::decode(bytes)?;
		if curve == oids::typed::SECP256K1.clone() {
			return Ok(KeyPairType::ECDSASECP256K1);
		}
		if curve == oids::typed::SECP256R1.clone() {
			return Ok(KeyPairType::ECDSASECP256R1);
		}
	}

	Err(SharableAttributesError::UnsupportedSubjectKey)
}

/// Generate a fresh Ed25519 account used only to seal the container before the
/// real recipients are granted access.
fn generate_transient_account() -> Result<GenericAccount> {
	let seed = Account::<KeyED25519>::generate_random_seed()?;
	let keyable = Keyable::Seed((seed, 0));
	let accountable = Accountable::KeyAndType(keyable, KeyED25519::KEY_PAIR_TYPE);
	let account = Account::<KeyED25519>::try_from(accountable)?;
	Ok(GenericAccount::Ed25519(account))
}

/// Inflate legacy zlib-wrapped contents; modern contents are already plain JSON.
fn maybe_inflate(data: Vec<u8>) -> Vec<u8> {
	if data.first() != Some(&ZLIB_MAGIC) {
		return data;
	}

	match miniz_oxide::inflate::decompress_to_vec_zlib(&data) {
		Ok(inflated) => inflated,
		Err(_) => data,
	}
}

/// Wrap encoded container bytes in the shared PEM envelope.
fn encode_pem(encoded: &[u8]) -> String {
	let body = base64_encode(encoded);
	let mut pem = String::from(PEM_BEGIN);
	for chunk in body.as_bytes().chunks(PEM_LINE_LENGTH) {
		let line = core::str::from_utf8(chunk).unwrap_or_default();
		pem.push('\n');
		pem.push_str(line);
	}

	pem.push('\n');
	pem.push_str(PEM_END);

	pem
}

/// Strip the PEM envelope and decode the base64 body into container bytes.
fn decode_pem(pem: &str) -> Result<Vec<u8>> {
	let mut body = String::new();
	for line in pem.lines() {
		let trimmed = line.trim();
		if trimmed.is_empty() || trimmed.starts_with("-----") {
			continue;
		}
		body.push_str(trimmed);
	}

	if body.is_empty() {
		return Err(SharableAttributesError::InvalidPem);
	}

	Ok(base64_decode(body)?)
}

#[cfg(test)]
mod tests {
	use keetanetwork_account::GenericAccount;
	use keetanetwork_asn1::SubjectPublicKeyInfo;
	use keetanetwork_crypto::prelude::IntoSecret;
	use keetanetwork_x509::utils::create_dn;
	use keetanetwork_x509::SerialNumber;

	use super::*;
	use crate::certificates::KycCertificateBuilder;
	use crate::doc_utils::{create_secp256k1_generic_account, create_secp256k1_test_account};

	const EMAIL: &[u8] = b"john@example.com";

	/// DER-encode a UTF8String, matching how a sensitive attribute's disclosed
	/// proof value is carried (tag `0x0C`, single-byte length).
	fn der_utf8_string(value: &[u8]) -> Vec<u8> {
		let mut encoded = vec![0x0C, value.len() as u8];
		encoded.extend_from_slice(value);
		encoded
	}

	/// Issue a leaf certificate carrying one plain and one sensitive attribute,
	/// returning it alongside the subject signing account.
	fn issue_certificate() -> (KycCertificate, GenericAccount) {
		let subject = create_secp256k1_test_account(Some(0));
		let issuer = create_secp256k1_test_account(Some(1));
		let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Subject")]).expect("subject dn");
		let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Issuer")]).expect("issuer dn");
		let spki = SubjectPublicKeyInfo::try_from(&subject).expect("subject spki");
		let certificate = KycCertificateBuilder::for_end_entity()
			.with_subject_dn(subject_dn)
			.with_issuer_dn(issuer_dn)
			.with_serial_number(SerialNumber::from(9u64))
			.with_validity_days(365)
			.with_subject_public_key(spki)
			.with_plain_attribute("postalCode", "12345")
			.with_sensitive_attribute("email", EMAIL.to_vec().into_secret())
			.build(&subject.keypair, &issuer.keypair)
			.expect("certificate");

		(certificate, GenericAccount::EcdsaSecp256k1(subject))
	}

	#[test]
	fn round_trip_discloses_validated_attributes() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let (certificate, subject) = issue_certificate();
		let expected_postal = certificate
			.get_kyc_attribute("postalCode")
			.map(|attribute| attribute.as_ref().to_vec());

		let intermediates: [X509Certificate; 0] = [];
		let names = ["email", "postalCode"];
		let mut sharable =
			SharableCertificateAttributes::from_certificate(&certificate, &subject, &intermediates, names)?;

		let accounts = [create_secp256k1_generic_account(Some(2))];
		sharable.grant_access(accounts)?;
		let pem = sharable.to_pem()?;

		let principals = [create_secp256k1_generic_account(Some(2))];
		let mut opened = SharableCertificateAttributes::from_pem(&pem, principals)?;
		assert_eq!(opened.attribute_buffer("email")?, Some(der_utf8_string(EMAIL)));
		assert_eq!(opened.attribute_buffer("postalCode")?, expected_postal);
		Ok(())
	}

	#[test]
	fn attribute_value_decodes_disclosed_buffers() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let (certificate, subject) = issue_certificate();
		let intermediates: [X509Certificate; 0] = [];
		let names = ["email", "postalCode"];
		let mut sharable =
			SharableCertificateAttributes::from_certificate(&certificate, &subject, &intermediates, names)?;

		let accounts = [create_secp256k1_generic_account(Some(2))];
		sharable.grant_access(accounts)?;
		let pem = sharable.to_pem()?;

		let principals = [create_secp256k1_generic_account(Some(2))];
		let mut opened = SharableCertificateAttributes::from_pem(&pem, principals)?;
		assert_eq!(opened.attribute_value("email")?, Some(EMAIL.to_vec()));
		assert_eq!(opened.attribute_value("postalCode")?, Some(b"12345".to_vec()));
		assert_eq!(opened.attribute_value("missing")?, None);
		Ok(())
	}

	#[test]
	fn export_without_principals_is_rejected() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let (certificate, subject) = issue_certificate();
		let intermediates: [X509Certificate; 0] = [];
		let names = ["email"];
		let mut sharable =
			SharableCertificateAttributes::from_certificate(&certificate, &subject, &intermediates, names)?;

		let outcome = sharable.export();
		assert!(matches!(outcome, Err(SharableAttributesError::NoPrincipals)));
		Ok(())
	}

	#[test]
	fn opening_without_a_granted_principal_fails() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let (certificate, subject) = issue_certificate();
		let intermediates: [X509Certificate; 0] = [];
		let names = ["email"];
		let mut sharable =
			SharableCertificateAttributes::from_certificate(&certificate, &subject, &intermediates, names)?;

		let accounts = [create_secp256k1_generic_account(Some(2))];
		sharable.grant_access(accounts)?;
		let pem = sharable.to_pem()?;

		let principals = [create_secp256k1_generic_account(Some(3))];
		let mut opened = SharableCertificateAttributes::from_pem(&pem, principals)?;
		assert!(opened.attribute_buffer("email").is_err());
		Ok(())
	}
}

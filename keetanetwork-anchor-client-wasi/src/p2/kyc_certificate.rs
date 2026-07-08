//! The `certificates` KYC leaf resource of the P2 component.

use keetanetwork_anchor::certificates::KycCertificate as CoreKycCertificate;
use keetanetwork_anchor_bindings::certificate as kyc_cert_ops;

use super::account::AccountResource;
use super::certificate::CertificateResource;
use super::exports::keeta::anchor::certificates::{
	Guest as CertificatesGuest, GuestKycCertificate, KycCertificate as WitKycCertificate,
};
use super::exports::keeta::client::crypto::{AccountBorrow, Certificate as WitCertificate, CertificateBorrow};
use super::keeta::anchor::types::{
	AttributeProof as WitAttributeProof, AttributeReference as WitAttributeReference, IssueAttribute, KycAttribute,
};
use super::{collect_certificates, seconds_to_millis, CodedError, Component};

/// A KYC leaf certificate: a base certificate plus parsed KYC attributes.
pub(crate) struct KycCertificateResource {
	pub(crate) certificate: CoreKycCertificate,
}

impl CertificatesGuest for Component {
	type KycCertificate = KycCertificateResource;
}

impl GuestKycCertificate for KycCertificateResource {
	fn parse(pem: String) -> Result<WitKycCertificate, CodedError> {
		let certificate = kyc_cert_ops::from_pem(&pem)?;
		Ok(WitKycCertificate::new(Self { certificate }))
	}

	#[allow(clippy::too_many_arguments)]
	fn issue(
		subject: AccountBorrow<'_>,
		issuer: AccountBorrow<'_>,
		subject_dn: String,
		issuer_dn: String,
		serial: u64,
		not_before: i64,
		not_after: i64,
		is_ca: bool,
		attributes: Vec<IssueAttribute>,
	) -> Result<WitKycCertificate, CodedError> {
		let subject_account = &subject.get::<AccountResource>().account;
		let issuer_account = &issuer.get::<AccountResource>().account;
		let issue_attributes: Vec<kyc_cert_ops::IssueAttribute> = attributes
			.into_iter()
			.map(|attribute| kyc_cert_ops::IssueAttribute {
				name: attribute.name,
				sensitive: attribute.sensitive,
				value: attribute.value,
			})
			.collect();

		let certificate = kyc_cert_ops::issue(
			subject_account.as_ref(),
			issuer_account.as_ref(),
			&subject_dn,
			&issuer_dn,
			serial,
			not_before,
			not_after,
			is_ca,
			&issue_attributes,
		)?;

		Ok(WitKycCertificate::new(Self { certificate }))
	}

	fn base(&self) -> WitCertificate {
		WitCertificate::new(CertificateResource { certificate: self.certificate.to_x509().clone() })
	}

	fn pem(&self) -> Result<String, CodedError> {
		Ok(kyc_cert_ops::pem(&self.certificate)?)
	}

	fn valid_at(&self, unix_seconds: i64) -> bool {
		seconds_to_millis(unix_seconds)
			.ok()
			.and_then(|millis| kyc_cert_ops::valid_at(&self.certificate, millis).ok())
			.unwrap_or(false)
	}

	fn verify(
		&self,
		trusted_roots: Vec<CertificateBorrow<'_>>,
		intermediates: Vec<CertificateBorrow<'_>>,
		unix_seconds: i64,
	) -> Result<bool, CodedError> {
		let roots = collect_certificates(&trusted_roots);
		let bridges = collect_certificates(&intermediates);
		let millis = seconds_to_millis(unix_seconds)?;

		Ok(kyc_cert_ops::verify(&self.certificate, &roots, &bridges, millis)?)
	}

	fn attributes(&self) -> Vec<KycAttribute> {
		kyc_cert_ops::attributes(&self.certificate)
			.into_iter()
			.map(|(name, sensitive)| KycAttribute { name, sensitive })
			.collect()
	}

	fn plain_attribute(&self, name: String) -> Result<Vec<u8>, CodedError> {
		Ok(kyc_cert_ops::plain_attribute(&self.certificate, &name)?)
	}

	fn decrypt_attribute(&self, name: String, subject: AccountBorrow<'_>) -> Result<Vec<u8>, CodedError> {
		let account = &subject.get::<AccountResource>().account;
		Ok(kyc_cert_ops::decrypt_attribute_with_account(&self.certificate, &name, account)?)
	}

	fn prove(&self, name: String, subject: AccountBorrow<'_>) -> Result<WitAttributeProof, CodedError> {
		let account = &subject.get::<AccountResource>().account;
		let proof = kyc_cert_ops::prove_attribute_with_account(&self.certificate, &name, account)?;
		Ok(WitAttributeProof { value: proof.value, salt: proof.salt })
	}

	fn validate_proof(
		&self,
		name: String,
		subject: AccountBorrow<'_>,
		proof: WitAttributeProof,
	) -> Result<bool, CodedError> {
		let account = &subject.get::<AccountResource>().account;
		let proof = kyc_cert_ops::AttributeProof { value: proof.value, salt: proof.salt };
		Ok(kyc_cert_ops::validate_attribute_proof_with_account(&self.certificate, &name, account, proof)?)
	}

	fn external_references(
		&self,
		subject: AccountBorrow<'_>,
		names: Vec<String>,
	) -> Result<Vec<WitAttributeReference>, CodedError> {
		let account = &subject.get::<AccountResource>().account;
		let records = kyc_cert_ops::external_references_with_account(&self.certificate, account, &names)?;
		let references = records
			.into_iter()
			.map(|record| WitAttributeReference {
				attribute: record.attribute,
				id: record.id,
				url: record.url,
				content_type: record.content_type,
				digest_algorithm: record.digest_algorithm,
				encryption_algorithm: record.encryption_algorithm,
			})
			.collect();

		Ok(references)
	}
}

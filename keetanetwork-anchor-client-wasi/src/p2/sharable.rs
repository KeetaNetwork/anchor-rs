//! The `sharable` selectively disclosed attributes resource of the P2 component.

use core::cell::RefCell;
use std::sync::Arc;

use keetanetwork_anchor::sharable_attributes::{
	ExternalBlobs, SharableCertificateAttributes as CoreSharableCertificateAttributes,
};
use keetanetwork_anchor_bindings::sharable_attributes as sharable_ops;

use super::account::AccountResource;
use super::certificate::CertificateResource;
use super::exports::keeta::anchor::certificates::KycCertificate as WitKycCertificate;
use super::exports::keeta::anchor::sharable::{
	Guest as SharableGuest, GuestSharableCertificateAttributes, KycCertificateBorrow,
	SharableCertificateAttributes as WitSharableCertificateAttributes,
};
use super::exports::keeta::client::crypto::{AccountBorrow, Certificate as WitCertificate, CertificateBorrow};
use super::kyc_certificate::KycCertificateResource;
use super::{collect_accounts, collect_certificates, CodedError, Component};

/// A sealed, selectively disclosed subset of a certificate's attributes.
pub(crate) struct SharableCertificateAttributesResource {
	bundle: RefCell<CoreSharableCertificateAttributes>,
}

impl SharableGuest for Component {
	type SharableCertificateAttributes = SharableCertificateAttributesResource;
}

impl GuestSharableCertificateAttributes for SharableCertificateAttributesResource {
	fn from_certificate(
		certificate: KycCertificateBorrow<'_>,
		subject: AccountBorrow<'_>,
		intermediates: Vec<CertificateBorrow<'_>>,
		names: Vec<String>,
	) -> Result<WitSharableCertificateAttributes, CodedError> {
		let certificate = &certificate.get::<KycCertificateResource>().certificate;
		let subject = Arc::clone(&subject.get::<AccountResource>().account);
		let intermediates = collect_certificates(&intermediates);
		let bundle = sharable_ops::from_certificate(certificate, &subject, &intermediates, &names)?;

		Ok(WitSharableCertificateAttributes::new(Self { bundle: RefCell::new(bundle) }))
	}

	fn from_certificate_with_references(
		certificate: KycCertificateBorrow<'_>,
		subject: AccountBorrow<'_>,
		intermediates: Vec<CertificateBorrow<'_>>,
		names: Vec<String>,
		blobs: Vec<(String, Vec<u8>)>,
	) -> Result<WitSharableCertificateAttributes, CodedError> {
		let certificate = &certificate.get::<KycCertificateResource>().certificate;
		let subject = Arc::clone(&subject.get::<AccountResource>().account);
		let intermediates = collect_certificates(&intermediates);
		let blobs = ExternalBlobs::from_iter(blobs);
		let bundle =
			sharable_ops::from_certificate_with_references(certificate, &subject, &intermediates, &names, blobs)?;

		Ok(WitSharableCertificateAttributes::new(Self { bundle: RefCell::new(bundle) }))
	}

	fn from_encoded(
		data: Vec<u8>,
		principals: Vec<AccountBorrow<'_>>,
	) -> Result<WitSharableCertificateAttributes, CodedError> {
		let principals = collect_accounts(&principals);
		let bundle = sharable_ops::from_encoded(&data, &principals)?;
		Ok(WitSharableCertificateAttributes::new(Self { bundle: RefCell::new(bundle) }))
	}

	fn from_pem(
		pem: String,
		principals: Vec<AccountBorrow<'_>>,
	) -> Result<WitSharableCertificateAttributes, CodedError> {
		let principals = collect_accounts(&principals);
		let bundle = sharable_ops::from_pem(&pem, &principals)?;
		Ok(WitSharableCertificateAttributes::new(Self { bundle: RefCell::new(bundle) }))
	}

	fn grant_access(&self, accounts: Vec<AccountBorrow<'_>>) -> Result<(), CodedError> {
		let accounts = collect_accounts(&accounts);
		sharable_ops::grant_access(&mut self.bundle.borrow_mut(), &accounts)?;
		Ok(())
	}

	fn revoke_access(&self, public_key: Vec<u8>) -> Result<(), CodedError> {
		sharable_ops::revoke_access(&mut self.bundle.borrow_mut(), &public_key)?;
		Ok(())
	}

	fn principals(&self) -> Result<Vec<Vec<u8>>, CodedError> {
		Ok(sharable_ops::principals(&self.bundle.borrow())?)
	}

	fn export_encoded(&self) -> Result<Vec<u8>, CodedError> {
		Ok(sharable_ops::export(&mut self.bundle.borrow_mut())?)
	}

	fn to_pem(&self) -> Result<String, CodedError> {
		Ok(sharable_ops::to_pem(&mut self.bundle.borrow_mut())?)
	}

	fn certificate(&self) -> Result<WitKycCertificate, CodedError> {
		let certificate = sharable_ops::certificate(&mut self.bundle.borrow_mut())?;
		Ok(WitKycCertificate::new(KycCertificateResource { certificate }))
	}

	fn intermediates(&self) -> Result<Vec<WitCertificate>, CodedError> {
		let intermediates = sharable_ops::intermediates(&mut self.bundle.borrow_mut())?;
		Ok(intermediates
			.into_iter()
			.map(|certificate| WitCertificate::new(CertificateResource { certificate }))
			.collect())
	}

	fn attribute_names(&self) -> Result<Vec<String>, CodedError> {
		Ok(sharable_ops::attribute_names(&mut self.bundle.borrow_mut())?)
	}

	fn attribute_buffer(&self, name: String) -> Result<Option<Vec<u8>>, CodedError> {
		Ok(sharable_ops::attribute_buffer(&mut self.bundle.borrow_mut(), &name)?)
	}

	fn attribute_value(&self, name: String) -> Result<Option<Vec<u8>>, CodedError> {
		Ok(sharable_ops::attribute_value(&mut self.bundle.borrow_mut(), &name)?)
	}

	fn reference_blob(&self, name: String, id: String) -> Result<Option<Vec<u8>>, CodedError> {
		Ok(sharable_ops::reference_blob(&mut self.bundle.borrow_mut(), &name, &id)?)
	}
}

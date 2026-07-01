//! The `crypto` base X.509 certificate resource of the P2 component.

use keetanetwork_bindings::x509 as x509_ops;
use keetanetwork_x509::certificates::Certificate as X509Certificate;

use super::exports::keeta::client::crypto::{Certificate as WitCertificate, GuestCertificate};
use super::{seconds_to_millis, CodedError};

/// A base X.509 certificate: a provider CA, a trust root, or an intermediate.
pub(crate) struct CertificateResource {
	pub(crate) certificate: X509Certificate,
}

impl GuestCertificate for CertificateResource {
	fn parse(pem: String) -> Result<WitCertificate, CodedError> {
		let certificate = x509_ops::certificate_from_pem(&pem)?;
		Ok(WitCertificate::new(Self { certificate }))
	}

	fn pem(&self) -> Result<String, CodedError> {
		Ok(x509_ops::certificate_pem(&self.certificate)?)
	}

	fn valid_at(&self, unix_seconds: i64) -> bool {
		seconds_to_millis(unix_seconds)
			.ok()
			.and_then(|millis| x509_ops::certificate_valid_at(&self.certificate, millis).ok())
			.unwrap_or(false)
	}

	fn subject(&self) -> String {
		x509_ops::certificate_subject(&self.certificate)
	}

	fn issuer(&self) -> String {
		x509_ops::certificate_issuer(&self.certificate)
	}

	fn serial(&self) -> String {
		x509_ops::certificate_serial(&self.certificate)
	}

	fn not_before(&self) -> i64 {
		x509_ops::certificate_not_before(&self.certificate)
	}

	fn not_after(&self) -> i64 {
		x509_ops::certificate_not_after(&self.certificate)
	}

	fn subject_public_key(&self) -> Result<String, CodedError> {
		Ok(x509_ops::certificate_subject_public_key(&self.certificate)?)
	}
}

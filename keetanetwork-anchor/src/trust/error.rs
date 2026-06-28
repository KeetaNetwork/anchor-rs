//! Errors raised by the certificate-chain trust gate.

use core::fmt::{Display, Formatter, Result as FmtResult};

use snafu::Snafu;

/// Why a certificate-chain requirement rejected an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRequiredKind {
	/// The account published no certificates at all.
	Missing,
	/// Certificates exist but none chain to a trusted issuer.
	Untrusted,
}

impl Display for CertificateRequiredKind {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
		let reason = match self {
			Self::Missing => "account has no published certificates",
			Self::Untrusted => "account certificates chain to no trusted issuer",
		};

		formatter.write_str(reason)
	}
}

/// The reason a certificate-chain gate rejected a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub))]
pub enum TrustError {
	/// The account did not satisfy the configured certificate-chain requirement.
	#[snafu(display("certificate chain required: {kind}"))]
	CertificateRequired {
		/// Whether certificates were missing or merely untrusted.
		kind: CertificateRequiredKind,
	},
}

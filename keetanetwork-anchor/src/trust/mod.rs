//! Certificate-chain trust gate.
//!
//! Decides whether an account's published certificates chain to
//! a trusted issuer.

mod error;

pub use error::{CertificateRequiredKind, TrustError};

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use keetanetwork_x509::certificates::Certificate;

/// An account's published certificate together with the intermediate
/// certificates needed to chain it toward a trusted issuer.
#[derive(Debug, Clone)]
pub struct CertificateRecord {
	/// The leaf certificate published by the account.
	pub certificate: Certificate,
	/// Intermediates that help chain `certificate` toward a trusted root.
	pub intermediates: Vec<Certificate>,
}

/// Outcome of evaluating an account's certificates against a trust set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateChainStatus {
	/// At least one record chains to a trusted issuer.
	Trusted,
	/// The account published no certificates.
	NoCerts,
	/// Certificates exist but none chain to a trusted issuer.
	Untrusted,
}

/// Evaluate whether any record chains to one of `trusted_issuers` at `moment`.
///
/// The `trusted_issuers` are the trust anchors; a record's own intermediates
/// only help build the chain and are never themselves treated as anchors.
pub fn evaluate_certificate_chain(
	records: &[CertificateRecord],
	trusted_issuers: &[Certificate],
	moment: DateTime<Utc>,
) -> CertificateChainStatus {
	if records.is_empty() {
		return CertificateChainStatus::NoCerts;
	}
	if trusted_issuers.is_empty() {
		return CertificateChainStatus::Untrusted;
	}

	let roots: BTreeSet<Certificate> = trusted_issuers.iter().cloned().collect();
	let any_trusted = records
		.iter()
		.any(|record| record_chains_to_root(record, &roots, moment));

	if any_trusted {
		CertificateChainStatus::Trusted
	} else {
		CertificateChainStatus::Untrusted
	}
}

/// Assert an account satisfies the requirement, mapping failure to a typed
/// [`TrustError`].
pub fn assert_certificate_chain(
	records: &[CertificateRecord],
	trusted_issuers: &[Certificate],
	moment: DateTime<Utc>,
) -> Result<(), TrustError> {
	let kind = match evaluate_certificate_chain(records, trusted_issuers, moment) {
		CertificateChainStatus::Trusted => return Ok(()),
		CertificateChainStatus::NoCerts => CertificateRequiredKind::Missing,
		CertificateChainStatus::Untrusted => CertificateRequiredKind::Untrusted,
	};

	Err(TrustError::CertificateRequired { kind })
}

/// A record chains to a trusted root when its leaf is valid at `moment` and is
/// either itself a trusted anchor or builds a chain ending at one.
fn record_chains_to_root(record: &CertificateRecord, roots: &BTreeSet<Certificate>, moment: DateTime<Utc>) -> bool {
	let candidate = &record.certificate;
	if !candidate.is_valid_at(moment).unwrap_or(false) {
		return false;
	}
	if roots.contains(candidate) {
		return true;
	}

	let mut available = record.intermediates.clone();
	available.extend(roots.iter().cloned());

	let chain: Vec<Certificate> = candidate.verify_chain(available).collect();

	chain
		.last()
		.map(|root| roots.contains(root))
		.unwrap_or(false)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::doc_utils::create_secp256k1_test_account;
	use keetanetwork_account::{Account, KeyECDSASECP256K1};
	use keetanetwork_asn1::SubjectPublicKeyInfo;
	use keetanetwork_x509::builder::CertificateBuilder;
	use keetanetwork_x509::utils::create_dn;
	use keetanetwork_x509::{oids, SerialNumber};

	type TestResult = Result<(), Box<dyn core::error::Error>>;

	struct Authority {
		certificate: Certificate,
		account: Account<KeyECDSASECP256K1>,
		common_name: &'static str,
	}

	fn authority(index: u32, common_name: &'static str) -> Result<Authority, Box<dyn core::error::Error>> {
		let account = create_secp256k1_test_account(Some(index));
		let dn = create_dn(&[(oids::CN, common_name)])?;
		let spki = SubjectPublicKeyInfo::try_from(&account)?;
		let certificate = CertificateBuilder::for_ca()
			.without_common_extensions()
			.with_subject_dn(dn.clone())
			.with_issuer_dn(dn)
			.with_serial_number(SerialNumber::from(u64::from(index) + 100))
			.with_validity_days(3650)
			.with_subject_public_key(spki)
			.build(&account.keypair)?;

		Ok(Authority { certificate, account, common_name })
	}

	fn leaf_signed_by(
		index: u32,
		common_name: &'static str,
		issuer: &Authority,
	) -> Result<Certificate, Box<dyn core::error::Error>> {
		let account = create_secp256k1_test_account(Some(index));
		let subject_dn = create_dn(&[(oids::CN, common_name)])?;
		let issuer_dn = create_dn(&[(oids::CN, issuer.common_name)])?;
		let spki = SubjectPublicKeyInfo::try_from(&account)?;
		let certificate = CertificateBuilder::for_end_entity()
			.without_common_extensions()
			.with_subject_dn(subject_dn)
			.with_issuer_dn(issuer_dn)
			.with_serial_number(SerialNumber::from(u64::from(index) + 200))
			.with_validity_days(365)
			.with_subject_public_key(spki)
			.build(&issuer.account.keypair)?;

		Ok(certificate)
	}

	fn record(certificate: Certificate, intermediates: Vec<Certificate>) -> CertificateRecord {
		CertificateRecord { certificate, intermediates }
	}

	#[test]
	fn chain_status_matches_trust_set() -> TestResult {
		let ca = authority(1, "Anchor Test CA")?;
		let leaf = leaf_signed_by(2, "Anchor Test Leaf", &ca)?;
		let foreign = authority(3, "Foreign CA")?;
		let now = Utc::now();

		let cases = [
			(
				"leaf chains to trusted CA",
				vec![record(leaf.clone(), Vec::new())],
				vec![ca.certificate.clone()],
				CertificateChainStatus::Trusted,
			),
			(
				"trusted CA presented directly",
				vec![record(ca.certificate.clone(), Vec::new())],
				vec![ca.certificate.clone()],
				CertificateChainStatus::Trusted,
			),
			(
				"foreign cert is untrusted",
				vec![record(foreign.certificate.clone(), Vec::new())],
				vec![ca.certificate.clone()],
				CertificateChainStatus::Untrusted,
			),
			("no records means no certs", Vec::new(), vec![ca.certificate.clone()], CertificateChainStatus::NoCerts),
			(
				"empty trust set is untrusted",
				vec![record(leaf.clone(), Vec::new())],
				Vec::new(),
				CertificateChainStatus::Untrusted,
			),
		];

		for (label, records, trusted, expected) in cases {
			let status = evaluate_certificate_chain(&records, &trusted, now);
			assert_eq!(status, expected, "{label}");
		}

		Ok(())
	}

	#[test]
	fn assert_maps_status_to_typed_error() -> TestResult {
		let ca = authority(1, "Anchor Test CA")?;
		let leaf = leaf_signed_by(2, "Anchor Test Leaf", &ca)?;
		let foreign = authority(3, "Foreign CA")?;
		let now = Utc::now();
		let trusted = [ca.certificate.clone()];

		let trusted_ok = assert_certificate_chain(&[record(leaf, Vec::new())], &trusted, now);
		assert!(trusted_ok.is_ok(), "trusted leaf must pass the gate");

		let missing = assert_certificate_chain(&[], &trusted, now);
		assert!(
			matches!(missing, Err(TrustError::CertificateRequired { kind: CertificateRequiredKind::Missing })),
			"no certificates must report missing"
		);

		let untrusted = assert_certificate_chain(&[record(foreign.certificate, Vec::new())], &trusted, now);
		assert!(
			matches!(untrusted, Err(TrustError::CertificateRequired { kind: CertificateRequiredKind::Untrusted })),
			"foreign certificate must report untrusted"
		);

		Ok(())
	}
}

//! Evaluating an account's published certificates against a trust set.
//!
//! Bridges the ledger read ([`KeetaClient::certificates`]) to the core chain
//! evaluation ([`keetanetwork_anchor::trust::evaluate_certificate_chain`]),
//! porting the reference `verifyAccountCertificateChain`.
//!
//! [`KeetaClient::certificates`]: keetanetwork_client::KeetaClient::certificates

use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use keetanetwork_anchor::trust::{evaluate_certificate_chain, CertificateChainStatus, CertificateRecord};
use keetanetwork_client::KeetaClient;
use keetanetwork_x509::certificates::Certificate;

use crate::error::ResolverError;
use crate::resolver::AccountCertificate;

/// Read `account`'s published certificates through the node `client` and
/// evaluate them against `trusted_issuers` at `moment`.
///
/// # Errors
///
/// Returns [`ResolverError::Node`] when the ledger read fails; unparsable
/// records are skipped, not errored.
pub async fn verify_account_certificate_chain(
	client: &KeetaClient,
	account: &str,
	trusted_issuers: &[Certificate],
	moment: DateTime<Utc>,
) -> Result<CertificateChainStatus, ResolverError> {
	let records = client.certificates(account).await?;
	Ok(evaluate_published_chain(&records, trusted_issuers, moment))
}

/// Evaluate published `records` against `trusted_issuers` at `moment`.
///
/// A record whose certificate or intermediates do not parse is skipped, never
/// treated as trusted; skipped records still count as published, so an account
/// whose every record is malformed reports [`CertificateChainStatus::Untrusted`]
/// rather than [`CertificateChainStatus::NoCerts`].
pub fn evaluate_published_chain(
	records: &[AccountCertificate],
	trusted_issuers: &[Certificate],
	moment: DateTime<Utc>,
) -> CertificateChainStatus {
	if records.is_empty() {
		return CertificateChainStatus::NoCerts;
	}

	let parsed: Vec<CertificateRecord> = records.iter().filter_map(parse_record).collect();
	if parsed.is_empty() {
		return CertificateChainStatus::Untrusted;
	}

	evaluate_certificate_chain(&parsed, trusted_issuers, moment)
}

/// Parse one published record's PEMs, or `None` when any part is malformed.
fn parse_record(record: &AccountCertificate) -> Option<CertificateRecord> {
	let certificate: Certificate = record.certificate.parse().ok()?;
	let intermediates: Vec<Certificate> = record
		.intermediates
		.iter()
		.map(|pem| pem.parse().ok())
		.collect::<Option<_>>()?;

	Some(CertificateRecord { certificate, intermediates })
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;
	use alloc::vec;

	use super::*;

	#[test]
	fn no_published_records_report_no_certs() {
		let status = evaluate_published_chain(&[], &[], Utc::now());
		assert_eq!(status, CertificateChainStatus::NoCerts);
	}

	#[test]
	fn a_malformed_record_reports_untrusted_not_no_certs() {
		let records = vec![AccountCertificate { certificate: "not a pem".to_string(), intermediates: Vec::new() }];
		let status = evaluate_published_chain(&records, &[], Utc::now());
		assert_eq!(status, CertificateChainStatus::Untrusted);
	}

	#[test]
	fn a_record_with_a_malformed_intermediate_is_skipped() {
		let records = vec![AccountCertificate {
			certificate: "not a pem".to_string(),
			intermediates: vec!["also not a pem".to_string()],
		}];
		let status = evaluate_published_chain(&records, &[], Utc::now());
		assert_eq!(status, CertificateChainStatus::Untrusted);
	}
}

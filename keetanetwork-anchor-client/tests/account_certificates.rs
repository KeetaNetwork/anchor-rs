//! The on-chain certificate read and trust evaluation against the live harness.

mod harness;

use std::error::Error;
use std::str::FromStr;

use chrono::{Duration, Utc};
use harness::KycHarness;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::doc_utils::create_secp256k1_test_account;
use keetanetwork_anchor::trust::CertificateChainStatus;
use keetanetwork_anchor_client::{verify_account_certificate_chain, AccountCertificate, KeetaClient};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::certificates::Certificate;
use keetanetwork_x509::utils::create_dn;
use keetanetwork_x509::{oids, SerialNumber};

type TestResult = Result<(), Box<dyn Error>>;

/// A self-signed CA the ledger never saw, to exercise the untrusted path.
fn foreign_ca() -> Result<Certificate, Box<dyn Error>> {
	let account = create_secp256k1_test_account(Some(3));
	let dn = create_dn(&[(oids::CN, "Foreign CA")])?;
	let spki = SubjectPublicKeyInfo::try_from(&account)?;
	let ca = CertificateBuilder::for_ca()
		.without_common_extensions()
		.with_subject_dn(dn.clone())
		.with_issuer_dn(dn)
		.with_serial_number(SerialNumber::from(301u64))
		.with_validity_days(3650)
		.with_subject_public_key(spki)
		.build(&account.keypair)?;

	Ok(ca)
}

/// The published record whose certificate parses equal to `pem`. A missing
/// record is a test bug, so the helper may panic.
fn record_for<'records>(records: &'records [AccountCertificate], pem: &str) -> &'records AccountCertificate {
	let wanted: Certificate = pem.parse().expect("harness PEM parses");
	records
		.iter()
		.find(|record| record.certificate.parse::<Certificate>().ok().as_ref() == Some(&wanted))
		.expect("published record reads back")
}

#[tokio::test]
async fn published_certificates_read_back_with_and_without_intermediates() -> TestResult {
	let mut kyc = KycHarness::start()?;
	let _anchor = kyc.start_kyc_anchor(None, true)?;
	let chain = kyc.publish_certificate_chain()?;
	let client = KeetaClient::new(&chain.api);

	let account = GenericAccount::from_str(&chain.account)?;
	let records = client.certificates(&account).await?;
	assert_eq!(records.len(), 2, "both published records must read back");

	let ca: Certificate = chain.ca.parse()?;
	let with_intermediates = record_for(&records, &chain.leaf);
	let intermediates: Vec<Certificate> = with_intermediates
		.intermediates
		.iter()
		.map(|pem| pem.parse::<Certificate>())
		.collect::<Result<_, _>>()?;
	assert_eq!(intermediates, [ca], "the recorded CA bundle must survive the round trip");

	let without_intermediates = record_for(&records, &chain.bare);
	assert!(
		without_intermediates.intermediates.is_empty(),
		"a record published without intermediates must decode as empty"
	);

	kyc.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn published_chain_status_matches_the_trust_set() -> TestResult {
	let mut kyc = KycHarness::start()?;
	let anchor = kyc.start_kyc_anchor(None, true)?;
	let chain = kyc.publish_certificate_chain()?;
	let client = KeetaClient::new(&chain.api);

	let ca: Certificate = chain.ca.parse()?;
	let now = Utc::now();
	/* The harness leaves expire after an hour, so two hours out is past expiry. */
	let after_expiry = now + Duration::hours(2);

	let cases = [
		(
			"leaf chains to the anchor CA",
			chain.account.as_str(),
			vec![ca.clone()],
			now,
			CertificateChainStatus::Trusted,
		),
		(
			"leaf against a foreign trust set",
			chain.account.as_str(),
			vec![foreign_ca()?],
			now,
			CertificateChainStatus::Untrusted,
		),
		(
			"leaf evaluated past its expiry",
			chain.account.as_str(),
			vec![ca.clone()],
			after_expiry,
			CertificateChainStatus::Untrusted,
		),
		(
			"account with no published certificates",
			anchor.root.as_str(),
			vec![ca],
			now,
			CertificateChainStatus::NoCerts,
		),
	];

	for (label, account, trusted, moment, expected) in cases {
		let account = GenericAccount::from_str(account)?;
		let status = verify_account_certificate_chain(&client, &account, &trusted, moment).await?;
		assert_eq!(status, expected, "{label}");
	}

	kyc.shutdown()?;
	Ok(())
}

//! External blob references end to end: the client fetch layer (`data:` and
//! harness HTTP URLs), both live cross-implementation directions against the
//! TypeScript reference, and the pinned build-side divergence.

mod harness;

use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use harness::{KycHarness, SharableHarness};
use keetanetwork_account::{GenericAccount, KeyECDSASECP256K1};
use keetanetwork_anchor::certificates::{KycCertificate, KycCertificateBuilder};
use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
use keetanetwork_anchor::kyc_schema::{AttributeReference, DigestInfo, ExternalReference, ReferenceEncryption};
use keetanetwork_anchor::sharable_attributes::error::SharableAttributesError;
use keetanetwork_anchor::sharable_attributes::{FromCertificateOptions, SharableCertificateAttributes};
use keetanetwork_anchor::testing::create_account_from_seed_hex;
use keetanetwork_anchor_client::{fetch_external_blobs, sharable_with_references, AnchorClientError, ReqwestTransport};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::prelude::{HashAlgorithm, IntoSecret};
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use keetanetwork_x509::utils::create_dn;
use keetanetwork_x509::SerialNumber;
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The subject seed the leaf is issued for on both sides.
const SUBJECT_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// The recipient seed the bundle is sealed to on both sides.
const RECIPIENT_SEED: &str = "3333333333333333333333333333333333333333333333333333333333333333";
/// The attribute carrying the external reference.
const LICENSE: &str = "documentDriversLicense";
/// The referenced blob's plaintext, digest-certified by the reference.
const BLOB_PLAINTEXT: &[u8] = b"NOT REALLY A PNG";

/// The subject signing account shared by every fixture.
fn subject_account() -> Arc<GenericAccount> {
	let subject = create_account_from_seed_hex::<KeyECDSASECP256K1>(SUBJECT_SEED, 0);
	Arc::new(GenericAccount::EcdsaSecp256k1(subject))
}

/// Seal `plaintext` to `subject` as a locked encrypted container, the raw
/// stored form a reference blob is served in.
fn seal_blob(plaintext: &[u8], subject: &Arc<GenericAccount>) -> Vec<u8> {
	let options = FromPlaintextOptions { locked: Some(true), signer: None };
	let principals = Some(vec![Arc::clone(subject)]);
	let mut container = EncryptedContainer::from_plaintext(plaintext.to_vec(), principals, options);

	container.get_encoded().expect("sealed blob encodes")
}

/// The drivers-license attribute value referencing `url` with a `digest`
/// certifying the blob plaintext, in the byte shape both implementations decode.
fn license_value(url: &str, digest: &[u8]) -> Value {
	json!({
		"documentNumber": "DL-7",
		"front": {
			"external": { "url": url, "contentType": "image/png" },
			"digest": { "digestAlgorithm": "sha3-256", "digest": { "type": "Buffer", "data": digest } },
			"encryptionAlgorithm": "1.3.6.1.4.1.62675.2",
		},
	})
}

/// Issue a leaf for the shared subject carrying the sensitive license value.
fn issue_license_certificate(value: &Value) -> Result<KycCertificate, Box<dyn Error>> {
	let subject = create_account_from_seed_hex::<KeyECDSASECP256K1>(SUBJECT_SEED, 0);
	let issuer = create_account_from_seed_hex::<KeyECDSASECP256K1>(RECIPIENT_SEED, 1);
	let spki = SubjectPublicKeyInfo::try_from(&subject)?;
	let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Subject")])?;
	let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Issuer")])?;
	let license_bytes = serde_json::to_vec(value)?;

	let certificate = KycCertificateBuilder::for_end_entity()
		.with_subject_dn(subject_dn)
		.with_issuer_dn(issuer_dn)
		.with_serial_number(SerialNumber::from(21u64))
		.with_validity_days(365)
		.with_subject_public_key(spki)
		.with_sensitive_attribute(LICENSE, license_bytes.into_secret())
		.build(&subject.keypair, &issuer.keypair)?;

	Ok(certificate)
}

/// A `data:` URL carrying `bytes` base64-inline.
fn data_url(bytes: &[u8]) -> String {
	format!("data:application/octet-string;base64,{}", STANDARD.encode(bytes))
}

/// Build the bundle with references fetched over `transport`, grant the shared
/// recipient, and export the PEM.
async fn export_with_references(certificate: &KycCertificate) -> Result<String, Box<dyn Error>> {
	let transport = ReqwestTransport::try_default()?;
	let subject = subject_account();
	let mut sharable =
		sharable_with_references(&transport, certificate, &subject, [LICENSE], FromCertificateOptions::default())
			.await?;

	let recipient = create_account_from_seed_hex::<KeyECDSASECP256K1>(RECIPIENT_SEED, 0);
	sharable.grant_access([GenericAccount::EcdsaSecp256k1(recipient)])?;

	Ok(sharable.to_pem()?)
}

/// Open a bundle PEM with the shared recipient key.
fn open_as_recipient(pem: &str) -> Result<SharableCertificateAttributes, Box<dyn Error>> {
	let recipient = create_account_from_seed_hex::<KeyECDSASECP256K1>(RECIPIENT_SEED, 0);
	let principals = [GenericAccount::EcdsaSecp256k1(recipient)];

	Ok(SharableCertificateAttributes::from_pem(pem, principals)?)
}

/// The plaintext the reference reader resolved for the license reference `id`
/// in an `open_sharable` harness response.
fn ts_resolved_blob(opened: &Value, id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
	let blob = opened
		.get("blobs")
		.and_then(|blobs| blobs.get(LICENSE))
		.and_then(|references| references.get(id))
		.ok_or("the reference must resolve the inlined blob")?;
	let data = blob
		.get("data")
		.and_then(Value::as_str)
		.ok_or("the resolved blob must carry base64 data")?;

	Ok(STANDARD.decode(data)?)
}

#[tokio::test]
async fn fetch_external_blobs_decodes_data_urls_offline() -> TestResult {
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let reference = AttributeReference {
		external: ExternalReference { url: data_url(BLOB_PLAINTEXT), content_type: "image/png".to_string() },
		digest: DigestInfo { algorithm: HashAlgorithm::Sha3_256, digest },
		encryption: ReferenceEncryption::KeetaEncryptedContainerV1,
	};

	let transport = ReqwestTransport::try_default()?;
	let blobs = fetch_external_blobs(&transport, [&reference]).await?;

	assert_eq!(
		blobs.get(&reference.id()),
		Some(BLOB_PLAINTEXT),
		"a data: URL must decode inline without touching the network"
	);
	Ok(())
}

#[tokio::test]
async fn wrapped_harness_blobs_unwrap_through_http() -> TestResult {
	let subject = subject_account();
	let sealed = seal_blob(BLOB_PLAINTEXT, &subject);
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);

	// The harness serves the sealed blob wrapped in the storage-service
	// `{data, mimeType}` JSON convention; the fetch layer must unwrap it.
	let mut harness = KycHarness::start()?;
	let url = harness.serve_blob(&sealed, "image/png", true)?;

	let certificate = issue_license_certificate(&license_value(&url, &digest))?;
	let pem = export_with_references(&certificate).await?;
	harness.shutdown()?;

	let mut opened = open_as_recipient(&pem)?;
	assert_eq!(
		opened.reference_blob(LICENSE, &id)?,
		Some(BLOB_PLAINTEXT.to_vec()),
		"the wrapped HTTP blob must ingest digest-verified"
	);
	Ok(())
}

#[tokio::test]
async fn raw_harness_blobs_pass_through_http_into_a_bundle_typescript_opens() -> TestResult {
	let subject = subject_account();
	let sealed = seal_blob(BLOB_PLAINTEXT, &subject);
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);

	// The harness serves the sealed blob raw (no JSON wrapper); the fetch
	// layer must pass the DER body through untouched.
	let mut harness = KycHarness::start()?;
	let url = harness.serve_blob(&sealed, "application/octet-stream", false)?;

	let certificate = issue_license_certificate(&license_value(&url, &digest))?;
	let pem = export_with_references(&certificate).await?;

	let opened = harness.open_sharable(&pem, RECIPIENT_SEED, &[LICENSE])?;
	harness.shutdown()?;

	let recovered = ts_resolved_blob(&opened, &id)?;
	assert_eq!(
		recovered, BLOB_PLAINTEXT,
		"the reference reader must recover the raw HTTP-sourced blob byte-for-byte"
	);
	Ok(())
}

#[tokio::test]
async fn typescript_opens_a_rust_bundle_with_references() -> TestResult {
	let subject = subject_account();
	let sealed = seal_blob(BLOB_PLAINTEXT, &subject);
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);

	let certificate = issue_license_certificate(&license_value(&data_url(&sealed), &digest))?;
	let pem = export_with_references(&certificate).await?;

	// The reference reader resolves `$blob` on the Rust-built bundle and
	// hash-verifies the payload itself (it throws on an access-time mismatch).
	let mut harness = KycHarness::start()?;
	let opened = harness.open_sharable(&pem, RECIPIENT_SEED, &[LICENSE])?;
	harness.shutdown()?;

	let recovered = ts_resolved_blob(&opened, &id)?;
	assert_eq!(
		recovered, BLOB_PLAINTEXT,
		"the reference reader must recover the referenced plaintext byte-for-byte"
	);
	Ok(())
}

#[tokio::test]
async fn rust_ingests_a_typescript_built_bundle_with_references() -> TestResult {
	let subject = subject_account();
	let sealed = seal_blob(BLOB_PLAINTEXT, &subject);
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);
	let attributes = json!([
		{ "name": LICENSE, "sensitive": true, "value": license_value(&data_url(&sealed), &digest) }
	]);

	// The reference builder walks `$blob`, fetches the data: URL, decrypts, and
	// in-lines the verified payload into the bundle it exports.
	let mut harness = SharableHarness::start()?;
	let built = harness.build_sharable(SUBJECT_SEED, RECIPIENT_SEED, &attributes)?;
	harness.shutdown()?;

	let pem = built
		.get("pem")
		.and_then(Value::as_str)
		.ok_or("the reference must export the bundle PEM")?;

	let mut opened = open_as_recipient(pem)?;
	assert_eq!(
		opened.reference_blob(LICENSE, &id)?,
		Some(BLOB_PLAINTEXT.to_vec()),
		"the Rust reader must recover the TypeScript-inlined blob digest-verified"
	);
	Ok(())
}

#[tokio::test]
async fn a_corrupted_blob_errors_in_rust_where_typescript_omits_it() -> TestResult {
	// The reference certifies BLOB_PLAINTEXT but the URL serves different
	// sealed content, so decryption succeeds and the digest check fails.
	let subject = subject_account();
	let corrupted = seal_blob(b"tampered content", &subject);
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);
	let value = license_value(&data_url(&corrupted), &digest);

	// TypeScript build-side swallows the mismatch and emits the bundle without
	// the reference (certificates.ts catch -> undefined).
	let attributes = json!([{ "name": LICENSE, "sensitive": true, "value": value }]);
	let mut harness = SharableHarness::start()?;
	let built = harness.build_sharable(SUBJECT_SEED, RECIPIENT_SEED, &attributes)?;

	harness.shutdown()?;

	let pem = built
		.get("pem")
		.and_then(Value::as_str)
		.ok_or("the reference must still export a bundle for the corrupted blob")?;
	let mut opened = open_as_recipient(pem)?;
	assert_eq!(
		opened.reference_blob(LICENSE, &id)?,
		None,
		"TypeScript must have silently omitted the corrupted reference"
	);

	// Rust build-side is a deliberate divergence: the same corrupted blob must
	// fail loud instead of silently dropping the reference.
	let certificate = issue_license_certificate(&value)?;
	let transport = ReqwestTransport::try_default()?;
	let outcome =
		sharable_with_references(&transport, &certificate, &subject, [LICENSE], FromCertificateOptions::default())
			.await;
	assert!(
		matches!(
			outcome,
			Err(AnchorClientError::Sharable { source: SharableAttributesError::ReferenceDigestMismatch { .. } })
		),
		"Rust must surface the digest mismatch instead of omitting the reference"
	);
	Ok(())
}

#[test]
fn external_references_survive_the_leaf_pem_round_trip() -> TestResult {
	let subject = subject_account();
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);
	let url = data_url(b"placeholder");

	let certificate = issue_license_certificate(&license_value(&url, &digest))?;
	let pem = certificate.to_x509().to_pem()?;
	let re_parsed = KycCertificate::new(X509Certificate::from_str(&pem)?);

	let discovered = re_parsed.external_references(subject.as_ref(), [LICENSE])?;
	let references = discovered
		.get(LICENSE)
		.ok_or("the re-parsed leaf must expose the license references")?;
	assert_eq!(references.len(), 1, "exactly one reference must be discovered");
	assert_eq!(references[0].id(), id, "the reference id must be the uppercase-hex digest");
	assert_eq!(references[0].external.url, url, "the reference URL must survive the round trip");
	Ok(())
}

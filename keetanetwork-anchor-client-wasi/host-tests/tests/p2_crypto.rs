//! wasmtime P2 offline `crypto` tests.
//!
//! These drive the exported `account`, `certificate`, and `kyc-certificate`
//! resources with no network and no harness — only the prebuilt component.

mod common;
mod wasmtime_p2;

use common::BoxError;
use wasmtime_p2::{coded, component_built, instantiate};

/// The deterministic seed `doc_utils` derives its test subject from; the KYC
/// fixture below is signed for the secp256k1 account at index 0 of this seed.
const SUBJECT_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";
const ALGORITHM: &str = "ecdsa_secp256k1";

/// Unix seconds inside the fixture's one-year validity (2026-06-28..2027-06-28).
const VALID_AT: i64 = 1_797_292_800;
/// Unix seconds before the fixture is valid (the epoch).
const BEFORE_VALIDITY: i64 = 0;
/// Unix seconds long after the fixture expires (2100).
const AFTER_VALIDITY: i64 = 4_102_444_800;

/// A KYC certificate carrying `postalCode` (plain) plus `email` and `fullName`
/// (sensitive), issued to the secp256k1 subject at index 0 of [`SUBJECT_SEED`].
const FIXTURE_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDzTCCA3SgAwIBAgICMDkwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxYLVGVzdCBJ
c3N1ZXIwIhgPMjAyNjA2MjgyMzIwNDVaGA8yMDI3MDYyODIzMjA0NVowFzEVMBMG
A1UEAxYMVGVzdCBTdWJqZWN0MDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACpkFiKH+5
y+/csZUSPRIZwON061asGjraczszX1LL2HujggLOMIICyjAOBgNVHQ8BAf8EBAMC
AMAwggK2BgorBgEEAYPpUwAABIICpjCCAqIwggFKBgorBgEEAYPpUwEDgYIBOjCC
ATYCAQAwga0GCWCGSAFlAwQBLgQMfrJEYqEtjXoXFJrDBIGRBFEOgNX6ho8+Fil3
91HDLYxx5u/l5UuOQFnJizMqoBkD/64XdrGWeURzt5ERG33SBxNJLaIbGLfU+w+a
mu8HII50cSOjYYGalY7HbfAxqp0QStJZC9FTnr5+jHXQLSrfLnViXjPSz9sk7+xq
eptUlXaromEIBaKAzavrUB8xlayBDh6hXNEToOjxmSai5f4khTBfBDD4fEMxz1aM
wJbcmH5fi75NVNQH//2775k63qU3kWwuGu4yMrwa0TVvAd274S0xbC8GCWCGSAFl
AwQCCAQgEj0cBCSSIdCPXWPhbdFGvSuSbegC0XhbAG82dmNRkbIEIA87wpxepdKD
7qOY7UUEd9YUxIeSSBFwM2KPhO30zl+DMIIBQgYKKwYBBAGD6VMBAIGCATIwggEu
AgEAMIGtBglghkgBZQMEAS4EDKznmG0IQycoVdJ9VQSBkQT/6Qumd90HGs1cof3u
5derYnULnG3pbLxExHPqdzIwnOcXyFvGR8DDgBXYmUCspHjH3AQN6wYDfQ0IQ89F
uakNlpGpGMWy152544+VG3fbrJmPkRhxKHPpYmQfiUGMqF0kGE7tLwzbC7cLx0ni
jkkXUwlX5/UV3kJT3wBQciD1gKgl4euhYNxAfuyLtkZaZhkwXwQwJXrikAzhMr8q
kKtaDkAohxfngm3mLEzsE+MmuI7hobUEIm59Uze8K3JG35L7OfVABglghkgBZQME
AggEIGJ8nq65ul0UKAY3UL84Mg0Iddj9VYVNBa3oTnANZXYfBBgqlBgcLrd4of/W
Hu4NJE0IKwCL+Gnbok4wDAYDVQURgAUxMjM0NTAKBggqhkjOPQQDAgNHADBEAiBY
mcOwl1yNkItpFWeWby4gqa0rHOw7U0bHxpk9kYWHbgIgVbO0xyOAB7ByOqMO40Qh
or6z8/Cbh+JIKGADPmGawrE=
-----END CERTIFICATE-----
";

/// Skip when the component has not been built.
macro_rules! require_component {
	() => {
		if !component_built() {
			eprintln!("skipping P2 crypto test: build the wasm32-wasip2 component first");
			return Ok(());
		}
	};
}

#[tokio::test]
async fn account_signs_and_verifies_a_message() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();

	let account = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;

	let algorithm = crypto.account().call_algorithm(&mut store, account).await?;
	assert_eq!(algorithm, ALGORITHM, "the account must report its derivation algorithm");

	let address = crypto.account().call_address(&mut store, account).await?;
	assert!(address.starts_with("keeta_"), "the address must be a textual keeta address");

	let message = b"sign over wasi".to_vec();
	let signature = crypto
		.account()
		.call_sign(&mut store, account, &message)
		.await?
		.map_err(coded)?;
	assert!(!signature.is_empty(), "the signature must be non-empty");

	let valid = crypto
		.account()
		.call_verify(&mut store, account, &message, &signature)
		.await?;
	assert!(valid, "the account must verify its own signature");

	let tampered = b"sign over waso".to_vec();
	let rejected = crypto
		.account()
		.call_verify(&mut store, account, &tampered, &signature)
		.await?;
	assert!(!rejected, "a signature must not verify against a different message");

	Ok(())
}

#[tokio::test]
async fn certificate_round_trips_pem_and_reports_validity() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();

	let certificate = crypto
		.certificate()
		.call_parse(&mut store, FIXTURE_PEM)
		.await?
		.map_err(coded)?;

	let pem = crypto
		.certificate()
		.call_pem(&mut store, certificate)
		.await?
		.map_err(coded)?;
	assert!(pem.contains("BEGIN CERTIFICATE"), "the PEM encoding must be a certificate block");

	let inside = crypto
		.certificate()
		.call_valid_at(&mut store, certificate, VALID_AT)
		.await?;
	assert!(inside, "the certificate must be valid inside its window");

	let before = crypto
		.certificate()
		.call_valid_at(&mut store, certificate, BEFORE_VALIDITY)
		.await?;
	assert!(!before, "the certificate must be invalid before its window");

	let after = crypto
		.certificate()
		.call_valid_at(&mut store, certificate, AFTER_VALIDITY)
		.await?;
	assert!(!after, "the certificate must be invalid after its window");

	Ok(())
}

#[tokio::test]
async fn certificate_reports_metadata() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();

	let certificate = crypto
		.certificate()
		.call_parse(&mut store, FIXTURE_PEM)
		.await?
		.map_err(coded)?;

	let subject = crypto.certificate().call_subject(&mut store, certificate).await?;
	assert!(subject.contains("Test Subject"), "the subject DN must name the fixture subject");

	let issuer = crypto.certificate().call_issuer(&mut store, certificate).await?;
	assert!(issuer.contains("Test Issuer"), "the issuer DN must name the fixture issuer");

	let serial = crypto.certificate().call_serial(&mut store, certificate).await?;
	assert_eq!(serial, "12345", "the serial must decode to its base-10 form");

	let not_before = crypto.certificate().call_not_before(&mut store, certificate).await?;
	let not_after = crypto.certificate().call_not_after(&mut store, certificate).await?;
	assert!(not_before < not_after, "the validity window must be ordered");
	assert!(
		not_before <= VALID_AT && VALID_AT <= not_after,
		"the in-window moment must fall inside the reported validity window"
	);

	// The subject public key must equal the public key of the account derived
	// from the same seed, so a holder can match a certificate to its account.
	let account = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let account_key = crypto.account().call_public_key(&mut store, account).await?;
	let subject_key = crypto
		.certificate()
		.call_subject_public_key(&mut store, certificate)
		.await?
		.map_err(coded)?;
	assert_eq!(subject_key, account_key, "the subject public key must equal the subject account's public key");

	Ok(())
}

#[tokio::test]
async fn kyc_certificate_reads_chains_and_decrypts() -> Result<(), BoxError> {
	require_component!();
	let (mut store, bindings) = instantiate().await?;
	let crypto = bindings.keeta_client_crypto();
	let certificates = bindings.keeta_anchor_certificates();

	let leaf = certificates
		.kyc_certificate()
		.call_parse(&mut store, FIXTURE_PEM)
		.await?
		.map_err(coded)?;

	let attributes = certificates
		.kyc_certificate()
		.call_attributes(&mut store, leaf)
		.await?;
	assert_eq!(attributes.len(), 3, "the fixture carries three KYC attributes");

	let sensitive = attributes
		.iter()
		.filter(|attribute| attribute.sensitive)
		.count();
	assert_eq!(sensitive, 2, "two of the fixture's attributes are sensitive");

	let postal = certificates
		.kyc_certificate()
		.call_plain_attribute(&mut store, leaf, "postalCode")
		.await?
		.map_err(coded)?;
	assert_eq!(postal, b"12345", "the plain postal code must read back verbatim");

	let valid = certificates
		.kyc_certificate()
		.call_valid_at(&mut store, leaf, VALID_AT)
		.await?;
	assert!(valid, "the leaf must be valid inside its window");

	let base = certificates
		.kyc_certificate()
		.call_base(&mut store, leaf)
		.await?;
	let base_pem = crypto
		.certificate()
		.call_pem(&mut store, base)
		.await?
		.map_err(coded)?;
	assert!(base_pem.contains("BEGIN CERTIFICATE"), "the base certificate must encode to PEM");

	// The fixture is self-trusting: its own base certificate, parsed as a root,
	// anchors the chain at a moment inside its validity.
	let root = crypto
		.certificate()
		.call_parse(&mut store, FIXTURE_PEM)
		.await?
		.map_err(coded)?;
	let trusted = certificates
		.kyc_certificate()
		.call_verify(&mut store, leaf, &[root], &[], VALID_AT)
		.await?
		.map_err(coded)?;
	assert!(trusted, "the leaf must chain to its own certificate as a trusted root");
	let untrusted = certificates
		.kyc_certificate()
		.call_verify(&mut store, leaf, &[], &[], VALID_AT)
		.await?
		.map_err(coded)?;
	assert!(!untrusted, "the leaf must not verify with an empty trust set");

	// Reproduce the subject account from the same seed and decrypt a sensitive
	// claim, proving the borrow<account> decryption path round-trips.
	let subject = crypto
		.account()
		.call_from_seed(&mut store, SUBJECT_SEED, 0, ALGORITHM)
		.await?
		.map_err(coded)?;
	let email = certificates
		.kyc_certificate()
		.call_decrypt_attribute(&mut store, leaf, "email", subject)
		.await?
		.map_err(coded)?;
	assert_eq!(email, b"john@example.com", "the decrypted email must match the issued claim");

	Ok(())
}

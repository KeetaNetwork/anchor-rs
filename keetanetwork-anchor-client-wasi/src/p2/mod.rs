//! WASI Preview 2 component: the `crypto` primitives plus the networked KYC `client`.

#![allow(clippy::arc_with_non_send_sync)]

use core::future::Future;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::certificates::KycCertificate as CoreKycCertificate;
use keetanetwork_anchor_bindings::certificate as kyc_cert_ops;
use keetanetwork_anchor_bindings::error::CodedError as CoreCodedError;
use keetanetwork_anchor_client::resilience::{ResilientTransport, WasiRuntime};
use keetanetwork_anchor_client::{
	AnchorClientError, AnchorContext, AnchorHttpTransport, AnchorOutcome, Certificates, CountryCode, ExpectedCost,
	KycClient, KycOperations, KycProvider, Resolver, Verification, VerificationStatus, WasiTransport,
};
use keetanetwork_bindings::account as account_ops;
use keetanetwork_bindings::x509 as x509_ops;
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use wstd::runtime::block_on;

wit_bindgen::generate!({
	world: "keeta-anchor-kyc",
	path: "wit",
	// The world re-exports the vendored `keeta:client` `crypto` interface and
	// `use`s its `types`, so generate bindings for those foreign interfaces too.
	generate_all,
});

use exports::keeta::anchor::certificates::{
	Guest as CertificatesGuest, GuestKycCertificate, KycCertificate as WitKycCertificate,
};
use exports::keeta::anchor::kyc::{Client, Guest as KycGuest, GuestClient};
use exports::keeta::client::crypto::{
	Account as WitAccount, AccountBorrow, Certificate as WitCertificate, CertificateBorrow, Guest as CryptoGuest,
	GuestAccount, GuestCertificate,
};
use keeta::anchor::types::{
	AttributeProof as WitAttributeProof, CertificateGroup, CertificatesOutcome, ExpectedCost as WitExpectedCost,
	IssueAttribute, KycAttribute, KycOperations as WitOperations, KycProvider as WitProvider, StatusOutcome,
	Verification as WitVerification, VerificationOutcome, VerificationStatus as WitVerificationStatus,
};
use keeta::client::types::CodedError;

/// An erased Keeta account shared by reference across the `crypto` boundary.
type AccountRef = Arc<GenericAccount>;

/// Multiply Unix `seconds` into milliseconds for the millisecond-based cores,
/// rejecting a value that would overflow.
fn seconds_to_millis(seconds: i64) -> Result<i64, CodedError> {
	seconds
		.checked_mul(1000)
		.ok_or_else(|| CodedError { code: "INVALID_DATE".into(), message: "unix seconds out of range".into() })
}

struct Component;

impl CryptoGuest for Component {
	type Account = AccountResource;
	type Certificate = CertificateResource;
}

impl CertificatesGuest for Component {
	type KycCertificate = KycCertificateResource;
}

// ---------------------------------------------------------------------------
// account resource
// ---------------------------------------------------------------------------

/// A signing or read-only account, stored erased over its algorithm.
struct AccountResource {
	account: AccountRef,
}

impl GuestAccount for AccountResource {
	fn from_seed(seed: String, index: u32, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_seed(&seed, index, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_private_key(key: String, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_private_key(&key, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_passphrase(words: Vec<String>, index: u32, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_passphrase(words, index, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_public_key(key: String, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_public_key(&key, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_address(address: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_address(&address)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn generate_seed() -> String {
		account_ops::generate_seed().unwrap_or_default()
	}

	fn generate_passphrase() -> Vec<String> {
		account_ops::generate_passphrase().unwrap_or_default()
	}

	fn address(&self) -> String {
		account_ops::account_address(&self.account)
	}

	fn algorithm(&self) -> String {
		account_ops::account_algorithm(&self.account)
	}

	fn public_key(&self) -> String {
		account_ops::account_public_key(&self.account)
	}

	fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(account_ops::account_sign(&self.account, &message)?)
	}

	fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
		account_ops::account_verify(&self.account, &message, &signature)
	}

	fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(account_ops::account_encrypt(&self.account, &plaintext)?)
	}

	fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(account_ops::account_decrypt(&self.account, &ciphertext)?)
	}
}

// ---------------------------------------------------------------------------
// certificate resource
// ---------------------------------------------------------------------------

/// A base X.509 certificate: a provider CA, a trust root, or an intermediate.
struct CertificateResource {
	certificate: X509Certificate,
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
}

// ---------------------------------------------------------------------------
// kyc-certificate resource
// ---------------------------------------------------------------------------

/// A KYC leaf certificate: a base certificate plus parsed KYC attributes.
struct KycCertificateResource {
	certificate: CoreKycCertificate,
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
}

/// Clone each borrowed base certificate out for the chain evaluator.
fn collect_certificates(borrows: &[CertificateBorrow<'_>]) -> Vec<X509Certificate> {
	borrows
		.iter()
		.map(|borrow| borrow.get::<CertificateResource>().certificate.clone())
		.collect()
}

// ---------------------------------------------------------------------------
// kyc client resource
// ---------------------------------------------------------------------------

/// The resource state backing the exported `client`.
struct KycSession {
	inner: KycClient,
}

impl KycGuest for Component {
	type Client = KycSession;
}

impl GuestClient for KycSession {
	fn with_account(node_url: String, root: String, signer: AccountBorrow<'_>) -> Result<Client, CodedError> {
		let account = Arc::clone(&signer.get::<AccountResource>().account);
		Ok(Client::new(Self { inner: build_client(node_url, root, account) }))
	}

	fn providers(&self, countries: Vec<String>) -> Result<Vec<WitProvider>, CodedError> {
		let codes = country_codes(&countries)?;
		let providers = run(async { self.inner.providers(&codes).await })?;
		Ok(providers.into_iter().map(WitProvider::from).collect())
	}

	fn create_verification(
		&self,
		provider: WitProvider,
		countries: Vec<String>,
		redirect_url: Option<String>,
	) -> Result<VerificationOutcome, CodedError> {
		let provider = KycProvider::try_from(provider)?;
		let codes = country_codes(&countries)?;
		let redirect = redirect_url.as_deref();
		let outcome = run(async {
			self.inner
				.create_verification(&provider, &codes, redirect)
				.await
		})?;
		Ok(outcome.into())
	}

	fn get_certificates(&self, provider: WitProvider, id: String) -> Result<CertificatesOutcome, CodedError> {
		let provider = KycProvider::try_from(provider)?;
		let outcome = run(async { self.inner.get_certificates(&provider, &id).await })?;
		Ok(outcome.into())
	}

	fn get_verification_status(&self, provider: WitProvider, id: String) -> Result<StatusOutcome, CodedError> {
		let provider = KycProvider::try_from(provider)?;
		let outcome = run(async { self.inner.get_verification_status(&provider, &id).await })?;
		Ok(outcome.into())
	}
}

/// Build a networked KYC client signed by `signer`: a `wasi:http` transport
/// wrapped in the resilience policy, a metadata resolver reading `root` via the
/// node API at `node_url`, and the bound `signer`.
fn build_client(node_url: String, root: String, signer: Arc<GenericAccount>) -> KycClient {
	let base: Arc<dyn AnchorHttpTransport> = Arc::new(WasiTransport::default());
	let transport: Arc<dyn AnchorHttpTransport> = Arc::new(ResilientTransport::new(base, WasiRuntime));
	let resolver = Resolver::new(transport.clone(), node_url, [root]);
	let context = AnchorContext::new(resolver, transport, signer);
	KycClient::new(context)
}

/// Drive an async client call to completion on the `wstd` reactor, projecting
/// its error to the WIT boundary type.
fn run<T>(future: impl Future<Output = Result<T, AnchorClientError>>) -> Result<T, CodedError> {
	block_on(future).map_err(CodedError::from)
}

/// Parse ISO `values` into canonical country codes for discovery and requests.
fn country_codes(values: &[String]) -> Result<Vec<CountryCode>, CodedError> {
	values
		.iter()
		.map(|value| {
			CountryCode::try_from(value.as_str())
				.map_err(|_| CodedError { code: "INVALID_COUNTRY".into(), message: "invalid country code".into() })
		})
		.collect()
}

// ---------------------------------------------------------------------------
// Boundary conversions: core domain values to/from the generated WIT types.
// ---------------------------------------------------------------------------

impl From<AnchorClientError> for CodedError {
	fn from(error: AnchorClientError) -> Self {
		Self { code: error.code().into(), message: error.to_string() }
	}
}

impl From<CoreCodedError> for CodedError {
	fn from(error: CoreCodedError) -> Self {
		Self { code: error.code, message: error.message }
	}
}

impl From<KycProvider> for WitProvider {
	fn from(provider: KycProvider) -> Self {
		let country_codes = provider
			.country_codes
			.map(|codes| codes.iter().map(|code| code.as_str().to_string()).collect());

		Self { id: provider.id, ca: provider.ca, operations: WitOperations::from(provider.operations), country_codes }
	}
}

impl TryFrom<WitProvider> for KycProvider {
	type Error = CodedError;

	fn try_from(provider: WitProvider) -> Result<Self, Self::Error> {
		let country_codes = provider
			.country_codes
			.map(|codes| country_codes(&codes))
			.transpose()?;

		Ok(Self {
			id: provider.id,
			ca: provider.ca,
			operations: KycOperations::from(provider.operations),
			country_codes,
		})
	}
}

impl From<KycOperations> for WitOperations {
	fn from(operations: KycOperations) -> Self {
		Self {
			create_verification: operations.create_verification,
			get_certificates: operations.get_certificates,
			get_verification_status: operations.get_verification_status,
			check_locality: operations.check_locality,
			get_estimate: operations.get_estimate,
		}
	}
}

impl From<WitOperations> for KycOperations {
	fn from(operations: WitOperations) -> Self {
		Self {
			create_verification: operations.create_verification,
			get_certificates: operations.get_certificates,
			get_verification_status: operations.get_verification_status,
			check_locality: operations.check_locality,
			get_estimate: operations.get_estimate,
		}
	}
}

impl From<ExpectedCost> for WitExpectedCost {
	fn from(cost: ExpectedCost) -> Self {
		Self { min: cost.min, max: cost.max, token: cost.token }
	}
}

impl From<AnchorOutcome<Verification>> for VerificationOutcome {
	fn from(outcome: AnchorOutcome<Verification>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => Self::Ready(WitVerification {
				id: value.id,
				web_url: value.web_url,
				expected_cost: value.expected_cost.into(),
			}),
			AnchorOutcome::Retry { after_ms } => Self::Retry(after_ms),
		}
	}
}

impl From<AnchorOutcome<VerificationStatus>> for StatusOutcome {
	fn from(outcome: AnchorOutcome<VerificationStatus>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => Self::Ready(WitVerificationStatus { status: value.status }),
			AnchorOutcome::Retry { after_ms } => Self::Retry(after_ms),
		}
	}
}

impl From<AnchorOutcome<Certificates>> for CertificatesOutcome {
	fn from(outcome: AnchorOutcome<Certificates>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => {
				let groups = value
					.results
					.into_iter()
					.map(|certificate| CertificateGroup {
						certificate: certificate.certificate,
						intermediates: certificate.intermediates,
					})
					.collect();
				Self::Ready(groups)
			}
			AnchorOutcome::Retry { after_ms } => Self::Retry(after_ms),
		}
	}
}

export!(Component);

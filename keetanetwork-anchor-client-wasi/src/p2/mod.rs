//! WASI Preview 2 component exposing the networked KYC anchor client.
//!
//! The generic [`KycClient<K>`](keetanetwork_anchor_client::KycClient) is bound
//! to a concrete key type at the boundary: `with-signer` matches the spec's
//! algorithm name and selects the matching variant of [`AnyKyc`].

#![allow(clippy::arc_with_non_send_sync)]

use core::future::Future;
use std::sync::Arc;

use keetanetwork_account::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair};
use keetanetwork_anchor_bindings::account::{account_from_seed, invalid_algorithm};
use keetanetwork_anchor_client::resilience::{ResilientTransport, WasiRuntime};
use keetanetwork_anchor_client::{
	AnchorClientError, AnchorContext, AnchorHttpTransport, AnchorOutcome, Certificate, Certificates, CountryCode,
	KycClient, KycOperations, KycProvider, Resolver, Verification, VerificationStatus, WasiTransport,
};
use wstd::runtime::block_on;

wit_bindgen::generate!({
	world: "keeta-anchor-kyc",
	path: "wit",
});

use exports::keeta::anchor::kyc::{Client, Guest, GuestClient};
use keeta::anchor::types::{
	Certificate as WitCertificate, Certificates as WitCertificates, CertificatesOutcome, CodedError,
	KycOperations as WitOperations, KycProvider as WitProvider, SignerSpec, StatusOutcome,
	Verification as WitVerification, VerificationOutcome, VerificationStatus as WitVerificationStatus,
};

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

/// Build a networked KYC client for a concrete key type: a `wasi:http`
/// transport wrapped in the resilience policy, a metadata resolver reading the
/// `root` account via the node API at `node_url`, and a signer from the spec.
fn build_client<K>(node_url: String, root: String, seed: &str, index: u32) -> Result<KycClient<K>, CodedError>
where
	K: KeyPair,
{
	let signer = account_from_seed::<K>(seed, index)?;
	let base: Arc<dyn AnchorHttpTransport> = Arc::new(WasiTransport::default());
	let transport: Arc<dyn AnchorHttpTransport> = Arc::new(ResilientTransport::new(base, WasiRuntime));
	let resolver = Resolver::new(transport.clone(), node_url, [root]);
	let context = AnchorContext::new(resolver, transport, signer);
	Ok(KycClient::new(context))
}

/// A KYC client monomorphized over one signing algorithm. The variants differ
/// in size, so each is boxed.
enum AnyKyc {
	Ed25519(Box<KycClient<KeyED25519>>),
	Secp256k1(Box<KycClient<KeyECDSASECP256K1>>),
	Secp256r1(Box<KycClient<KeyECDSASECP256R1>>),
}

/// Run `body` against the inner client whatever its algorithm, binding it to
/// `client` in each arm.
macro_rules! on_client {
	($session:expr, $client:ident => $body:expr) => {
		match &$session.inner {
			AnyKyc::Ed25519($client) => $body,
			AnyKyc::Secp256k1($client) => $body,
			AnyKyc::Secp256r1($client) => $body,
		}
	};
}

/// The resource state backing the exported `client`.
struct KycSession {
	inner: AnyKyc,
}

struct Component;

impl Guest for Component {
	type Client = KycSession;
}

impl GuestClient for KycSession {
	fn with_signer(node_url: String, root: String, spec: SignerSpec) -> Result<Client, CodedError> {
		let seed = spec.seed.as_str();
		let inner = match spec.algorithm.as_str() {
			"ed25519" => AnyKyc::Ed25519(Box::new(build_client::<KeyED25519>(node_url, root, seed, spec.index)?)),
			"ecdsa_secp256k1" => {
				AnyKyc::Secp256k1(Box::new(build_client::<KeyECDSASECP256K1>(node_url, root, seed, spec.index)?))
			}
			"ecdsa_secp256r1" => {
				AnyKyc::Secp256r1(Box::new(build_client::<KeyECDSASECP256R1>(node_url, root, seed, spec.index)?))
			}
			_ => return Err(invalid_algorithm().into()),
		};

		Ok(Client::new(Self { inner }))
	}

	fn providers(&self, countries: Vec<String>) -> Result<Vec<WitProvider>, CodedError> {
		let codes = country_codes(&countries)?;
		let providers = run(async { on_client!(self, client => client.providers(&codes).await) })?;
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
		let outcome =
			run(async { on_client!(self, client => client.create_verification(&provider, &codes, redirect).await) })?;
		Ok(outcome.into())
	}

	fn get_certificates(&self, provider: WitProvider, id: String) -> Result<CertificatesOutcome, CodedError> {
		let provider = KycProvider::try_from(provider)?;
		let outcome = run(async { on_client!(self, client => client.get_certificates(&provider, &id).await) })?;
		Ok(outcome.into())
	}

	fn get_verification_status(&self, provider: WitProvider, id: String) -> Result<StatusOutcome, CodedError> {
		let provider = KycProvider::try_from(provider)?;
		let outcome = run(async { on_client!(self, client => client.get_verification_status(&provider, &id).await) })?;
		Ok(outcome.into())
	}
}

// ---------------------------------------------------------------------------
// Boundary conversions: core domain values to/from the generated WIT types.
// ---------------------------------------------------------------------------

impl From<AnchorClientError> for CodedError {
	fn from(error: AnchorClientError) -> Self {
		Self { code: error_code(&error).into(), message: error.to_string() }
	}
}

impl From<keetanetwork_anchor_bindings::error::CodedError> for CodedError {
	fn from(error: keetanetwork_anchor_bindings::error::CodedError) -> Self {
		Self { code: error.code, message: error.message }
	}
}

/// The stable boundary code for an anchor client failure.
fn error_code(error: &AnchorClientError) -> &'static str {
	match error {
		AnchorClientError::Transport { .. } => "TRANSPORT",
		AnchorClientError::Resolver { .. } => "RESOLVER",
		AnchorClientError::Url { .. } => "INVALID_URL",
		AnchorClientError::Signing { .. } => "SIGNING",
		AnchorClientError::Request { .. } => "REQUEST",
		AnchorClientError::Body { .. } => "INVALID_BODY",
		AnchorClientError::Service { .. } => "SERVICE",
		AnchorClientError::UnsupportedOperation { .. } => "UNSUPPORTED_OPERATION",
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

impl From<AnchorOutcome<Verification>> for VerificationOutcome {
	fn from(outcome: AnchorOutcome<Verification>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => Self::Ready(WitVerification { id: value.id, web_url: value.web_url }),
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
				let results = value
					.results
					.into_iter()
					.map(|Certificate { certificate }| WitCertificate { certificate })
					.collect();
				Self::Ready(WitCertificates { results })
			}
			AnchorOutcome::Retry { after_ms } => Self::Retry(after_ms),
		}
	}
}

export!(Component);

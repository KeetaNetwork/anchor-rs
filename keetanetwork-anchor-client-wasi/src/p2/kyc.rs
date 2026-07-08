//! The networked `kyc` client resource of the P2 component, plus the boundary
//! conversions between the core KYC domain values and the generated WIT types.

use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_client::resilience::{ResilientTransport, WasiRuntime};
use keetanetwork_anchor_client::{
	AnchorContext, AnchorHttpTransport, AnchorOutcome, Certificates, CountryCode, ExpectedCost, KycClient,
	KycOperations, KycProvider, Resolver, Verification, VerificationStatus, WasiTransport,
};

use super::account::AccountResource;
use super::exports::keeta::anchor::kyc::{Client, Guest as KycGuest, GuestClient};
use super::exports::keeta::client::crypto::AccountBorrow;
use super::keeta::anchor::types::{
	CertificateGroup, CertificatesOutcome, ExpectedCost as WitExpectedCost, KycOperations as WitOperations,
	KycProvider as WitProvider, StatusOutcome, Verification as WitVerification, VerificationOutcome,
	VerificationStatus as WitVerificationStatus,
};
use super::{run, CodedError, Component};

/// The resource state backing the exported `client`.
pub(crate) struct KycSession {
	inner: KycClient,
}

impl KycGuest for Component {
	type Client = KycSession;
}

impl GuestClient for KycSession {
	fn with_account(
		node_url: String,
		root: AccountBorrow<'_>,
		signer: AccountBorrow<'_>,
	) -> Result<Client, CodedError> {
		let root = Arc::clone(&root.get::<AccountResource>().account);
		let account = Arc::clone(&signer.get::<AccountResource>().account);
		let inner = build_client(node_url, root, account);

		Ok(Client::new(Self { inner }))
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
/// wrapped in the resilience policy, a metadata resolver reading `root`
/// through the node client at `node_url`, and the bound `signer`.
fn build_client(node_url: String, root: Arc<GenericAccount>, signer: Arc<GenericAccount>) -> KycClient {
	let base: Arc<dyn AnchorHttpTransport> = Arc::new(WasiTransport::default());
	let transport: Arc<dyn AnchorHttpTransport> = Arc::new(ResilientTransport::new(base, WasiRuntime));
	let client = super::node_client(&node_url);
	let resolver = Resolver::new(client, transport.clone(), [root]);
	let context = AnchorContext::new(resolver, transport, signer);

	KycClient::new(context)
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
			AnchorOutcome::Ready(value) => Self::Ready(WitVerificationStatus {
				status: value.status,
				requires_manual_verification: value.requires_manual_verification,
			}),
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

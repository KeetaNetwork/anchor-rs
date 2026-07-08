//! The networked KYC surface of the P1 core module.
//!
//! Each export reads its arguments from guest memory through the shared node
//! readers, drives the shared [`KycClient`] to completion on the host I/O shim,
//! and returns a JSON payload bytes handle (or records a coded error) on the
//! shared `handle + last_error` ABI.

use core::cell::RefCell;

use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_anchor_bindings::registry::HandleRegistry;
use keetanetwork_anchor_client::{
	AnchorClientError, AnchorContext, AnchorOutcome, Certificate, Certificates, CountryCode, ExpectedCost, KycClient,
	KycOperations, KycProvider, Resolver, Verification, VerificationStatus,
};
use keetanetwork_client_wasi::{account, bytes_result, string_in};
use serde::{Deserialize, Serialize};

use super::transport::{block_on, host_transport};

thread_local! {
	static SESSIONS: RefCell<HandleRegistry<KycClient>> = const { RefCell::new(HandleRegistry::new("kyc-client")) };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/// Build a KYC client resolving `root`'s on-chain metadata via the node API at
/// `node_url`, signed by the account behind `account_handle` (from the shared
/// `keeta_account_*` registry); returns a client handle (`0` on error; see the
/// last error).
///
/// # Safety
///
/// Each `(ptr, len)` pair MUST describe an initialized, readable guest buffer.
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_with_account(
	node_url_ptr: i32,
	node_url_len: i32,
	root_ptr: i32,
	root_len: i32,
	account_handle: i32,
) -> i32 {
	let (Some(node_url), Some(root)) =
		(unsafe { string_in(node_url_ptr, node_url_len) }, unsafe { string_in(root_ptr, root_len) })
	else {
		return 0;
	};
	let Some(root) = super::parse_account(&root) else {
		return 0;
	};
	let Some(signer) = account(account_handle) else {
		return 0;
	};

	insert(build_client(node_url, root, signer))
}

/// Every provider serving all `countries` (a JSON array of ISO codes), as a JSON
/// array of providers; returns a bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_kyc_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_providers(handle: i32, countries_ptr: i32, countries_len: i32) -> i32 {
	let Some(countries) = (unsafe { string_in(countries_ptr, countries_len) }) else {
		return 0;
	};

	bytes_result(providers(handle, &countries))
}

/// Begin a verification with `provider` (JSON) for `countries` (JSON array),
/// optionally redirecting to `redirect` (empty for none); returns a JSON
/// verification outcome bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_kyc_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_create_verification(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	countries_ptr: i32,
	countries_len: i32,
	redirect_ptr: i32,
	redirect_len: i32,
) -> i32 {
	let (Some(provider), Some(countries), Some(redirect)) = (
		unsafe { string_in(provider_ptr, provider_len) },
		unsafe { string_in(countries_ptr, countries_len) },
		unsafe { string_in(redirect_ptr, redirect_len) },
	) else {
		return 0;
	};

	bytes_result(create_verification(handle, &provider, &countries, &redirect))
}

/// The certificates issued for verification `id` under `provider` (JSON), as a
/// JSON certificates outcome bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_kyc_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_get_certificates(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	id_ptr: i32,
	id_len: i32,
) -> i32 {
	let (Some(provider), Some(id)) =
		(unsafe { string_in(provider_ptr, provider_len) }, unsafe { string_in(id_ptr, id_len) })
	else {
		return 0;
	};

	bytes_result(get_certificates(handle, &provider, &id))
}

/// The status of verification `id` under `provider` (JSON), as a JSON status
/// outcome bytes handle (`0` on error).
///
/// # Safety
///
/// See [`keeta_kyc_with_account`].
#[no_mangle]
pub unsafe extern "C" fn keeta_kyc_get_verification_status(
	handle: i32,
	provider_ptr: i32,
	provider_len: i32,
	id_ptr: i32,
	id_len: i32,
) -> i32 {
	let (Some(provider), Some(id)) =
		(unsafe { string_in(provider_ptr, provider_len) }, unsafe { string_in(id_ptr, id_len) })
	else {
		return 0;
	};

	bytes_result(get_verification_status(handle, &provider, &id))
}

/// Release a client handle, ignoring an unknown one.
#[no_mangle]
pub extern "C" fn keeta_kyc_free(handle: i32) {
	SESSIONS.with_borrow_mut(|sessions| sessions.remove(handle));
}

// ---------------------------------------------------------------------------
// Operation bodies
// ---------------------------------------------------------------------------

fn providers(handle: i32, countries_json: &str) -> Result<Vec<u8>, CodedError> {
	let countries = parse_countries(countries_json)?;
	let providers = with_session(handle, |client| block_on(async { client.providers(&countries).await }))?;
	let payload: Vec<ProviderDto> = providers.into_iter().map(ProviderDto::from).collect();

	encode(&payload)
}

fn create_verification(
	handle: i32,
	provider_json: &str,
	countries_json: &str,
	redirect: &str,
) -> Result<Vec<u8>, CodedError> {
	let provider = parse_provider(provider_json)?;
	let countries = parse_countries(countries_json)?;
	let redirect = (!redirect.is_empty()).then_some(redirect);

	let outcome = with_session(handle, |client| {
		block_on(async {
			client
				.create_verification(&provider, &countries, redirect)
				.await
		})
	})?;

	encode(&VerificationOutcomeDto::from(outcome))
}

fn get_certificates(handle: i32, provider_json: &str, id: &str) -> Result<Vec<u8>, CodedError> {
	let provider = parse_provider(provider_json)?;
	let outcome = with_session(handle, |client| block_on(async { client.get_certificates(&provider, id).await }))?;

	encode(&CertificatesOutcomeDto::from(outcome))
}

fn get_verification_status(handle: i32, provider_json: &str, id: &str) -> Result<Vec<u8>, CodedError> {
	let provider = parse_provider(provider_json)?;
	let outcome =
		with_session(handle, |client| block_on(async { client.get_verification_status(&provider, id).await }))?;

	encode(&StatusOutcomeDto::from(outcome))
}

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// Build a networked KYC client signed by `signer`.
fn build_client(node_url: String, root: Arc<GenericAccount>, signer: Arc<GenericAccount>) -> KycClient {
	let transport = host_transport();
	let client = super::node::node_client(&node_url);
	let resolver = Resolver::new(client, transport.clone(), [root]);
	let context = AnchorContext::new(resolver, transport, signer);

	KycClient::new(context)
}

/// Store `client` under a fresh handle and return it.
fn insert(client: KycClient) -> i32 {
	SESSIONS.with_borrow_mut(|sessions| sessions.store(client))
}

/// Resolve `handle` and run `call` against the stored client, recording an
/// error for a missing handle or a client failure.
fn with_session<T>(
	handle: i32,
	call: impl FnOnce(&KycClient) -> Result<T, AnchorClientError>,
) -> Result<T, CodedError> {
	SESSIONS
		.with_borrow(|sessions| sessions.with(handle, call))?
		.map_err(coded)
}

// ---------------------------------------------------------------------------
// Argument parsing + error mapping
// ---------------------------------------------------------------------------

/// Parse a JSON array of ISO codes into canonical country codes.
fn parse_countries(json: &str) -> Result<Vec<CountryCode>, CodedError> {
	let values: Vec<String> = serde_json::from_str(json).map_err(invalid_input)?;
	canonical(values)
}

/// Canonicalize ISO codes, rejecting an empty or malformed one.
fn canonical(values: Vec<String>) -> Result<Vec<CountryCode>, CodedError> {
	values
		.iter()
		.map(|value| CountryCode::try_from(value.as_str()).map_err(|_| invalid_country()))
		.collect()
}

/// Parse a provider argument from its JSON representation.
fn parse_provider(json: &str) -> Result<KycProvider, CodedError> {
	let dto: ProviderDto = serde_json::from_str(json).map_err(invalid_input)?;

	provider_from_dto(dto)
}

/// Serialize a payload to JSON result bytes.
fn encode<T>(value: &T) -> Result<Vec<u8>, CodedError>
where
	T: Serialize,
{
	serde_json::to_vec(value).map_err(|error| CodedError::new("ENCODE", error.to_string()))
}

/// The coded error for an anchor client failure.
fn coded(error: AnchorClientError) -> CodedError {
	CodedError::new(error.code(), error.to_string())
}

/// The coded error for an un-parseable JSON argument.
fn invalid_input(error: serde_json::Error) -> CodedError {
	CodedError::new("INVALID_INPUT", error.to_string())
}

/// The coded error for an empty or malformed country code.
fn invalid_country() -> CodedError {
	CodedError::new("INVALID_COUNTRY", "invalid country code")
}

// ---------------------------------------------------------------------------
// JSON data transfer objects
// ---------------------------------------------------------------------------

/// The KYC operation endpoint templates a provider advertises.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationsDto {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	create_verification: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	get_certificates: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	get_verification_status: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	check_locality: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	get_estimate: Option<String>,
}

/// A KYC provider discovered from on-chain service metadata.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderDto {
	id: String,
	ca: String,
	operations: OperationsDto,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	country_codes: Option<Vec<String>>,
}

/// An in-progress verification.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationDto {
	id: String,
	web_url: String,
	expected_cost: ExpectedCostDto,
}

/// The cost a provider expects to charge for a verification.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedCostDto {
	min: String,
	max: String,
	token: String,
}

/// A verification's provider-reported status.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusDto {
	status: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	requires_manual_verification: Option<bool>,
}

/// One issued, PEM-encoded certificate and the intermediates bridging it to a
/// trust root.
#[derive(Serialize)]
struct CertificateDto {
	certificate: String,
	intermediates: Vec<String>,
}

/// The certificates issued for a verification.
#[derive(Serialize)]
struct CertificatesDto {
	results: Vec<CertificateDto>,
}

/// A verification result, ready or retry-after-millis.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum VerificationOutcomeDto {
	Ready { verification: VerificationDto },
	Retry { after_ms: u32 },
}

/// A status result, ready or retry-after-millis.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum StatusOutcomeDto {
	Ready { status: StatusDto },
	Retry { after_ms: u32 },
}

/// A certificates result, ready or retry-after-millis.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum CertificatesOutcomeDto {
	Ready { certificates: CertificatesDto },
	Retry { after_ms: u32 },
}

// ---------------------------------------------------------------------------
// Domain <-> DTO conversions
// ---------------------------------------------------------------------------

impl From<KycProvider> for ProviderDto {
	fn from(provider: KycProvider) -> Self {
		let country_codes = provider
			.country_codes
			.map(|codes| codes.iter().map(|code| code.as_str().to_string()).collect());

		Self { id: provider.id, ca: provider.ca, operations: provider.operations.into(), country_codes }
	}
}

impl From<KycOperations> for OperationsDto {
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

/// Build a validated [`KycProvider`] from its DTO.
fn provider_from_dto(dto: ProviderDto) -> Result<KycProvider, CodedError> {
	let country_codes = dto.country_codes.map(canonical).transpose()?;

	Ok(KycProvider { id: dto.id, ca: dto.ca, operations: operations_from_dto(dto.operations), country_codes })
}

/// Build [`KycOperations`] from its DTO.
fn operations_from_dto(dto: OperationsDto) -> KycOperations {
	KycOperations {
		create_verification: dto.create_verification,
		get_certificates: dto.get_certificates,
		get_verification_status: dto.get_verification_status,
		check_locality: dto.check_locality,
		get_estimate: dto.get_estimate,
	}
}

impl From<Verification> for VerificationDto {
	fn from(verification: Verification) -> Self {
		Self { id: verification.id, web_url: verification.web_url, expected_cost: verification.expected_cost.into() }
	}
}

impl From<ExpectedCost> for ExpectedCostDto {
	fn from(cost: ExpectedCost) -> Self {
		Self { min: cost.min, max: cost.max, token: cost.token }
	}
}

impl From<VerificationStatus> for StatusDto {
	fn from(status: VerificationStatus) -> Self {
		Self { status: status.status, requires_manual_verification: status.requires_manual_verification }
	}
}

impl From<Certificate> for CertificateDto {
	fn from(certificate: Certificate) -> Self {
		Self { certificate: certificate.certificate, intermediates: certificate.intermediates }
	}
}

impl From<Certificates> for CertificatesDto {
	fn from(certificates: Certificates) -> Self {
		Self {
			results: certificates
				.results
				.into_iter()
				.map(CertificateDto::from)
				.collect(),
		}
	}
}

impl From<AnchorOutcome<Verification>> for VerificationOutcomeDto {
	fn from(outcome: AnchorOutcome<Verification>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => Self::Ready { verification: value.into() },
			AnchorOutcome::Retry { after_ms } => Self::Retry { after_ms },
		}
	}
}

impl From<AnchorOutcome<VerificationStatus>> for StatusOutcomeDto {
	fn from(outcome: AnchorOutcome<VerificationStatus>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => Self::Ready { status: value.into() },
			AnchorOutcome::Retry { after_ms } => Self::Retry { after_ms },
		}
	}
}

impl From<AnchorOutcome<Certificates>> for CertificatesOutcomeDto {
	fn from(outcome: AnchorOutcome<Certificates>) -> Self {
		match outcome {
			AnchorOutcome::Ready(value) => Self::Ready { certificates: value.into() },
			AnchorOutcome::Retry { after_ms } => Self::Retry { after_ms },
		}
	}
}

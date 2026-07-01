//! The JSON contract shared by both asset-movement bindings.
//!
//! Both the P1 core module and the P2 component carry the asset-movement
//! domain's polymorphic requests and responses as JSON. This module
//! is the single place that projects that JSON to and from the shared
//! [`AssetMovementClient`] types, so the two bindings stay byte-identical.

use std::collections::BTreeMap;

use keetanetwork_anchor_bindings::error::CodedError;
use keetanetwork_anchor_client::AssetMovementOperations;
use keetanetwork_anchor_client::{
	AccountStatus, AssetMovementBlocker, AssetMovementProvider, AssetOrPair, CreateForwardingAddressRequest,
	CreateForwardingTemplateRequest, EndpointAuth, ExecuteTransferRequest, ForwardingAddressFilter,
	ForwardingDestination, InitiateForwardingTemplateRequest, ListForwardingAddressesRequest,
	ListForwardingTemplatesRequest, ListTransactionsRequest, OperationEndpoint, Pagination, PersistentAddressFilter,
	ProviderFilter, ProviderSearch, ShareKycRequest, TransactionEndpointFilter, TransactionRefFilter,
	TransferDestination, TransferRequest, TransferSource,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// The coded error for an unparseable JSON argument.
fn invalid_input(error: serde_json::Error) -> CodedError {
	CodedError::new("INVALID_INPUT", error.to_string())
}

/// The coded error for a malformed argument value.
fn invalid(reason: &str) -> CodedError {
	CodedError::new("INVALID_INPUT", reason.to_string())
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Serialize a payload to JSON result bytes.
pub(crate) fn encode<T>(value: &T) -> Result<Vec<u8>, CodedError>
where
	T: Serialize,
{
	serde_json::to_vec(value).map_err(|error| CodedError::new("ENCODE", error.to_string()))
}

/// Encode discovered providers as a JSON array.
pub(crate) fn encode_providers(providers: Vec<AssetMovementProvider>) -> Result<Vec<u8>, CodedError> {
	let payload: Vec<ProviderDto> = providers.into_iter().map(ProviderDto::from).collect();
	encode(&payload)
}

/// Encode a single provider (or JSON `null` when absent).
pub(crate) fn encode_provider(provider: Option<AssetMovementProvider>) -> Result<Vec<u8>, CodedError> {
	match provider {
		Some(provider) => encode(&ProviderDto::from(provider)),
		None => encode(&Value::Null),
	}
}

/// Encode an account status as its JSON output.
pub(crate) fn encode_account_status(status: &AccountStatus) -> Result<Vec<u8>, CodedError> {
	encode(&account_status_json(status))
}

/// A JSON `{}` acknowledgement for a void operation.
pub(crate) fn encode_ack() -> Result<Vec<u8>, CodedError> {
	encode(&json!({}))
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Narrow discovered `providers` to those passing `filter` (id and account).
pub(crate) fn filter_providers(
	providers: Vec<AssetMovementProvider>,
	filter: &ProviderFilter,
) -> Vec<AssetMovementProvider> {
	providers
		.into_iter()
		.filter(|provider| accepts(filter, provider))
		.collect()
}

/// Whether `provider` passes `filter` (id and account narrowing).
fn accepts(filter: &ProviderFilter, provider: &AssetMovementProvider) -> bool {
	let id_ok = filter.id.as_deref().is_none_or(|id| id == provider.id);
	let account_ok = filter
		.account
		.as_deref()
		.is_none_or(|account| provider.account.as_deref() == Some(account));
	id_ok && account_ok
}

// ---------------------------------------------------------------------------
// Provider round-trip
// ---------------------------------------------------------------------------

/// Parse a provider argument from its JSON representation.
pub(crate) fn parse_provider(json: &str) -> Result<AssetMovementProvider, CodedError> {
	let dto: ProviderDto = serde_json::from_str(json).map_err(invalid_input)?;
	Ok(dto.into())
}

/// The authentication an operation requires.
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum AuthDto {
	None,
	Optional,
	Required,
}

impl From<EndpointAuth> for AuthDto {
	fn from(auth: EndpointAuth) -> Self {
		match auth {
			EndpointAuth::None => Self::None,
			EndpointAuth::Optional => Self::Optional,
			EndpointAuth::Required => Self::Required,
		}
	}
}

impl From<AuthDto> for EndpointAuth {
	fn from(auth: AuthDto) -> Self {
		match auth {
			AuthDto::None => Self::None,
			AuthDto::Optional => Self::Optional,
			AuthDto::Required => Self::Required,
		}
	}
}

/// One advertised operation endpoint.
#[derive(Serialize, Deserialize)]
struct EndpointDto {
	url: String,
	auth: AuthDto,
}

/// A discovered asset-movement provider, as an opaque round-trip blob.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderDto {
	id: String,
	operations: BTreeMap<String, EndpointDto>,
	#[serde(default)]
	supported_assets: Vec<Value>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	location_metadata: Option<Value>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	legal: Option<Value>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	account: Option<String>,
}

impl From<AssetMovementProvider> for ProviderDto {
	fn from(provider: AssetMovementProvider) -> Self {
		let operations = provider
			.operations
			.iter()
			.map(|(name, endpoint)| {
				(name.to_string(), EndpointDto { url: endpoint.url.clone(), auth: endpoint.auth.into() })
			})
			.collect();

		Self {
			id: provider.id,
			operations,
			supported_assets: provider.supported_assets,
			location_metadata: provider.location_metadata,
			legal: provider.legal,
			account: provider.account,
		}
	}
}

impl From<ProviderDto> for AssetMovementProvider {
	fn from(dto: ProviderDto) -> Self {
		let operations: AssetMovementOperations = dto
			.operations
			.into_iter()
			.map(|(name, endpoint)| (name, OperationEndpoint { url: endpoint.url, auth: endpoint.auth.into() }))
			.collect();

		Self {
			id: dto.id,
			operations,
			supported_assets: dto.supported_assets,
			location_metadata: dto.location_metadata,
			legal: dto.legal,
			account: dto.account,
		}
	}
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Parse a request DTO from its JSON representation.
fn parse<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T, CodedError> {
	serde_json::from_str(json).map_err(invalid_input)
}

/// Parse a transfer request (simulate or initiate).
pub(crate) fn transfer_request(json: &str) -> Result<TransferRequest, CodedError> {
	parse::<TransferReqDto>(json)?.into_core()
}

/// Parse an execute-transfer request.
pub(crate) fn execute_request(json: &str) -> Result<ExecuteTransferRequest, CodedError> {
	Ok(parse::<ExecuteReqDto>(json)?.into_core())
}

/// Parse an initiate-forwarding-template request.
pub(crate) fn initiate_template_request(json: &str) -> Result<InitiateForwardingTemplateRequest, CodedError> {
	parse::<InitiateTemplateDto>(json)?.into_core()
}

/// Parse a create-forwarding-template request.
pub(crate) fn create_template_request(json: &str) -> Result<CreateForwardingTemplateRequest, CodedError> {
	parse::<CreateTemplateDto>(json)?.into_core()
}

/// Parse a list-forwarding-templates request.
pub(crate) fn list_templates_request(json: &str) -> Result<ListForwardingTemplatesRequest, CodedError> {
	Ok(parse::<ListTemplatesDto>(json)?.into_core())
}

/// Parse a create-forwarding-address request.
pub(crate) fn create_address_request(json: &str) -> Result<CreateForwardingAddressRequest, CodedError> {
	parse::<CreateAddressDto>(json)?.into_core()
}

/// Parse a list-forwarding-addresses request.
pub(crate) fn list_addresses_request(json: &str) -> Result<ListForwardingAddressesRequest, CodedError> {
	parse::<ListAddressesDto>(json)?.into_core()
}

/// Parse a list-transactions request.
pub(crate) fn list_transactions_request(json: &str) -> Result<ListTransactionsRequest, CodedError> {
	parse::<ListTransactionsDto>(json)?.into_core()
}

/// Parse a share-KYC request.
pub(crate) fn share_kyc_request(json: &str) -> Result<ShareKycRequest, CodedError> {
	Ok(parse::<ShareKycDto>(json)?.into_core())
}

/// Parse a provider-search argument from its JSON representation.
pub(crate) fn parse_provider_search(json: &str) -> Result<ProviderSearch, CodedError> {
	parse::<ProviderSearchDto>(json)?.into_core()
}

/// A transfer search: an optional asset, endpoints, and directional rails.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ProviderSearchDto {
	#[serde(default)]
	asset: Option<Value>,
	#[serde(default)]
	from: Option<String>,
	#[serde(default)]
	to: Option<String>,
	#[serde(default)]
	inbound_rails: Vec<String>,
	#[serde(default)]
	outbound_rails: Vec<String>,
}

impl ProviderSearchDto {
	fn into_core(self) -> Result<ProviderSearch, CodedError> {
		let asset = match self.asset {
			Some(value) => Some(asset_or_pair(value)?),
			None => None,
		};

		Ok(ProviderSearch {
			asset,
			from: self.from,
			to: self.to,
			inbound_rails: self.inbound_rails,
			outbound_rails: self.outbound_rails,
		})
	}
}

/// Convert a JSON asset (a bare string or `{ from, to }`) into an
/// [`AssetOrPair`].
fn asset_or_pair(value: Value) -> Result<AssetOrPair, CodedError> {
	match value {
		Value::String(asset) => Ok(AssetOrPair::Single(asset)),
		Value::Object(map) => {
			let from = str_field(&map, "from")?;
			let to = str_field(&map, "to")?;
			Ok(AssetOrPair::Pair { from, to })
		}
		_ => Err(invalid("asset must be a string or a { from, to } pair")),
	}
}

/// Read a required string field from a JSON object.
fn str_field(map: &serde_json::Map<String, Value>, key: &str) -> Result<String, CodedError> {
	map.get(key)
		.and_then(Value::as_str)
		.map(str::to_string)
		.ok_or_else(|| invalid("missing required string field"))
}

/// Project a JSON `value` (a string or a number) into the decimal string the
/// transfer carries.
fn value_string(value: Value) -> Result<String, CodedError> {
	match value {
		Value::String(text) => Ok(text),
		Value::Number(number) => Ok(number.to_string()),
		_ => Err(invalid("value must be a string or a number")),
	}
}

/// Pagination bounds shared by the list operations.
#[derive(Deserialize, Default)]
struct PaginationDto {
	#[serde(default)]
	limit: Option<u32>,
	#[serde(default)]
	offset: Option<u32>,
}

impl From<PaginationDto> for Pagination {
	fn from(dto: PaginationDto) -> Self {
		Self { limit: dto.limit, offset: dto.offset }
	}
}

/// The source of a transfer.
#[derive(Deserialize)]
struct SourceDto {
	location: String,
	#[serde(default)]
	source: Option<Value>,
}

/// The destination of a transfer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DestinationDto {
	location: String,
	#[serde(default)]
	recipient: Option<Value>,
	#[serde(default)]
	deposit_message: Option<String>,
}

/// A request to simulate or initiate a transfer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferReqDto {
	asset: Value,
	from: SourceDto,
	to: DestinationDto,
	value: Value,
	#[serde(default)]
	allowed_rails: Vec<String>,
}

impl TransferReqDto {
	fn into_core(self) -> Result<TransferRequest, CodedError> {
		Ok(TransferRequest {
			asset: asset_or_pair(self.asset)?,
			from: TransferSource { location: self.from.location, source: self.from.source },
			to: TransferDestination {
				location: self.to.location,
				recipient: self.to.recipient,
				deposit_message: self.to.deposit_message,
			},
			value: value_string(self.value)?,
			allowed_rails: self.allowed_rails,
		})
	}
}

/// A request to execute a pull instruction.
#[derive(Deserialize)]
struct ExecuteReqDto {
	id: String,
	instruction: Value,
}

impl ExecuteReqDto {
	fn into_core(self) -> ExecuteTransferRequest {
		ExecuteTransferRequest { id: self.id, instruction: self.instruction }
	}
}

/// A request to open a persistent-forwarding template session.
#[derive(Deserialize)]
struct InitiateTemplateDto {
	asset: Value,
	location: String,
}

impl InitiateTemplateDto {
	fn into_core(self) -> Result<InitiateForwardingTemplateRequest, CodedError> {
		Ok(InitiateForwardingTemplateRequest { asset: asset_or_pair(self.asset)?, location: self.location })
	}
}

/// A request to create a persistent-forwarding template (direct or completion).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTemplateDto {
	#[serde(default)]
	asset: Option<Value>,
	#[serde(default)]
	location: Option<String>,
	#[serde(default)]
	address: Option<Value>,
	#[serde(default)]
	id: Option<String>,
	#[serde(default)]
	data: Option<Value>,
}

impl CreateTemplateDto {
	fn into_core(self) -> Result<CreateForwardingTemplateRequest, CodedError> {
		if let Some(data) = self.data {
			return Ok(CreateForwardingTemplateRequest::Completion { id: self.id, data });
		}

		let (Some(asset), Some(location), Some(address)) = (self.asset, self.location, self.address) else {
			return Err(invalid("a direct template requires asset, location, and address"));
		};

		Ok(CreateForwardingTemplateRequest::Direct { asset: asset_or_pair(asset)?, location, address })
	}
}

/// A request to list persistent-forwarding templates.
#[derive(Deserialize, Default)]
struct ListTemplatesDto {
	#[serde(default)]
	asset: Option<Vec<String>>,
	#[serde(default)]
	location: Option<Vec<String>>,
}

impl ListTemplatesDto {
	fn into_core(self) -> ListForwardingTemplatesRequest {
		ListForwardingTemplatesRequest { asset: self.asset, location: self.location }
	}
}

/// A request to create a persistent-forwarding address.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateAddressDto {
	source_location: String,
	asset: Value,
	#[serde(default)]
	outgoing_rail: Option<String>,
	#[serde(default)]
	incoming_rail: Option<String>,
	#[serde(default)]
	destination_location: Option<String>,
	#[serde(default)]
	destination_address: Option<Value>,
	#[serde(default)]
	persistent_address_template_id: Option<String>,
}

impl CreateAddressDto {
	fn into_core(self) -> Result<CreateForwardingAddressRequest, CodedError> {
		let destination =
			match (self.destination_location, self.destination_address, self.persistent_address_template_id) {
				(Some(location), Some(address), _) => ForwardingDestination::Address { location, address },
				(_, _, Some(persistent_address_template_id)) => {
					ForwardingDestination::Template { persistent_address_template_id }
				}
				_ => {
					return Err(invalid("a forwarding address requires either a destination address or a template id"))
				}
			};

		Ok(CreateForwardingAddressRequest {
			source_location: self.source_location,
			asset: asset_or_pair(self.asset)?,
			outgoing_rail: self.outgoing_rail,
			incoming_rail: self.incoming_rail,
			destination,
		})
	}
}

/// One filter over persistent-forwarding addresses.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AddressFilterDto {
	#[serde(default)]
	source_location: Option<String>,
	#[serde(default)]
	destination_location: Option<String>,
	#[serde(default)]
	asset: Option<String>,
	#[serde(default)]
	destination_address: Option<String>,
	#[serde(default)]
	persistent_address_template_id: Option<String>,
}

impl From<AddressFilterDto> for ForwardingAddressFilter {
	fn from(dto: AddressFilterDto) -> Self {
		Self {
			source_location: dto.source_location,
			destination_location: dto.destination_location,
			asset: dto.asset,
			destination_address: dto.destination_address,
			persistent_address_template_id: dto.persistent_address_template_id,
		}
	}
}

/// A request to list persistent-forwarding addresses.
#[derive(Deserialize, Default)]
struct ListAddressesDto {
	#[serde(default)]
	search: Option<Vec<AddressFilterDto>>,
	#[serde(default)]
	pagination: PaginationDto,
}

impl ListAddressesDto {
	fn into_core(self) -> Result<ListForwardingAddressesRequest, CodedError> {
		let search = self.search.map(|filters| {
			filters
				.into_iter()
				.map(ForwardingAddressFilter::from)
				.collect()
		});
		Ok(ListForwardingAddressesRequest { search, pagination: self.pagination.into() })
	}
}

/// A persistent-address filter for listing transactions.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistentAddressFilterDto {
	location: String,
	#[serde(default)]
	persistent_address: Option<String>,
	#[serde(default)]
	persistent_address_template: Option<String>,
}

impl From<PersistentAddressFilterDto> for PersistentAddressFilter {
	fn from(dto: PersistentAddressFilterDto) -> Self {
		Self {
			location: dto.location,
			persistent_address: dto.persistent_address,
			persistent_address_template: dto.persistent_address_template,
		}
	}
}

/// A source/destination endpoint filter for listing transactions.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointFilterDto {
	location: String,
	#[serde(default)]
	user_address: Option<String>,
	#[serde(default)]
	asset: Option<String>,
}

impl From<EndpointFilterDto> for TransactionEndpointFilter {
	fn from(dto: EndpointFilterDto) -> Self {
		Self { location: dto.location, user_address: dto.user_address, asset: dto.asset }
	}
}

/// A specific-transaction filter for listing transactions.
#[derive(Deserialize)]
struct TransactionRefDto {
	location: String,
	transaction: Value,
}

impl From<TransactionRefDto> for TransactionRefFilter {
	fn from(dto: TransactionRefDto) -> Self {
		Self { location: dto.location, transaction: dto.transaction }
	}
}

/// A request to list asset-movement transactions.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListTransactionsDto {
	#[serde(default)]
	persistent_addresses: Option<Vec<PersistentAddressFilterDto>>,
	#[serde(default)]
	from: Option<EndpointFilterDto>,
	#[serde(default)]
	to: Option<EndpointFilterDto>,
	#[serde(default)]
	transactions: Option<Vec<TransactionRefDto>>,
	#[serde(default)]
	pagination: PaginationDto,
}

impl ListTransactionsDto {
	fn into_core(self) -> Result<ListTransactionsRequest, CodedError> {
		Ok(ListTransactionsRequest {
			persistent_addresses: self.persistent_addresses.map(|filters| {
				filters
					.into_iter()
					.map(PersistentAddressFilter::from)
					.collect()
			}),
			from: self.from.map(TransactionEndpointFilter::from),
			to: self.to.map(TransactionEndpointFilter::from),
			transactions: self.transactions.map(|filters| {
				filters
					.into_iter()
					.map(TransactionRefFilter::from)
					.collect()
			}),
			pagination: self.pagination.into(),
		})
	}
}

/// A request to share KYC attributes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareKycDto {
	attributes: String,
	#[serde(default)]
	tos_agreement: Option<Value>,
}

impl ShareKycDto {
	fn into_core(self) -> ShareKycRequest {
		ShareKycRequest { attributes: self.attributes, tos_agreement: self.tos_agreement }
	}
}

// ---------------------------------------------------------------------------
// Account-status output
// ---------------------------------------------------------------------------

/// Project an [`AccountStatus`] into its JSON output.
fn account_status_json(status: &AccountStatus) -> Value {
	match status {
		AccountStatus::Ready => json!({ "actionRequired": false }),
		AccountStatus::ActionRequired { blockers } => {
			let blockers: Vec<Value> = blockers.iter().map(blocker_json).collect();
			json!({ "actionRequired": true, "blockers": blockers })
		}
	}
}

/// Project an [`AssetMovementBlocker`] into its JSON output.
fn blocker_json(blocker: &AssetMovementBlocker) -> Value {
	match blocker {
		AssetMovementBlocker::KycShareNeeded {
			tos_flow,
			needed_attributes,
			share_with_principals,
			accepted_issuers,
		} => json!({
			"type": "kycShareNeeded",
			"tosFlow": tos_flow,
			"neededAttributes": needed_attributes,
			"shareWithPrincipals": share_with_principals,
			"acceptedIssuers": accepted_issuers,
		}),
		AssetMovementBlocker::AdditionalKycNeeded { to_complete_flow } => {
			json!({ "type": "additionalKycNeeded", "toCompleteFlow": to_complete_flow })
		}
		AssetMovementBlocker::OperationNotSupported { for_asset, for_rail } => {
			json!({ "type": "operationNotSupported", "forAsset": for_asset, "forRail": for_rail })
		}
		AssetMovementBlocker::UserActionNeeded { actions_needed } => {
			json!({ "type": "userActionNeeded", "actionsNeeded": actions_needed })
		}
		AssetMovementBlocker::Other { name, code, message } => {
			json!({ "type": "other", "name": name, "code": code, "message": message })
		}
	}
}

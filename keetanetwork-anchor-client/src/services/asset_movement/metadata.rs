//! Asset-movement service metadata: the operation endpoints a provider
//! advertises, their per-operation authentication, and the [`ServiceQuery`]
//! that projects a verified `services.assetMovement` entry into a provider.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::Value;

use crate::resolver::ServiceQuery;

/// The authentication an operation requires, read from the published metadata.
///
/// A bare-string endpoint, or one without an `authentication` block, is
/// [`None`](EndpointAuth::None). `getAccountStatus` is always published as
/// [`Required`](EndpointAuth::Required).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointAuth {
	/// No signature is expected.
	#[default]
	None,
	/// The request is signed only when an account is supplied.
	Optional,
	/// The request must be signed.
	Required,
}

impl EndpointAuth {
	/// Whether an account holder should sign this operation. The Rust client
	/// always holds a signer, so `optional` is treated as `required`.
	pub fn signs(self) -> bool {
		matches!(self, Self::Optional | Self::Required)
	}
}

/// One advertised operation: the URL template and its authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationEndpoint {
	/// The URL template, with `{id}`-style placeholders.
	pub url: String,
	/// The authentication the operation requires.
	pub auth: EndpointAuth,
}

/// The operation names the asset-movement service can advertise.
///
/// Names match the metadata keys byte-for-byte so lookups round-trip with the
/// TypeScript reference.
pub const OPERATION_NAMES: [&str; 14] = [
	"initiateTransfer",
	"simulateTransfer",
	"executeTransfer",
	"getTransferStatus",
	"getAccountStatus",
	"initiatePersistentForwardingTemplate",
	"createPersistentForwardingTemplate",
	"listPersistentForwardingTemplate",
	"createPersistentForwarding",
	"listPersistentForwarding",
	"deactivatePersistentForwardingTemplate",
	"deactivatePersistentForwarding",
	"listTransactions",
	"shareKYC",
];

/// The advertised operations of an asset-movement provider, keyed by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetMovementOperations {
	entries: Vec<(String, OperationEndpoint)>,
}

impl AssetMovementOperations {
	/// The endpoint advertised for `operation`, when present.
	pub fn get(&self, operation: &str) -> Option<&OperationEndpoint> {
		self.entries
			.iter()
			.find_map(|(name, endpoint)| (name == operation).then_some(endpoint))
	}

	/// Whether `operation` is advertised.
	pub fn contains(&self, operation: &str) -> bool {
		self.get(operation).is_some()
	}

	/// The advertised operation names, in metadata order.
	pub fn names(&self) -> impl Iterator<Item = &str> {
		self.entries.iter().map(|(name, _)| name.as_str())
	}

	/// The advertised `(name, endpoint)` pairs, in metadata order.
	pub fn iter(&self) -> impl Iterator<Item = (&str, &OperationEndpoint)> {
		self.entries
			.iter()
			.map(|(name, endpoint)| (name.as_str(), endpoint))
	}

	/// Read the `operations` object of a metadata entry.
	fn from_entry(entry: &Value) -> Self {
		let mut entries = Vec::new();
		let Some(map) = entry.get("operations").and_then(Value::as_object) else {
			return Self { entries };
		};

		for (name, endpoint) in map {
			if let Some(endpoint) = parse_endpoint(name, endpoint) {
				entries.push((name.clone(), endpoint));
			}
		}

		Self { entries }
	}
}

impl FromIterator<(String, OperationEndpoint)> for AssetMovementOperations {
	fn from_iter<I: IntoIterator<Item = (String, OperationEndpoint)>>(iter: I) -> Self {
		Self { entries: iter.into_iter().collect() }
	}
}

/// A validated asset-movement provider resolved from service metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMovementProvider {
	/// The provider id (the key under `services.assetMovement`).
	pub id: String,
	/// The operation endpoints the provider advertises.
	pub operations: AssetMovementOperations,
	/// The assets the provider supports, as raw metadata values.
	pub supported_assets: Vec<Value>,
	/// Per-chain location metadata, when advertised.
	pub location_metadata: Option<Value>,
	/// Legal disclaimers, when advertised.
	pub legal: Option<Value>,
	/// The account that signed the entry (for account-based lookup), when
	/// present.
	pub account: Option<String>,
}

impl AssetMovementProvider {
	/// Read a provider from its metadata `id` and `entry`.
	fn from_entry(id: String, entry: &Value) -> Self {
		let operations = AssetMovementOperations::from_entry(entry);
		let supported_assets = entry
			.get("supportedAssets")
			.and_then(Value::as_array)
			.cloned()
			.unwrap_or_default();
		let location_metadata = entry
			.get("locationMetadata")
			.filter(|value| !value.is_null())
			.cloned();
		let legal = entry.get("legal").filter(|value| !value.is_null()).cloned();
		let account = entry
			.get("account")
			.and_then(Value::as_str)
			.map(str::to_string);

		Self { id, operations, supported_assets, location_metadata, legal, account }
	}
}

/// Narrows a provider lookup to a specific id or signing account.
///
/// A default (empty) filter accepts every provider; setting [`id`](Self::id) or
/// [`account`](Self::account) keeps only the matching entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderFilter {
	/// Keep only the provider with this id.
	pub id: Option<String>,
	/// Keep only the provider whose entry was signed by this account.
	pub account: Option<String>,
}

impl ProviderFilter {
	/// A filter selecting the provider with `id`.
	pub fn by_id(id: impl Into<String>) -> Self {
		Self { id: Some(id.into()), account: None }
	}

	/// A filter selecting the provider signed by `account`.
	pub fn by_account(account: impl Into<String>) -> Self {
		Self { id: None, account: Some(account.into()) }
	}

	/// Whether `provider` passes this filter.
	fn accepts(&self, provider: &AssetMovementProvider) -> bool {
		let id_ok = self.id.as_deref().is_none_or(|id| id == provider.id);
		let account_ok = self
			.account
			.as_deref()
			.is_none_or(|account| provider.account.as_deref() == Some(account));
		id_ok && account_ok
	}
}

/// Selects asset-movement providers, optionally narrowed by id or account.
pub struct AssetMovementQuery;

impl ServiceQuery for AssetMovementQuery {
	const SERVICE: &'static str = "assetMovement";
	type Criteria = ProviderFilter;
	type Provider = AssetMovementProvider;

	fn parse(id: String, entry: &Value, criteria: &ProviderFilter) -> Option<AssetMovementProvider> {
		let provider = AssetMovementProvider::from_entry(id, entry);
		criteria.accepts(&provider).then_some(provider)
	}
}

/// Read one `ServiceMetadataEndpoint` value: a bare URL string, or a
/// `{ url, options: { authentication: { type } } }` object.
fn parse_endpoint(name: &str, value: &Value) -> Option<OperationEndpoint> {
	if let Some(url) = value.as_str() {
		return Some(OperationEndpoint { url: url.to_string(), auth: auth_override(name, EndpointAuth::None) });
	}

	let url = value.get("url").and_then(Value::as_str)?.to_string();
	let auth = value
		.get("options")
		.and_then(|options| options.get("authentication"))
		.and_then(|authentication| authentication.get("type"))
		.and_then(Value::as_str)
		.map(parse_auth_type)
		.unwrap_or(EndpointAuth::None);

	Some(OperationEndpoint { url, auth: auth_override(name, auth) })
}

/// `getAccountStatus` is always authenticated regardless of what the metadata
/// says, matching the server's unconditional `required` publish.
fn auth_override(name: &str, auth: EndpointAuth) -> EndpointAuth {
	match name {
		"getAccountStatus" => EndpointAuth::Required,
		_ => auth,
	}
}

/// Map a metadata `authentication.type` string to [`EndpointAuth`].
fn parse_auth_type(value: &str) -> EndpointAuth {
	match value {
		"required" => EndpointAuth::Required,
		"optional" => EndpointAuth::Optional,
		_ => EndpointAuth::None,
	}
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	#[test]
	fn a_bare_string_endpoint_defaults_to_no_auth() {
		let entry = json!({ "operations": { "simulateTransfer": "https://anchor.example/api/simulateTransfer" } });
		let provider = AssetMovementProvider::from_entry("p".into(), &entry);
		let endpoint = provider
			.operations
			.get("simulateTransfer")
			.expect("advertised endpoint");
		assert_eq!(endpoint.auth, EndpointAuth::None);
		assert_eq!(endpoint.url, "https://anchor.example/api/simulateTransfer");
	}

	#[test]
	fn an_object_endpoint_reads_its_required_auth() {
		let entry = json!({
			"operations": {
				"initiateTransfer": {
					"url": "https://anchor.example/api/initiateTransfer",
					"options": { "authentication": { "method": "keeta-account", "type": "required" } }
				}
			}
		});
		let provider = AssetMovementProvider::from_entry("p".into(), &entry);
		let endpoint = provider
			.operations
			.get("initiateTransfer")
			.expect("advertised endpoint");
		assert_eq!(endpoint.auth, EndpointAuth::Required);
	}

	#[test]
	fn get_account_status_is_always_required() {
		let entry = json!({ "operations": { "getAccountStatus": "https://anchor.example/api/getAccountStatus" } });
		let provider = AssetMovementProvider::from_entry("p".into(), &entry);
		let endpoint = provider
			.operations
			.get("getAccountStatus")
			.expect("advertised endpoint");
		assert_eq!(endpoint.auth, EndpointAuth::Required);
	}

	#[test]
	fn a_filter_by_id_keeps_only_the_matching_provider() {
		let filter = ProviderFilter::by_id("wanted");
		let wanted = AssetMovementProvider::from_entry("wanted".into(), &json!({ "operations": {} }));
		let other = AssetMovementProvider::from_entry("other".into(), &json!({ "operations": {} }));
		assert!(filter.accepts(&wanted));
		assert!(!filter.accepts(&other));
	}

	#[test]
	fn a_filter_by_account_matches_the_entry_signer() {
		let filter = ProviderFilter::by_account("keeta_signer");
		let mut provider = AssetMovementProvider::from_entry("p".into(), &json!({ "operations": {} }));
		provider.account = Some("keeta_signer".into());
		assert!(filter.accepts(&provider));
	}
}

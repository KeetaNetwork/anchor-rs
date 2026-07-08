//! Asset-movement service metadata: the operation endpoints a provider
//! advertises, their per-operation authentication, and the [`ServiceQuery`]
//! that projects a verified `services.assetMovement` entry into a provider.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::asset::AssetOrPair;
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
	pub fn get(&self, operation: impl AsRef<str>) -> Option<&OperationEndpoint> {
		let operation = operation.as_ref();
		self.entries
			.iter()
			.find_map(|(name, endpoint)| (name == operation).then_some(endpoint))
	}

	/// Whether `operation` is advertised.
	pub fn contains(&self, operation: impl AsRef<str>) -> bool {
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

/// Content a client may render directly, the reference
/// `ClientRenderableContent`: markdown or plain text with no display
/// guarantees, so it must carry context only, never critical information.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientRenderableContent {
	/// Markdown the client may render.
	Markdown {
		/// The markdown source.
		content: String,
	},
	/// Plain text the client shows verbatim.
	Plaintext {
		/// The text.
		content: String,
	},
}

/// Why a provider publishes a disclaimer. The reference schema currently
/// defines only `general`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisclaimerPurpose {
	/// A general disclaimer.
	General,
}

/// One legal disclaimer a provider publishes under its `legal` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Disclaimer {
	/// Why the provider publishes this disclaimer.
	pub purpose: DisclaimerPurpose,
	/// The renderable disclaimer body.
	pub content: ClientRenderableContent,
}

/// The token metadata a provider advertises for one asset at one location,
/// the reference `AnchorTokenLocationMetadata`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenLocationMetadata {
	/// The token's decimal places (published as a number or numeric string).
	#[serde(deserialize_with = "decimal_places")]
	pub decimal_places: u32,
	/// The token's logo URI, when advertised.
	#[serde(rename = "logoURI", default)]
	pub logo_uri: Option<String>,
	/// The display name, when advertised.
	#[serde(default)]
	pub display_name: Option<String>,
	/// The `$`-prefixed ticker, when advertised.
	#[serde(default)]
	pub ticker: Option<String>,
}

/// Read a `decimalPlaces` value published as a JSON number or numeric string
/// (the reference `TokenMetadataJSON` allows both).
fn decimal_places<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
	#[derive(Deserialize)]
	#[serde(untagged)]
	enum Raw {
		Number(u32),
		Text(String),
	}

	match Raw::deserialize(deserializer)? {
		Raw::Number(value) => Ok(value),
		Raw::Text(text) => text.trim().parse().map_err(D::Error::custom),
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

	/// The legal disclaimers the provider advertises, or [`None`] when its
	/// metadata carries none. Malformed entries are skipped, mirroring the
	/// reference `getLegalDisclaimers`.
	pub fn legal_disclaimers(&self) -> Option<Vec<Disclaimer>> {
		let disclaimers = self.legal.as_ref()?.get("disclaimers")?.as_array()?;
		let parsed = disclaimers
			.iter()
			.filter_map(|entry| serde_json::from_value(entry.clone()).ok())
			.collect();

		Some(parsed)
	}

	/// The token metadata advertised for `asset` at the canonical `location`
	/// (e.g. `chain:evm:100`), or [`None`] when the provider publishes none.
	/// Mirrors the reference `getAssetMetadataForLocation`.
	pub fn asset_metadata_for_location(
		&self,
		location: impl AsRef<str>,
		asset: impl AsRef<str>,
	) -> Option<TokenLocationMetadata> {
		let per_location = self.location_metadata.as_ref()?.get(location.as_ref())?;
		let metadata = per_location.get("assets")?.get(asset.as_ref())?;
		let parsed = serde_json::from_value(metadata.clone());

		parsed.ok()
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

/// A transfer search: the asset (or conversion pair), the endpoints value must
/// move between, and the rails each endpoint must advertise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderSearch {
	/// The asset or conversion pair to move.
	pub asset: Option<AssetOrPair>,
	/// The canonical source location the provider must support.
	pub from: Option<String>,
	/// The canonical destination location the provider must support.
	pub to: Option<String>,
	/// Inbound rails the source endpoint must advertise (any one matches).
	pub inbound_rails: Vec<String>,
	/// Outbound rails the destination endpoint must advertise (any one matches).
	pub outbound_rails: Vec<String>,
}

impl ProviderSearch {
	/// A search for `asset` with no endpoint or rail constraints.
	pub fn for_asset(asset: impl Into<AssetOrPair>) -> Self {
		Self { asset: Some(asset.into()), ..Self::default() }
	}

	/// Constrain the source location.
	pub fn from(mut self, location: impl Into<String>) -> Self {
		self.from = Some(location.into());
		self
	}

	/// Constrain the destination location.
	pub fn to(mut self, location: impl Into<String>) -> Self {
		self.to = Some(location.into());
		self
	}

	/// Require the source endpoint to advertise `rail` inbound (or common).
	pub fn inbound(mut self, rail: impl Into<String>) -> Self {
		self.inbound_rails.push(rail.into());
		self
	}

	/// Require the destination endpoint to advertise `rail` outbound (or common).
	pub fn outbound(mut self, rail: impl Into<String>) -> Self {
		self.outbound_rails.push(rail.into());
		self
	}

	/// Whether `provider` advertises a supported-asset path satisfying this
	/// search.
	pub fn accepts(&self, provider: &AssetMovementProvider) -> bool {
		provider
			.supported_assets
			.iter()
			.any(|entry| self.entry_matches(entry))
	}

	/// Whether an entry advertises any `paths[]` satisfying this search. Asset,
	/// location, and rail matching all happen per path endpoint (the entry's
	/// top-level `asset` is a catalog label and is not consulted, mirroring the
	/// reference `filterSupportedAssets`).
	fn entry_matches(&self, entry: &Value) -> bool {
		entry
			.get("paths")
			.and_then(Value::as_array)
			.is_some_and(|paths| paths.iter().any(|path| self.path_matches(path)))
	}

	/// Whether a path's endpoint pair satisfies the asset, location, and rail
	/// constraints in either source/destination orientation.
	fn path_matches(&self, path: &Value) -> bool {
		let Some(pair) = path.get("pair").and_then(Value::as_array) else {
			return false;
		};
		let [first, second] = pair.as_slice() else {
			return false;
		};

		self.orientation_matches(first, second) || self.orientation_matches(second, first)
	}

	/// Whether `source`/`dest` satisfy the asset ids, the from/to locations, and
	/// the inbound/outbound rails.
	fn orientation_matches(&self, source: &Value, dest: &Value) -> bool {
		self.asset_matches(source, dest)
			&& location_matches(self.from.as_deref(), source)
			&& location_matches(self.to.as_deref(), dest)
			&& rails_orientation_matches(&self.inbound_rails, &self.outbound_rails, source, dest)
	}

	/// Whether the oriented endpoint ids carry the searched asset. A single
	/// asset matches on either endpoint id; a pair must match `from`/`to`
	/// directionally. An unset search asset matches any pair.
	fn asset_matches(&self, source: &Value, dest: &Value) -> bool {
		let Some(asset) = &self.asset else {
			return true;
		};

		let source_id = source.get("id").and_then(Value::as_str);
		let dest_id = dest.get("id").and_then(Value::as_str);
		match asset {
			AssetOrPair::Single(name) => source_id == Some(name.as_str()) || dest_id == Some(name.as_str()),
			AssetOrPair::Pair { from, to } => source_id == Some(from.as_str()) && dest_id == Some(to.as_str()),
		}
	}
}

/// The rail direction an endpoint advertises.
#[derive(Clone, Copy)]
enum Direction {
	/// Rails value can arrive on.
	Inbound,
	/// Rails value can leave on.
	Outbound,
}

/// Whether `endpoint`'s location matches `wanted`. An unset `wanted` matches
/// any.
fn location_matches(wanted: Option<&str>, endpoint: &Value) -> bool {
	let Some(wanted) = wanted else {
		return true;
	};

	endpoint.get("location").and_then(Value::as_str) == Some(wanted)
}

/// Whether the oriented pair advertises rails satisfying the search. A path
/// with no inbound rails on the source and no outbound rails on the
/// destination carries value in neither direction and never matches, mirroring
/// the reference `filterSupportedAssets`.
fn rails_orientation_matches(inbound: &[String], outbound: &[String], source: &Value, dest: &Value) -> bool {
	let inbound_pool = endpoint_rails(source, Direction::Inbound);
	let outbound_pool = endpoint_rails(dest, Direction::Outbound);
	if inbound_pool.is_empty() && outbound_pool.is_empty() {
		return false;
	}

	rail_pool_matches(inbound, &inbound_pool) && rail_pool_matches(outbound, &outbound_pool)
}

/// The rails `endpoint` advertises in `direction`, including its `common` rails.
fn endpoint_rails(endpoint: &Value, direction: Direction) -> Vec<String> {
	let Some(rails) = endpoint.get("rails") else {
		return Vec::new();
	};

	let directional = match direction {
		Direction::Inbound => "inbound",
		Direction::Outbound => "outbound",
	};

	let mut names = rail_names(rails.get(directional));
	names.extend(rail_names(rails.get("common")));
	names
}

/// Whether `pool` advertises at least one of `wanted`. An empty `wanted`
/// matches any non-empty pool.
fn rail_pool_matches(wanted: &[String], pool: &[String]) -> bool {
	wanted.is_empty()
		|| wanted
			.iter()
			.any(|rail| pool.iter().any(|have| have == rail))
}

/// The rail names in a `rails.{inbound,outbound,common}` array, each a bare
/// string or a `{ rail }` object.
fn rail_names(rails: Option<&Value>) -> Vec<String> {
	rails
		.and_then(Value::as_array)
		.map(|entries| entries.iter().filter_map(rail_name).collect())
		.unwrap_or_default()
}

/// The rail name of a bare-string or `{ rail }` entry.
fn rail_name(entry: &Value) -> Option<String> {
	if let Some(name) = entry.as_str() {
		return Some(name.to_string());
	}

	entry
		.get("rail")
		.and_then(Value::as_str)
		.map(str::to_string)
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

	/// A provider advertising an EVM<->Keeta `KEETA_SEND` path whose endpoints
	/// carry distinct asset ids (`evm:0x5` and `token`) and symmetric rails.
	fn searchable_provider() -> AssetMovementProvider {
		let entry = json!({
			"operations": {},
			"supportedAssets": [{
				"asset": "token",
				"paths": [{
					"pair": [
						{ "id": "evm:0x5", "location": "chain:evm:100", "rails": { "inbound": ["KEETA_SEND"], "common": ["KEETA_SEND"] } },
						{ "id": "token", "location": "chain:keeta:100", "rails": { "outbound": ["KEETA_SEND"], "common": ["KEETA_SEND"] } }
					]
				}]
			}]
		});
		AssetMovementProvider::from_entry("p".into(), &entry)
	}

	#[test]
	fn a_matching_asset_and_endpoints_are_accepted() {
		let search = ProviderSearch::for_asset("token")
			.from("chain:evm:100")
			.to("chain:keeta:100")
			.inbound("KEETA_SEND")
			.outbound("KEETA_SEND");
		assert!(search.accepts(&searchable_provider()));
	}

	#[test]
	fn a_reversed_orientation_still_matches_a_symmetric_search() {
		let search = ProviderSearch::for_asset("token")
			.from("chain:keeta:100")
			.to("chain:evm:100");
		assert!(search.accepts(&searchable_provider()));
	}

	#[test]
	fn an_unadvertised_asset_is_rejected() {
		let search = ProviderSearch::for_asset("other");
		assert!(!search.accepts(&searchable_provider()));
	}

	#[test]
	fn an_unadvertised_location_is_rejected() {
		let search = ProviderSearch::for_asset("token").from("chain:evm:1");
		assert!(!search.accepts(&searchable_provider()));
	}

	#[test]
	fn an_unadvertised_rail_is_rejected() {
		let search = ProviderSearch::for_asset("token")
			.from("chain:evm:100")
			.inbound("ACH");
		assert!(!search.accepts(&searchable_provider()));
	}

	#[test]
	fn a_bare_asset_search_matches_any_supported_path() {
		let search = ProviderSearch::for_asset("token");
		assert!(search.accepts(&searchable_provider()));
	}

	#[test]
	fn a_chain_side_asset_id_matches_its_endpoint() {
		let search = ProviderSearch::for_asset("evm:0x5").from("chain:evm:100");
		assert!(search.accepts(&searchable_provider()));
	}

	#[test]
	fn a_directional_pair_matches_its_orientation() {
		let search = ProviderSearch::for_asset(AssetOrPair::Pair { from: "evm:0x5".into(), to: "token".into() });
		assert!(search.accepts(&searchable_provider()));
	}

	#[test]
	fn a_pair_with_an_unadvertised_leg_is_rejected() {
		let search = ProviderSearch::for_asset(AssetOrPair::Pair { from: "evm:0x5".into(), to: "unlisted".into() });
		assert!(!search.accepts(&searchable_provider()));
	}

	/// A provider publishing one general markdown disclaimer, one malformed
	/// disclaimer, and per-location token metadata with a string
	/// `decimalPlaces`.
	fn decorated_provider() -> AssetMovementProvider {
		let entry = json!({
			"operations": {},
			"legal": {
				"disclaimers": [
					{ "purpose": "general", "content": { "type": "markdown", "content": "Read this." } },
					{ "purpose": "unsupported", "content": { "type": "markdown", "content": "Skipped." } }
				]
			},
			"locationMetadata": {
				"chain:evm:100": {
					"assets": {
						"evm:0x5": {
							"decimalPlaces": "6",
							"logoURI": "https://cdn.example/usdc.svg",
							"displayName": "Circle USDC",
							"ticker": "$USDC"
						}
					}
				}
			}
		});
		AssetMovementProvider::from_entry("p".into(), &entry)
	}

	#[test]
	fn legal_disclaimers_parse_and_skip_malformed_entries() {
		let disclaimers = decorated_provider().legal_disclaimers();
		assert!(matches!(disclaimers.as_deref(), Some([Disclaimer {
			purpose: DisclaimerPurpose::General,
			content: ClientRenderableContent::Markdown { content },
		}]) if content == "Read this."));
	}

	#[test]
	fn a_provider_without_legal_metadata_has_no_disclaimers() {
		let provider = AssetMovementProvider::from_entry("p".into(), &json!({ "operations": {} }));
		assert!(provider.legal_disclaimers().is_none());
	}

	#[test]
	fn asset_metadata_resolves_by_location_and_asset() {
		let metadata = decorated_provider().asset_metadata_for_location("chain:evm:100", "evm:0x5");
		let expected = TokenLocationMetadata {
			decimal_places: 6,
			logo_uri: Some("https://cdn.example/usdc.svg".into()),
			display_name: Some("Circle USDC".into()),
			ticker: Some("$USDC".into()),
		};
		assert_eq!(metadata, Some(expected));
	}

	#[test]
	fn an_unadvertised_location_or_asset_has_no_metadata() {
		let provider = decorated_provider();
		assert!(provider
			.asset_metadata_for_location("chain:evm:1", "evm:0x5")
			.is_none());
		assert!(provider
			.asset_metadata_for_location("chain:evm:100", "evm:0x6")
			.is_none());
	}

	#[test]
	fn a_rail_less_path_is_rejected() {
		let entry = json!({
			"operations": {},
			"supportedAssets": [{
				"asset": "token",
				"paths": [{
					"pair": [
						{ "id": "token", "location": "chain:keeta:100", "rails": {} },
						{ "id": "evm:0x5", "location": "chain:evm:100", "rails": {} }
					]
				}]
			}]
		});
		let provider = AssetMovementProvider::from_entry("p".into(), &entry);
		let search = ProviderSearch::for_asset("token");
		assert!(!search.accepts(&provider));
	}
}

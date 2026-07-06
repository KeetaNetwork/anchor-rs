//! Asset-movement request inputs and the two byte-exact projections each one
//! produces: the transport `fields` sent in the request body (the TypeScript
//! `serializeRequest`) and the [`Signable`] payload that is signed.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use keetanetwork_anchor::signing::{object_to_signable, Signable, SigningError};
use serde_json::{Map, Value};

use super::asset::AssetOrPair;

/// A signed payload, either canonical object JSON or a fixed string tuple.
type Payload = Vec<Signable<'static>>;

/// The transport request fields, without the `account` the caller injects.
type Fields = Map<String, Value>;

/// Pagination bounds shared by the list operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pagination {
	/// Maximum number of results to return.
	pub limit: Option<u32>,
	/// Number of results to skip.
	pub offset: Option<u32>,
}

impl Pagination {
	/// The transport `{ limit?, offset? }` value, or [`None`] when both are absent.
	fn to_value(&self) -> Option<Value> {
		let mut map = Map::new();
		insert_u32(&mut map, "limit", self.limit);
		insert_u32(&mut map, "offset", self.offset);
		(!map.is_empty()).then_some(Value::Object(map))
	}
}

/// The source of a transfer: a location and an optional persistent-address
/// reference to debit from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferSource {
	/// The canonical source location string.
	pub location: String,
	/// An optional persistent-address (or template) reference to debit from.
	pub source: Option<Value>,
}

/// The destination of a transfer: a location, a recipient, and an optional
/// deposit message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferDestination {
	/// The canonical destination location string.
	pub location: String,
	/// The recipient (a resolved address or a persistent-address reference).
	/// Required to initiate a transfer; optional to simulate one.
	pub recipient: Option<Value>,
	/// An optional deposit message (e.g. a bank transfer reference note).
	pub deposit_message: Option<String>,
}

/// A request to simulate or initiate an asset transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
	/// The asset or pair to move.
	pub asset: AssetOrPair,
	/// The source of the transfer.
	pub from: TransferSource,
	/// The destination of the transfer.
	pub to: TransferDestination,
	/// The amount to move, a decimal string in the asset's smallest unit.
	pub value: String,
	/// Optional allow-list of rails; the anchor errors if none are available.
	pub allowed_rails: Vec<String>,
}

impl TransferRequest {
	/// The transport fields for `initiateTransfer` / `simulateTransfer`.
	pub fn transport_fields(&self) -> Fields {
		let mut from = Map::new();
		from.insert("location".into(), Value::String(self.from.location.clone()));

		insert_some(&mut from, "source", self.from.source.clone());

		let mut to = Map::new();
		to.insert("location".into(), Value::String(self.to.location.clone()));

		insert_some(&mut to, "recipient", self.to.recipient.clone());
		insert_some(&mut to, "depositMessage", self.to.deposit_message.clone().map(Value::String));

		let mut fields = Map::new();
		if !self.allowed_rails.is_empty() {
			let rails = self
				.allowed_rails
				.iter()
				.cloned()
				.map(Value::String)
				.collect();
			fields.insert("allowedRails".into(), Value::Array(rails));
		}

		fields.insert("value".into(), Value::String(self.value.clone()));
		fields.insert("from".into(), Value::Object(from));
		fields.insert("to".into(), Value::Object(to));
		fields.insert("asset".into(), self.asset.to_canonical_value());

		fields
	}

	/// The signed payload for `initiateTransfer` / `simulateTransfer`.
	pub fn signable(&self) -> Result<Payload, SigningError> {
		let mut to = Map::new();
		to.insert("location".into(), Value::String(self.to.location.clone()));

		insert_some(&mut to, "recipient", self.to.recipient.clone());
		insert_some(&mut to, "depositMessage", self.to.deposit_message.clone().map(Value::String));

		let value = serde_json::json!({
			"asset": self.asset.to_canonical_value(),
			"from": { "location": self.from.location },
			"to": Value::Object(to),
			"value": self.value,
		});

		object_to_signable(&value)
	}
}

/// A request to execute a pull instruction for a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteTransferRequest {
	/// The transfer id (carried in the URL).
	pub id: String,
	/// The `{ type, pullFrom }` instruction to execute.
	pub instruction: Value,
}

impl ExecuteTransferRequest {
	/// The transport fields (the id travels in the URL).
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();
		fields.insert("instruction".into(), self.instruction.clone());
		fields
	}

	/// The signed payload `{ id, instruction }`.
	pub fn signable(&self) -> Result<Payload, SigningError> {
		object_to_signable(&serde_json::json!({ "id": self.id, "instruction": self.instruction }))
	}
}

/// A request to open a persistent-forwarding template session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiatePersistentForwardingTemplateRequest {
	/// The asset (or pair) the template forwards.
	pub asset: AssetOrPair,
	/// The canonical location the template forwards to.
	pub location: String,
}

impl InitiatePersistentForwardingTemplateRequest {
	/// The transport fields for `initiatePersistentForwardingTemplate`.
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();
		fields.insert("location".into(), Value::String(self.location.clone()));
		fields.insert("asset".into(), self.asset.to_canonical_value());
		fields
	}

	/// The signed payload `{ asset: { from, to }, location }`.
	pub fn signable(&self) -> Result<Payload, SigningError> {
		object_to_signable(&serde_json::json!({
			"asset": self.asset.to_pair_value(),
			"location": self.location,
		}))
	}
}

/// A request to create a persistent-forwarding template, either directly from a
/// resolved address or by completing a prior session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatePersistentForwardingTemplateRequest {
	/// Create directly from a resolved destination address.
	Direct {
		/// The asset (or pair) the template forwards.
		asset: AssetOrPair,
		/// The canonical destination location.
		location: String,
		/// The resolved destination address.
		address: Value,
	},
	/// Complete a session started by an initiate call.
	Completion {
		/// The session id, when the anchor issued one.
		id: Option<String>,
		/// The provider-specific completion payload.
		data: Value,
	},
}

impl CreatePersistentForwardingTemplateRequest {
	/// The transport fields for `createPersistentForwardingTemplate`.
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();
		match self {
			Self::Direct { asset, location, address } => {
				fields.insert("location".into(), Value::String(location.clone()));
				fields.insert("asset".into(), asset.to_canonical_value());
				fields.insert("address".into(), address.clone());
			}
			Self::Completion { id, data } => {
				insert_some(&mut fields, "id", id.clone().map(Value::String));
				fields.insert("data".into(), data.clone());
			}
		}

		fields
	}

	/// The signed payload: `{ asset: { from, to }, location, address }` for a
	/// direct create, `{ id?, data }` for a completion.
	pub fn signable(&self) -> Result<Payload, SigningError> {
		let value = match self {
			Self::Direct { asset, location, address } => serde_json::json!({
				"asset": asset.to_pair_value(),
				"location": location,
				"address": address,
			}),
			Self::Completion { id, data } => {
				let mut map = Map::new();
				insert_some(&mut map, "id", id.clone().map(Value::String));
				map.insert("data".into(), data.clone());
				Value::Object(map)
			}
		};
		object_to_signable(&value)
	}
}

/// The destination of a persistent-forwarding address: a resolved address at a
/// location, or a prior template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardingDestination {
	/// A resolved destination address at a canonical location.
	Address {
		/// The canonical destination location.
		location: String,
		/// The resolved destination address.
		address: Value,
	},
	/// A previously created persistent-address template.
	Template {
		/// The template id.
		persistent_address_template_id: String,
	},
}

/// A request to create a persistent-forwarding address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePersistentForwardingAddressRequest {
	/// The canonical source location.
	pub source_location: String,
	/// The asset (or pair) forwarded.
	pub asset: AssetOrPair,
	/// The outgoing rail, when constrained.
	pub outgoing_rail: Option<String>,
	/// The incoming rail, when constrained.
	pub incoming_rail: Option<String>,
	/// Where the address forwards to.
	pub destination: ForwardingDestination,
}

impl CreatePersistentForwardingAddressRequest {
	/// The shared base fields, before the destination discriminant.
	fn base(&self) -> Fields {
		let mut fields = Map::new();
		fields.insert("sourceLocation".into(), Value::String(self.source_location.clone()));
		fields.insert("asset".into(), self.asset.to_canonical_value());

		insert_some(&mut fields, "incomingRail", self.incoming_rail.clone().map(Value::String));
		insert_some(&mut fields, "outgoingRail", self.outgoing_rail.clone().map(Value::String));

		fields
	}

	/// The transport fields for `createPersistentForwarding`.
	pub fn transport_fields(&self) -> Fields {
		let mut fields = self.base();
		match &self.destination {
			ForwardingDestination::Address { location, address } => {
				fields.insert("destinationAddress".into(), address.clone());
				fields.insert("destinationLocation".into(), Value::String(location.clone()));
			}
			ForwardingDestination::Template { persistent_address_template_id } => {
				fields.insert(
					"persistentAddressTemplateId".into(),
					Value::String(persistent_address_template_id.clone()),
				);
			}
		}

		fields
	}

	/// The signed payload over source, asset, rails, and the destination.
	pub fn signable(&self) -> Result<Payload, SigningError> {
		let mut map = Map::new();
		map.insert("sourceLocation".into(), Value::String(self.source_location.clone()));
		map.insert("asset".into(), self.asset.to_canonical_value());

		insert_some(&mut map, "outgoingRail", self.outgoing_rail.clone().map(Value::String));
		insert_some(&mut map, "incomingRail", self.incoming_rail.clone().map(Value::String));

		match &self.destination {
			ForwardingDestination::Address { location, address } => {
				map.insert("destinationLocation".into(), Value::String(location.clone()));
				map.insert("destinationAddress".into(), address.clone());
			}
			ForwardingDestination::Template { persistent_address_template_id } => {
				map.insert("persistentAddressTemplateId".into(), Value::String(persistent_address_template_id.clone()));
			}
		}

		object_to_signable(&Value::Object(map))
	}
}

/// A request to list persistent-forwarding templates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListForwardingAddressTemplatesRequest {
	/// Filter to these canonical assets, when set.
	pub asset: Option<Vec<String>>,
	/// Filter to these canonical locations, when set.
	pub location: Option<Vec<String>>,
}

impl ListForwardingAddressTemplatesRequest {
	/// The transport fields for `listPersistentForwardingTemplate`.
	///
	/// Matches the reference `serializeRequest`, which carries only the asset
	/// and location filters (pagination is not serialized).
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();

		insert_some(&mut fields, "asset", self.asset.clone().map(string_array));
		insert_some(&mut fields, "location", self.location.clone().map(string_array));

		fields
	}

	/// The signed payload `['list-templates']`.
	pub fn signable(&self) -> Payload {
		literal(&["list-templates"])
	}
}

/// One filter over persistent-forwarding addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForwardingAddressFilter {
	/// Canonical source location.
	pub source_location: Option<String>,
	/// Canonical destination location.
	pub destination_location: Option<String>,
	/// Canonical asset.
	pub asset: Option<String>,
	/// Destination address.
	pub destination_address: Option<String>,
	/// Persistent-address template id.
	pub persistent_address_template_id: Option<String>,
}

impl ForwardingAddressFilter {
	fn to_value(&self) -> Value {
		let mut map = Map::new();
		insert_some(&mut map, "sourceLocation", self.source_location.clone().map(Value::String));
		insert_some(&mut map, "destinationLocation", self.destination_location.clone().map(Value::String));
		insert_some(&mut map, "asset", self.asset.clone().map(Value::String));
		insert_some(&mut map, "destinationAddress", self.destination_address.clone().map(Value::String));
		insert_some(
			&mut map,
			"persistentAddressTemplateId",
			self.persistent_address_template_id
				.clone()
				.map(Value::String),
		);
		Value::Object(map)
	}
}

/// A request to list persistent-forwarding addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListForwardingAddressesRequest {
	/// Search filters, any of which may match.
	pub search: Option<Vec<ForwardingAddressFilter>>,
	/// Pagination bounds.
	pub pagination: Pagination,
}

impl ListForwardingAddressesRequest {
	/// The transport fields for `listPersistentForwarding`.
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();
		if let Some(search) = &self.search {
			let items = search
				.iter()
				.map(ForwardingAddressFilter::to_value)
				.collect();
			fields.insert("search".into(), Value::Array(items));
		}

		insert_some(&mut fields, "pagination", self.pagination.to_value());

		fields
	}

	/// The signed payload `['list-persistent-forwarding-addresses']`.
	pub fn signable(&self) -> Payload {
		literal(&["list-persistent-forwarding-addresses"])
	}
}

/// A persistent-address filter for listing transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentAddressFilter {
	/// Canonical location.
	pub location: String,
	/// A persistent address, when filtering by address.
	pub persistent_address: Option<String>,
	/// A persistent-address template, when filtering by template.
	pub persistent_address_template: Option<String>,
}

impl PersistentAddressFilter {
	fn to_value(&self) -> Value {
		let mut map = Map::new();
		map.insert("location".into(), Value::String(self.location.clone()));
		insert_some(&mut map, "persistentAddress", self.persistent_address.clone().map(Value::String));
		insert_some(&mut map, "persistentAddressTemplate", self.persistent_address_template.clone().map(Value::String));
		Value::Object(map)
	}
}

/// A source/destination endpoint filter for listing transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEndpointFilter {
	/// Canonical location.
	pub location: String,
	/// The user's address at this endpoint, when filtering by it.
	pub user_address: Option<String>,
	/// The canonical asset, when filtering by it.
	pub asset: Option<String>,
}

impl TransactionEndpointFilter {
	fn to_value(&self) -> Value {
		let mut map = Map::new();
		map.insert("location".into(), Value::String(self.location.clone()));
		insert_some(&mut map, "userAddress", self.user_address.clone().map(Value::String));
		insert_some(&mut map, "asset", self.asset.clone().map(Value::String));
		Value::Object(map)
	}
}

/// A specific-transaction filter for listing transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRefFilter {
	/// Canonical location.
	pub location: String,
	/// A partial `{ id?, nonce? }` transaction reference.
	pub transaction: Value,
}

impl TransactionRefFilter {
	fn to_value(&self) -> Value {
		serde_json::json!({ "location": self.location, "transaction": self.transaction })
	}
}

/// A request to list asset-movement transactions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListTransactionsRequest {
	/// Persistent-address filters.
	pub persistent_addresses: Option<Vec<PersistentAddressFilter>>,
	/// A source-endpoint filter.
	pub from: Option<TransactionEndpointFilter>,
	/// A destination-endpoint filter.
	pub to: Option<TransactionEndpointFilter>,
	/// Specific-transaction filters.
	pub transactions: Option<Vec<TransactionRefFilter>>,
	/// Pagination bounds.
	pub pagination: Pagination,
}

impl ListTransactionsRequest {
	/// The transport fields for `listTransactions`.
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();

		insert_some(&mut fields, "pagination", self.pagination.to_value());

		if let Some(addresses) = &self.persistent_addresses {
			let items = addresses
				.iter()
				.map(PersistentAddressFilter::to_value)
				.collect();
			fields.insert("persistentAddresses".into(), Value::Array(items));
		}

		insert_some(&mut fields, "from", self.from.as_ref().map(TransactionEndpointFilter::to_value));
		insert_some(&mut fields, "to", self.to.as_ref().map(TransactionEndpointFilter::to_value));

		if let Some(transactions) = &self.transactions {
			let items = transactions
				.iter()
				.map(TransactionRefFilter::to_value)
				.collect();
			fields.insert("transactions".into(), Value::Array(items));
		}

		fields
	}

	/// The signed payload `['list-transactions']`.
	pub fn signable(&self) -> Payload {
		literal(&["list-transactions"])
	}
}

/// A request to share KYC attributes with an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareKycRequest {
	/// The exported sharable-attributes string.
	pub attributes: String,
	/// An optional terms-of-service agreement reference (`{ id }`).
	pub tos_agreement: Option<Value>,
}

impl ShareKycRequest {
	/// The transport fields for `shareKYC`.
	pub fn transport_fields(&self) -> Fields {
		let mut fields = Map::new();
		fields.insert("attributes".into(), Value::String(self.attributes.clone()));

		insert_some(&mut fields, "tosAgreement", self.tos_agreement.clone());

		fields
	}

	/// The signed payload `['share-kyc']`.
	pub fn signable(&self) -> Payload {
		literal(&["share-kyc"])
	}
}

/// The signed payload for an id-only operation (deactivate, get-status), a
/// fixed literal followed by the id.
pub fn id_literal(literal_tag: &str, id: &str) -> Payload {
	alloc::vec![Signable::from(literal_tag.to_string()), Signable::from(id.to_string())]
}

/// A fixed string-tuple payload, e.g. `['get-account-status']`.
pub fn literal(parts: &[&str]) -> Payload {
	parts
		.iter()
		.map(|part| Signable::from(part.to_string()))
		.collect()
}

/// Insert `key` only when `value` is present.
fn insert_some(fields: &mut Fields, key: &str, value: Option<Value>) {
	if let Some(value) = value {
		fields.insert(key.to_string(), value);
	}
}

/// Insert a `u32` as a JSON number only when present.
fn insert_u32(fields: &mut Fields, key: &str, value: Option<u32>) {
	if let Some(value) = value {
		fields.insert(key.to_string(), Value::Number(value.into()));
	}
}

/// A JSON array of strings.
fn string_array(values: Vec<String>) -> Value {
	Value::Array(values.into_iter().map(Value::String).collect())
}

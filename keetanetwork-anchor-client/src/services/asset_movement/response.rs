//! Typed asset-movement responses.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use super::asset::AssetOrPair;
use super::metadata::ClientRenderableContent;

/// A canonical asset id, or an `{ id, location }` object locating it, the
/// reference `AssetOrAssetWithLocation`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AssetOrAssetWithLocation {
	/// A bare canonical asset id.
	Id(String),
	/// An asset id at a canonical location.
	AtLocation {
		/// The canonical asset id.
		id: String,
		/// The canonical location string.
		location: String,
	},
}

/// One fee line item in a breakdown, the reference `ResolvedFeeLineItem` /
/// `UnresolvedFeeLineItem` union flattened: a fixed fee carries `value`, an
/// unresolved variable fee carries `basisPoints`, a resolved variable fee
/// carries both.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeLineItem {
	/// Why the fee applies (`RAIL`, `NETWORK`, `PROVIDER`, `OTHER`, or
	/// `VALUE_VARIABLE`), kept verbatim so unknown purposes round-trip.
	pub purpose: String,
	/// The fee amount in the asset's smallest unit, when resolved.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub value: Option<String>,
	/// The variable-fee basis points (1 bps = 0.01%), when variable. Kept as a
	/// JSON number since the reference type permits any `number`.
	#[serde(rename = "basisPoints", default, skip_serializing_if = "Option::is_none")]
	pub basis_points: Option<Number>,
	/// The asset the fee is denominated in; the transferred asset when unset.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asset: Option<AssetOrAssetWithLocation>,
	/// Renderable details about the fee, when provided.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub details: Option<ClientRenderableContent>,
	/// Fields this client does not model, preserved for round-tripping.
	#[serde(flatten)]
	pub extra: Map<String, Value>,
}

/// A fee breakdown, the reference `AssetFeeBreakdown` /
/// `PersistentAddressAssetFeeBreakdown`: its line items, with an optional
/// pre-computed total.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeBreakdown {
	/// The individual fee line items.
	#[serde(rename = "lineItems", default)]
	pub line_items: Vec<FeeLineItem>,
	/// The total fee in the asset's smallest unit; the sum of the line items
	/// when unset.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub total: Option<String>,
	/// The asset the total is priced in; the transferred asset when unset.
	#[serde(rename = "totalPricedIn", default, skip_serializing_if = "Option::is_none")]
	pub total_priced_in: Option<AssetOrAssetWithLocation>,
	/// Fields this client does not model, preserved for round-tripping.
	#[serde(flatten)]
	pub extra: Map<String, Value>,
}

/// The smallest transfer a persistent-forwarding address accepts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinimumTransferValue {
	/// The canonical asset the minimum is denominated in.
	pub asset: String,
	/// The minimum value in the asset's smallest unit.
	pub value: String,
}

/// One persistent-forwarding address, the reference
/// `KeetaPersistentForwardingAddressDetails`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardingAddress {
	/// The provider's address id, when assigned.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub id: Option<String>,
	/// The forwarding address, resolved or obfuscated.
	pub address: Value,
	/// A deposit message the sender must attach, when required.
	#[serde(rename = "depositMessage", default, skip_serializing_if = "Option::is_none")]
	pub deposit_message: Option<Value>,
	/// The asset (or conversion pair) the address forwards.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asset: Option<AssetOrPair>,
	/// The location deposits arrive at.
	#[serde(rename = "sourceLocation", default, skip_serializing_if = "Option::is_none")]
	pub source_location: Option<Value>,
	/// The location deposits forward to.
	#[serde(rename = "destinationLocation", default, skip_serializing_if = "Option::is_none")]
	pub destination_location: Option<Value>,
	/// The destination address, resolved or obfuscated.
	#[serde(rename = "destinationAddress", default, skip_serializing_if = "Option::is_none")]
	pub destination_address: Option<Value>,
	/// The rail used to forward out of the address.
	#[serde(rename = "outgoingRail", default, skip_serializing_if = "Option::is_none")]
	pub outgoing_rail: Option<String>,
	/// The rails accepted into the address.
	#[serde(rename = "incomingRail", default, skip_serializing_if = "Option::is_none")]
	pub incoming_rail: Option<Vec<String>>,
	/// The smallest accepted transfer, when the provider enforces one.
	#[serde(rename = "minimumTransferValue", default, skip_serializing_if = "Option::is_none")]
	pub minimum_transfer_value: Option<MinimumTransferValue>,
	/// The fee breakdown applied to forwarded transfers, when advertised.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fees: Option<FeeBreakdown>,
	/// Fields this client does not model, preserved for round-tripping.
	#[serde(flatten)]
	pub extra: Map<String, Value>,
}

/// An initiated transfer: its id and the instruction choices to complete it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
	/// The provider's transfer id, used to poll status and execute.
	pub id: String,
	/// The instruction choices for completing the transfer.
	#[serde(rename = "instructionChoices", default)]
	pub instruction_choices: Vec<Value>,
}

/// A simulated transfer: the instruction choices, without an id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimulatedTransfer {
	/// The simulated instruction choices.
	#[serde(rename = "instructionChoices", default)]
	pub instruction_choices: Vec<Value>,
}

/// A transfer's status: the underlying transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferStatus {
	/// The transaction record.
	pub transaction: Value,
}

/// A persistent-forwarding template session opened by an initiate call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateSession {
	/// The session id.
	pub id: String,
	/// When the session expires (ISO 8601).
	#[serde(rename = "expiresAt")]
	pub expires_at: String,
	/// The provider-specific session data (e.g. a Plaid link token).
	pub data: Value,
}

/// A created persistent-forwarding template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardingTemplate {
	/// The template id.
	pub id: String,
	/// The location the template forwards to.
	pub location: Value,
	/// The asset the template forwards.
	pub asset: Value,
	/// The (obfuscated) destination address.
	pub address: Value,
}

/// A page of persistent-forwarding templates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplatePage {
	/// The templates on this page.
	#[serde(default)]
	pub templates: Vec<Value>,
	/// The total count across all pages, as a decimal string.
	#[serde(default)]
	pub total: String,
}

/// A page of persistent-forwarding addresses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressPage {
	/// The addresses on this page.
	#[serde(default)]
	pub addresses: Vec<ForwardingAddress>,
	/// The total count across all pages, as a decimal string.
	#[serde(default)]
	pub total: String,
}

/// A page of asset-movement transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionPage {
	/// The transactions on this page.
	#[serde(default)]
	pub transactions: Vec<Value>,
	/// The total count across all pages, as a decimal string.
	#[serde(default)]
	pub total: String,
}

/// The outcome of a share-KYC request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareKycOutcome {
	/// Whether the anchor is still processing the shared attributes.
	#[serde(rename = "isPending", default)]
	pub is_pending: bool,
	/// A URL to poll while the share is pending, when provided.
	#[serde(rename = "promiseURL", default)]
	pub promise_url: Option<String>,
}

/// Parse a decimal `total` string into a count, when it is a valid integer.
pub fn parse_total(total: impl AsRef<str>) -> Option<u64> {
	total.as_ref().parse().ok()
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	#[test]
	fn a_fee_breakdown_without_a_total_parses() {
		let value = json!({
			"lineItems": [
				{ "purpose": "VALUE_VARIABLE", "basisPoints": 50, "details": { "type": "markdown", "content": "50 bps" } }
			]
		});

		let breakdown: Result<FeeBreakdown, _> = serde_json::from_value(value);
		assert!(matches!(
			breakdown,
			Ok(FeeBreakdown { ref line_items, total: None, total_priced_in: None, .. })
				if matches!(line_items.as_slice(), [FeeLineItem { basis_points: Some(ref bps), value: None, .. }] if bps.as_u64() == Some(50))
		));
	}

	#[test]
	fn a_fee_breakdown_with_a_located_total_parses() {
		let value = json!({
			"lineItems": [
				{ "purpose": "RAIL", "value": "10", "asset": { "id": "USD", "location": "bank-account:us" } }
			],
			"total": "10",
			"totalPricedIn": { "id": "USD", "location": "bank-account:us" }
		});

		let breakdown: Result<FeeBreakdown, _> = serde_json::from_value(value);
		assert!(matches!(
			breakdown,
			Ok(FeeBreakdown {
				total: Some(ref total),
				total_priced_in: Some(AssetOrAssetWithLocation::AtLocation { ref id, ref location }),
				..
			}) if total == "10" && id == "USD" && location == "bank-account:us"
		));
	}

	#[test]
	fn a_bare_string_fee_asset_parses() {
		let value = json!({ "lineItems": [{ "purpose": "NETWORK", "value": "1", "asset": "USD" }] });
		let breakdown: Result<FeeBreakdown, _> = serde_json::from_value(value);
		assert!(matches!(
			breakdown,
			Ok(FeeBreakdown { ref line_items, .. })
				if matches!(line_items.as_slice(), [FeeLineItem { asset: Some(AssetOrAssetWithLocation::Id(ref id)), .. }] if id == "USD")
		));
	}

	#[test]
	fn a_forwarding_address_parses_its_minimum_transfer_value_and_fees() {
		let value = json!({
			"id": "addr-1",
			"address": "0xabc",
			"asset": { "from": "USD", "to": "EUR" },
			"minimumTransferValue": { "asset": "USD", "value": "500" },
			"fees": { "lineItems": [{ "purpose": "VALUE_VARIABLE", "basisPoints": 25 }] }
		});

		let address: Result<ForwardingAddress, _> = serde_json::from_value(value);
		assert!(matches!(
			address,
			Ok(ForwardingAddress {
				asset: Some(AssetOrPair::Pair { ref from, ref to }),
				minimum_transfer_value: Some(MinimumTransferValue { ref asset, ref value }),
				fees: Some(_),
				..
			}) if from == "USD" && to == "EUR" && asset == "USD" && value == "500"
		));
	}

	#[test]
	fn a_forwarding_address_round_trips_unknown_fields() -> Result<(), serde_json::Error> {
		let value = json!({
			"address": "0xabc",
			"asset": "USD",
			"providerExtension": { "custom": true }
		});

		let address: ForwardingAddress = serde_json::from_value(value.clone())?;
		assert_eq!(serde_json::to_value(&address)?, value);
		Ok(())
	}
}

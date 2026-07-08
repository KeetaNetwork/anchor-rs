//! Typed asset-movement responses.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
	pub addresses: Vec<Value>,
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

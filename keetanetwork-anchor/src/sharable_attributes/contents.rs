//! JSON contents schema carried inside a sharable certificate container.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// The decoded container payload: the leaf certificate, optional intermediate
/// chain, and the selectively disclosed attributes keyed by friendly name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct ContentsJson {
	pub certificate: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub intermediates: Option<Vec<String>>,
	pub attributes: BTreeMap<String, AttributeEntry>,
}

/// A single disclosed attribute: its sensitivity flag, its value, and any
/// preserved external blob references (resolution is out of scope here, so the
/// map is carried opaquely).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct AttributeEntry {
	pub sensitive: bool,
	pub value: AttributeValueJson,
	#[serde(default)]
	pub references: BTreeMap<String, String>,
}

/// The disclosed value: a proof for sensitive attributes, or a base64 plaintext
/// of the raw certificate value for plain attributes. Untagged so the transport
/// shape decides the variant, matching the TypeScript union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum AttributeValueJson {
	Proof(ProofJson),
	Plain(String),
}

/// A sensitive attribute proof: the base64 plaintext and its salted hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct ProofJson {
	pub value: String,
	pub hash: ProofHashJson,
}

/// The salt half of a [`ProofJson`], base64-encoded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct ProofHashJson {
	pub salt: String,
}

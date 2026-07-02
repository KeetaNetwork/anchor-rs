//! Movable-asset values and their canonical form.
//!
//! A movable asset is named by its canonical string: an ISO currency code, a
//! `$`-prefixed custom currency, a Keeta token public key, or an external-chain
//! asset (`evm:0x…`, `solana:…`, `bitcoin:…`, `tron:…`). A transfer may name a
//! single asset or a `{ from, to }` pair.

use alloc::string::String;

use serde_json::{json, Value};

/// A single movable asset or a `{ from, to }` pair, each in canonical string
/// form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetOrPair {
	/// One asset, moved from and to the same denomination.
	Single(String),
	/// A conversion pair: `from` is exchanged into `to`.
	Pair {
		/// The source asset.
		from: String,
		/// The destination asset.
		to: String,
	},
}

impl AssetOrPair {
	/// The canonical JSON the anchor signs and sends: a bare string for a
	/// single asset, or `{ "from", "to" }` for a pair.
	pub fn to_canonical_value(&self) -> Value {
		match self {
			Self::Single(asset) => Value::String(asset.clone()),
			Self::Pair { from, to } => json!({ "from": from, "to": to }),
		}
	}

	/// The `{ from, to }` form, promoting a single asset to a same-denomination
	/// pair. Some signing payloads always canonicalize the asset as a pair.
	pub fn to_pair_value(&self) -> Value {
		match self {
			Self::Single(asset) => json!({ "from": asset, "to": asset }),
			Self::Pair { from, to } => json!({ "from": from, "to": to }),
		}
	}
}

impl<T: Into<String>> From<T> for AssetOrPair {
	fn from(asset: T) -> Self {
		Self::Single(asset.into())
	}
}

/// The canonical string for an already-string asset input.
pub fn canonicalize_asset(input: impl Into<String>) -> String {
	input.into()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_single_asset_canonicalizes_to_a_bare_string() {
		let asset = AssetOrPair::from("evm:0x5");
		assert_eq!(asset.to_canonical_value(), json!("evm:0x5"));
	}

	#[test]
	fn a_pair_canonicalizes_to_from_and_to() {
		let pair = AssetOrPair::Pair { from: "USD".into(), to: "EUR".into() };
		assert_eq!(pair.to_canonical_value(), json!({ "from": "USD", "to": "EUR" }));
	}

	#[test]
	fn a_single_asset_promotes_to_a_same_denomination_pair() {
		let asset = AssetOrPair::from("USD");
		assert_eq!(asset.to_pair_value(), json!({ "from": "USD", "to": "USD" }));
	}
}

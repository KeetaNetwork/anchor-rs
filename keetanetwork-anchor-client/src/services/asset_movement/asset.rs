//! Movable-asset values and their canonical form.
//!
//! A movable asset is named by its canonical string: an ISO currency code, a
//! `$`-prefixed custom currency, a Keeta token public key, or an external-chain
//! asset (`evm:0x…`, `solana:…`, `bitcoin:…`, `tron:…`). A transfer may name a
//! single asset or a `{ from, to }` pair.

use alloc::format;
use alloc::string::String;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// The prefix naming an EVM chain asset (`evm:0x…`).
const EVM_PREFIX: &str = "evm:0x";

/// A single movable asset or a `{ from, to }` pair, each in canonical string
/// form.
///
/// Serde maps the reference wire form verbatim: a bare string for a single
/// asset, `{ "from", "to" }` for a pair. Canonicalization (EIP-55 casing) is
/// applied only by [`Self::to_canonical_value`] and [`Self::to_pair_value`],
/// so decoded provider data round-trips unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
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
	/// single asset, or `{ "from", "to" }` for a pair. EVM assets are
	/// canonicalized to their EIP-55 checksum casing, mirroring the reference
	/// `convertAssetSearchInputToCanonical`.
	pub fn to_canonical_value(&self) -> Value {
		match self {
			Self::Single(asset) => Value::String(canonicalize_asset(asset.as_str())),
			Self::Pair { from, to } => {
				json!({ "from": canonicalize_asset(from.as_str()), "to": canonicalize_asset(to.as_str()) })
			}
		}
	}

	/// The `{ from, to }` form, promoting a single asset to a same-denomination
	/// pair. Some signing payloads always canonicalize the asset as a pair.
	pub fn to_pair_value(&self) -> Value {
		match self {
			Self::Single(asset) => {
				let canonical = canonicalize_asset(asset.as_str());
				json!({ "from": canonical, "to": canonical })
			}
			Self::Pair { from, to } => {
				json!({ "from": canonicalize_asset(from.as_str()), "to": canonicalize_asset(to.as_str()) })
			}
		}
	}
}

impl<T: Into<String>> From<T> for AssetOrPair {
	fn from(asset: T) -> Self {
		Self::Single(asset.into())
	}
}

/// The canonical string for an asset input: an EVM asset is normalized to its
/// EIP-55 checksum casing; every other asset passes through untouched.
/// Mirrors the reference `normalizeChainAssetCasing`, except that a malformed
/// EVM asset (a further `:` separator, which the reference `parseEVMAsset`
/// rejects with an error) passes through verbatim, since canonicalization here
/// is infallible.
pub fn canonicalize_asset(input: impl Into<String>) -> String {
	let input = input.into();
	let Some(address) = input.strip_prefix(EVM_PREFIX) else {
		return input;
	};
	if address.contains(':') {
		return input;
	}

	format!("{EVM_PREFIX}{}", eip55_checksum(address))
}

/// The EIP-55 checksum casing of a bare hex address body (no `0x`): the digit
/// at each position is upper-cased when the same position's nibble of the
/// Keccak-256 hash of the lower-cased body is `>= 8`.
fn eip55_checksum(address: &str) -> String {
	let lower = address.to_lowercase();
	let hash = Keccak256::digest(lower.as_bytes());

	lower
		.chars()
		.enumerate()
		.map(|(position, character)| {
			let byte = hash.get(position / 2).copied().unwrap_or_default();
			let nibble = if position % 2 == 0 {
				byte >> 4
			} else {
				byte & 0x0f
			};
			if nibble >= 8 {
				character.to_ascii_uppercase()
			} else {
				character
			}
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The EIP-55 reference vector in its canonical checksum casing.
	const CHECKSUMMED: &str = "evm:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

	#[test]
	fn a_single_asset_canonicalizes_to_a_bare_string() {
		let asset = AssetOrPair::from("USD");
		assert_eq!(asset.to_canonical_value(), json!("USD"));
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

	#[test]
	fn a_lowercase_evm_asset_canonicalizes_to_its_checksum_casing() {
		let canonical = canonicalize_asset("evm:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
		assert_eq!(canonical, CHECKSUMMED);
	}

	#[test]
	fn an_uppercase_evm_asset_canonicalizes_to_its_checksum_casing() {
		let canonical = canonicalize_asset("evm:0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED");
		assert_eq!(canonical, CHECKSUMMED);
	}

	#[test]
	fn a_checksummed_evm_asset_is_unchanged() {
		assert_eq!(canonicalize_asset(CHECKSUMMED), CHECKSUMMED);
	}

	#[test]
	fn a_non_evm_asset_is_passed_through_untouched() {
		assert_eq!(
			canonicalize_asset("tron:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
			"tron:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
		);
		assert_eq!(canonicalize_asset("USD"), "USD");
	}

	#[test]
	fn a_malformed_evm_asset_with_an_extra_separator_is_passed_through() {
		assert_eq!(canonicalize_asset("evm:0xabc:def"), "evm:0xabc:def");
	}

	#[test]
	fn an_empty_evm_address_body_keeps_its_prefix() {
		assert_eq!(canonicalize_asset("evm:0x"), "evm:0x");
	}

	#[test]
	fn a_single_evm_asset_canonicalizes_its_casing() {
		let asset = AssetOrPair::from("evm:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
		assert_eq!(asset.to_canonical_value(), json!(CHECKSUMMED));
	}

	#[test]
	fn a_pair_canonicalizes_each_evm_leg() {
		let pair =
			AssetOrPair::Pair { from: "evm:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".into(), to: "USD".into() };
		assert_eq!(pair.to_pair_value(), json!({ "from": CHECKSUMMED, "to": "USD" }));
	}
}

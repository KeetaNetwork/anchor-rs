//! Asset-location values and their canonical string form.
//!
//! An asset location names *where* value sits: a chain (Keeta/EVM/Solana/
//! Bitcoin/Tron), a bank account, or a mobile wallet. The canonical string form
//! (`chain:evm:100`, `bank-account:CHECKING`, ...) is the byte-exact shape the
//! anchor signs and sends.

use alloc::string::{String, ToString};
use core::fmt::{self, Display};
use core::str::FromStr;

use crate::error::ResolverError;

/// A chain a location can name. Keeta/EVM identify by a non-negative integer;
/// Solana/Bitcoin/Tron by a validated string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainLocation {
	/// A Keeta network, identified by its non-negative integer network id.
	Keeta {
		/// The network id (decimal digits; a `bigint` on the wire).
		network_id: String,
	},
	/// An EVM network, identified by its non-negative integer chain id.
	Evm {
		/// The chain id (decimal digits; a `bigint` on the wire).
		chain_id: String,
	},
	/// A Solana cluster, identified by its base58 genesis hash.
	Solana {
		/// The 43/44-char base58 genesis hash.
		genesis_hash: String,
	},
	/// A Bitcoin network, identified by its 4-byte (8 hex chars) magic bytes.
	Bitcoin {
		/// The 8-hex-char magic bytes.
		magic_bytes: String,
	},
	/// A Tron network, identified by its human-readable alias.
	Tron {
		/// `mainnet`, `shasta`, `nile`, or `custom:<name>`.
		network_alias: String,
	},
}

/// Where an asset sits: a chain, a bank account, or a mobile wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetLocation {
	/// A blockchain location.
	Chain(ChainLocation),
	/// A bank account, identified by its account type (e.g. `CHECKING`).
	BankAccount {
		/// The bank account type.
		account_type: String,
	},
	/// A mobile wallet, identified by its account type.
	MobileWallet {
		/// The mobile wallet account type.
		account_type: String,
	},
}

impl AssetLocation {
	/// The canonical string form the anchor signs and sends.
	pub fn to_canonical(&self) -> String {
		self.to_string()
	}
}

impl Display for AssetLocation {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Chain(ChainLocation::Keeta { network_id }) => write!(formatter, "chain:keeta:{network_id}"),
			Self::Chain(ChainLocation::Evm { chain_id }) => write!(formatter, "chain:evm:{chain_id}"),
			Self::Chain(ChainLocation::Solana { genesis_hash }) => write!(formatter, "chain:solana:{genesis_hash}"),
			Self::Chain(ChainLocation::Bitcoin { magic_bytes }) => write!(formatter, "chain:bitcoin:{magic_bytes}"),
			Self::Chain(ChainLocation::Tron { network_alias }) => write!(formatter, "chain:tron:{network_alias}"),
			Self::BankAccount { account_type } => write!(formatter, "bank-account:{account_type}"),
			Self::MobileWallet { account_type } => write!(formatter, "mobile-wallet:{account_type}"),
		}
	}
}

impl FromStr for AssetLocation {
	type Err = ResolverError;

	fn from_str(input: &str) -> Result<Self, Self::Err> {
		let (kind, rest) = input.split_once(':').ok_or(FIELD)?;
		match kind {
			"chain" => Ok(Self::Chain(parse_chain(rest)?)),
			"bank-account" => Ok(Self::BankAccount { account_type: non_empty(rest)? }),
			"mobile-wallet" => Ok(Self::MobileWallet { account_type: non_empty(rest)? }),
			_ => Err(FIELD),
		}
	}
}

/// The location field error, shared by every malformed-location case.
const FIELD: ResolverError = ResolverError::Field { field: "assetLocation" };

/// Parse the `<chainType>:<id>` tail of a `chain:` location.
fn parse_chain(rest: &str) -> Result<ChainLocation, ResolverError> {
	let (chain_type, id) = rest.split_once(':').ok_or(FIELD)?;
	if id.is_empty() || id.contains(':') {
		return Err(FIELD);
	}

	match chain_type {
		"keeta" => Ok(ChainLocation::Keeta { network_id: non_negative_integer(id)? }),
		"evm" => Ok(ChainLocation::Evm { chain_id: non_negative_integer(id)? }),
		"solana" => Ok(ChainLocation::Solana { genesis_hash: solana_genesis_hash(id)? }),
		"bitcoin" => Ok(ChainLocation::Bitcoin { magic_bytes: bitcoin_magic_bytes(id)? }),
		"tron" => Ok(ChainLocation::Tron { network_alias: tron_network_alias(id)? }),
		_ => Err(FIELD),
	}
}

/// Accept a non-empty component, rejecting an empty one.
fn non_empty(value: &str) -> Result<String, ResolverError> {
	match value.is_empty() {
		true => Err(FIELD),
		false => Ok(value.to_string()),
	}
}

/// Accept a non-negative decimal integer (`bigint`-valued keeta/evm id).
fn non_negative_integer(value: &str) -> Result<String, ResolverError> {
	match !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
		true => Ok(value.to_string()),
		false => Err(FIELD),
	}
}

/// Validate a Solana genesis hash: 43/44 base58 characters.
fn solana_genesis_hash(value: &str) -> Result<String, ResolverError> {
	let length_ok = matches!(value.len(), 43 | 44);
	let charset_ok = value.bytes().all(is_base58);
	match length_ok && charset_ok {
		true => Ok(value.to_string()),
		false => Err(FIELD),
	}
}

/// Whether `byte` is a Bitcoin/Solana base58 character (no `0OIl`).
fn is_base58(byte: u8) -> bool {
	matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

/// Validate Bitcoin magic bytes: 8 hex characters (4 bytes).
fn bitcoin_magic_bytes(value: &str) -> Result<String, ResolverError> {
	match value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
		true => Ok(value.to_string()),
		false => Err(FIELD),
	}
}

/// Validate a Tron network alias: a known alias or `custom:<name>`.
fn tron_network_alias(value: &str) -> Result<String, ResolverError> {
	let known = matches!(value, "mainnet" | "shasta" | "nile");
	let custom = value
		.strip_prefix("custom:")
		.is_some_and(|name| !name.is_empty());
	match known || custom {
		true => Ok(value.to_string()),
		false => Err(FIELD),
	}
}

/// The canonical string for an already-string location input.
pub fn canonicalize_location(input: impl Into<String>) -> String {
	input.into()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn evm_location_round_trips_through_its_canonical_string() {
		let parsed = AssetLocation::from_str("chain:evm:100").expect("valid evm location");
		assert_eq!(parsed, AssetLocation::Chain(ChainLocation::Evm { chain_id: "100".into() }));
		assert_eq!(parsed.to_canonical(), "chain:evm:100");
	}

	#[test]
	fn keeta_location_round_trips() {
		let parsed = AssetLocation::from_str("chain:keeta:0").expect("valid keeta location");
		assert_eq!(parsed.to_canonical(), "chain:keeta:0");
	}

	#[test]
	fn bank_and_mobile_locations_carry_their_account_type() {
		let bank = AssetLocation::from_str("bank-account:CHECKING").expect("valid bank location");
		let mobile = AssetLocation::from_str("mobile-wallet:MPESA").expect("valid mobile location");
		assert_eq!(bank, AssetLocation::BankAccount { account_type: "CHECKING".into() });
		assert_eq!(mobile, AssetLocation::MobileWallet { account_type: "MPESA".into() });
	}

	#[test]
	fn tron_accepts_known_and_custom_aliases() {
		assert!(AssetLocation::from_str("chain:tron:mainnet").is_ok());
		assert!(AssetLocation::from_str("chain:tron:custom:my-net").is_err());
	}

	#[test]
	fn a_negative_evm_id_is_rejected() {
		assert!(AssetLocation::from_str("chain:evm:-1").is_err());
	}

	#[test]
	fn bitcoin_magic_bytes_must_be_eight_hex_chars() {
		assert!(AssetLocation::from_str("chain:bitcoin:0b110907").is_ok());
		assert!(AssetLocation::from_str("chain:bitcoin:zzzz").is_err());
	}

	#[test]
	fn an_unknown_kind_is_rejected() {
		assert!(AssetLocation::from_str("galaxy:andromeda").is_err());
	}
}

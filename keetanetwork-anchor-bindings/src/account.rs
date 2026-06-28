//! Account algorithm mapping and construction shared across binding boundaries.
//!
//! The canonical algorithm names ([`CRYPTO_ALGORITHMS`]) are the transport identifiers
//! every host language and the TypeScript reference agree on; they are distinct
//! from the curve names in `keetanetwork-crypto`.

use alloc::format;
use alloc::vec::Vec;

use keetanetwork_account::{
	Account, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair, KeyPairType,
	Keyable,
};

use crate::error::CodedError;

/// Code rejecting an unknown signing algorithm.
pub const INVALID_ALGORITHM: &str = "INVALID_ALGORITHM";
/// Code for a seed that does not derive an account.
pub const INVALID_SEED: &str = "INVALID_SEED";

/// Canonical map from algorithm name to crypto key type.
pub const CRYPTO_ALGORITHMS: [(&str, KeyPairType); 3] = [
	("ed25519", KeyPairType::ED25519),
	("ecdsa_secp256k1", KeyPairType::ECDSASECP256K1),
	("ecdsa_secp256r1", KeyPairType::ECDSASECP256R1),
];

/// The algorithm name for `key_type`, or `"other"` for identifier accounts.
pub fn algorithm_name(key_type: KeyPairType) -> &'static str {
	CRYPTO_ALGORITHMS
		.iter()
		.find_map(|(name, candidate)| (*candidate == key_type).then_some(*name))
		.unwrap_or("other")
}

/// The coded error rejecting an unknown algorithm, naming the accepted set.
pub fn invalid_algorithm() -> CodedError {
	let names: Vec<&str> = CRYPTO_ALGORITHMS.iter().map(|(name, _)| *name).collect();
	CodedError::new(INVALID_ALGORITHM, format!("algorithm must be one of: {}", names.join(", ")))
}

/// Construct a [`GenericAccount`] from `keyable` for the named `algorithm`.
///
/// Use this where the key type is dynamic (offline signing/address derivation);
/// [`account_from_seed`] keeps the static key type for the generic clients.
///
/// # Errors
///
/// Returns [`INVALID_ALGORITHM`] for an unknown algorithm, or an `ACCOUNT` error
/// when the key material does not yield an account.
pub fn from_keyable(keyable: Keyable, algorithm: &str) -> Result<GenericAccount, CodedError> {
	let account = match algorithm {
		"ed25519" => Account::<KeyED25519>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ED25519))
			.map(GenericAccount::Ed25519),
		"ecdsa_secp256k1" => {
			Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256K1))
				.map(GenericAccount::EcdsaSecp256k1)
		}
		"ecdsa_secp256r1" => {
			Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256R1))
				.map(GenericAccount::EcdsaSecp256r1)
		}
		_ => return Err(invalid_algorithm()),
	};

	account.map_err(|error| CodedError::new("ACCOUNT", error.as_ref()))
}

/// Derive a statically-typed [`Account`] from a 32-byte hex `seed` at `index`.
///
/// The concrete key type `K` selects the algorithm, so a caller dispatching over
/// a generic client (e.g. the WASI KYC component) picks `K` and reuses this.
///
/// # Errors
///
/// Returns [`INVALID_SEED`] when `seed` is not a 32-byte hex string or the key
/// cannot be derived.
pub fn account_from_seed<K>(seed: &str, index: u32) -> Result<Account<K>, CodedError>
where
	K: KeyPair,
{
	let keyable = Keyable::from((seed, index));
	let accountable = Accountable::KeyAndType(keyable, K::KEY_PAIR_TYPE);
	let account =
		Account::<K>::try_from(accountable).map_err(|_| CodedError::new(INVALID_SEED, "seed must be 32-byte hex"))?;
	Ok(account)
}

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_account::account::AccountSigner;

	/// A deterministic 32-byte hex seed.
	const SEED: &str = "0011223344556677889900112233445566778899001122334455667788990011";

	#[test]
	fn algorithm_names_round_trip_every_crypto_type() {
		for (name, key_type) in CRYPTO_ALGORITHMS {
			assert_eq!(algorithm_name(key_type), name);
		}
	}

	#[test]
	fn identifier_types_report_other() {
		assert_eq!(algorithm_name(KeyPairType::TOKEN), "other");
	}

	#[test]
	fn from_keyable_builds_and_signs_for_every_algorithm() {
		for (name, _) in CRYPTO_ALGORITHMS {
			let account = from_keyable(Keyable::from((SEED, 0)), name);
			assert!(matches!(&account, Ok(built) if built.to_string().starts_with("keeta_")));

			let signature = account.and_then(|built| {
				built
					.sign(b"message", None)
					.map_err(|error| CodedError::new("SIGN", error.as_ref()))
			});
			assert!(matches!(signature, Ok(bytes) if !bytes.is_empty()));
		}
	}

	#[test]
	fn from_keyable_rejects_an_unknown_algorithm() {
		let result = from_keyable(Keyable::from((SEED, 0)), "rsa");
		assert!(matches!(result, Err(error) if error.code == INVALID_ALGORITHM));
	}

	#[test]
	fn account_from_seed_derives_a_stable_typed_account() {
		let first = account_from_seed::<KeyED25519>(SEED, 0);
		let again = account_from_seed::<KeyED25519>(SEED, 0);
		assert!(matches!((first, again), (Ok(a), Ok(b)) if a.to_string() == b.to_string()));
	}

	#[test]
	fn account_from_seed_rejects_a_malformed_seed() {
		let result = account_from_seed::<KeyED25519>("not-hex", 0);
		assert!(matches!(result, Err(error) if error.code == INVALID_SEED));
	}
}

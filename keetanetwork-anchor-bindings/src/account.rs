//! Account algorithm mapping, construction, and anchor-specific derivation.

use alloc::format;
use alloc::vec::Vec;

use keetanetwork_account::{Account, Accountable, KeyPair, Keyable};

use crate::error::CodedError;

pub use keetanetwork_bindings::account::{algorithm_name, from_keyable, CRYPTO_ALGORITHMS};

/// Code rejecting an unknown signing algorithm.
pub const INVALID_ALGORITHM: &str = "INVALID_ALGORITHM";
/// Code for a seed that does not derive an account.
pub const INVALID_SEED: &str = "INVALID_SEED";

/// The coded error rejecting an unknown algorithm, naming the accepted set.
pub fn invalid_algorithm() -> CodedError {
	let names: Vec<&str> = CRYPTO_ALGORITHMS.iter().map(|(name, _)| *name).collect();
	CodedError::new(INVALID_ALGORITHM, format!("algorithm must be one of: {}", names.join(", ")))
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
	use keetanetwork_account::KeyED25519;

	use super::*;

	/// A deterministic 32-byte hex seed.
	const SEED: &str = "0011223344556677889900112233445566778899001122334455667788990011";

	#[test]
	fn invalid_algorithm_names_the_accepted_set() {
		let error = invalid_algorithm();
		assert_eq!(error.code, INVALID_ALGORITHM);
		assert!(error.message.contains("ed25519"));
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

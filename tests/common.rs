#![allow(dead_code)]

use std::convert::TryFrom;

use accounts::{Account, Accountable, IntoSecret, Keyable, Seed};

/// Test data from TypeScript test
pub const TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

/// Helper function to create a test seed array.
pub fn create_test_seed_array() -> Seed {
	let seed_bytes = hex::decode(TEST_SEED).unwrap();

	let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();
	seed_array.into_secret()
}

/// Helper function to create an account from seed for different key types.
pub fn create_account_from_seed<T>(index: u32) -> Account<T>
where
	T: accounts::KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = accounts::AccountError>,
{
	let seed_array = create_test_seed_array();
	let seed = Keyable::Seed((seed_array, index));

	let accountable = Accountable::KeyAndType(seed, T::KEY_PAIR_TYPE);
	Account::<T>::try_from(accountable).unwrap()
}

/// Helper function to create a public key only account (no private key).
pub fn create_public_key_only_account<T>(full_account: &Account<T>) -> Account<T>
where
	T: accounts::KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = accounts::AccountError>,
{
	let public_key_string = full_account.keypair.to_public_key_string();
	let keyable = Keyable::PublicKeyString(public_key_string);

	let accountable = Accountable::KeyAndType(keyable, T::KEY_PAIR_TYPE);
	Account::<T>::try_from(accountable).unwrap()
}

//! Account Creation Example
//!
//! This example demonstrates creating accounts from seeds.
//! This is a basic building block for certificate creation.

use keetanetwork_account::{Account, AccountPublicKey, Accountable, KeyECDSASECP256K1, KeyPair, Keyable};
use keetanetwork_crypto::prelude::IntoSecret;

const TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

/// Main function to demonstrate account creation
fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Step 1: Create an issuer account from a seed
	let issuer_account = create_account_from_seed(TEST_SEED, 0)?;
	let public_key = issuer_account.keypair.to_public_key_string()?;
	println!("Public key: {public_key}");

	// Step 2: Create a subject account (different index)
	let subject_account = create_account_from_seed(TEST_SEED, 1)?;
	let subject_public_key = subject_account.keypair.to_public_key_string()?;
	println!("Public key: {subject_public_key}");

	Ok(())
}

/// Helper function to create an account from a hex seed string
fn create_account_from_seed(
	seed_hex: &str,
	index: u32,
) -> Result<Account<KeyECDSASECP256K1>, Box<dyn std::error::Error>> {
	// Use the HexSeed variant directly - much cleaner!
	let seed_secret = seed_hex.to_string().into_secret();
	let keyable = Keyable::HexSeed((seed_secret, index));
	let accountable = Accountable::KeyAndType(keyable, KeyECDSASECP256K1::KEY_PAIR_TYPE);
	let account = Account::<KeyECDSASECP256K1>::try_from(accountable)?;

	Ok(account)
}

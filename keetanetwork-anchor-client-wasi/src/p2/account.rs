//! The `crypto` account resource of the P2 component.

use keetanetwork_bindings::account as account_ops;

use super::certificate::CertificateResource;
use super::exports::keeta::client::crypto::{Account as WitAccount, Guest as CryptoGuest, GuestAccount};
use super::{AccountRef, CodedError, Component};

/// A signing or read-only account, stored erased over its algorithm.
pub(crate) struct AccountResource {
	pub(crate) account: AccountRef,
}

impl CryptoGuest for Component {
	type Account = AccountResource;
	type Certificate = CertificateResource;
}

impl GuestAccount for AccountResource {
	fn from_seed(seed: String, index: u32, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_seed(&seed, index, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_private_key(key: String, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_private_key(&key, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_passphrase(words: Vec<String>, index: u32, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_passphrase(words, index, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_public_key(key: String, algorithm: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_public_key(&key, &algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_address(address: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_address(&address)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn generate_seed() -> String {
		account_ops::generate_seed().unwrap_or_default()
	}

	fn generate_passphrase() -> Vec<String> {
		account_ops::generate_passphrase().unwrap_or_default()
	}

	fn address(&self) -> String {
		account_ops::account_address(&self.account)
	}

	fn algorithm(&self) -> String {
		account_ops::account_algorithm(&self.account)
	}

	fn public_key(&self) -> String {
		account_ops::account_public_key(&self.account)
	}

	fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(account_ops::account_sign(&self.account, &message)?)
	}

	fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
		account_ops::account_verify(&self.account, &message, &signature)
	}

	fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(account_ops::account_encrypt(&self.account, &plaintext)?)
	}

	fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(account_ops::account_decrypt(&self.account, &ciphertext)?)
	}
}

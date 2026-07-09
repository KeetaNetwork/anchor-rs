//! The `crypto` account resource of the P2 component.

use keetanetwork_account::{AccountPublicKey, KeyPairType};
use keetanetwork_bindings::account as account_ops;

use super::certificate::CertificateResource;
use super::exports::keeta::client::crypto::{Account as WitAccount, Guest as CryptoGuest, GuestAccount};
use super::keeta::client::types::{
	AccountKind as WitAccountKind, IdentifierKind as WitIdentifierKind, KeyAlgorithm as WitKeyAlgorithm,
};
use super::{AccountRef, CodedError, Component};

/// A signing or read-only account, stored erased over its algorithm.
pub(crate) struct AccountResource {
	pub(crate) account: AccountRef,
}

impl CryptoGuest for Component {
	type Account = AccountResource;
	type Certificate = CertificateResource;
}

/// The canonical name of a signing algorithm, as understood by the shared
/// account constructors.
fn algorithm_name(algorithm: WitKeyAlgorithm) -> &'static str {
	match algorithm {
		WitKeyAlgorithm::Ed25519 => "ed25519",
		WitKeyAlgorithm::EcdsaSecp256k1 => "ecdsa_secp256k1",
		WitKeyAlgorithm::EcdsaSecp256r1 => "ecdsa_secp256r1",
	}
}

impl GuestAccount for AccountResource {
	fn from_seed(seed: String, index: u32, algorithm: Option<WitKeyAlgorithm>) -> Result<WitAccount, CodedError> {
		let algorithm = algorithm.map_or(account_ops::DEFAULT_ALGORITHM, algorithm_name);
		let account = account_ops::account_from_seed(&seed, index, algorithm)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_private_key(key: String, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_private_key(&key, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_passphrase(words: Vec<String>, index: u32, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_passphrase(words, index, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_public_key(key: String, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_public_key(&key, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_public_key_string(public_key_string: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_public_key_string(&public_key_string)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_public_key_and_type(key_and_type: String) -> Result<WitAccount, CodedError> {
		let account = account_ops::account_from_public_key_and_type(&key_and_type)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn generate_seed() -> String {
		account_ops::generate_seed().unwrap_or_default()
	}

	fn generate_passphrase() -> Vec<String> {
		account_ops::generate_passphrase().unwrap_or_default()
	}

	fn public_key_string(&self) -> String {
		account_ops::account_public_key_string(&self.account)
	}

	fn kind(&self) -> WitAccountKind {
		match self.account.to_keypair_type() {
			KeyPairType::ED25519 => WitAccountKind::Signing(WitKeyAlgorithm::Ed25519),
			KeyPairType::ECDSASECP256K1 => WitAccountKind::Signing(WitKeyAlgorithm::EcdsaSecp256k1),
			KeyPairType::ECDSASECP256R1 => WitAccountKind::Signing(WitKeyAlgorithm::EcdsaSecp256r1),
			KeyPairType::NETWORK => WitAccountKind::Identifier(WitIdentifierKind::Network),
			KeyPairType::TOKEN => WitAccountKind::Identifier(WitIdentifierKind::Token),
			KeyPairType::STORAGE => WitAccountKind::Identifier(WitIdentifierKind::Storage),
			KeyPairType::MULTISIG => WitAccountKind::Identifier(WitIdentifierKind::Multisig),
		}
	}

	fn public_key(&self) -> String {
		account_ops::account_public_key(&self.account)
	}

	fn public_key_and_type_string(&self) -> String {
		account_ops::account_public_key_and_type_string(&self.account)
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

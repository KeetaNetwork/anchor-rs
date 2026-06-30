//! Hybrid-encrypted, optionally-signed data containers.
//!
//! An [`EncryptedContainer`] holds a payload that is always zlib-compressed and
//! either left as plaintext or sealed to a set of principals. Each principal
//! gets the AES-256 body key wrapped to its own public key, so any one of them
//! can open the container while the body is stored once. An optional detached
//! signature (RFC 5652 `SignerInfo`) covers the compressed bytes and stays
//! valid across decryption and re-encryption.
//!
//! # Examples
//!
//! Plaintext round-trip with no principals:
//!
//! ```
//! use keetanetwork_anchor::encrypted_container::EncryptedContainer;
//!
//! let mut container = EncryptedContainer::from_plaintext(b"hello".to_vec(), None, Default::default());
//! let encoded = container.get_encoded()?;
//!
//! let mut restored = EncryptedContainer::from_encoded(&encoded, None)?;
//! assert_eq!(restored.get_plaintext()?, b"hello");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Seal to a principal and reopen:
//!
//! ```
//! # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
//! use keetanetwork_anchor::encrypted_container::EncryptedContainer;
//!
//! # let alice = create_secp256k1_generic_account(Some(0));
//! let mut sealed = EncryptedContainer::from_plaintext(b"secret".to_vec(), Some(vec![alice]), Default::default());
//! let encoded = sealed.get_encoded()?;
//!
//! # let alice_again = create_secp256k1_generic_account(Some(0));
//! let mut opened = EncryptedContainer::from_encrypted(&encoded, vec![alice_again])?;
//! assert_eq!(opened.get_plaintext()?, b"secret");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod codec;
pub mod error;

use alloc::vec::Vec;

use keetanetwork_account::account::AccountPublicKey;
use keetanetwork_account::GenericAccount;

use crate::encrypted_container::codec::{BareContainer, CipherMaterial, Encryption};
use crate::encrypted_container::error::Result;
use crate::generated::SignerInfo;

pub use crate::encrypted_container::error::EncryptedContainerError;
pub use crate::encrypted_container::error::EncryptedContainerError as Error;

/// Options for [`EncryptedContainer::from_plaintext`].
#[derive(Debug, Default)]
pub struct FromPlaintextOptions {
	/// When set, overrides the default plaintext-access policy. The default
	/// locks plaintext access for encrypted containers and leaves it open for
	/// plaintext containers.
	pub locked: Option<bool>,
	/// An account whose detached signature is attached when the container is
	/// encoded.
	pub signer: Option<GenericAccount>,
}

/// A hybrid-encrypted, optionally-signed data container.
///
/// Plaintext and encoded forms are computed lazily and cached. Mutating access
/// (granting, revoking, replacing the plaintext) invalidates the cached encoded
/// form so the next [`EncryptedContainer::get_encoded`] reflects the change.
#[derive(Debug)]
pub struct EncryptedContainer {
	encrypted: bool,
	principals: Vec<GenericAccount>,
	may_access_plaintext: bool,
	signer: Option<GenericAccount>,
	parsed_signer_info: Option<SignerInfo>,
	plaintext: Option<Vec<u8>>,
	encoded: Option<Vec<u8>>,
}

impl EncryptedContainer {
	fn new(principals: Option<Vec<GenericAccount>>, signer: Option<GenericAccount>) -> Self {
		let encrypted = principals.is_some();
		Self {
			encrypted,
			principals: principals.unwrap_or_default(),
			may_access_plaintext: true,
			signer,
			parsed_signer_info: None,
			plaintext: Some(Vec::new()),
			encoded: None,
		}
	}

	/// Build a container from plaintext.
	///
	/// A `Some` principal set seals the payload to those accounts; `None`
	/// leaves it as plaintext. By default an encrypted container disables
	/// direct plaintext access on this instance; override with
	/// [`FromPlaintextOptions::locked`].
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let mut container = EncryptedContainer::from_plaintext(b"hi".to_vec(), None, Default::default());
	/// assert!(!container.is_encrypted());
	/// assert_eq!(container.get_plaintext()?, b"hi");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn from_plaintext(
		data: impl Into<Vec<u8>>,
		principals: Option<Vec<GenericAccount>>,
		options: FromPlaintextOptions,
	) -> Self {
		let encrypted = principals.is_some();
		let mut container = Self::new(principals, options.signer);
		let locked = options.locked.unwrap_or(encrypted);
		if locked {
			container.disable_plaintext();
		}

		container.set_plaintext(data);
		container
	}

	/// Build a container from an encoded blob that may be plaintext or
	/// encrypted.
	///
	/// The container's encryption state follows the blob: a plaintext blob
	/// clears the principal set, an encrypted blob keeps it. Provided
	/// principals are matched against the blob's key stores so private keys are
	/// retained for later decryption.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::UnsupportedVersion`] -- unknown container version.
	/// - [`EncryptedContainerError::UnsupportedCipherAlgorithm`] -- unknown body cipher.
	/// - [`EncryptedContainerError::InvalidPrincipals`] -- the blob is encrypted but no principals were supplied.
	/// - [`EncryptedContainerError::Asn1Error`] -- the blob is not well-formed DER.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let mut source = EncryptedContainer::from_plaintext(b"note".to_vec(), None, Default::default());
	/// let encoded = source.get_encoded()?;
	///
	/// let mut restored = EncryptedContainer::from_encoded(&encoded, None)?;
	/// assert_eq!(restored.get_plaintext()?, b"note");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn from_encoded(data: impl AsRef<[u8]>, principals: Option<Vec<GenericAccount>>) -> Result<Self> {
		let mut container = Self::new(principals, None);
		container.set_encoded(data);
		container.compute_and_set_key_info(false)?;

		Ok(container)
	}

	/// Build a container from a blob that must be encrypted.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::EncryptionRequired`] -- the blob is plaintext.
	/// - Otherwise as [`EncryptedContainer::from_encoded`].
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// # let principal = create_secp256k1_generic_account(Some(0));
	/// let mut sealed = EncryptedContainer::from_plaintext(b"secret".to_vec(), Some(vec![principal]), Default::default());
	/// let encoded = sealed.get_encoded()?;
	///
	/// # let principal_again = create_secp256k1_generic_account(Some(0));
	/// let mut opened = EncryptedContainer::from_encrypted(&encoded, vec![principal_again])?;
	/// assert_eq!(opened.get_plaintext()?, b"secret");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn from_encrypted(
		data: impl AsRef<[u8]>,
		principals: impl IntoIterator<Item = impl Into<GenericAccount>>,
	) -> Result<Self> {
		let principals = principals.into_iter().map(Into::into).collect();
		let mut container = Self::new(Some(principals), None);
		container.set_encoded(data);
		container.compute_and_set_key_info(true)?;

		Ok(container)
	}

	/// Replace the plaintext payload, invalidating any cached encoded form.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let mut container = EncryptedContainer::from_plaintext(b"old".to_vec(), None, Default::default());
	/// container.set_plaintext(b"new".to_vec());
	/// assert_eq!(container.get_plaintext()?, b"new");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn set_plaintext(&mut self, data: impl Into<Vec<u8>>) {
		self.plaintext = Some(data.into());
		self.encoded = None;
	}

	fn set_encoded(&mut self, data: impl AsRef<[u8]>) {
		self.encoded = Some(data.as_ref().to_vec());
		self.plaintext = None;
	}

	/// Disable direct plaintext access on this instance.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::encrypted_container::{EncryptedContainer, Error};
	///
	/// let mut container = EncryptedContainer::from_plaintext(b"hidden".to_vec(), None, Default::default());
	/// container.disable_plaintext();
	/// assert!(matches!(container.get_plaintext(), Err(Error::PlaintextDisabled)));
	/// ```
	pub fn disable_plaintext(&mut self) -> &mut Self {
		self.may_access_plaintext = false;
		self
	}

	/// Whether the container is sealed to a principal set.
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let plain = EncryptedContainer::from_plaintext(b"x".to_vec(), None, Default::default());
	/// assert!(!plain.is_encrypted());
	///
	/// # let principal = create_secp256k1_generic_account(Some(0));
	/// let sealed = EncryptedContainer::from_plaintext(b"x".to_vec(), Some(vec![principal]), Default::default());
	/// assert!(sealed.is_encrypted());
	/// ```
	pub fn is_encrypted(&self) -> bool {
		self.encrypted
	}

	/// Whether a signer is attached or a signature is present.
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
	///
	/// # let signer = create_secp256k1_generic_account(Some(0));
	/// let options = FromPlaintextOptions { locked: None, signer: Some(signer) };
	/// let container = EncryptedContainer::from_plaintext(b"x".to_vec(), None, options);
	/// assert!(container.is_signed());
	/// ```
	pub fn is_signed(&self) -> bool {
		self.signer.is_some() || self.parsed_signer_info.is_some()
	}

	/// The accounts that can open this container.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::AccessManagementNotAllowed`] -- the container is plaintext.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let principal = create_secp256k1_generic_account(Some(0));
	/// let sealed = EncryptedContainer::from_plaintext(b"x".to_vec(), Some(vec![principal]), Default::default());
	/// assert_eq!(sealed.principals()?.len(), 1);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn principals(&self) -> Result<&[GenericAccount]> {
		if !self.encrypted {
			return Err(EncryptedContainerError::AccessManagementNotAllowed);
		}

		Ok(&self.principals)
	}

	/// Return the decrypted, decompressed plaintext.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::PlaintextDisabled`] -- plaintext access was disabled.
	/// - [`EncryptedContainerError::NoMatchingKey`] -- no supplied principal can decrypt.
	/// - [`EncryptedContainerError::DecompressionFailed`] -- the body is not valid zlib.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let mut container = EncryptedContainer::from_plaintext(b"data".to_vec(), None, Default::default());
	/// assert_eq!(container.get_plaintext()?, b"data");
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn get_plaintext(&mut self) -> Result<Vec<u8>> {
		if !self.may_access_plaintext {
			return Err(EncryptedContainerError::PlaintextDisabled);
		}

		self.compute_plaintext()?;

		let plaintext = self
			.plaintext
			.clone()
			.ok_or(EncryptedContainerError::NoPlaintextAvailable)?;

		Ok(plaintext)
	}

	/// Return the DER-encoded container, computing it from the plaintext when
	/// not already cached.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::NoPlaintextAvailable`] -- nothing to encode.
	/// - [`EncryptedContainerError::EncryptionRequired`] -- encrypted with an empty principal set.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor::encrypted_container::EncryptedContainer;
	///
	/// let mut container = EncryptedContainer::from_plaintext(b"data".to_vec(), None, Default::default());
	/// let encoded = container.get_encoded()?;
	/// assert!(!encoded.is_empty());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn get_encoded(&mut self) -> Result<Vec<u8>> {
		self.compute_encoded()?;

		let encoded = self
			.encoded
			.clone()
			.ok_or(EncryptedContainerError::NoEncodedDataAvailable)?;

		Ok(encoded)
	}

	/// Grant the given accounts access, invalidating the cached encoded form.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::AccessManagementNotAllowed`] -- the container is plaintext.
	/// - Decryption errors from materializing the plaintext first.
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
	///
	/// # let owner = create_secp256k1_generic_account(Some(0));
	/// let options = FromPlaintextOptions { locked: Some(false), signer: None };
	/// let mut container = EncryptedContainer::from_plaintext(b"shared".to_vec(), Some(vec![owner]), options);
	///
	/// # let reader = create_secp256k1_generic_account(Some(1));
	/// container.grant_access(vec![reader])?;
	/// assert_eq!(container.principals()?.len(), 2);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn grant_access(&mut self, accounts: impl IntoIterator<Item = impl Into<GenericAccount>>) -> Result<&mut Self> {
		self.compute_plaintext()?;
		self.assert_access_management_allowed()?;
		self.encoded = None;
		self.principals.extend(accounts.into_iter().map(Into::into));

		Ok(self)
	}

	/// Revoke the account identified by its type-prefixed public key,
	/// invalidating the cached encoded form.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::AccessManagementNotAllowed`] -- the container is plaintext.
	/// - Decryption errors from materializing the plaintext first.
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_account::AccountPublicKey;
	/// use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
	///
	/// # let owner = create_secp256k1_generic_account(Some(0));
	/// # let reader = create_secp256k1_generic_account(Some(1));
	/// let options = FromPlaintextOptions { locked: Some(false), signer: None };
	/// let mut container = EncryptedContainer::from_plaintext(b"shared".to_vec(), Some(vec![owner, reader]), options);
	///
	/// let reader_key = create_secp256k1_generic_account(Some(1)).to_public_key_with_type();
	/// container.revoke_access(&reader_key)?;
	/// assert_eq!(container.principals()?.len(), 1);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn revoke_access(&mut self, public_key_and_type: impl AsRef<[u8]>) -> Result<&mut Self> {
		self.compute_plaintext()?;
		self.assert_access_management_allowed()?;
		self.encoded = None;

		let target = public_key_and_type.as_ref();
		self.principals.retain(|principal| {
			let principal_key = principal.to_public_key_with_type();
			principal_key.as_slice() != target
		});

		Ok(self)
	}

	/// The signing account, reconstructed from the attached signer or parsed signature.
	/// This does not return the private keyed account, use [`signer`](Self::signer) instead.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::AccountError`] -- the stored public key is not a valid account.
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
	///
	/// # let signer = create_secp256k1_generic_account(Some(0));
	/// let options = FromPlaintextOptions { locked: None, signer: Some(signer) };
	/// let container = EncryptedContainer::from_plaintext(b"x".to_vec(), None, options);
	/// assert!(container.signing_account()?.is_some());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn signing_account(&self) -> Result<Option<GenericAccount>> {
		if let Some(signer) = &self.signer {
			let public_key = signer.to_public_key_with_type();
			let account = codec::account_from_public_key(&public_key)?;
			return Ok(Some(account));
		}
		if let Some(signer_info) = &self.parsed_signer_info {
			let account = codec::account_from_public_key(signer_info.sid.as_ref())?;
			return Ok(Some(account));
		}

		Ok(None)
	}

	/// Borrow the attached signer with its private key intact.
	///
	/// This is the non-consuming counterpart to
	/// [`signing_account`](Self::signing_account): it returns the signer exactly
	/// as supplied (private key included) without cloning or moving it. Returns
	/// `None` when the container carries only a parsed signature, since no
	/// private key is recoverable from encoded bytes.
	pub fn signer(&self) -> Option<&GenericAccount> {
		self.signer.as_ref()
	}

	/// Move the attached signer out, downgrading the container to its
	/// public-only identity.
	///
	/// Unlike [`signing_account`](Self::signing_account), which only ever yields
	/// a public-only account, this returns the original signer with its private
	/// key intact and leaves a public-only account in its place.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::AccountError`] -- the signer's public key is not valid.
	pub fn take_signing_account(&mut self) -> Result<Option<GenericAccount>> {
		let Some(signer) = self.signer.take() else {
			return Ok(None);
		};

		let public_only = codec::account_from_public_key(&signer.to_public_key_with_type())?;

		self.signer = Some(public_only);

		Ok(Some(signer))
	}

	/// Verify the detached signature over the compressed payload.
	///
	/// # Errors
	///
	/// - [`EncryptedContainerError::NotSigned`] -- no signature is present.
	/// - [`EncryptedContainerError::UnsupportedDigestAlgorithm`] / [`EncryptedContainerError::UnsupportedSignatureAlgorithm`].
	/// - Decryption errors from materializing the compressed bytes.
	///
	/// # Examples
	///
	/// ```
	/// # use keetanetwork_anchor::doc_utils::create_secp256k1_generic_account;
	/// use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
	///
	/// # let signer = create_secp256k1_generic_account(Some(0));
	/// let options = FromPlaintextOptions { locked: None, signer: Some(signer) };
	/// let mut container = EncryptedContainer::from_plaintext(b"authentic".to_vec(), None, options);
	/// let encoded = container.get_encoded()?;
	///
	/// let mut restored = EncryptedContainer::from_encoded(&encoded, None)?;
	/// assert!(restored.verify_signature()?);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn verify_signature(&mut self) -> Result<bool> {
		self.ensure_signer_info_parsed()?;
		let signer_info = self
			.parsed_signer_info
			.clone()
			.ok_or(EncryptedContainerError::NotSigned)?;
		let compressed = self.compute_signed_compressed()?;

		codec::verify(&signer_info, &compressed)
	}

	fn assert_access_management_allowed(&self) -> Result<()> {
		if self.encrypted {
			Ok(())
		} else {
			Err(EncryptedContainerError::AccessManagementNotAllowed)
		}
	}

	/// Parse the encoded blob, align the encryption state and principal set with
	/// it, and capture any signer info.
	fn compute_and_set_key_info(&mut self, must_be_encrypted: bool) -> Result<BareContainer> {
		let encoded = self
			.encoded
			.as_ref()
			.ok_or(EncryptedContainerError::NoEncodedDataAvailable)?;
		let bare = codec::parse(encoded)?;

		if must_be_encrypted && !bare.is_encrypted() {
			return Err(EncryptedContainerError::EncryptionRequired);
		}

		match &bare.body {
			codec::ContainerBody::Encrypted(encrypted) => {
				if !self.encrypted {
					return Err(EncryptedContainerError::InvalidPrincipals);
				}

				let provided = core::mem::take(&mut self.principals);
				self.principals = merge_principals(&encrypted.key_stores, provided)?;
				self.encrypted = true;
			}
			codec::ContainerBody::Plaintext { .. } => {
				self.encrypted = false;
				self.principals.clear();
			}
		}

		if let Some(signer_info) = &bare.signer_info {
			self.parsed_signer_info = Some(signer_info.clone());
		}

		Ok(bare)
	}

	fn compute_plaintext(&mut self) -> Result<()> {
		if self.plaintext.is_some() {
			return Ok(());
		}

		let decoded = self.decode_from_encoded()?;
		self.plaintext = Some(decoded.plaintext);
		Ok(())
	}

	fn compute_signed_compressed(&mut self) -> Result<Vec<u8>> {
		let decoded = self.decode_from_encoded()?;
		Ok(decoded.compressed)
	}

	fn decode_from_encoded(&mut self) -> Result<codec::DecodedBody> {
		if self.encoded.is_none() {
			return Err(EncryptedContainerError::NoEncodedDataAvailable);
		}

		let bare = self.compute_and_set_key_info(self.encrypted)?;
		let principals: &[GenericAccount] = if bare.is_encrypted() {
			&self.principals
		} else {
			&[]
		};

		codec::decode_body(&bare.body, principals)
	}

	fn compute_encoded(&mut self) -> Result<()> {
		if self.encoded.is_some() {
			return Ok(());
		}

		let computed = if self.encrypted {
			self.encode_encrypted()?
		} else {
			self.encode_plaintext()?
		};

		self.encoded = Some(computed);
		Ok(())
	}

	fn encode_plaintext(&self) -> Result<Vec<u8>> {
		let plaintext = self
			.plaintext
			.as_ref()
			.ok_or(EncryptedContainerError::NoPlaintextAvailable)?;
		codec::encode(plaintext, None, self.signer.as_ref())
	}

	fn encode_encrypted(&self) -> Result<Vec<u8>> {
		let plaintext = self
			.plaintext
			.as_ref()
			.ok_or(EncryptedContainerError::NoPlaintextAvailable)?;
		if self.principals.is_empty() {
			return Err(EncryptedContainerError::EncryptionRequired);
		}

		let material = CipherMaterial::random()?;
		let encryption = Encryption { principals: &self.principals, material: &material };
		codec::encode(plaintext, Some(encryption), self.signer.as_ref())
	}

	fn ensure_signer_info_parsed(&mut self) -> Result<()> {
		let needs_parse = self.parsed_signer_info.is_none() && self.signer.is_some();
		if !needs_parse {
			return Ok(());
		}

		self.compute_encoded()?;

		let encoded = self
			.encoded
			.as_ref()
			.ok_or(EncryptedContainerError::NoEncodedDataAvailable)?;

		let bare = codec::parse(encoded)?;
		if let Some(signer_info) = bare.signer_info {
			self.parsed_signer_info = Some(signer_info);
		}

		Ok(())
	}
}

/// Rebuild the principal set from the blob's key stores, substituting any
/// provided account that matches so its private key is retained.
fn merge_principals(
	key_stores: &[crate::generated::KeyStore],
	provided: Vec<GenericAccount>,
) -> Result<Vec<GenericAccount>> {
	let mut remaining = provided;
	let mut merged = Vec::with_capacity(key_stores.len());
	for store in key_stores {
		let store_public_key = store.public_key.as_ref();
		let matching = remaining.iter().position(|principal| {
			let principal_key = principal.to_public_key_with_type();
			principal_key.as_slice() == store_public_key
		});

		match matching {
			Some(index) => merged.push(remaining.swap_remove(index)),
			None => merged.push(codec::account_from_public_key(store_public_key)?),
		}
	}

	Ok(merged)
}

#[cfg(test)]
mod tests {
	use alloc::vec;

	use keetanetwork_account::{Account, Accountable, KeyECDSASECP256K1, KeyPair, Keyable};
	use keetanetwork_crypto::prelude::IntoSecret;

	use super::*;

	const SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

	fn to_generic(account: Account<impl KeyPair>) -> GenericAccount {
		let private_key = account
			.keypair
			.take_private_key()
			.expect("test account holds a private key");

		GenericAccount::try_from(private_key).expect("generic account from private key")
	}

	/// A secp256k1 generic account derived from the fixed seed at `index`, so the
	/// same principal is reproducible for sealing and reopening.
	fn secp256k1(index: u32) -> GenericAccount {
		let keyable = Keyable::HexSeed((SEED.to_string().into_secret(), index));
		let accountable = Accountable::KeyAndType(keyable, KeyECDSASECP256K1::KEY_PAIR_TYPE);
		let account = Account::<KeyECDSASECP256K1>::try_from(accountable).expect("secp256k1 account");

		to_generic(account)
	}

	/// A container sealed to principal 0 under the default (locked) policy.
	fn sealed(payload: &[u8]) -> EncryptedContainer {
		let data = payload.to_vec();
		let principals = Some(vec![secp256k1(0)]);
		let options = FromPlaintextOptions::default();

		EncryptedContainer::from_plaintext(data, principals, options)
	}

	/// A plaintext container carrying an attached, private-keyed signer.
	fn signed(payload: &[u8]) -> EncryptedContainer {
		let options = FromPlaintextOptions { locked: Some(false), signer: Some(secp256k1(0)) };
		EncryptedContainer::from_plaintext(payload.to_vec(), None, options)
	}

	#[test]
	fn locked_encrypted_container_blocks_plaintext() {
		let mut container = sealed(b"top-secret");
		let outcome = container.get_plaintext();
		assert!(matches!(outcome, Err(EncryptedContainerError::PlaintextDisabled)));
	}

	#[test]
	fn principals_rejected_on_plaintext_container() {
		let container = EncryptedContainer::from_plaintext(b"x".to_vec(), None, FromPlaintextOptions::default());
		let outcome = container.principals();
		assert!(matches!(outcome, Err(EncryptedContainerError::AccessManagementNotAllowed)));
	}

	#[test]
	fn from_encoded_rejects_encrypted_blob_without_principals() -> core::result::Result<(), Box<dyn std::error::Error>>
	{
		let mut container = sealed(b"data");
		let encoded = container.get_encoded()?;
		let outcome = EncryptedContainer::from_encoded(&encoded, None);
		assert!(matches!(outcome, Err(EncryptedContainerError::InvalidPrincipals)));
		Ok(())
	}

	#[test]
	fn revoked_principal_loses_access_while_remaining_one_keeps_it(
	) -> core::result::Result<(), Box<dyn std::error::Error>> {
		let mut container = EncryptedContainer::from_plaintext(
			b"shared".to_vec(),
			Some(vec![secp256k1(0)]),
			FromPlaintextOptions { locked: Some(false), signer: None },
		);

		container.grant_access(vec![secp256k1(1)])?;
		assert_eq!(container.principals()?.len(), 2);

		let revoked_key = secp256k1(1).to_public_key_with_type();
		container.revoke_access(&revoked_key)?;
		assert_eq!(container.principals()?.len(), 1);

		let encoded = container.get_encoded()?;
		let mut reopened = EncryptedContainer::from_encrypted(&encoded, vec![secp256k1(0)])?;
		assert_eq!(reopened.get_plaintext()?, b"shared");
		Ok(())
	}

	#[test]
	fn signer_borrow_exposes_attached_signer() {
		let container = signed(b"data");
		assert!(container.signer().is_some());
	}

	#[test]
	fn parsed_only_container_has_no_borrowable_signer() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let mut container = signed(b"data");
		let encoded = container.get_encoded()?;
		let reopened = EncryptedContainer::from_encoded(&encoded, None)?;
		assert!(reopened.signer().is_none());
		assert!(reopened.signing_account()?.is_some());
		Ok(())
	}

	#[test]
	fn take_signing_account_downgrades_container_to_public_only() -> core::result::Result<(), Box<dyn std::error::Error>>
	{
		let mut container = signed(b"data");
		container.take_signing_account()?.ok_or("signer present")?;

		let outcome = container.get_encoded();
		assert!(matches!(outcome, Err(EncryptedContainerError::SignerRequiresPrivateKey)));
		Ok(())
	}

	#[test]
	fn take_signing_account_preserves_the_private_key() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let mut container = signed(b"data");
		let taken = container.take_signing_account()?.ok_or("signer present")?;

		let options = FromPlaintextOptions { locked: Some(false), signer: Some(taken) };
		let mut resigned = EncryptedContainer::from_plaintext(b"data".to_vec(), None, options);
		assert!(resigned.get_encoded().is_ok());
		Ok(())
	}

	#[test]
	fn take_signing_account_is_none_without_a_signer() -> core::result::Result<(), Box<dyn std::error::Error>> {
		let mut container = sealed(b"data");
		assert!(container.take_signing_account()?.is_none());
		Ok(())
	}
}

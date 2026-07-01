//! The `containers` encrypted-container resource of the P2 component.

use core::cell::RefCell;
use std::sync::Arc;

use keetanetwork_anchor::encrypted_container::EncryptedContainer as CoreEncryptedContainer;
use keetanetwork_anchor_bindings::encrypted_container as ec_ops;

use super::account::AccountResource;
use super::exports::keeta::anchor::containers::{
	EncryptedContainer as WitEncryptedContainer, Guest as ContainersGuest, GuestEncryptedContainer,
};
use super::exports::keeta::client::crypto::AccountBorrow;
use super::{collect_accounts, optional_slice, CodedError, Component};

/// A hybrid-encrypted, optionally signed container.
pub(crate) struct EncryptedContainerResource {
	container: RefCell<CoreEncryptedContainer>,
}

impl ContainersGuest for Component {
	type EncryptedContainer = EncryptedContainerResource;
}

impl GuestEncryptedContainer for EncryptedContainerResource {
	fn from_plaintext(
		data: Vec<u8>,
		principals: Vec<AccountBorrow<'_>>,
		locked: Option<bool>,
		signer: Option<AccountBorrow<'_>>,
	) -> WitEncryptedContainer {
		let principals = collect_accounts(&principals);
		let signer = signer.map(|signer| Arc::clone(&signer.get::<AccountResource>().account));
		let container = ec_ops::from_plaintext(data, optional_slice(&principals), locked, signer.as_ref());
		WitEncryptedContainer::new(Self { container: RefCell::new(container) })
	}

	fn from_encoded(data: Vec<u8>, principals: Vec<AccountBorrow<'_>>) -> Result<WitEncryptedContainer, CodedError> {
		let principals = collect_accounts(&principals);
		let container = ec_ops::from_encoded(&data, optional_slice(&principals))?;
		Ok(WitEncryptedContainer::new(Self { container: RefCell::new(container) }))
	}

	fn from_encrypted(data: Vec<u8>, principals: Vec<AccountBorrow<'_>>) -> Result<WitEncryptedContainer, CodedError> {
		let principals = collect_accounts(&principals);
		let container = ec_ops::from_encrypted(&data, &principals)?;
		Ok(WitEncryptedContainer::new(Self { container: RefCell::new(container) }))
	}

	fn get_plaintext(&self) -> Result<Vec<u8>, CodedError> {
		Ok(ec_ops::get_plaintext(&mut self.container.borrow_mut())?)
	}

	fn get_encoded(&self) -> Result<Vec<u8>, CodedError> {
		Ok(ec_ops::get_encoded(&mut self.container.borrow_mut())?)
	}

	fn is_encrypted(&self) -> bool {
		ec_ops::is_encrypted(&self.container.borrow())
	}

	fn is_signed(&self) -> bool {
		ec_ops::is_signed(&self.container.borrow())
	}

	fn verify_signature(&self) -> Result<bool, CodedError> {
		Ok(ec_ops::verify_signature(&mut self.container.borrow_mut())?)
	}

	fn signing_account(&self) -> Result<Option<Vec<u8>>, CodedError> {
		Ok(ec_ops::signing_account(&self.container.borrow())?)
	}

	fn principals(&self) -> Result<Vec<Vec<u8>>, CodedError> {
		Ok(ec_ops::principals(&self.container.borrow())?)
	}

	fn grant_access(&self, accounts: Vec<AccountBorrow<'_>>) -> Result<(), CodedError> {
		let accounts = collect_accounts(&accounts);
		ec_ops::grant_access(&mut self.container.borrow_mut(), &accounts)?;
		Ok(())
	}

	fn revoke_access(&self, public_key: Vec<u8>) -> Result<(), CodedError> {
		ec_ops::revoke_access(&mut self.container.borrow_mut(), &public_key)?;
		Ok(())
	}
}

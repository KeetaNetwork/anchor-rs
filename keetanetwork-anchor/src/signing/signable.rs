//! The signable payload model.
//!
//! A [`Signable`] part is one element appended to the ASN.1 `SEQUENCE` of
//! verification bytes.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use keetanetwork_account::{Account, AccountPublicKey, KeyPair};

/// A single element of a signable payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signable<'a> {
	/// A UTF-8 string element.
	Text(Cow<'a, str>),
	/// An integer element (the I-JSON safe range).
	Integer(i64),
	/// An account element, carried as its `publicKeyAndType` bytes.
	Account(Cow<'a, [u8]>),
}

impl Signable<'_> {
	/// A [`Signable::Account`] from an account's `publicKeyAndType` bytes
	/// (`[key_type_byte || raw_public_key]`).
	pub fn from_account<K: KeyPair>(account: &Account<K>) -> Signable<'static> {
		Signable::Account(Cow::Owned(account.to_public_key_with_type()))
	}
}

impl<'a> From<&'a str> for Signable<'a> {
	fn from(value: &'a str) -> Self {
		Signable::Text(Cow::Borrowed(value))
	}
}

impl From<String> for Signable<'_> {
	fn from(value: String) -> Self {
		Signable::Text(Cow::Owned(value))
	}
}

impl<'a> From<Cow<'a, str>> for Signable<'a> {
	fn from(value: Cow<'a, str>) -> Self {
		Signable::Text(value)
	}
}

impl From<i64> for Signable<'_> {
	fn from(value: i64) -> Self {
		Signable::Integer(value)
	}
}

impl From<i32> for Signable<'_> {
	fn from(value: i32) -> Self {
		Signable::Integer(i64::from(value))
	}
}

/// Borrow a domain value as the ordered parts of a signable payload.
pub trait ToSignable {
	/// The ordered parts that make up the payload.
	fn to_signable(&self) -> Vec<Signable<'_>>;
}

impl ToSignable for [Signable<'_>] {
	fn to_signable(&self) -> Vec<Signable<'_>> {
		self.to_vec()
	}
}

impl ToSignable for Vec<Signable<'_>> {
	fn to_signable(&self) -> Vec<Signable<'_>> {
		self.to_vec()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn str_borrows_without_allocating() {
		let part = Signable::from("hello");
		assert!(matches!(part, Signable::Text(Cow::Borrowed("hello"))));
	}

	#[test]
	fn i32_widens_to_integer() {
		let part = Signable::from(7_i32);
		assert!(matches!(part, Signable::Integer(7)));
	}

	#[test]
	fn to_signable_clones_slice_parts() {
		let parts = [Signable::from("a"), Signable::from(1_i64)];
		let collected = parts.as_slice().to_signable();
		assert_eq!(collected.len(), 2);
	}
}

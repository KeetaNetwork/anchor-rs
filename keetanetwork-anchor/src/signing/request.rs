//! Signed HTTP requests: project a [`Signed`] envelope onto a URL's query
//! string (or a request body's `account` + `signed` fields) and verify it.

use alloc::string::String;
use core::str::FromStr;

use keetanetwork_account::GenericAccount;
use url::Url;

use super::error::RequestError;
use super::{verify_envelope, Signed, ToSignable, VerifyOptions};

/// Query-parameter key carrying the envelope nonce.
const PARAM_NONCE: &str = "signed.nonce";
/// Query-parameter key carrying the envelope timestamp.
const PARAM_TIMESTAMP: &str = "signed.timestamp";
/// Query-parameter key carrying the base64 signature.
const PARAM_SIGNATURE: &str = "signed.signature";
/// Query-parameter key carrying the signing account's public-key string.
const PARAM_ACCOUNT: &str = "account";

/// The `signed.*` keys, in the order the TypeScript reference appends them.
const SIGNED_PARAMS: [&str; 3] = [PARAM_NONCE, PARAM_TIMESTAMP, PARAM_SIGNATURE];

/// Attach `signed` and `account` to `base` as query parameters.
///
/// Fails with [`RequestError::DuplicateParameter`] if `base` already carries a
/// `signed.*` key, so an existing signature is never silently overwritten.
pub fn add_signature_to_url(base: &Url, account: impl AsRef<str>, signed: &Signed) -> Result<Url, RequestError> {
	for name in SIGNED_PARAMS {
		let already_present = base.query_pairs().any(|(key, _)| key == name);
		if already_present {
			return Err(RequestError::DuplicateParameter { name });
		}
	}

	let mut url = base.clone();
	{
		let mut pairs = url.query_pairs_mut();
		pairs.append_pair(PARAM_NONCE, &signed.nonce);
		pairs.append_pair(PARAM_TIMESTAMP, &signed.timestamp);
		pairs.append_pair(PARAM_SIGNATURE, &signed.signature);
		pairs.append_pair(PARAM_ACCOUNT, account.as_ref());
	}

	Ok(url)
}

/// Read the `account` string and [`Signed`] envelope back out of a signed URL.
///
/// Fails with [`RequestError::IncompleteSignature`] when only some of the
/// `signed.*` fields are present, and [`RequestError::MissingAuthentication`]
/// when no credentials are present at all.
pub fn parse_signature_from_url(url: &Url) -> Result<(String, Signed), RequestError> {
	let mut nonce = None;
	let mut timestamp = None;
	let mut signature = None;
	let mut account = None;

	for (key, value) in url.query_pairs() {
		match key.as_ref() {
			PARAM_NONCE => nonce = Some(value.into_owned()),
			PARAM_TIMESTAMP => timestamp = Some(value.into_owned()),
			PARAM_SIGNATURE => signature = Some(value.into_owned()),
			PARAM_ACCOUNT => account = Some(value.into_owned()),
			_ => {}
		}
	}

	let signed = match (nonce, timestamp, signature) {
		(Some(nonce), Some(timestamp), Some(signature)) => Signed { nonce, timestamp, signature },
		(None, None, None) => return Err(RequestError::MissingAuthentication),
		_ => return Err(RequestError::IncompleteSignature),
	};

	let account = account.ok_or(RequestError::MissingAuthentication)?;

	Ok((account, signed))
}

/// Verify a URL-signed request and return the authenticated account.
pub fn verify_url<T>(url: &Url, data: &T, options: &VerifyOptions) -> Result<GenericAccount, RequestError>
where
	T: ToSignable + ?Sized,
{
	let (account_string, signed) = parse_signature_from_url(url)?;
	let account = GenericAccount::from_str(&account_string)?;

	verify_envelope(&account, data, &signed, options)?;

	Ok(account)
}

/// Verify a body-signed request and return the authenticated account.
pub fn verify_body<T>(
	account: impl AsRef<str>,
	signed: &Signed,
	data: &T,
	options: &VerifyOptions,
) -> Result<GenericAccount, RequestError>
where
	T: ToSignable + ?Sized,
{
	let account = GenericAccount::from_str(account.as_ref())?;

	verify_envelope(&account, data, signed, options)?;

	Ok(account)
}

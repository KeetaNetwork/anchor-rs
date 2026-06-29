//! Anchor request signing, byte-compatible with the TypeScript reference.

mod canonical;
mod error;
mod format;
mod request;
mod signable;

pub use canonical::object_to_signable;
pub use error::{RequestError, SigningError, VerifyError};
pub use request::{add_signature_to_url, parse_signature_from_url, verify_body, verify_url};
pub use signable::{Signable, ToSignable};
pub use url::Url;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use format::format_data;
use keetanetwork_account::account::AccountSigner;
use keetanetwork_account::{Account, GenericAccount, KeyPair};
use uuid::Uuid;

/// Default allowed clock skew.
pub const DEFAULT_MAX_SKEW_MS: i64 = 5 * 60 * 1000;

/// A signed payload envelope. `{ nonce, timestamp, signature }` where
/// `signature` is base64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
	/// Per-request nonce.
	pub nonce: String,
	/// ISO 8601 / RFC 3339 timestamp with millisecond precision and a `Z` zone.
	pub timestamp: String,
	/// Base64-encoded signature over the canonical verification bytes.
	pub signature: String,
}

/// The deterministic inputs to [`sign_with`]: a nonce and a timestamp.
///
/// Exposed so callers (and parity fixtures) can sign with fixed values; use
/// [`SignParams::generate`] for fresh ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignParams {
	/// Per-request nonce.
	pub nonce: String,
	/// ISO 8601 timestamp string.
	pub timestamp: String,
}

impl SignParams {
	/// Fixed signing parameters.
	pub fn new(nonce: impl Into<String>, timestamp: impl Into<String>) -> Self {
		Self { nonce: nonce.into(), timestamp: timestamp.into() }
	}

	/// Fresh parameters: a random UUID nonce and the current time, formatted
	/// identically to JavaScript's `Date.prototype.toISOString`.
	pub fn generate() -> Self {
		let nonce = Uuid::new_v4().hyphenated().to_string();
		let timestamp = format_iso8601(Utc::now());
		Self { nonce, timestamp }
	}
}

impl Default for SignParams {
	fn default() -> Self {
		Self::generate()
	}
}

/// Options for [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOptions {
	/// Maximum allowed difference between the signed timestamp and
	/// [`reference_time`](Self::reference_time), in milliseconds.
	pub max_skew_ms: i64,
	/// The instant skew is measured against.
	pub reference_time: DateTime<Utc>,
}

impl Default for VerifyOptions {
	fn default() -> Self {
		Self { max_skew_ms: DEFAULT_MAX_SKEW_MS, reference_time: Utc::now() }
	}
}

impl VerifyOptions {
	/// Verify the signature only, accepting any timestamp.
	///
	/// Service-metadata entries are signed once and served continuously, so the
	/// reference (`maxSkewMs: Infinity`) places no bound on their age.
	pub fn unbounded() -> Self {
		Self { max_skew_ms: i64::MAX, reference_time: DateTime::<Utc>::UNIX_EPOCH }
	}
}

/// Sign `data` with `account`, generating a fresh nonce and timestamp.
///
/// This is the common path. Use [`sign_with`] to supply deterministic
/// [`SignParams`] (e.g. for reproducible tests or replayed requests).
pub fn sign<A, T>(account: &A, data: &T) -> Result<Signed, SigningError>
where
	A: AccountSigner + VerifyingAccount + ?Sized,
	T: ToSignable + ?Sized,
{
	let params = SignParams::generate();
	sign_with(account, data, &params)
}

/// Sign `data` with `account` using explicit [`SignParams`].
pub fn sign_with<A, T>(account: &A, data: &T, params: &SignParams) -> Result<Signed, SigningError>
where
	A: AccountSigner + VerifyingAccount + ?Sized,
	T: ToSignable + ?Sized,
{
	ensure_canonical_timestamp(&params.timestamp)?;

	let verification = verification_data(account, data, params)?;
	let signature = account.sign(&verification, None)?;
	let encoded = STANDARD.encode(signature);

	Ok(Signed { nonce: params.nonce.clone(), timestamp: params.timestamp.clone(), signature: encoded })
}

/// The exact bytes [`sign_with`] signs: the ASN.1 DER verification payload for
/// `data` under `account` and `params`.
pub fn verification_data<A, T>(account: &A, data: &T, params: &SignParams) -> Result<Vec<u8>, SigningError>
where
	A: VerifyingAccount + ?Sized,
	T: ToSignable + ?Sized,
{
	let parts = data.to_signable();
	let signer = account.public_key_with_type();
	format_data(&signer, &params.nonce, &params.timestamp, &parts)
}

/// Verify a [`Signed`] envelope over `data` against `account`.
///
/// Returns `Ok(())` when the signature is authentic and timely. Each [`Err`]
/// variant names *why* it was rejected ([`VerifyError`]) so the caller can react
/// (retry on [`ClockSkew`](VerifyError::ClockSkew), reject on
/// [`SignatureMismatch`](VerifyError::SignatureMismatch)).
pub fn verify<K, T>(account: &Account<K>, data: &T, signed: &Signed, options: &VerifyOptions) -> Result<(), VerifyError>
where
	K: KeyPair,
	T: ToSignable + ?Sized,
{
	verify_envelope(account, data, signed, options)
}

/// An account that can verify a signature and expose its `publicKeyAndType`
/// transport bytes. Implemented for both the statically typed [`Account`]
/// and the runtime-typed [`GenericAccount`].
pub trait VerifyingAccount {
	fn public_key_with_type(&self) -> Vec<u8>;
	fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError>;
}

impl<K> VerifyingAccount for Account<K>
where
	K: KeyPair,
{
	fn public_key_with_type(&self) -> Vec<u8> {
		self.to_public_key_with_type()
	}

	fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
		self.verify(message, signature, None)
			.map_err(|_| VerifyError::SignatureMismatch)
	}
}

impl VerifyingAccount for GenericAccount {
	fn public_key_with_type(&self) -> Vec<u8> {
		self.to_public_key_with_type()
	}

	fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
		self.verify(message, signature, None)
			.map_err(|_| VerifyError::SignatureMismatch)
	}
}

/// Verify a [`Signed`] envelope against any [`VerifyingAccount`]: enforce the
/// canonical timestamp, the clock-skew window, then the signature itself.
pub(crate) fn verify_envelope<A, T>(
	account: &A,
	data: &T,
	signed: &Signed,
	options: &VerifyOptions,
) -> Result<(), VerifyError>
where
	A: VerifyingAccount + ?Sized,
	T: ToSignable + ?Sized,
{
	let parsed_timestamp = DateTime::parse_from_rfc3339(&signed.timestamp)?;
	let timestamp = parsed_timestamp.with_timezone(&Utc);
	if format_iso8601(timestamp) != signed.timestamp {
		return Err(VerifyError::MalformedTimestamp);
	}

	let skew = (timestamp.timestamp_millis() - options.reference_time.timestamp_millis()).abs();
	if skew > options.max_skew_ms {
		return Err(VerifyError::ClockSkew { skew_ms: skew, max_ms: options.max_skew_ms });
	}

	let signature = STANDARD.decode(&signed.signature)?;
	let parts = data.to_signable();
	let signer = account.public_key_with_type();
	let verification = format_data(&signer, &signed.nonce, &signed.timestamp, &parts)?;

	account.verify_signature(&verification, &signature)
}

/// Format `instant` exactly as JavaScript's `Date.prototype.toISOString`:
/// millisecond precision with a trailing `Z`.
fn format_iso8601(instant: DateTime<Utc>) -> String {
	instant.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Reject a timestamp that [`verify`] would later refuse: it must be a strict
/// ISO 8601 instant with millisecond precision and a `Z` zone, so signing and
/// verification stay symmetric (no envelope this API would refuse to verify).
fn ensure_canonical_timestamp(timestamp: &str) -> Result<(), SigningError> {
	let parsed = DateTime::parse_from_rfc3339(timestamp)?;
	if format_iso8601(parsed.with_timezone(&Utc)) != timestamp {
		return Err(SigningError::NonCanonicalTimestamp);
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn format_iso8601_uses_milliseconds_and_zulu() {
		let instant = DateTime::parse_from_rfc3339("2024-01-02T03:04:05.678Z")
			.unwrap()
			.with_timezone(&Utc);
		assert_eq!(format_iso8601(instant), "2024-01-02T03:04:05.678Z");
	}

	#[test]
	fn generate_produces_a_hyphenated_uuid_nonce() {
		let params = SignParams::generate();
		assert_eq!(params.nonce.len(), 36);
		assert_eq!(params.nonce.matches('-').count(), 4);
	}
}

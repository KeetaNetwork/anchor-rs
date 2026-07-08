//! Reading a metadata document from a location, dispatched by scheme.
//!
//! A [`MetadataLocation`] names where a document lives: an on-chain account read
//! through the node client (`keetanet://<account>/metadata`), or an
//! `https`/`http` URL read directly. [`read_document`] fetches and parses one
//! into JSON.

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use core::str::FromStr;

use keetanetwork_account::GenericAccount;
use keetanetwork_client::KeetaClient;
use serde_json::{Map, Value};

use super::decode::{decode_base64, parse_metadata};
use crate::error::ResolverError;
use crate::transport::AnchorHttpTransport;

/// The `keetanet:` path that addresses an account's service metadata.
const METADATA_PATH: &str = "metadata";

/// No-content status: a valid empty metadata document.
const NO_CONTENT: u16 = 204;

/// Where a metadata document is read from, by scheme.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MetadataLocation {
	/// On-chain metadata for `account`, read via the node API.
	KeetaNet {
		/// The account whose `info.metadata` holds the document.
		account: Arc<GenericAccount>,
	},

	/// Metadata read directly from an `https` URL.
	Https {
		/// The absolute `https` URL.
		url: String,
	},

	/// Metadata read directly from an `http` URL.
	Http {
		/// The absolute `http` URL.
		url: String,
	},
}

impl FromStr for MetadataLocation {
	type Err = ResolverError;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		if let Some(rest) = value.strip_prefix("keetanet://") {
			return keetanet_location(rest);
		}
		if value.starts_with("https://") {
			return Ok(Self::Https { url: value.to_string() });
		}
		if value.starts_with("http://") {
			return Ok(Self::Http { url: value.to_string() });
		}

		Err(ResolverError::UnsupportedScheme { scheme: scheme_of(value) })
	}
}

/// Parse the host/path of a `keetanet://` reference into a location.
///
/// The reference resolver serves metadata only at the `/metadata` path; any
/// other path is unsupported.
fn keetanet_location(rest: &str) -> Result<MetadataLocation, ResolverError> {
	let mut parts = rest.splitn(2, '/');
	let account = parts.next().unwrap_or_default();
	let path = parts.next();

	if account.is_empty() {
		return Err(ResolverError::Field { field: "keetanet account" });
	}

	if path != Some(METADATA_PATH) {
		return Err(ResolverError::UnsupportedScheme { scheme: "keetanet".to_string() });
	}

	let account = GenericAccount::from_str(account)?;
	Ok(MetadataLocation::KeetaNet { account: Arc::new(account) })
}

/// The scheme portion of `value` (before `://`), for error reporting.
fn scheme_of(value: &str) -> String {
	match value.split_once("://") {
		Some((scheme, _)) => scheme.to_string(),
		None => value.to_string(),
	}
}

/// Fetch and parse the metadata document at `location`: an on-chain account
/// through the node `client`, or a remote URL over `transport`.
///
/// # Errors
///
/// Returns [`ResolverError::Node`] when a ledger read fails,
/// [`ResolverError::NotFound`] when a remote read does not succeed, or a
/// decode error ([`ResolverError::Base64`], [`ResolverError::Utf8`],
/// [`ResolverError::Json`]) when the bytes are not a valid metadata document.
pub(crate) async fn read_document(
	client: &KeetaClient,
	transport: &dyn AnchorHttpTransport,
	location: &MetadataLocation,
) -> Result<Value, ResolverError> {
	match location {
		MetadataLocation::KeetaNet { account } => read_keetanet(client, account).await,
		MetadataLocation::Https { url } | MetadataLocation::Http { url } => read_https(transport, url).await,
	}
}

/// Read an account's on-chain metadata through the node client, mirroring the
/// reference resolver's `client.getAccountInfo(account)`.
///
/// The base64 service-metadata blob is the account state's `info.metadata`
/// field. An empty or absent field is a valid empty document.
async fn read_keetanet(client: &KeetaClient, account: &GenericAccount) -> Result<Value, ResolverError> {
	let state = client.state(account).await?;
	let metadata = state
		.info
		.and_then(|info| info.metadata)
		.unwrap_or_default();

	if metadata.is_empty() {
		return Ok(Value::Object(Map::new()));
	}

	let raw = decode_base64(&metadata)?;
	parse_metadata(&raw)
}

/// Read metadata directly from an `https`/`http` URL.
async fn read_https(transport: &dyn AnchorHttpTransport, url: &str) -> Result<Value, ResolverError> {
	let response = transport.get(url).await?;
	if response.status == NO_CONTENT {
		return Ok(Value::Object(Map::new()));
	}

	if !response.is_success() {
		return Err(ResolverError::NotFound { location: url.to_string() });
	}

	parse_metadata(&response.body)
}

#[cfg(test)]
mod tests {
	use alloc::format;

	use keetanetwork_account::{AccountPublicKey, KeyED25519};
	use keetanetwork_anchor::testing::create_account_from_seed;

	use super::*;

	/// A real, parseable `keeta_...` address for location tests.
	fn test_address() -> String {
		create_account_from_seed::<KeyED25519>(0)
			.keypair
			.to_public_key_string()
			.expect("test account renders an address")
	}

	#[test]
	fn keetanet_reference_parses_to_an_account_location() {
		let address = test_address();
		let location = MetadataLocation::from_str(&format!("keetanet://{address}/metadata"));
		assert!(matches!(location, Ok(MetadataLocation::KeetaNet { account }) if account.to_string() == address));
	}

	#[test]
	fn keetanet_reference_rejects_a_malformed_account() {
		let location = MetadataLocation::from_str("keetanet://keeta_abc/metadata");
		assert!(matches!(location, Err(ResolverError::Account { .. })));
	}

	#[test]
	fn keetanet_reference_rejects_a_non_metadata_path() {
		let location = MetadataLocation::from_str("keetanet://keeta_abc/other");
		assert!(matches!(location, Err(ResolverError::UnsupportedScheme { .. })));
	}

	#[test]
	fn https_and_http_references_parse_to_url_locations() {
		let https = MetadataLocation::from_str("https://example.test/meta");
		assert!(matches!(https, Ok(MetadataLocation::Https { url }) if url == "https://example.test/meta"));

		let http = MetadataLocation::from_str("http://example.test/meta");
		assert!(matches!(http, Ok(MetadataLocation::Http { url }) if url == "http://example.test/meta"));
	}

	#[test]
	fn an_unknown_scheme_is_rejected() {
		let location = MetadataLocation::from_str("ftp://example.test/meta");
		assert!(matches!(location, Err(ResolverError::UnsupportedScheme { scheme }) if scheme == "ftp"));
	}
}

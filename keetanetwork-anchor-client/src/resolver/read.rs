//! Reading a metadata document from a location, dispatched by scheme.
//!
//! A [`MetadataLocation`] names where a document lives: an on-chain account read
//! through the node API (`keetanet://<account>/metadata`), or an `https`/`http`
//! URL read directly. [`read_document`] fetches and parses one into JSON.

use alloc::string::{String, ToString};

use core::str::FromStr;

use serde_json::{Map, Value};

use super::decode::{decode_base64, parse_metadata};
use crate::error::ResolverError;
use crate::transport::AnchorHttpTransport;

/// The `keetanet:` path that addresses an account's service metadata.
const METADATA_PATH: &str = "metadata";

/// No-content status: a valid empty metadata document.
const NO_CONTENT: u16 = 204;

/// Where a metadata document is read from, by scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MetadataLocation {
	/// On-chain metadata for `account`, read via the node API.
	KeetaNet {
		/// The `keeta_...` account whose `info.metadata` holds the document.
		account: String,
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

	Ok(MetadataLocation::KeetaNet { account: account.to_string() })
}

/// The scheme portion of `value` (before `://`), for error reporting.
fn scheme_of(value: &str) -> String {
	match value.split_once("://") {
		Some((scheme, _)) => scheme.to_string(),
		None => value.to_string(),
	}
}

/// Fetch and parse the metadata document at `location` over `transport`.
///
/// # Errors
///
/// Returns [`ResolverError::NotFound`] when a remote read does not succeed, or a
/// decode error ([`ResolverError::Base64`], [`ResolverError::Utf8`],
/// [`ResolverError::Json`]) when the bytes are not a valid metadata document.
pub(crate) async fn read_document(
	transport: &dyn AnchorHttpTransport,
	node_api: &str,
	location: &MetadataLocation,
) -> Result<Value, ResolverError> {
	match location {
		MetadataLocation::KeetaNet { account } => read_keetanet(transport, node_api, account).await,
		MetadataLocation::Https { url } | MetadataLocation::Http { url } => read_https(transport, url).await,
	}
}

/// Read an account's on-chain metadata via `GET {node_api}/node/ledger/account/{account}`.
///
/// The node returns the account state as JSON; the base64 service-metadata blob
/// is the `info.metadata` field. An empty field is a valid empty document.
async fn read_keetanet(
	transport: &dyn AnchorHttpTransport,
	node_api: &str,
	account: &str,
) -> Result<Value, ResolverError> {
	let url = alloc::format!("{node_api}/node/ledger/account/{account}");
	let response = transport.get(&url).await?;
	if !response.is_success() {
		return Err(ResolverError::NotFound { location: url });
	}

	let text = core::str::from_utf8(&response.body).map_err(|_| ResolverError::Utf8)?;
	let state: Value = serde_json::from_str(text)?;
	let metadata = state
		.get("info")
		.and_then(|info| info.get("metadata"))
		.and_then(Value::as_str)
		.unwrap_or_default();

	if metadata.is_empty() {
		return Ok(Value::Object(Map::new()));
	}

	let raw = decode_base64(metadata)?;
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
	use super::*;

	#[test]
	fn keetanet_reference_parses_to_an_account_location() {
		let location = MetadataLocation::from_str("keetanet://keeta_abc/metadata");
		assert!(matches!(location, Ok(MetadataLocation::KeetaNet { account }) if account == "keeta_abc"));
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

//! `ExternalURL` indirection resolution, exercised hermetically.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use keetanetwork_anchor_client::{
	AnchorHttpTransport, HttpResponse, Resolver, ResolverError, ServiceQuery, TransportError,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The node API the transport answers account reads under.
const NODE_API: &str = "http://node.test/api";

/// The `ExternalURL` discriminator the reference and resolver agree on.
const EXTERNAL_URL_MARKER: &str = "2b828e33-2692-46e9-817e-9b93d63f28fd";

/// A `keetanet://<account>/metadata` reference string.
fn keetanet(account: &str) -> String {
	format!("keetanet://{account}/metadata")
}

/// An `ExternalURL` indirection node pointing at `url`.
fn external(url: &str) -> Value {
	json!({ "external": EXTERNAL_URL_MARKER, "url": url })
}

/// A minimal version-1 root document advertising one unsigned `kyc` entry.
fn root_with_kyc(entry_id: &str) -> Value {
	json!({ "version": 1, "currencyMap": {}, "services": { "kyc": { entry_id: {} } } })
}

/// A version-1 root whose single `kyc` entry carries a signature that cannot
/// verify (account present, but the signature is not over its operations).
fn root_with_tampered_kyc(entry_id: &str) -> Value {
	let entry = json!({
		// cspell:disable-next-line
		"account": "keeta_aabfovvyefaaiiz254qeqhba6h2l4uv7ks6a7lpc4usmjcmo3fmlsrgmccnzl7a",
		"operations": {},
		"signed": { "nonce": "n", "timestamp": "2024-01-02T03:04:05.678Z", "signature": "AA==" },
	});

	json!({ "version": 1, "currencyMap": {}, "services": { "kyc": { entry_id: entry } } })
}

/// One `(account, document)` entry for the in-memory node.
fn published(account: &str, document: Value) -> (String, Value) {
	(account.to_string(), document)
}

/// Account strings as owned roots, in priority order.
fn roots(accounts: &[&str]) -> Vec<String> {
	accounts.iter().map(|account| account.to_string()).collect()
}

/// An in-memory node: each account maps to the JSON document its on-chain
/// `info.metadata` would decode to.
#[derive(Debug, Default)]
struct MapTransport {
	documents: BTreeMap<String, Value>,
}

impl MapTransport {
	/// A transport serving `documents`, keyed by account string.
	fn new(documents: impl IntoIterator<Item = (String, Value)>) -> Self {
		Self { documents: documents.into_iter().collect() }
	}

	/// The account segment of a `…/node/ledger/account/<account>` URL.
	fn account_of(url: &str) -> Option<&str> {
		url.rsplit('/').next()
	}
}

#[async_trait]
impl AnchorHttpTransport for MapTransport {
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
		let Some(account) = Self::account_of(url) else {
			return Ok(HttpResponse::new(404, Vec::new()));
		};

		let Some(document) = self.documents.get(account) else {
			return Ok(HttpResponse::new(404, Vec::new()));
		};

		let metadata = STANDARD.encode(serde_json::to_vec(document).unwrap());
		let body = json!({ "info": { "metadata": metadata } });
		Ok(HttpResponse::new(200, serde_json::to_vec(&body).unwrap()))
	}

	async fn post(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse, TransportError> {
		Ok(HttpResponse::new(405, Vec::new()))
	}
}

/// A query that surfaces every entry id under `services.kyc`.
struct EntryIds;

impl ServiceQuery for EntryIds {
	const SERVICE: &'static str = "kyc";
	type Criteria = ();
	type Provider = String;

	fn parse(id: String, _entry: &Value, _criteria: &()) -> Option<String> {
		Some(id)
	}
}

/// Resolve every `kyc` entry id from `documents`, rooted at `roots`.
async fn resolve_ids(
	documents: impl IntoIterator<Item = (String, Value)>,
	roots: Vec<String>,
) -> Result<Vec<String>, ResolverError> {
	let transport = Arc::new(MapTransport::new(documents));
	let resolver = Resolver::new(transport, NODE_API, roots);

	resolver.lookup::<EntryIds>(&()).await
}

#[tokio::test]
async fn a_root_level_external_url_is_followed() -> TestResult {
	// The root account holds nothing but an indirection to the real document.
	let root = published("root", external(&keetanet("leaf")));
	let leaf = published("leaf", root_with_kyc("prov_leaf"));
	let documents = [root, leaf];

	let providers = resolve_ids(documents, roots(&["root"])).await?;
	assert_eq!(
		providers,
		vec!["prov_leaf".to_string()],
		"a root-level ExternalURL must resolve to its target document"
	);
	Ok(())
}

#[tokio::test]
async fn a_nested_external_url_is_followed() -> TestResult {
	// The indirection sits deep in the tree: services.kyc is the external node.
	let root_document = json!({
		"version": 1,
		"currencyMap": {},
		"services": { "kyc": external(&keetanet("kyc_map")) },
	});
	let root = published("root", root_document);
	let kyc_map = published("kyc_map", json!({ "prov_nested": {} }));
	let documents = [root, kyc_map];

	let providers = resolve_ids(documents, roots(&["root"])).await?;
	assert_eq!(
		providers,
		vec!["prov_nested".to_string()],
		"an ExternalURL nested under services must resolve in place"
	);
	Ok(())
}

#[tokio::test]
async fn a_chain_of_external_urls_is_followed() -> TestResult {
	// root -> mid -> leaf: the replacement of each external node is itself
	// re-examined, so the chain must collapse to the final document.
	let root = published("root", external(&keetanet("mid")));
	let mid = published("mid", external(&keetanet("leaf")));
	let leaf = published("leaf", root_with_kyc("prov_chain"));
	let documents = [root, mid, leaf];

	let providers = resolve_ids(documents, roots(&["root"])).await?;
	assert_eq!(providers, vec!["prov_chain".to_string()], "a chain of ExternalURLs must resolve to the final document");
	Ok(())
}

#[tokio::test]
async fn a_self_referential_external_url_resolves_to_null() {
	// root points at itself: the cycle must collapse to null, leaving no valid
	// root document and therefore no metadata at all.
	let root = published("root", external(&keetanet("root")));
	let documents = [root];

	let outcome = resolve_ids(documents, roots(&["root"])).await;
	assert!(
		matches!(outcome, Err(ResolverError::NoRootMetadata)),
		"a self-referential root must yield no valid metadata"
	);
}

#[tokio::test]
async fn a_mutual_external_url_cycle_resolves_to_null() {
	// root -> other -> root: the second visit to a URL already on the branch
	// must break the loop, again leaving no valid root document.
	let root = published("root", external(&keetanet("other")));
	let other = published("other", external(&keetanet("root")));
	let documents = [root, other];

	let outcome = resolve_ids(documents, roots(&["root"])).await;
	assert!(
		matches!(outcome, Err(ResolverError::NoRootMetadata)),
		"a mutual ExternalURL cycle must yield no valid metadata"
	);
}

#[tokio::test]
async fn a_tampered_higher_priority_entry_shadows_and_drops_the_lower() -> TestResult {
	let high = published("high", root_with_tampered_kyc("prov"));
	let low = published("low", root_with_kyc("prov"));
	let documents = [high, low];

	let providers = resolve_ids(documents, roots(&["high", "low"])).await?;
	assert!(
		providers.is_empty(),
		"a shadowed id whose winning entry fails verification must not fall back to a lower root"
	);
	Ok(())
}

#[tokio::test]
async fn distinct_entries_across_roots_are_in_union() -> TestResult {
	// Different ids from each root coexist.
	let high = published("high", root_with_kyc("prov_high"));
	let low = published("low", root_with_kyc("prov_low"));
	let documents = [high, low];

	let providers = resolve_ids(documents, roots(&["high", "low"])).await?;
	assert_eq!(
		providers,
		vec!["prov_high".to_string(), "prov_low".to_string()],
		"entries with distinct ids from multiple roots must all surface"
	);
	Ok(())
}

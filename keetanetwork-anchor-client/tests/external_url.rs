//! `ExternalURL` indirection resolution against live on-chain roots.

mod harness;

use std::collections::BTreeMap;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use harness::KycHarness;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_client::{
	AnchorHttpTransport, HttpResponse, KeetaClient, Resolver, ResolverError, ServiceQuery, TransportError,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

/// The web host the transport answers external document reads under.
const DOCS_HOST: &str = "http://docs.test";

/// The `ExternalURL` discriminator the reference and resolver agree on.
const EXTERNAL_URL_MARKER: &str = "2b828e33-2692-46e9-817e-9b93d63f28fd";

/// An external web document URL under the test host.
fn doc_url(name: &str) -> String {
	format!("{DOCS_HOST}/{name}")
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

/// An in-memory web host serving external metadata documents: each name under
/// [`DOCS_HOST`] maps to the JSON document its URL returns.
#[derive(Debug, Default)]
struct DocHost {
	documents: BTreeMap<String, Value>,
}

impl DocHost {
	/// A host serving `documents`, keyed by URL name.
	fn new(documents: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
		Self {
			documents: documents
				.into_iter()
				.map(|(name, document)| (name.to_string(), document))
				.collect(),
		}
	}
}

#[async_trait]
impl AnchorHttpTransport for DocHost {
	async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
		let document = url
			.strip_prefix(DOCS_HOST)
			.and_then(|path| path.strip_prefix('/'))
			.and_then(|name| self.documents.get(name));

		match document {
			Some(document) => Ok(HttpResponse::new(200, serde_json::to_vec(document).expect("document serializes"))),
			None => Ok(HttpResponse::new(404, Vec::new())),
		}
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

/// A running harness anchor plus the ids resolved from live roots.
///
/// Publishes each document in `roots` on-chain (in priority order), serves
/// `docs` as the external web host, and resolves every `kyc` entry id.
fn resolve_ids(
	roots: &[Value],
	docs: impl IntoIterator<Item = (&'static str, Value)>,
) -> Result<Result<Vec<String>, ResolverError>, Box<dyn Error>> {
	let mut kyc = KycHarness::start()?;
	let _anchor = kyc.start_kyc_anchor(None, true)?;

	let mut published = Vec::new();
	let mut api = String::new();
	for document in roots {
		let root = kyc.publish_metadata(document)?;
		api = root.api;
		published.push(GenericAccount::from_str(&root.root)?);
	}

	let client = KeetaClient::new(&api);
	let host = Arc::new(DocHost::new(docs));
	let resolver = Resolver::new(client, host, published);
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let ids = runtime.block_on(resolver.lookup::<EntryIds>(&()));

	kyc.shutdown()?;
	Ok(ids)
}

#[test]
fn a_root_level_external_url_is_followed() -> TestResult {
	// The root account holds nothing but an indirection to the real document.
	let roots = [external(&doc_url("leaf"))];
	let docs = [("leaf", root_with_kyc("prov_leaf"))];

	let providers = resolve_ids(&roots, docs)??;
	assert_eq!(
		providers,
		vec!["prov_leaf".to_string()],
		"a root-level ExternalURL must resolve to its target document"
	);
	Ok(())
}

#[test]
fn a_nested_external_url_is_followed() -> TestResult {
	// The indirection sits deep in the tree: services.kyc is the external node.
	let roots = [json!({
		"version": 1,
		"currencyMap": {},
		"services": { "kyc": external(&doc_url("kyc_map")) },
	})];
	let docs = [("kyc_map", json!({ "prov_nested": {} }))];

	let providers = resolve_ids(&roots, docs)??;
	assert_eq!(
		providers,
		vec!["prov_nested".to_string()],
		"an ExternalURL nested under services must resolve in place"
	);
	Ok(())
}

#[test]
fn a_chain_of_external_urls_is_followed() -> TestResult {
	// root -> mid -> leaf: the replacement of each external node is itself
	// re-examined, so the chain must collapse to the final document.
	let roots = [external(&doc_url("mid"))];
	let docs = [("mid", external(&doc_url("leaf"))), ("leaf", root_with_kyc("prov_chain"))];

	let providers = resolve_ids(&roots, docs)??;
	assert_eq!(providers, vec!["prov_chain".to_string()], "a chain of ExternalURLs must resolve to the final document");
	Ok(())
}

#[test]
fn a_keetanet_external_url_resolves_through_the_ledger() -> TestResult {
	// The external reference addresses another on-chain account, so the hop is
	// resolved through the live node client like the root itself.
	let mut kyc = KycHarness::start()?;
	let _anchor = kyc.start_kyc_anchor(None, true)?;

	let leaf = kyc.publish_metadata(&root_with_kyc("prov_ledger"))?;
	let root = kyc.publish_metadata(&external(&format!("keetanet://{}/metadata", leaf.root)))?;

	let client = KeetaClient::new(&root.api);
	let host = Arc::new(DocHost::default());
	let resolver = Resolver::new(client, host, [GenericAccount::from_str(&root.root)?]);
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let providers = runtime.block_on(resolver.lookup::<EntryIds>(&()))?;

	assert_eq!(
		providers,
		vec!["prov_ledger".to_string()],
		"a keetanet ExternalURL must resolve through the live ledger"
	);

	kyc.shutdown()?;
	Ok(())
}

#[test]
fn a_self_referential_external_url_resolves_to_null() -> TestResult {
	// The external document points at itself: the cycle must collapse to null,
	// leaving no valid root document and therefore no metadata at all.
	let roots = [external(&doc_url("loop"))];
	let docs = [("loop", external(&doc_url("loop")))];

	let outcome = resolve_ids(&roots, docs)?;
	assert!(
		matches!(outcome, Err(ResolverError::NoRootMetadata)),
		"a self-referential ExternalURL must yield no valid metadata"
	);
	Ok(())
}

#[test]
fn a_mutual_external_url_cycle_resolves_to_null() -> TestResult {
	// a -> b -> a: the second visit to a URL already on the branch must break
	// the loop, again leaving no valid root document.
	let roots = [external(&doc_url("a"))];
	let docs = [("a", external(&doc_url("b"))), ("b", external(&doc_url("a")))];

	let outcome = resolve_ids(&roots, docs)?;
	assert!(
		matches!(outcome, Err(ResolverError::NoRootMetadata)),
		"a mutual ExternalURL cycle must yield no valid metadata"
	);
	Ok(())
}

#[test]
fn a_tampered_higher_priority_entry_shadows_and_drops_the_lower() -> TestResult {
	let roots = [root_with_tampered_kyc("prov"), root_with_kyc("prov")];

	let providers = resolve_ids(&roots, [])??;
	assert!(
		providers.is_empty(),
		"a shadowed id whose winning entry fails verification must not fall back to a lower root"
	);
	Ok(())
}

#[test]
fn distinct_entries_across_roots_are_in_union() -> TestResult {
	// Different ids from each root coexist.
	let roots = [root_with_kyc("prov_high"), root_with_kyc("prov_low")];

	let providers = resolve_ids(&roots, [])??;
	assert_eq!(
		providers,
		vec!["prov_high".to_string(), "prov_low".to_string()],
		"entries with distinct ids from multiple roots must all surface"
	);
	Ok(())
}

//! On-chain service-metadata resolution.
//!
//! [`Resolver`] reads each root account's service metadata through the node
//! client (`keetanet://<account>/metadata`), follows any `ExternalURL`
//! indirection at any depth, and projects each verified entry through a
//! [`ServiceQuery`].

mod decode;
mod metadata;
mod query;
mod read;

pub use decode::{decode_base64, parse_metadata};
pub use metadata::{CountryCode, KycOperations, KycProvider};
pub use query::ServiceQuery;

/// One certificate an account published on-chain: the PEM-encoded leaf and the
/// PEM-encoded intermediates recorded alongside it (the node client's record).
pub use keetanetwork_client::Certificate as AccountCertificate;

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::str::FromStr;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::signing::{object_to_signable, verify_body, Signed, VerifyOptions};
use keetanetwork_client::KeetaClient;
use serde_json::{Map, Value};

use crate::error::ResolverError;
use crate::transport::AnchorHttpTransport;
use decode::as_external_url;
use metadata::{signed_fields, SignedJson};
use read::{read_document, MetadataLocation};

/// Namespace tag bound into every service-metadata signature.
pub(crate) const METADATA_SIGNATURE_NAMESPACE: &str = "keetanet/anchor/service-metadata/v1";

/// The metadata schema version this resolver understands.
const SUPPORTED_VERSION: u64 = 1;

/// One step in a path to a node within a metadata document.
enum Segment {
	/// An object key.
	Key(String),

	/// An array index.
	Index(usize),
}

/// Resolves anchor services from one or more on-chain root accounts.
#[derive(Clone)]
pub struct Resolver {
	client: KeetaClient,
	transport: Arc<dyn AnchorHttpTransport>,
	roots: Vec<Arc<GenericAccount>>,
}

impl Resolver {
	/// A resolver reading `roots` (in priority order) through the node
	/// `client`, signing nothing (metadata reads are unauthenticated).
	///
	/// Each root is an account whose `info.metadata` holds the
	/// service-metadata document. The `transport` reads `ExternalURL`
	/// metadata indirections, which live outside the ledger.
	pub fn new(
		client: KeetaClient,
		transport: Arc<dyn AnchorHttpTransport>,
		roots: impl IntoIterator<Item = impl Into<Arc<GenericAccount>>>,
	) -> Self {
		Self { client, transport, roots: roots.into_iter().map(Into::into).collect() }
	}

	/// Collect every provider matching `criteria`, across all roots.
	///
	/// Roots are consulted in priority order. ID precedence is resolved before
	/// signature verification, matching the reference's merge-then-filter: an id
	/// present in a higher-priority root takes that root's entry and shadows the
	/// same id in every lower-priority root, even when that winning entry is
	/// then dropped for a failed signature. Within a root, entries are taken in
	/// id order. Entries whose optional signature does not verify, or that the
	/// query rejects, are skipped.
	///
	/// # Errors
	///
	/// Returns [`ResolverError::NoRootMetadata`] when no root yields a valid
	/// (version 1) document. Unreadable roots and malformed or unverifiable
	/// individual entries are skipped, not errored.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor_client::ServiceQuery;
	/// use serde_json::Value;
	///
	/// struct Names;
	///
	/// impl ServiceQuery for Names {
	///     const SERVICE: &'static str = "kyc";
	///     type Criteria = ();
	///     type Provider = String;
	///     fn parse(id: String, _entry: &Value, _criteria: &()) -> Option<String> {
	///         Some(id)
	///     }
	/// }
	/// ```
	pub async fn lookup<Q>(&self, criteria: &Q::Criteria) -> Result<Vec<Q::Provider>, ResolverError>
	where
		Q: ServiceQuery,
	{
		let documents = self.root_documents().await;
		if documents.is_empty() {
			return Err(ResolverError::NoRootMetadata);
		}

		let mut seen = BTreeSet::new();
		let mut providers = Vec::new();
		for document in &documents {
			let Some(entries) = service_entries(document, Q::SERVICE) else {
				continue;
			};

			for (id, entry) in entries {
				if !seen.insert(id.clone()) {
					continue;
				}

				if !entry_signature_ok(entry) {
					continue;
				}

				if let Some(provider) = Q::parse(id.clone(), entry, criteria) {
					providers.push(provider);
				}
			}
		}

		Ok(providers)
	}

	/// The fully-resolved, version-1 document for each readable root, in
	/// priority order. Unreadable or unsupported roots are skipped.
	async fn root_documents(&self) -> Vec<Value> {
		let mut documents = Vec::new();
		for account in &self.roots {
			let location = MetadataLocation::KeetaNet { account: Arc::clone(account) };
			let Ok(mut document) = read_document(&self.client, self.transport.as_ref(), &location).await else {
				continue;
			};

			self.resolve_external_urls(&mut document).await;
			if document.get("version").and_then(Value::as_u64) != Some(SUPPORTED_VERSION) {
				continue;
			}

			documents.push(document);
		}

		documents
	}

	/// Replace every `ExternalURL` node in `document` with the document it
	/// points to, at any depth.
	///
	/// Walks the tree iteratively, tracking the chain of URLs that led to each
	/// node so a reference back into its own chain resolves to `null` rather
	/// than looping. A reference that cannot be read also resolves to `null`.
	async fn resolve_external_urls(&self, document: &mut Value) {
		let mut pending: Vec<(Vec<Segment>, BTreeSet<String>)> = Vec::new();
		pending.push((Vec::new(), BTreeSet::new()));

		while let Some((path, ancestors)) = pending.pop() {
			let external = node_at(document, &path)
				.and_then(as_external_url)
				.map(str::to_string);
			match external {
				Some(url) => {
					self.expand_external(document, path, ancestors, url, &mut pending)
						.await
				}
				None => push_children(document, &path, &ancestors, &mut pending),
			}
		}
	}

	/// Resolve one `ExternalURL` at `path`, replacing it in place and queuing
	/// the replacement for further resolution.
	async fn expand_external(
		&self,
		document: &mut Value,
		path: Vec<Segment>,
		ancestors: BTreeSet<String>,
		url: String,
		pending: &mut Vec<(Vec<Segment>, BTreeSet<String>)>,
	) {
		if ancestors.contains(&url) {
			set_at(document, &path, Value::Null);
			return;
		}

		let fetched = match MetadataLocation::from_str(&url) {
			Ok(location) => read_document(&self.client, self.transport.as_ref(), &location)
				.await
				.ok(),
			Err(_) => None,
		};

		match fetched {
			Some(value) => {
				set_at(document, &path, value);
				let mut chain = ancestors;
				chain.insert(url);
				pending.push((path, chain));
			}
			None => set_at(document, &path, Value::Null),
		}
	}
}

/// Queue every child of the container at `path` for resolution.
fn push_children(
	document: &Value,
	path: &[Segment],
	ancestors: &BTreeSet<String>,
	pending: &mut Vec<(Vec<Segment>, BTreeSet<String>)>,
) {
	match node_at(document, path) {
		Some(Value::Object(map)) => {
			for key in map.keys() {
				pending.push((extend(path, Segment::Key(key.clone())), ancestors.clone()));
			}
		}
		Some(Value::Array(items)) => {
			for index in 0..items.len() {
				pending.push((extend(path, Segment::Index(index)), ancestors.clone()));
			}
		}
		_ => {}
	}
}

/// A copy of `path` with one more [`Segment`] appended.
fn extend(path: &[Segment], segment: Segment) -> Vec<Segment> {
	let mut child = Vec::with_capacity(path.len() + 1);
	for step in path {
		child.push(step.clone());
	}

	child.push(segment);
	child
}

impl Clone for Segment {
	fn clone(&self) -> Self {
		match self {
			Self::Key(key) => Self::Key(key.clone()),
			Self::Index(index) => Self::Index(*index),
		}
	}
}

/// The node reached by following `path` from `root`, when it exists.
fn node_at<'doc>(root: &'doc Value, path: &[Segment]) -> Option<&'doc Value> {
	let mut current = root;
	for segment in path {
		current = match segment {
			Segment::Key(key) => current.get(key)?,
			Segment::Index(index) => current.get(index)?,
		};
	}

	Some(current)
}

/// Replace the node at `path` with `value`, if the path still resolves.
fn set_at(root: &mut Value, path: &[Segment], value: Value) {
	let Some((last, parents)) = path.split_last() else {
		*root = value;
		return;
	};

	let mut current = root;
	for segment in parents {
		let next = match segment {
			Segment::Key(key) => current.get_mut(key),
			Segment::Index(index) => current.get_mut(index),
		};

		match next {
			Some(node) => current = node,
			None => return,
		}
	}

	let slot = match last {
		Segment::Key(key) => current.get_mut(key),
		Segment::Index(index) => current.get_mut(index),
	};

	if let Some(node) = slot {
		*node = value;
	}
}

/// The `services.<service>` entry map, when present and well-formed.
fn service_entries<'doc>(document: &'doc Value, service: &str) -> Option<&'doc Map<String, Value>> {
	document
		.get("services")
		.and_then(|services| services.get(service))
		.and_then(Value::as_object)
}

/// Whether a provider entry's optional signature is acceptable.
///
/// An entry with neither `account` nor `signed` is accepted. An entry with one
/// but not the other, or whose signature fails verification, is rejected.
fn entry_signature_ok(entry: &Value) -> bool {
	let account = entry.get("account").and_then(Value::as_str);
	let signed = entry.get("signed");
	match (account, signed) {
		(None, None) => true,
		(Some(account), Some(signed)) => verify_entry(account, entry, signed),
		_ => false,
	}
}

/// Verify a signed provider entry against the namespace-bound signed fields.
fn verify_entry(account: &str, entry: &Value, signed: &Value) -> bool {
	let Some(operations) = entry.get("operations") else {
		return false;
	};

	let legal = entry.get("legal");
	let fields = signed_fields(account, operations, legal);
	let parts = match object_to_signable(&fields) {
		Ok(parts) => parts,
		Err(_) => return false,
	};

	let Some(envelope) = signed_envelope(signed) else {
		return false;
	};

	verify_body(account, &envelope, &parts, &VerifyOptions::unbounded()).is_ok()
}

/// Read a `{ nonce, timestamp, signature }` value into a [`Signed`] envelope.
fn signed_envelope(signed: &Value) -> Option<Signed> {
	let parsed: SignedJson = serde_json::from_value(signed.clone()).ok()?;
	Some(Signed { nonce: parsed.nonce, timestamp: parsed.timestamp, signature: parsed.signature })
}

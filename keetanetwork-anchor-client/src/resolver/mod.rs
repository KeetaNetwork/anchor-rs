//! On-chain service-metadata resolution.
//!
//! [`Resolver`] fetches a root account's metadata via a [`MetadataSource`],
//! follows any top-level `ExternalURL` indirection, and projects each verified
//! entry through a [`ServiceQuery`].

mod decode;
mod metadata;
mod query;
mod source;

pub use decode::{decode_base64, parse_metadata};
pub use metadata::{CountryCode, KycOperations, KycProvider};
pub use query::ServiceQuery;
pub use source::{HttpsMetadataSource, InlineMetadataSource, MetadataSource};

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_anchor::signing::{object_to_signable, verify_body, Signed, VerifyOptions};
use serde_json::{Map, Value};

use crate::error::ResolverError;
use decode::as_external_url;
use metadata::{signed_fields, SignedJson};

/// Namespace tag bound into every service-metadata signature.
pub(crate) const METADATA_SIGNATURE_NAMESPACE: &str = "keetanet/anchor/service-metadata/v1";

/// Resolves anchor services from one or more root metadata locations.
#[derive(Clone)]
pub struct Resolver {
	source: Arc<dyn MetadataSource>,
	roots: Vec<String>,
}

impl Resolver {
	/// A resolver reading `roots` (in priority order) through `source`.
	pub fn new(source: Arc<dyn MetadataSource>, roots: impl IntoIterator<Item = String>) -> Self {
		Self { source, roots: roots.into_iter().collect() }
	}

	/// Collect every provider matching `criteria`, across all roots.
	///
	/// Roots are consulted in order; within a root, entries are taken in
	/// id order. Entries whose optional signature does not verify, or that the
	/// query rejects, are skipped.
	///
	/// # Errors
	///
	/// Returns a [`ResolverError`] when a root cannot be fetched or decoded.
	/// Malformed or unverifiable individual entries are skipped, not errored.
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
		let mut providers = Vec::new();
		for root in &self.roots {
			let document = self.resolve_root(root).await?;
			collect_providers::<Q>(&document, criteria, &mut providers);
		}

		Ok(providers)
	}

	/// Fetch and decode a root, following a top-level `ExternalURL` chain.
	async fn resolve_root(&self, location: &str) -> Result<Value, ResolverError> {
		let mut current = location.to_string();
		let mut seen = BTreeSet::new();

		loop {
			if !seen.insert(current.clone()) {
				return Err(ResolverError::ReferenceCycle);
			}

			let raw = self.source.fetch(&current).await?;
			let value = parse_metadata(&raw)?;
			match as_external_url(&value) {
				Some(url) => current = url.to_string(),
				None => return Ok(value),
			}
		}
	}
}

/// Project every verified entry under `services.<Q::SERVICE>` through the query.
fn collect_providers<Q>(document: &Value, criteria: &Q::Criteria, out: &mut Vec<Q::Provider>)
where
	Q: ServiceQuery,
{
	let Some(entries) = service_entries(document, Q::SERVICE) else {
		return;
	};

	for (id, entry) in entries {
		if !entry_signature_ok(entry) {
			continue;
		}

		if let Some(provider) = Q::parse(id.clone(), entry, criteria) {
			out.push(provider);
		}
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

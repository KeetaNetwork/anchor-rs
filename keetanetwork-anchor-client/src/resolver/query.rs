//! The per-service projection [`Resolver::lookup`](super::Resolver::lookup)
//! applies to each verified metadata entry.

use alloc::string::String;

use serde_json::Value;

/// Projects a verified `services.<SERVICE>` entry into a typed provider.
///
/// [`Resolver::lookup`](super::Resolver::lookup) owns the shared spine (fetch,
/// follow indirection, verify the entry signature). A query supplies only the
/// service name, the selection criteria, and how to read one entry.
pub trait ServiceQuery {
	/// The `services` map key this query reads (e.g. `"kyc"`).
	const SERVICE: &'static str;

	/// The selection input a caller supplies (e.g. requested country codes).
	type Criteria: ?Sized;

	/// The typed provider produced for a matching entry.
	type Provider;

	/// Read one verified entry, returning a provider when it matches
	/// `criteria`.
	///
	/// `id` is the entry key under `services.<SERVICE>`. Returning [`None`]
	/// drops the entry (malformed or out of scope) without failing the lookup.
	fn parse(id: String, entry: &Value, criteria: &Self::Criteria) -> Option<Self::Provider>;
}

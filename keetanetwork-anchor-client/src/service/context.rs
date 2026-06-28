//! The shared context a per-service client is built from.

use alloc::sync::Arc;

use keetanetwork_account::{Account, KeyPair};

use super::caller::AnchorCaller;
use crate::resolver::Resolver;
use crate::transport::AnchorHttpTransport;

/// Bundles a [`Resolver`] for endpoint discovery with an [`AnchorCaller`] for
/// signed request execution.
///
/// A per-service client (e.g. [`KycClient`](crate::services::kyc::KycClient))
/// holds one context and delegates discovery and execution to it, so the
/// service client itself carries no transport or signing logic.
pub struct AnchorContext<K>
where
	K: KeyPair,
{
	resolver: Resolver,
	caller: AnchorCaller<K>,
}

impl<K> AnchorContext<K>
where
	K: KeyPair,
{
	/// A context resolving through `resolver` and signing requests with
	/// `signer` over `transport`.
	pub fn new(resolver: Resolver, transport: Arc<dyn AnchorHttpTransport>, signer: Account<K>) -> Self {
		let caller = AnchorCaller::new(transport, signer);
		Self { resolver, caller }
	}

	/// The resolver used to discover service providers.
	pub fn resolver(&self) -> &Resolver {
		&self.resolver
	}

	/// The caller used to execute signed requests.
	pub fn caller(&self) -> &AnchorCaller<K> {
		&self.caller
	}
}

//! Where root metadata bytes come from.
//!
//! A [`MetadataSource`] returns the raw (post-base64, pre-inflate) metadata for
//! a location string. [`InlineMetadataSource`] serves bytes held in memory.
//! [`HttpsMetadataSource`] reads them over an
//! [`AnchorHttpTransport`](crate::transport::AnchorHttpTransport).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use async_trait::async_trait;

use super::decode::decode_base64;
use crate::error::ResolverError;
use crate::marker::{MaybeSend, MaybeSync};

/// A source of raw service-metadata bytes keyed by location.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait MetadataSource: MaybeSend + MaybeSync {
	/// Fetch the raw (post-base64, pre-inflate) metadata for `location`.
	///
	/// # Errors
	///
	/// Returns [`ResolverError::NotFound`] when the location is unknown, or a
	/// [`ResolverError::Transport`] when a remote read fails.
	async fn fetch(&self, location: &str) -> Result<Vec<u8>, ResolverError>;
}

/// An in-memory [`MetadataSource`] mapping locations to raw metadata bytes.
#[derive(Debug, Default, Clone)]
pub struct InlineMetadataSource {
	entries: BTreeMap<String, Vec<u8>>,
}

impl InlineMetadataSource {
	/// Insert raw (post-base64) metadata bytes for `location`.
	pub fn insert(&mut self, location: impl Into<String>, raw: impl Into<Vec<u8>>) -> &mut Self {
		self.entries.insert(location.into(), raw.into());
		self
	}

	/// Insert metadata for `location` from its on-chain base64 `blob`.
	///
	/// # Errors
	///
	/// Returns [`ResolverError::Base64`] when `blob` is not valid base64.
	pub fn insert_base64(&mut self, location: impl Into<String>, blob: &str) -> Result<&mut Self, ResolverError> {
		let raw = decode_base64(blob)?;
		self.entries.insert(location.into(), raw);
		Ok(self)
	}
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl MetadataSource for InlineMetadataSource {
	async fn fetch(&self, location: &str) -> Result<Vec<u8>, ResolverError> {
		let found = self.entries.get(location).cloned();
		found.ok_or_else(|| ResolverError::NotFound { location: location.into() })
	}
}

pub use https::HttpsMetadataSource;

mod https {
	use alloc::boxed::Box;
	use alloc::sync::Arc;
	use alloc::vec::Vec;

	use async_trait::async_trait;

	use super::MetadataSource;
	use crate::error::ResolverError;
	use crate::transport::AnchorHttpTransport;

	/// No-content status: a valid empty metadata document.
	const NO_CONTENT: u16 = 204;

	/// A [`MetadataSource`] that reads HTTPS metadata over a transport.
	#[derive(Clone, Debug)]
	pub struct HttpsMetadataSource {
		transport: Arc<dyn AnchorHttpTransport>,
	}

	impl HttpsMetadataSource {
		/// Read metadata over `transport`.
		pub fn new(transport: Arc<dyn AnchorHttpTransport>) -> Self {
			Self { transport }
		}
	}

	#[cfg_attr(not(target_family = "wasm"), async_trait)]
	#[cfg_attr(target_family = "wasm", async_trait(?Send))]
	impl MetadataSource for HttpsMetadataSource {
		async fn fetch(&self, location: &str) -> Result<Vec<u8>, ResolverError> {
			let response = self.transport.get(location).await?;
			if response.status == NO_CONTENT {
				return Ok(Vec::from(b"{}".as_slice()));
			}
			if !response.is_success() {
				return Err(ResolverError::NotFound { location: location.into() });
			}

			Ok(response.body)
		}
	}
}

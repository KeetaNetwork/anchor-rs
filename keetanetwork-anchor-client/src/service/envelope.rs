//! Decode an anchor HTTP response into a typed [`AnchorOutcome`].

/// The result of an anchor operation that the provider may report as pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorOutcome<T> {
	/// The operation completed with a decoded value.
	Ready(T),

	/// The resource is not ready; retry after the suggested delay.
	Retry {
		/// Suggested delay before retrying, in milliseconds.
		after_ms: u32,
	},
}

impl<T> AnchorOutcome<T> {
	/// The ready value, or [`None`] when the provider asked the caller to retry.
	pub fn ready(self) -> Option<T> {
		match self {
			Self::Ready(value) => Some(value),
			Self::Retry { .. } => None,
		}
	}
}

#[cfg(feature = "http")]
pub(crate) use decode::classify;

#[cfg(feature = "http")]
mod decode {
	use serde::de::DeserializeOwned;
	use serde::Deserialize;

	use super::AnchorOutcome;
	use crate::error::AnchorClientError;
	use crate::transport::HttpResponse;

	/// The retry delay applied to a pending resource that gives no explicit hint.
	const DEFAULT_RETRY_MS: u32 = 500;

	/// The status a provider returns while a polled resource is not yet ready.
	const NOT_FOUND: u16 = 404;

	/// The common response fields every anchor operation shares.
	#[derive(Debug, Default, Deserialize)]
	struct Envelope {
		#[serde(default)]
		ok: Option<bool>,
		#[serde(default, rename = "retryAfter")]
		retry_after: Option<u32>,
	}

	/// Decode `response` into an [`AnchorOutcome`].
	///
	/// A `404`, or any response carrying `retryAfter`, becomes
	/// [`AnchorOutcome::Retry`]. Any other non-2xx status, or an `ok: false`
	/// envelope, becomes [`AnchorClientError::Service`]. A successful body
	/// decodes into `T`.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::Service`] when the anchor reports failure,
	/// or [`AnchorClientError::Body`] when a successful body does not decode
	/// into `T`.
	pub(crate) fn classify<T>(response: HttpResponse) -> Result<AnchorOutcome<T>, AnchorClientError>
	where
		T: DeserializeOwned,
	{
		let envelope = serde_json::from_slice::<Envelope>(&response.body).unwrap_or_default();
		if let Some(after_ms) = retry_delay(response.status, &envelope) {
			return Ok(AnchorOutcome::Retry { after_ms });
		}
		if !response.is_success() || envelope.ok == Some(false) {
			return Err(AnchorClientError::Service { status: response.status });
		}

		let value: T = serde_json::from_slice(&response.body)?;
		Ok(AnchorOutcome::Ready(value))
	}

	/// The retry delay for a pending resource: an explicit `retryAfter`,
	/// otherwise a default for a `404`.
	fn retry_delay(status: u16, envelope: &Envelope) -> Option<u32> {
		if let Some(after_ms) = envelope.retry_after {
			return Some(after_ms);
		}

		if status == NOT_FOUND {
			return Some(DEFAULT_RETRY_MS);
		}

		None
	}
}

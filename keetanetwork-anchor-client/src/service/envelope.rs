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

pub(crate) use decode::classify;

#[cfg(feature = "asset")]
pub(crate) use decode::pending_delay;

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

	/// The status a provider returns while an accepted operation is still
	/// processing (the reference share-KYC promise protocol polls until the
	/// `202` becomes a `200`).
	const ACCEPTED: u16 = 202;

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
	/// A `202`, a `404`, or any response carrying `retryAfter`, becomes
	/// [`AnchorOutcome::Retry`]. A failure envelope carrying a recognized
	/// asset-movement blocker code becomes the typed
	/// [`AnchorClientError::Blocker`]. Any other non-2xx status, or an
	/// `ok: false` envelope, becomes [`AnchorClientError::Service`]. A
	/// successful body decodes into `T`.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::Blocker`] or [`AnchorClientError::Service`]
	/// when the anchor reports failure, or [`AnchorClientError::Body`] when a
	/// successful body does not decode into `T`.
	pub(crate) fn classify<T>(response: HttpResponse) -> Result<AnchorOutcome<T>, AnchorClientError>
	where
		T: DeserializeOwned,
	{
		let envelope = serde_json::from_slice::<Envelope>(&response.body).unwrap_or_default();
		if let Some(after_ms) = retry_delay(&response, &envelope) {
			return Ok(AnchorOutcome::Retry { after_ms });
		}
		if !response.is_success() || envelope.ok == Some(false) {
			return Err(failure(response));
		}

		let value: T = serde_json::from_slice(&response.body)?;
		Ok(AnchorOutcome::Ready(value))
	}

	/// The typed error for a failure response: a recognized asset-movement
	/// blocker envelope rehydrates, anything else is a service failure.
	fn failure(response: HttpResponse) -> AnchorClientError {
		#[cfg(feature = "asset")]
		if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&response.body) {
			use crate::services::asset_movement::AssetMovementBlocker;

			let blocker = AssetMovementBlocker::from_transport(&body);
			if blocker.is_recognized() {
				return AnchorClientError::Blocker { blocker };
			}
		}

		AnchorClientError::Service { status: response.status }
	}

	/// The retry delay when `response` reports a pending resource, or [`None`]
	/// when it is settled. Unlike [`classify`], the body is only consulted for
	/// its optional `retryAfter` hint, so a settled response with an opaque
	/// body still resolves.
	#[cfg(feature = "asset")]
	pub(crate) fn pending_delay(response: &HttpResponse) -> Option<u32> {
		let envelope = serde_json::from_slice::<Envelope>(&response.body).unwrap_or_default();
		retry_delay(response, &envelope)
	}

	/// The retry delay for a pending resource: an explicit body `retryAfter`,
	/// otherwise the response's `Retry-After` header, otherwise a default for a
	/// `202` or a `404`.
	fn retry_delay(response: &HttpResponse, envelope: &Envelope) -> Option<u32> {
		if let Some(after_ms) = envelope.retry_after {
			return Some(after_ms);
		}

		if let Some(after_ms) = response.retry_after.as_ref().and_then(header_delay_ms) {
			return Some(after_ms);
		}

		if response.status == NOT_FOUND || response.status == ACCEPTED {
			return Some(DEFAULT_RETRY_MS);
		}

		None
	}

	/// A `Retry-After` header delay in milliseconds, when it resolves without a
	/// wall clock and fits the outcome's `u32` field.
	fn header_delay_ms(retry_after: &crate::transport::RetryAfter) -> Option<u32> {
		retry_after
			.to_millis()
			.and_then(|millis| u32::try_from(millis).ok())
	}

	#[cfg(test)]
	mod tests {
		use serde_json::Value;

		use super::*;
		use crate::transport::RetryAfter;

		#[test]
		fn a_retry_after_header_becomes_a_retry_outcome() {
			let response = HttpResponse::new(503, b"{}".to_vec()).with_retry_after(Some(RetryAfter::Seconds(2)));
			let outcome = classify::<Value>(response);
			assert!(matches!(outcome, Ok(AnchorOutcome::Retry { after_ms: 2_000 })));
		}

		#[test]
		fn a_body_hint_outranks_the_header() {
			let response = HttpResponse::new(503, br#"{"retryAfter":750}"#.to_vec())
				.with_retry_after(Some(RetryAfter::Seconds(2)));
			let outcome = classify::<Value>(response);
			assert!(matches!(outcome, Ok(AnchorOutcome::Retry { after_ms: 750 })));
		}

		#[test]
		fn a_not_found_without_a_hint_uses_the_default_delay() {
			let response = HttpResponse::new(NOT_FOUND, b"{}".to_vec());
			let outcome = classify::<Value>(response);
			assert!(matches!(outcome, Ok(AnchorOutcome::Retry { after_ms: DEFAULT_RETRY_MS })));
		}

		#[test]
		fn an_accepted_status_is_pending_even_with_an_opaque_body() {
			let response = HttpResponse::new(202, b"pending".to_vec());
			let outcome = classify::<Value>(response);
			assert!(matches!(outcome, Ok(AnchorOutcome::Retry { after_ms: DEFAULT_RETRY_MS })));
		}

		#[cfg(feature = "asset")]
		#[test]
		fn a_recognized_blocker_envelope_survives_a_forbidden_status() {
			use crate::services::asset_movement::AssetMovementBlocker;

			let body = serde_json::json!({
				"ok": false,
				"name": "KeetaAssetMovementAnchorKYCShareNeededError",
				"code": "KEETA_ANCHOR_ASSET_MOVEMENT_KYC_SHARE_NEEDED",
				"error": "share needed",
				"data": { "shareWithPrincipals": ["keeta_principal"], "acceptedIssuers": [] }
			});

			let response = HttpResponse::new(403, body.to_string().into_bytes());
			let outcome = classify::<Value>(response);
			assert!(matches!(
				outcome,
				Err(AnchorClientError::Blocker { blocker: AssetMovementBlocker::KycShareNeeded { .. } })
			));
		}

		#[cfg(feature = "asset")]
		#[test]
		fn an_unrecognized_failure_envelope_stays_a_service_error() {
			let body =
				serde_json::json!({ "ok": false, "name": "SomeError", "code": "SOMETHING_ELSE", "error": "boom" });
			let response = HttpResponse::new(403, body.to_string().into_bytes());

			let outcome = classify::<Value>(response);
			assert!(matches!(outcome, Err(AnchorClientError::Service { status: 403 })));
		}

		#[test]
		fn a_date_header_falls_back_to_the_body_or_default() {
			let response = HttpResponse::new(200, br#"{"ok":true}"#.to_vec())
				.with_retry_after(Some(RetryAfter::HttpDate("Wed, 21 Oct 2025 07:28:00 GMT".into())));
			let outcome = classify::<Value>(response);
			assert!(matches!(outcome, Ok(AnchorOutcome::Ready(_))));
		}
	}
}

//! Typed failures for the transport and resolver layers.

use alloc::string::{String, ToString};

use snafu::Snafu;
use url::ParseError;

use keetanetwork_anchor::signing::{RequestError, SigningError};

#[cfg(feature = "kyc")]
use keetanetwork_anchor::certificates::KycCertificateError;
#[cfg(feature = "kyc")]
use keetanetwork_anchor::sharable_attributes::error::SharableAttributesError;

/// A failure reaching an anchor over HTTP.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum TransportError {
	/// The request could not be sent or no response was received.
	#[snafu(display("transport request failed: {reason}"))]
	Request {
		/// The underlying client message.
		reason: String,
	},

	/// The target URL was not a valid absolute HTTP(S) URL.
	#[snafu(display("invalid request URL: {reason}"))]
	InvalidUrl {
		/// The underlying URL-parsing message.
		reason: String,
	},

	/// A resilience policy shed the request or spent its retry budget.
	#[cfg(feature = "resilience")]
	#[snafu(display("{source}"))]
	Resilience {
		/// The underlying resilience failure.
		source: alloc::boxed::Box<crate::resilience::ResilienceError>,
	},
}

#[cfg(feature = "resilience")]
impl From<crate::resilience::ResilienceError> for TransportError {
	fn from(error: crate::resilience::ResilienceError) -> Self {
		Self::Resilience { source: alloc::boxed::Box::new(error) }
	}
}

#[cfg(feature = "http")]
impl From<reqwest::Error> for TransportError {
	fn from(error: reqwest::Error) -> Self {
		Self::Request { reason: alloc::format!("{error}") }
	}
}

/// A failure decoding service metadata or resolving a provider.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ResolverError {
	/// The metadata blob was not valid base64.
	#[snafu(display("metadata base64 is invalid: {reason}"))]
	Base64 {
		/// The underlying decoder message.
		reason: String,
	},

	/// The decoded metadata bytes were not valid UTF-8 JSON text.
	#[snafu(display("metadata is not valid UTF-8"))]
	Utf8,

	/// The metadata JSON was malformed or did not match the expected shape.
	#[snafu(display("metadata JSON is invalid: {reason}"))]
	Json {
		/// The underlying JSON message.
		reason: String,
	},

	/// A required metadata field was missing or malformed.
	#[snafu(display("metadata field `{field}` is missing or malformed"))]
	Field {
		/// The offending field name.
		field: &'static str,
	},

	/// A metadata reference used a scheme this resolver cannot read.
	#[snafu(display("unsupported metadata reference scheme: {scheme}"))]
	UnsupportedScheme {
		/// The offending scheme.
		scheme: String,
	},

	/// A metadata location could not be read.
	#[snafu(display("metadata location not found: {location}"))]
	NotFound {
		/// The location that was requested.
		location: String,
	},

	/// No root account yielded a valid (version 1) metadata document.
	#[snafu(display("no valid root metadata found"))]
	NoRootMetadata,

	/// A reference did not name a valid `keeta_...` account.
	#[snafu(display("invalid account reference: {source}"), context(false))]
	Account {
		/// The underlying account-parsing failure.
		source: keetanetwork_account::AccountError,
	},

	/// Fetching metadata from the source failed at the transport layer.
	#[snafu(display("metadata fetch failed: {source}"), context(false))]
	Transport {
		/// The underlying transport failure.
		source: TransportError,
	},

	/// Reading on-chain state through the node client failed.
	#[cfg(feature = "codec")]
	#[snafu(display("node read failed: {source}"), context(false))]
	Node {
		/// The underlying node-client failure.
		source: keetanetwork_client::ClientError,
	},
}

impl From<base64::DecodeError> for ResolverError {
	fn from(error: base64::DecodeError) -> Self {
		Self::Base64 { reason: error.to_string() }
	}
}

#[cfg(feature = "codec")]
impl From<serde_json::Error> for ResolverError {
	fn from(error: serde_json::Error) -> Self {
		Self::Json { reason: error.to_string() }
	}
}

/// The unified error surface for the anchor client.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum AnchorClientError {
	/// A transport-layer failure.
	#[snafu(display("{source}"), context(false))]
	Transport {
		/// The underlying transport failure.
		source: TransportError,
	},

	/// A resolver-layer failure.
	#[snafu(display("{source}"), context(false))]
	Resolver {
		/// The underlying resolver failure.
		source: ResolverError,
	},

	/// An operation endpoint template did not yield a valid absolute URL.
	#[snafu(display("invalid operation URL: {reason}"))]
	Url {
		/// The underlying URL-parsing message.
		reason: String,
	},

	/// Producing the request signature failed.
	#[snafu(display("request signing failed: {source}"), context(false))]
	Signing {
		/// The underlying signing failure.
		source: SigningError,
	},

	/// Attaching the signature to the request URL failed.
	#[snafu(display("request URL signing failed: {source}"), context(false))]
	Request {
		/// The underlying URL-signing failure.
		source: RequestError,
	},

	/// The anchor returned a response body that did not match the operation.
	#[snafu(display("anchor response body is invalid: {reason}"))]
	Body {
		/// The underlying decoder message.
		reason: String,
	},

	/// The anchor rejected the request or reported a service-level failure.
	#[snafu(display("anchor request failed (status {status})"))]
	Service {
		/// The HTTP status the anchor returned.
		status: u16,
	},

	/// The resolved provider does not advertise a required operation.
	#[snafu(display("provider does not advertise the `{operation}` operation"))]
	UnsupportedOperation {
		/// The operation name that was missing.
		operation: &'static str,
	},

	/// A polled operation did not complete within its deadline.
	#[snafu(display("operation `{operation}` did not complete within {timeout_ms} ms"))]
	Timeout {
		/// The operation that was awaited.
		operation: &'static str,
		/// The deadline that elapsed, in milliseconds.
		timeout_ms: u32,
	},

	/// A referenced external blob could not be fetched.
	#[cfg(feature = "kyc")]
	#[snafu(display("reference fetch failed for `{url}` (status {status})"))]
	ReferenceFetch {
		/// The reference URL that was requested.
		url: String,
		/// The HTTP status the server returned (`0` for a malformed `data:`
		/// URL or container payload).
		status: u16,
	},

	/// A sharable-attributes operation failed in the core.
	#[cfg(feature = "kyc")]
	#[snafu(display("{source}"), context(false))]
	Sharable {
		/// The underlying sharable-attributes failure.
		source: SharableAttributesError,
	},
}

impl AnchorClientError {
	/// The stable, programmatic code identifying this failure, shared by every
	/// FFI boundary so a single mapping survives the addition of variants.
	pub fn code(&self) -> &'static str {
		match self {
			Self::Transport { .. } => "TRANSPORT",
			Self::Resolver { .. } => "RESOLVER",
			Self::Url { .. } => "INVALID_URL",
			Self::Signing { .. } => "SIGNING",
			Self::Request { .. } => "REQUEST",
			Self::Body { .. } => "INVALID_BODY",
			Self::Service { .. } => "SERVICE",
			Self::UnsupportedOperation { .. } => "UNSUPPORTED_OPERATION",
			Self::Timeout { .. } => "TIMEOUT",

			#[cfg(feature = "kyc")]
			Self::ReferenceFetch { .. } => "REFERENCE_FETCH",
			#[cfg(feature = "kyc")]
			Self::Sharable { .. } => "SHARABLE",
		}
	}
}

#[cfg(feature = "kyc")]
impl From<KycCertificateError> for AnchorClientError {
	fn from(error: KycCertificateError) -> Self {
		Self::Sharable { source: SharableAttributesError::from(error) }
	}
}

#[cfg(feature = "codec")]
impl From<serde_json::Error> for AnchorClientError {
	fn from(error: serde_json::Error) -> Self {
		Self::Body { reason: error.to_string() }
	}
}

impl From<ParseError> for AnchorClientError {
	fn from(error: ParseError) -> Self {
		Self::Url { reason: error.to_string() }
	}
}

#[cfg(all(test, feature = "kyc"))]
mod tests {
	use super::*;

	#[test]
	fn a_reference_fetch_failure_reports_its_code() {
		let error = AnchorClientError::ReferenceFetch { url: "https://example.test/blob".to_string(), status: 404 };
		assert_eq!(error.code(), "REFERENCE_FETCH");
	}

	#[test]
	fn a_sharable_failure_reports_its_code() {
		let error = AnchorClientError::from(SharableAttributesError::InvalidPem);
		assert_eq!(error.code(), "SHARABLE");
	}

	#[test]
	fn a_certificate_error_routes_through_sharable() {
		let error = AnchorClientError::from(KycCertificateError::UnsupportedSubjectKey);
		assert!(matches!(error, AnchorClientError::Sharable { source: SharableAttributesError::Certificate { .. } }));
	}
}

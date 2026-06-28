//! Transport-agnostic KeetaNet anchor client.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod marker;
pub mod transport;

#[cfg(feature = "resilience")]
pub mod resilience;

#[cfg(feature = "codec")]
pub mod resolver;

#[cfg(feature = "service")]
pub mod service;

#[cfg(any(feature = "kyc", feature = "fx", feature = "storage", feature = "asset"))]
pub mod services;

pub use error::{AnchorClientError, ResolverError, TransportError};
pub use transport::{AnchorHttpTransport, AnchorHttpTransportFactory, EmptyRetryAfter, HttpResponse, RetryAfter};

#[cfg(feature = "http")]
pub use transport::{ReqwestTransport, ReqwestTransportFactory};

#[cfg(feature = "resilience")]
pub use resilience::{
	lease_work_budget_ms, Backoff, Jitter, ResilienceError, ResilienceRuntime, ResilientTransport,
	ResilientTransportFactory, RetryPolicy, TokenBucket, DEFAULT_LEASE_MS,
};

#[cfg(all(feature = "resilience", feature = "std"))]
pub use resilience::TokioRuntime;

#[cfg(feature = "codec")]
pub use resolver::{
	decode_base64, parse_metadata, CountryCode, InlineMetadataSource, KycOperations, KycProvider, MetadataSource,
	Resolver, ServiceQuery,
};

#[cfg(all(feature = "codec", feature = "http"))]
pub use resolver::HttpsMetadataSource;

#[cfg(feature = "service")]
pub use service::{AnchorOutcome, Endpoint};

#[cfg(all(feature = "service", feature = "http"))]
pub use service::{AnchorCaller, AnchorContext, Auth, Call, Method};

#[cfg(feature = "kyc")]
pub use services::kyc::{Certificate, Certificates, KycQuery, Verification, VerificationStatus};

#[cfg(all(feature = "kyc", feature = "http"))]
pub use services::kyc::KycClient;

//! KYC anchor client: discover providers, then create and track verifications.
//!
//! [`KycQuery`] selects providers by country; [`KycClient`] runs the three
//! operations a KYC flow needs over the shared service layer.

use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::Value;

use crate::resolver::{CountryCode, KycProviderInfo, ServiceQuery};

/// Selects KYC providers that serve every requested country.
pub struct KycQuery;

impl ServiceQuery for KycQuery {
	const SERVICE: &'static str = "kyc";
	type Criteria = [CountryCode];
	type Provider = KycProviderInfo;

	fn parse(id: String, entry: &Value, criteria: &[CountryCode]) -> Option<KycProviderInfo> {
		let provider = KycProviderInfo::try_from((id, entry)).ok()?;
		provider.serves(criteria).then_some(provider)
	}
}

/// The countries KYC providers can validate, aggregated across every root
/// (the result of the reference `getSupportedCountries`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupportedCountries {
	/// At least one provider publishes no country list and validates
	/// worldwide.
	Worldwide,
	/// The sorted, deduplicated union of the providers' published country
	/// codes.
	Countries(Vec<CountryCode>),
}

impl FromIterator<KycProviderInfo> for SupportedCountries {
	fn from_iter<I: IntoIterator<Item = KycProviderInfo>>(providers: I) -> Self {
		let mut countries: Vec<CountryCode> = Vec::new();
		for provider in providers {
			let Some(codes) = provider.country_codes else {
				return Self::Worldwide;
			};

			countries.extend(codes);
		}

		countries.sort_by(|left, right| left.as_str().cmp(right.as_str()));
		countries.dedup();

		Self::Countries(countries)
	}
}

/// An in-progress verification a provider created.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Verification {
	/// The provider's verification id, used to poll status and certificates.
	pub id: String,

	/// The web URL where the user completes the verification flow.
	#[serde(rename = "webURL")]
	pub web_url: String,

	/// The cost the provider expects to charge for the verification.
	#[serde(rename = "expectedCost")]
	pub expected_cost: ExpectedCost,
}

/// The cost a provider expects to charge for a verification: a `token` and the
/// `min`/`max` bounds of the charge, both decimal strings in that token's units.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ExpectedCost {
	/// The minimum expected charge, a decimal string in `token` units.
	pub min: String,

	/// The maximum expected charge, a decimal string in `token` units.
	pub max: String,

	/// The token the charge is denominated in (its public key string).
	pub token: String,
}

/// A verification's current status.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct VerificationStatus {
	/// The provider-reported status (e.g. `pending`).
	pub status: String,

	/// Whether the provider requires a manual review to complete, when
	/// reported.
	#[serde(rename = "requiresManualVerification", default)]
	pub requires_manual_verification: Option<bool>,
}

/// A single issued certificate.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Certificate {
	/// The PEM-encoded leaf certificate.
	pub certificate: String,

	/// PEM-encoded intermediate certificates bridging the leaf to a trust root.
	#[serde(default)]
	pub intermediates: Vec<String>,
}

/// The certificates issued for a verification.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Certificates {
	/// The issued certificates.
	pub results: Vec<Certificate>,
}

pub use client::{KycClient, KycProvider};

mod client {
	use alloc::vec::Vec;
	use core::ops::Deref;

	use serde_json::{Map, Value};

	use super::{Certificates, KycQuery, SupportedCountries, Verification, VerificationStatus};
	use crate::error::AnchorClientError;
	use crate::resolver::{CountryCode, KycProviderInfo};
	use crate::service::{AnchorContext, AnchorOutcome, Auth, BodyEnvelope, Call, Endpoint, Method};

	/// A KYC anchor client over a shared [`AnchorContext`].
	///
	/// Discovery returns [`KycProvider`] handles carrying the resolved
	/// metadata; each operation lives on the handle. A stored
	/// [`KycProviderInfo`] snapshot rebinds through
	/// [`provider`](Self::provider).
	pub struct KycClient {
		context: AnchorContext,
	}

	impl KycClient {
		/// A client discovering and signing through `context`.
		pub fn new(context: AnchorContext) -> Self {
			Self { context }
		}

		/// Every provider that serves all `countries`.
		///
		/// # Errors
		///
		/// Returns [`AnchorClientError`] when a metadata root cannot be fetched
		/// or decoded. Malformed or out-of-scope entries are skipped.
		pub async fn providers(&self, countries: &[CountryCode]) -> Result<Vec<KycProvider<'_>>, AnchorClientError> {
			let providers = self.lookup(countries).await?;
			Ok(providers
				.into_iter()
				.map(|info| self.provider(info))
				.collect())
		}

		/// The countries any provider can validate, folded across every root
		/// (the reference `getSupportedCountries`).
		///
		/// # Errors
		///
		/// Returns [`AnchorClientError`] when a metadata root cannot be fetched
		/// or decoded.
		pub async fn get_supported_countries(&self) -> Result<SupportedCountries, AnchorClientError> {
			let providers = self.lookup(&[]).await?;
			let supported = providers.into_iter().collect();

			Ok(supported)
		}

		/// Bind a stored [`KycProviderInfo`] snapshot back to this client,
		/// yielding the operation-carrying handle. This is the stateless
		/// per-call primitive FFI layers rebind through.
		pub fn provider(&self, info: KycProviderInfo) -> KycProvider<'_> {
			KycProvider { client: self, info }
		}

		/// Discover provider snapshots serving all `countries`.
		async fn lookup(&self, countries: &[CountryCode]) -> Result<Vec<KycProviderInfo>, AnchorClientError> {
			let providers = self
				.context
				.resolver()
				.lookup::<KycQuery>(countries)
				.await?;
			Ok(providers)
		}
	}

	/// A discovered KYC provider bound to its client: every operation lives
	/// here, and the resolved metadata snapshot is reachable through [`Deref`]
	/// and [`info`](Self::info).
	///
	/// The handle holds nothing live so it is freely cloned and cheaply rebound
	/// from a stored snapshot via [`KycClient::provider`].
	#[derive(Clone)]
	pub struct KycProvider<'c> {
		client: &'c KycClient,
		info: KycProviderInfo,
	}

	impl Deref for KycProvider<'_> {
		type Target = KycProviderInfo;

		fn deref(&self) -> &Self::Target {
			&self.info
		}
	}

	impl KycProvider<'_> {
		/// The resolved metadata snapshot.
		pub fn info(&self) -> &KycProviderInfo {
			&self.info
		}

		/// Unwrap the handle into its metadata snapshot, e.g. for storage or
		/// for crossing an FFI boundary.
		pub fn into_info(self) -> KycProviderInfo {
			self.info
		}

		/// Begin a verification for `countries`, optionally directing the user
		/// to `redirect_url` when the flow ends.
		///
		/// Signs the request body. `countries` are the search countries the
		/// verification is scoped to (the same set used to discover this
		/// provider).
		///
		/// # Errors
		///
		/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
		/// does not advertise `createVerification`, or any request failure.
		pub async fn create_verification(
			&self,
			countries: &[CountryCode],
			redirect_url: Option<&str>,
		) -> Result<AnchorOutcome<Verification>, AnchorClientError> {
			let endpoint = endpoint_for(self.info.operations.create_verification.as_deref(), "createVerification")?;
			let body = create_request_fields(countries, redirect_url);
			let method = Method::Post;
			let auth = Auth::SignedBody;

			let call = Call {
				endpoint: &endpoint,
				params: &[],
				method,
				auth,
				signed: &[],
				envelope: BodyEnvelope::Request,
				body: Some(body),
			};
			let outcome = self.client.context.caller().invoke(call).await?;
			Ok(outcome)
		}

		/// Fetch the certificates issued for verification `id`.
		///
		/// A pending verification yields [`AnchorOutcome::Retry`].
		///
		/// # Errors
		///
		/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
		/// does not advertise `getCertificates`, or any request failure.
		pub async fn get_certificates(
			&self,
			id: impl AsRef<str>,
		) -> Result<AnchorOutcome<Certificates>, AnchorClientError> {
			let endpoint = endpoint_for(self.info.operations.get_certificates.as_deref(), "getCertificates")?;
			let params = [("id", id.as_ref())];
			let method = Method::Get;
			let auth = Auth::None;
			let body = None;

			let call = Call {
				endpoint: &endpoint,
				params: &params,
				method,
				auth,
				signed: &[],
				envelope: BodyEnvelope::Request,
				body,
			};

			let outcome = self.client.context.caller().invoke(call).await?;
			Ok(outcome)
		}

		/// Read the status of verification `id` (signed URL).
		///
		/// # Errors
		///
		/// Returns [`AnchorClientError::UnsupportedOperation`] when the provider
		/// does not advertise `getVerificationStatus`, or any request failure.
		pub async fn get_verification_status(
			&self,
			id: impl AsRef<str>,
		) -> Result<AnchorOutcome<VerificationStatus>, AnchorClientError> {
			let endpoint =
				endpoint_for(self.info.operations.get_verification_status.as_deref(), "getVerificationStatus")?;
			let params = [("id", id.as_ref())];
			let method = Method::Get;
			let auth = Auth::SignedUrl;
			let body = None;

			let call = Call {
				endpoint: &endpoint,
				params: &params,
				method,
				auth,
				signed: &[],
				envelope: BodyEnvelope::Request,
				body,
			};
			let outcome = self.client.context.caller().invoke(call).await?;
			Ok(outcome)
		}
	}

	/// The endpoint for an advertised operation, or a typed error naming the
	/// missing one.
	fn endpoint_for(template: Option<&str>, operation: &'static str) -> Result<Endpoint, AnchorClientError> {
		let template = template.ok_or(AnchorClientError::UnsupportedOperation { operation })?;
		Ok(Endpoint::from(template))
	}

	/// The `createVerification` request fields the caller wraps and signs.
	fn create_request_fields(countries: &[CountryCode], redirect_url: Option<&str>) -> Value {
		let codes = countries
			.iter()
			.map(|country| Value::String(country.as_str().into()))
			.collect();

		let mut fields = Map::new();
		fields.insert("countryCodes".into(), Value::Array(codes));

		if let Some(url) = redirect_url {
			fields.insert("redirectURL".into(), Value::String(url.into()));
		}

		Value::Object(fields)
	}
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;
	use alloc::vec;

	use serde_json::json;

	use super::*;

	/// A provider entry advertising the given country codes, or none for a
	/// worldwide provider.
	fn provider(id: &str, countries: Option<&[&str]>) -> Option<KycProviderInfo> {
		let mut entry = json!({ "operations": {}, "ca": "ca-pem" });
		if let Some(codes) = countries {
			entry["countryCodes"] = json!(codes);
		}

		KycProviderInfo::try_from((id.to_string(), &entry)).ok()
	}

	#[test]
	fn supported_countries_union_is_sorted_and_deduplicated() {
		let providers = [provider("a", Some(&["us", "DE"])), provider("b", Some(&["de", "FR"]))];
		let folded: SupportedCountries = providers.into_iter().flatten().collect();
		let codes = vec!["DE", "FR", "US"];
		assert!(matches!(&folded, SupportedCountries::Countries(countries)
			if countries.iter().map(CountryCode::as_str).eq(codes)));
	}

	#[test]
	fn a_worldwide_provider_folds_to_worldwide() {
		let providers = [provider("a", Some(&["US"])), provider("b", None)];
		let folded: SupportedCountries = providers.into_iter().flatten().collect();
		assert_eq!(folded, SupportedCountries::Worldwide);
	}

	#[test]
	fn no_providers_fold_to_an_empty_union() {
		let folded: SupportedCountries = core::iter::empty().collect();
		assert!(matches!(folded, SupportedCountries::Countries(countries) if countries.is_empty()));
	}
}

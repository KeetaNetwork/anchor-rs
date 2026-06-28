//! Service-metadata serialization structs and the validated KYC domain types.
//!
//! The serialization structs deserialize the JSON as-is; [`KycProvider`] is the
//! validated domain value produced via [`TryFrom`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::Value;

use crate::error::ResolverError;

/// The validated fields of a KYC provider entry.
///
/// The signature (`account`/`signed`) and `legal` are verified separately from
/// the raw entry, so this reads only the fields a [`KycProvider`] carries.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KycProviderJson {
	pub operations: Value,
	#[serde(rename = "countryCodes", default)]
	pub country_codes: Option<Vec<String>>,
	pub ca: String,
}

/// The `signed` envelope on a provider entry.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SignedJson {
	pub nonce: String,
	pub timestamp: String,
	pub signature: String,
}

/// The KYC operation endpoints a provider exposes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KycOperations {
	/// Begin the KYC verification process.
	#[serde(default)]
	pub create_verification: Option<String>,
	/// Fetch issued certificates for a verification.
	#[serde(default)]
	pub get_certificates: Option<String>,
	/// Read the status of a verification.
	#[serde(default)]
	pub get_verification_status: Option<String>,
	/// Check whether the provider can service a more specific locality.
	#[serde(default)]
	pub check_locality: Option<String>,
	/// Request a verification cost estimate.
	#[serde(default)]
	pub get_estimate: Option<String>,
}

/// A canonical (upper-cased) ISO country code used for KYC locality matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryCode(String);

impl CountryCode {
	/// The canonical code string.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl TryFrom<&str> for CountryCode {
	type Error = ResolverError;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		let trimmed = value.trim();
		if trimmed.is_empty() {
			return Err(ResolverError::Field { field: "countryCode" });
		}

		Ok(Self(trimmed.to_uppercase()))
	}
}

/// A validated KYC provider resolved from service metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KycProvider {
	/// The provider id (the key under `services.kyc`).
	pub id: String,
	/// The provider's operation endpoints.
	pub operations: KycOperations,
	/// The countries the provider can validate, or [`None`] for worldwide.
	pub country_codes: Option<Vec<CountryCode>>,
	/// The provider's CA certificate (PEM), used to identify the provider.
	pub ca: String,
}

impl KycProvider {
	/// Whether this provider can validate accounts in every requested country.
	///
	/// A provider with no country list validates worldwide and always matches.
	pub fn serves(&self, requested: &[CountryCode]) -> bool {
		match &self.country_codes {
			None => true,
			Some(supported) => requested.iter().all(|code| supported.contains(code)),
		}
	}
}

impl TryFrom<(String, &Value)> for KycProvider {
	type Error = ResolverError;

	fn try_from((id, entry): (String, &Value)) -> Result<Self, Self::Error> {
		let json: KycProviderJson = serde_json::from_value(entry.clone())?;
		let operations: KycOperations = serde_json::from_value(json.operations)?;
		let country_codes = match json.country_codes {
			Some(codes) => Some(canonical_country_codes(&codes)?),
			None => None,
		};

		Ok(Self { id, operations, country_codes, ca: json.ca })
	}
}

fn canonical_country_codes(codes: &[String]) -> Result<Vec<CountryCode>, ResolverError> {
	let mut canonical = Vec::with_capacity(codes.len());
	for code in codes {
		let parsed = CountryCode::try_from(code.as_str())?;
		canonical.push(parsed);
	}

	Ok(canonical)
}

/// Build the JSON object the entry signature covers (the reference's
/// `extractSignedFields`): `{ namespace, account, operations, legal? }`.
pub(crate) fn signed_fields(account: &str, operations: &Value, legal: Option<&Value>) -> Value {
	let mut fields = serde_json::Map::new();
	fields.insert("namespace".to_string(), Value::String(super::METADATA_SIGNATURE_NAMESPACE.to_string()));
	fields.insert("account".to_string(), Value::String(account.to_string()));
	fields.insert("operations".to_string(), operations.clone());

	if let Some(legal) = legal {
		if !legal.is_null() {
			fields.insert("legal".to_string(), legal.clone());
		}
	}

	Value::Object(fields)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn country_code_canonicalizes_to_upper() -> Result<(), ResolverError> {
		let code = CountryCode::try_from("us")?;
		assert_eq!(code.as_str(), "US");
		Ok(())
	}

	#[test]
	fn worldwide_provider_matches_any_request() -> Result<(), ResolverError> {
		let provider = KycProvider {
			id: "p".to_string(),
			operations: KycOperations::default(),
			country_codes: None,
			ca: "ca".to_string(),
		};

		let requested = [CountryCode::try_from("US")?];
		assert!(provider.serves(&requested));
		Ok(())
	}

	#[test]
	fn bounded_provider_requires_all_requested_countries() -> Result<(), ResolverError> {
		let provider = KycProvider {
			id: "p".to_string(),
			operations: KycOperations::default(),
			country_codes: Some(alloc::vec![CountryCode::try_from("US")?]),
			ca: "ca".to_string(),
		};

		let in_list = [CountryCode::try_from("US")?];
		let out_of_list = [CountryCode::try_from("CA")?];
		assert!(provider.serves(&in_list));
		assert!(!provider.serves(&out_of_list));
		Ok(())
	}
}

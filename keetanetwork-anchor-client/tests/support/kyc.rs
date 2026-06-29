//! Driver for the KYC interop harness (`dist/kyc.js`).

use keetanetwork_anchor::signing::Signed;
use keetanetwork_anchor_client::{decode_base64, parse_metadata};
use serde_json::{json, Map, Value};

use super::driver::{field_str, optional_string_array, HarnessDriver, HarnessError};

/// A live KYC anchor HTTP server started by the harness, with its service
/// metadata published on-chain to a root account.
pub struct KycAnchor {
	/// The server base URL (`http://127.0.0.1:<port>`).
	pub url: String,
	/// The node API base URL the resolver reads the root account through.
	pub api: String,
	/// The root account whose on-chain `info.metadata` advertises the provider.
	pub root: String,
	/// The provider's CA certificate (PEM).
	pub ca: String,
	/// The metadata signer's `keeta_...` string, when the entry is signed.
	pub signer: Option<String>,
	/// The provider id (the key under `services.kyc`).
	pub provider_id: String,
	/// The provider's advertised country codes, when bounded.
	pub country_codes: Option<Vec<String>>,
	/// The base64 `formatMetadata` blob, used to read operation URLs directly.
	pub blob: String,
}

/// A metadata document published on-chain to a fresh root account, addressed by
/// the node API it was published through.
pub struct PublishedRoot {
	/// The node API base URL the resolver reads the root account through.
	pub api: String,
	/// The root account whose on-chain `info.metadata` holds the document.
	pub root: String,
}

impl KycAnchor {
	/// An operation endpoint the anchor advertises, read from the published
	/// `blob` so tests never hand-roll `/api/...` paths.
	fn operation_url(&self, name: &'static str) -> Result<String, HarnessError> {
		let raw = decode_base64(&self.blob)?;
		let document = parse_metadata(&raw)?;
		let url = document
			.get("services")
			.and_then(|services| services.get("kyc"))
			.and_then(|kyc| kyc.get(&self.provider_id))
			.and_then(|provider| provider.get("operations"))
			.and_then(|operations| operations.get(name))
			.and_then(Value::as_str)
			.ok_or(HarnessError::MissingField { field: name })?;
		Ok(url.to_string())
	}

	/// The `createVerification` endpoint.
	pub fn create_verification_url(&self) -> Result<String, HarnessError> {
		self.operation_url("createVerification")
	}

	/// The `getCertificates` endpoint for verification `id`.
	pub fn get_certificates_url(&self, id: &str) -> Result<String, HarnessError> {
		Ok(self.operation_url("getCertificates")?.replace("{id}", id))
	}

	/// The `getVerificationStatus` endpoint for verification `id`.
	pub fn get_verification_status_url(&self, id: &str) -> Result<String, HarnessError> {
		Ok(self
			.operation_url("getVerificationStatus")?
			.replace("{id}", id))
	}
}

/// Build the JSON body a signed `createVerification` POST carries.
///
/// Anchors wrap the POST under `request`, alongside the operation fields
/// (`countryCodes`) the anchor requires and the signed credential.
pub fn signed_request_body(account: &str, signed: &Signed, countries: &[&str]) -> Result<Vec<u8>, HarnessError> {
	let codes = countries
		.iter()
		.map(|code| Value::String((*code).to_string()))
		.collect::<Vec<_>>();

	let body = json!({
		"request": {
			"countryCodes": codes,
			"account": account,
			"signed": { "nonce": signed.nonce, "timestamp": signed.timestamp, "signature": signed.signature },
		},
	});

	Ok(serde_json::to_vec(&body)?)
}

/// A live KYC anchor harness driven over JSON lines.
pub struct KycHarness {
	driver: HarnessDriver,
}

impl KycHarness {
	/// Spawn the KYC harness and wait for its `ready` line.
	pub fn start() -> Result<Self, HarnessError> {
		Ok(Self { driver: HarnessDriver::spawn("kyc")? })
	}

	/// Start a live KYC anchor HTTP server advertising the given country codes,
	/// optionally signing its metadata entry.
	pub fn start_kyc_anchor(&mut self, country_codes: Option<&[&str]>, sign: bool) -> Result<KycAnchor, HarnessError> {
		let mut request = Map::new();
		request.insert("sign".to_string(), Value::Bool(sign));

		if let Some(codes) = country_codes {
			let values = codes
				.iter()
				.map(|code| Value::String((*code).to_string()))
				.collect();
			request.insert("countryCodes".to_string(), Value::Array(values));
		}

		let response = self
			.driver
			.request("startKycAnchor", Value::Object(request))?;
		let url = field_str(&response, "url")?.to_string();
		let api = field_str(&response, "api")?.to_string();
		let root = field_str(&response, "root")?.to_string();
		let ca = field_str(&response, "ca")?.to_string();
		let provider_id = field_str(&response, "providerId")?.to_string();
		let blob = field_str(&response, "blob")?.to_string();
		let country_codes = optional_string_array(&response, "countryCodes");
		let signer = response
			.get("signer")
			.and_then(Value::as_str)
			.map(str::to_string);

		Ok(KycAnchor { url, api, root, ca, signer, provider_id, country_codes, blob })
	}

	/// Publish `metadata` on-chain to a fresh root account on the running node,
	/// returning the node API and root account to resolve it through.
	///
	/// Requires a running anchor (started via [`start_kyc_anchor`]) so the
	/// document is published to the same node the anchor's metadata lives on.
	pub fn publish_metadata(&mut self, metadata: &Value) -> Result<PublishedRoot, HarnessError> {
		let response = self
			.driver
			.request("publishMetadata", json!({ "metadata": metadata }))?;
		let api = field_str(&response, "api")?.to_string();
		let root = field_str(&response, "root")?.to_string();

		Ok(PublishedRoot { api, root })
	}

	/// Stop the running KYC anchor server.
	pub fn stop_kyc_anchor(&mut self) -> Result<(), HarnessError> {
		self.driver
			.request("stopKycAnchor", Value::Object(Map::new()))?;
		Ok(())
	}

	/// Format an arbitrary metadata value into a base64 blob via the harness
	/// `formatMetadata`, to exercise decode independent of the server.
	pub fn build_metadata(&mut self, metadata: &Value) -> Result<String, HarnessError> {
		let response = self
			.driver
			.request("buildMetadata", json!({ "metadata": metadata }))?;
		Ok(field_str(&response, "blob")?.to_string())
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(self) -> Result<(), HarnessError> {
		self.driver.shutdown()
	}
}

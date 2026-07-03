//! Driver for the KYC interop harness (`dist/kyc.js`).

use keetanetwork_anchor::signing::Signed;
use keetanetwork_anchor_client::{decode_base64, parse_metadata};
use serde_json::{json, Map, Value};

use super::driver::{field_str, optional_string_array, HarnessDriver, HarnessError};

/// The subject seed shared by the issuer and the reader across the round-trip
/// between the Rust core and the reference anchor.
pub const SUBJECT_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// The attributes exercised by the round-trip, spanning a plain string scalar, a
/// date (`UTCTime`/`GeneralizedTime`), and two structured types whose CHOICE
/// fields carry the positional wrapper.
pub fn issue_attributes() -> Value {
	json!([
		{ "name": "fullName", "sensitive": true, "value": "Test User" },
		{ "name": "email", "sensitive": true, "value": "user@example.com" },
		{ "name": "dateOfBirth", "sensitive": true, "value": { "__date": "1980-01-01T00:00:00.000Z" } },
		{ "name": "address", "sensitive": true, "value": {
			"addressLines": ["100 Belgrave Street"],
			"addressType": "HOME",
			"streetName": "100 Belgrave Street",
			"townName": "Oldsmar",
			"countrySubDivision": "FL",
			"postalCode": "34677"
		} },
		{ "name": "entityType", "sensitive": true, "value": {
			"person": [{ "id": "123-45-6789", "schemeName": "SSN" }]
		} },
		{ "name": "documentPassport", "sensitive": true, "value": {
			"documentNumber": "X1234567",
			"fullName": "Jane Doe",
			"issuingCountry": "US",
			"nationality": "US",
			"address": { "country": "US", "postalCode": "34677", "townName": "Oldsmar" },
			"front": {
				"external": { "url": "https://example.test/doc", "contentType": "image/png" },
				"digest": {
					"digestAlgorithm": "sha3-256",
					"digest": { "type": "Buffer", "data": [1, 2, 3] }
				},
				"encryptionAlgorithm": "1.3.6.1.4.1.62675.2"
			}
		} }
	])
}

/// One issue attribute projected for both directions of the round-trip: its
/// `name`, the `semantic` bytes the core codec encodes, whether it is
/// `sensitive`, and the `expected` value a reader recovers.
pub struct AttributeCase {
	/// The attribute name.
	pub name: String,
	/// The semantic bytes the core codec encodes for it.
	pub semantic: Vec<u8>,
	/// Whether the attribute is encrypted.
	pub sensitive: bool,
	/// The value a reader recovers for it.
	pub expected: Value,
}

/// Project [`issue_attributes`] into the encode/compare cases shared by both
/// directions. The input is a fixed literal, so a malformed shape is a test bug.
pub fn attribute_cases() -> Vec<AttributeCase> {
	let attributes = issue_attributes();
	let entries = attributes.as_array().expect("issue attributes is an array");

	entries
		.iter()
		.map(|entry| {
			let name = entry
				.get("name")
				.and_then(Value::as_str)
				.expect("attribute name");
			let sensitive = entry
				.get("sensitive")
				.and_then(Value::as_bool)
				.expect("attribute sensitive flag");
			let value = entry.get("value").expect("attribute value");
			let (semantic, expected) = semantic_and_expected(value);

			AttributeCase { name: name.to_string(), semantic, sensitive, expected }
		})
		.collect()
}

/// Project an issue attribute's JSON value into the bytes the core codec encodes
/// and the value a reader emits for it.
fn semantic_and_expected(value: &Value) -> (Vec<u8>, Value) {
	match value {
		Value::String(text) => (text.clone().into_bytes(), value.clone()),
		Value::Object(map) => match map.get("__date") {
			Some(Value::String(iso)) => (iso.clone().into_bytes(), Value::String(iso.clone())),
			_ => (serde_json::to_vec(value).expect("structured attribute serializes"), value.clone()),
		},
		_ => panic!("issue attribute value must be a string or object"),
	}
}

/// Project decoded attribute bytes into the value to compare: a scalar is its
/// UTF-8 text, a structured attribute is its JSON object.
pub fn decoded_to_value(expected: &Value, bytes: Vec<u8>) -> Value {
	let text = String::from_utf8(bytes).expect("decoded attribute is UTF-8");
	match expected {
		Value::String(_) => Value::String(text),
		_ => serde_json::from_str(&text).expect("decoded structured attribute is JSON"),
	}
}

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

/// A certificate chain the harness published on-chain for a fresh holder: one
/// leaf recorded with the anchor's CA as its intermediate bundle and a second
/// leaf recorded without intermediates.
pub struct PublishedChain {
	/// The node API base URL the resolver reads the holder through.
	pub api: String,
	/// The holder account the records are published under.
	pub account: String,
	/// The leaf recorded with the CA intermediate (PEM).
	pub leaf: String,
	/// The leaf recorded without intermediates (PEM).
	pub bare: String,
	/// The CA that issued both leaves (PEM).
	pub ca: String,
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

	/// Publish a certificate chain on-chain for a fresh funded holder account
	/// on the running node: one record carrying the anchor's CA as its
	/// intermediate bundle and one recorded without intermediates.
	///
	/// Requires a running anchor (started via [`start_kyc_anchor`]).
	pub fn publish_certificate_chain(&mut self) -> Result<PublishedChain, HarnessError> {
		let response = self
			.driver
			.request("publishCertificateChain", Value::Object(Map::new()))?;
		let api = field_str(&response, "api")?.to_string();
		let account = field_str(&response, "account")?.to_string();
		let leaf = field_str(&response, "leaf")?.to_string();
		let bare = field_str(&response, "bare")?.to_string();
		let ca = field_str(&response, "ca")?.to_string();

		Ok(PublishedChain { api, account, leaf, bare, ca })
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

	/// Issue a populated leaf for `subject_seed` under the running anchor's CA,
	/// returning the response (`leaf` PEM, `ca`, and the read-back values).
	/// Requires a running anchor (started via [`start_kyc_anchor`]).
	pub fn issue_certificate(&mut self, subject_seed: &str, attributes: &Value) -> Result<Value, HarnessError> {
		self.driver
			.request("issueCertificate", json!({ "subjectSeed": subject_seed, "attributes": attributes }))
	}

	/// Read `attributes` back from an externally issued `leaf` (e.g. one built by
	/// the Rust core) using `subject_seed` to decrypt the sensitive ones. No
	/// running anchor is required.
	pub fn decode_certificate(
		&mut self,
		leaf: &str,
		subject_seed: &str,
		attributes: &[&str],
	) -> Result<Value, HarnessError> {
		self.driver.request(
			"decodeCertificate",
			json!({ "leaf": leaf, "subjectSeed": subject_seed, "attributes": attributes }),
		)
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(self) -> Result<(), HarnessError> {
		self.driver.shutdown()
	}
}

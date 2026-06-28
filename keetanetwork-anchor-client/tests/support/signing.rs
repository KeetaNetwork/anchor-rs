//! Driver for the signing interop harness (`dist/signing.js`).

use keetanetwork_anchor::signing::Signed;
use serde_json::{json, Value};

use super::driver::{field_bool, field_str, verified_account, HarnessDriver, HarnessError};

/// A signature produced by the harness `FormatData`/sign path.
pub struct HarnessSignature {
	/// The DER verification bytes, hex-encoded.
	pub verification_data: String,
	/// The base64-encoded signature.
	pub signature: String,
}

/// A live signing harness driven over JSON lines.
pub struct SigningHarness {
	driver: HarnessDriver,
}

impl SigningHarness {
	/// Spawn the signing harness and wait for its `ready` line.
	pub fn start() -> Result<Self, HarnessError> {
		Ok(Self { driver: HarnessDriver::spawn("signing")? })
	}

	/// The harness-owned signer's `publicKeyAndType` hex.
	pub fn signer_public_key_and_type(&self) -> Result<&str, HarnessError> {
		self.driver.ready_field("signerPublicKeyAndType")
	}

	/// The harness-owned signer's `publicKeyString` (the `keeta_…` address used
	/// as the URL/body `account` parameter).
	pub fn signer_public_key_string(&self) -> Result<&str, HarnessError> {
		self.driver.ready_field("signerPublicKeyString")
	}

	/// The harness-owned secondary account's `publicKeyAndType` hex, used for
	/// account-typed signable parts.
	pub fn secondary_public_key_and_type(&self) -> Result<&str, HarnessError> {
		self.driver.ready_field("secondaryPublicKeyAndType")
	}

	/// Sign `data` with the harness signer for a fixed nonce and timestamp,
	/// returning the hex verification bytes and base64 signature.
	pub fn sign(&mut self, nonce: &str, timestamp: &str, data: Value) -> Result<HarnessSignature, HarnessError> {
		let request = json!({ "nonce": nonce, "timestamp": timestamp, "data": data });
		let response = self.driver.request("sign", request)?;

		let verification_data = field_str(&response, "verificationData")?.to_string();
		let signature = field_str(&response, "signature")?.to_string();
		Ok(HarnessSignature { verification_data, signature })
	}

	/// Verify a Rust-produced signature using the harness verifier.
	pub fn verify(
		&mut self,
		public_key_and_type: &str,
		nonce: &str,
		timestamp: &str,
		signature: &str,
		data: Value,
	) -> Result<bool, HarnessError> {
		let request = json!({
			"publicKeyAndType": public_key_and_type,
			"nonce": nonce,
			"timestamp": timestamp,
			"signature": signature,
			"data": data,
		});

		let response = self.driver.request("verify", request)?;
		field_bool(&response, "valid")
	}

	/// Attach a signature to `base_url` via `addSignatureToURL`, returning the
	/// resulting URL string.
	pub fn add_signature_to_url(
		&mut self,
		base_url: &str,
		account: &str,
		signed: &Signed,
	) -> Result<String, HarnessError> {
		let request = json!({
			"baseUrl": base_url,
			"account": account,
			"nonce": signed.nonce,
			"timestamp": signed.timestamp,
			"signature": signed.signature,
		});

		let response = self.driver.request("addSignatureToURL", request)?;
		Ok(field_str(&response, "url")?.to_string())
	}

	/// Verify a URL-signed request via `verifyURLAuth`, returning the
	/// authenticated account string, or `None` when rejected.
	pub fn verify_url(&mut self, url: &str, data: Value) -> Result<Option<String>, HarnessError> {
		let response = self
			.driver
			.request("verifyURLAuth", json!({ "url": url, "data": data }))?;
		verified_account(&response)
	}

	/// Verify a body-signed request via `verifyBodyAuth`, returning the
	/// authenticated account string, or `None` when rejected.
	pub fn verify_body(&mut self, account: &str, signed: &Signed, data: Value) -> Result<Option<String>, HarnessError> {
		let request = json!({
			"account": account,
			"nonce": signed.nonce,
			"timestamp": signed.timestamp,
			"signature": signed.signature,
			"data": data,
		});

		let response = self.driver.request("verifyBodyAuth", request)?;
		verified_account(&response)
	}

	/// Canonicalize `value` via `objectToSignable`, returning the resulting
	/// signable string parts.
	pub fn object_to_signable(&mut self, value: &Value) -> Result<Vec<String>, HarnessError> {
		let response = self
			.driver
			.request("objectToSignable", json!({ "value": value }))?;
		let parts = response
			.get("signable")
			.and_then(Value::as_array)
			.ok_or(HarnessError::MissingField { field: "signable" })?;

		parts
			.iter()
			.map(|part| {
				part.as_str()
					.map(str::to_string)
					.ok_or(HarnessError::MissingField { field: "signable" })
			})
			.collect()
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(self) -> Result<(), HarnessError> {
		self.driver.shutdown()
	}
}

//! Test-only driver for the TypeScript anchor signing harness.
//!
//! Spawns `node node-harness/dist/anchor-sign.js` and exchanges one JSON object
//! per line (request on stdin, response on stdout).

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Lines, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use keetanetwork_anchor::signing::Signed;
use serde_json::{json, Map, Value};
use snafu::Snafu;

/// Errors raised while resolving or driving the TypeScript harness.
#[derive(Debug, Snafu)]
pub enum HarnessError {
	/// The compiled harness script was not found.
	#[snafu(display("harness script not found at {} (run `make node-harness`)", searched.display()))]
	ScriptNotFound {
		/// The path that was searched.
		searched: PathBuf,
	},

	/// Spawning or talking to the `node` process failed.
	#[snafu(display("node process I/O failed: {source}"))]
	Io {
		/// The underlying I/O error.
		source: std::io::Error,
	},

	/// The harness process closed its output stream unexpectedly.
	#[snafu(display("harness process ended unexpectedly"))]
	UnexpectedEof,

	/// A protocol line was not valid JSON.
	#[snafu(display("invalid harness protocol line: {source}"))]
	Protocol {
		/// The underlying JSON error.
		source: serde_json::Error,
	},

	/// The harness reported a command failure.
	#[snafu(display("harness command {command} failed: {message}"))]
	CommandFailed {
		/// The command that failed.
		command: String,
		/// The error message reported by the harness.
		message: String,
	},

	/// A response was missing an expected field.
	#[snafu(display("harness response missing field `{field}`"))]
	MissingField {
		/// The missing field name.
		field: &'static str,
	},
}

impl From<std::io::Error> for HarnessError {
	fn from(source: std::io::Error) -> Self {
		Self::Io { source }
	}
}

impl From<serde_json::Error> for HarnessError {
	fn from(source: serde_json::Error) -> Self {
		Self::Protocol { source }
	}
}

/// A signature produced by the harness `FormatData`/sign path.
pub struct HarnessSignature {
	/// The DER verification bytes, hex-encoded.
	pub verification_data: String,
	/// The base64-encoded signature.
	pub signature: String,
}

/// A live TypeScript anchor signing harness driven over JSON lines.
pub struct AnchorHarness {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
	ready: Value,
}

impl AnchorHarness {
	/// Spawn the harness and wait for its `ready` line.
	pub fn start() -> Result<Self, HarnessError> {
		let script = script_path()?;

		let mut child = Command::new("node")
			.arg(&script)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()?;

		let stdin = child.stdin.take().ok_or(HarnessError::UnexpectedEof)?;
		let stdout = child.stdout.take().ok_or(HarnessError::UnexpectedEof)?;

		let mut harness = Self { child, stdin, lines: BufReader::new(stdout).lines(), ready: Value::Null };

		let ready = harness.read_response("start")?;
		let event = ready.get("event").and_then(Value::as_str);
		if event != Some("ready") {
			return Err(HarnessError::CommandFailed { command: "start".to_string(), message: ready.to_string() });
		}

		harness.ready = ready;
		Ok(harness)
	}

	/// The harness-owned signer's `publicKeyAndType` hex.
	pub fn signer_public_key_and_type(&self) -> Result<&str, HarnessError> {
		self.ready_field("signerPublicKeyAndType")
	}

	/// The harness-owned signer's `publicKeyString` (the `keeta_…` address used
	/// as the URL/body `account` parameter).
	pub fn signer_public_key_string(&self) -> Result<&str, HarnessError> {
		self.ready_field("signerPublicKeyString")
	}

	/// The harness-owned secondary account's `publicKeyAndType` hex, used for
	/// account-typed signable parts.
	pub fn secondary_public_key_and_type(&self) -> Result<&str, HarnessError> {
		self.ready_field("secondaryPublicKeyAndType")
	}

	/// Sign `data` with the harness signer for a fixed nonce and timestamp,
	/// returning the hex verification bytes and base64 signature.
	pub fn sign(&mut self, nonce: &str, timestamp: &str, data: Value) -> Result<HarnessSignature, HarnessError> {
		let request = json!({ "nonce": nonce, "timestamp": timestamp, "data": data });
		let response = self.request("sign", request)?;

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

		let response = self.request("verify", request)?;
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

		let response = self.request("addSignatureToURL", request)?;
		Ok(field_str(&response, "url")?.to_string())
	}

	/// Verify a URL-signed request via `verifyURLAuth`, returning the
	/// authenticated account string, or `None` when rejected.
	pub fn verify_url(&mut self, url: &str, data: Value) -> Result<Option<String>, HarnessError> {
		let response = self.request("verifyURLAuth", json!({ "url": url, "data": data }))?;
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

		let response = self.request("verifyBodyAuth", request)?;
		verified_account(&response)
	}

	/// Canonicalize `value` via `objectToSignable`,
	/// returning the resulting signable string parts.
	pub fn object_to_signable(&mut self, value: &Value) -> Result<Vec<String>, HarnessError> {
		let response = self.request("objectToSignable", json!({ "value": value }))?;
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
	pub fn shutdown(mut self) -> Result<(), HarnessError> {
		self.request("shutdown", Value::Object(Map::new()))?;
		self.child.wait()?;
		Ok(())
	}

	fn ready_field(&self, field: &'static str) -> Result<&str, HarnessError> {
		field_str(&self.ready, field)
	}

	fn request(&mut self, command: &str, params: Value) -> Result<Value, HarnessError> {
		let mut object = match params {
			Value::Object(map) => map,
			_ => Map::new(),
		};

		object.insert("cmd".to_string(), Value::String(command.to_string()));
		writeln!(self.stdin, "{}", Value::Object(object))?;

		self.stdin.flush()?;
		self.read_response(command)
	}

	fn read_response(&mut self, command: &str) -> Result<Value, HarnessError> {
		let line = self.lines.next().ok_or(HarnessError::UnexpectedEof)??;
		let value: Value = serde_json::from_str(&line)?;
		if let Some(message) = value.get("error").and_then(Value::as_str) {
			return Err(HarnessError::CommandFailed { command: command.to_string(), message: message.to_string() });
		}

		Ok(value)
	}
}

impl Drop for AnchorHarness {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn field_str<'v>(value: &'v Value, field: &'static str) -> Result<&'v str, HarnessError> {
	value
		.get(field)
		.and_then(Value::as_str)
		.ok_or(HarnessError::MissingField { field })
}

fn field_bool(value: &Value, field: &'static str) -> Result<bool, HarnessError> {
	value
		.get(field)
		.and_then(Value::as_bool)
		.ok_or(HarnessError::MissingField { field })
}

/// Map a `{ valid, account }` verification response into the account string on
/// success, or `None` when the harness reported the signature as invalid.
fn verified_account(response: &Value) -> Result<Option<String>, HarnessError> {
	let valid = field_bool(response, "valid")?;
	if !valid {
		return Ok(None);
	}

	Ok(Some(field_str(response, "account")?.to_string()))
}

/// Resolve the compiled harness entrypoint inside this crate.
pub fn script_path() -> Result<PathBuf, HarnessError> {
	let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("node-harness/dist/anchor-sign.js");
	if !script.exists() {
		return Err(HarnessError::ScriptNotFound { searched: script });
	}

	Ok(script)
}

//! Shared JSON-lines driver for the live TypeScript KYC anchor harness.
//!
//! Both the P2 wasmtime e2e and the bound-language e2e boot the same harness
//! (`node-harness/dist/kyc.js`), publish signed service metadata on-chain, and
//! serve the production `KeetaNetKYCAnchorHTTPServer`.

#![allow(dead_code)]

use std::error::Error;
use std::io::{BufRead, BufReader, Lines, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Map, Value};

/// A boxed, thread-safe error so the driver composes with any test's `?`.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// The subject seed shared by the harness (issuer) and a binding (decryptor)
pub const SUBJECT_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// The attributes the harness issues, spanning every decoded shape: plain string
/// scalars, a date (UTCTime), and two structured types (`Address`, `EntityType`).
pub fn issue_attributes() -> Value {
	json!([
		{ "name": "fullName", "sensitive": true, "value": "Test User" },
		{ "name": "email", "sensitive": true, "value": "user@example.com" },
		{ "name": "dateOfBirth", "sensitive": true, "value": { "__date": "1980-01-01T00:00:00.000Z" } },
		{ "name": "address", "sensitive": true, "value": {
			"addressLines": ["100 Belgrave Street"],
			"streetName": "100 Belgrave Street",
			"townName": "Oldsmar",
			"countrySubDivision": "FL",
			"postalCode": "34677"
		} },
		{ "name": "entityType", "sensitive": true, "value": {
			"person": [{ "id": "123-45-6789", "schemeName": "SSN" }]
		} }
	])
}

/// Locate the compiled KYC harness entry (`dist/kyc.js`).
pub fn harness_path() -> PathBuf {
	if let Ok(path) = std::env::var("KYC_HARNESS") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../../keetanetwork-anchor-client/node-harness/dist/kyc.js")
}

/// Read a required string field from a harness response.
pub fn field_str(value: &Value, field: &str) -> Result<String, BoxError> {
	value
		.get(field)
		.and_then(Value::as_str)
		.map(str::to_string)
		.ok_or_else(|| format!("harness response missing field `{field}`").into())
}

/// A live KYC anchor harness driven over JSON lines.
pub struct KycHarness {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
}

impl KycHarness {
	/// Spawn `node dist/kyc.js` and wait for its `ready` line.
	pub fn start() -> Result<Self, BoxError> {
		let script = harness_path();
		if !script.exists() {
			return Err(format!("KYC harness not found at {} (run `make node-harness`)", script.display()).into());
		}

		let mut child = Command::new("node")
			.arg(&script)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()?;

		let stdin = child.stdin.take().ok_or("harness stdin unavailable")?;
		let stdout = child.stdout.take().ok_or("harness stdout unavailable")?;
		let mut lines = BufReader::new(stdout).lines();

		let ready = lines.next().ok_or("harness ended before ready")??;
		let ready: Value = serde_json::from_str(&ready)?;
		if ready.get("event").and_then(Value::as_str) != Some("ready") {
			return Err(format!("harness did not report ready: {ready}").into());
		}

		Ok(Self { child, stdin, lines })
	}

	/// Send a command with object params and return its response.
	pub fn request(&mut self, command: &str, params: Value) -> Result<Value, BoxError> {
		let mut object = match params {
			Value::Object(map) => map,
			_ => Map::new(),
		};
		object.insert("cmd".to_string(), Value::String(command.to_string()));
		writeln!(self.stdin, "{}", Value::Object(object))?;
		self.stdin.flush()?;

		let line = self
			.lines
			.next()
			.ok_or("harness ended before responding")??;
		let value: Value = serde_json::from_str(&line)?;
		if let Some(message) = value.get("error").and_then(Value::as_str) {
			return Err(format!("harness command `{command}` failed: {message}").into());
		}

		Ok(value)
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(mut self) -> Result<(), BoxError> {
		self.request("shutdown", Value::Object(Map::new()))?;
		self.child.wait()?;
		Ok(())
	}
}

impl Drop for KycHarness {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

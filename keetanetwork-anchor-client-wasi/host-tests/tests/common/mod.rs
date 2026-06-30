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
			"addressType": "HOME",
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

/// The reference value a reader recovers for each issued attribute: a scalar is
/// its string, a `{ "__date": "<ISO>" }` is that ISO string, and a structured
/// value is its object unchanged. Mirrors the reference reader's `getValue`.
pub fn expected_attributes() -> Map<String, Value> {
	let mut expected = Map::new();
	for entry in issue_attributes().as_array().into_iter().flatten() {
		let (Some(name), Some(value)) = (entry.get("name").and_then(Value::as_str), entry.get("value")) else {
			continue;
		};

		let projected = match value.get("__date").and_then(Value::as_str) {
			Some(iso) => Value::String(iso.to_string()),
			None => value.clone(),
		};
		expected.insert(name.to_string(), projected);
	}

	expected
}

/// The names of the issued attributes, in order.
pub fn attribute_names() -> Vec<String> {
	issue_attributes()
		.as_array()
		.into_iter()
		.flatten()
		.filter_map(|entry| entry.get("name").and_then(Value::as_str).map(str::to_string))
		.collect()
}

/// Reshape a flat binding proof `{ value, salt }` into the reference reader's
/// nested `{ value, hash: { salt } }`.
pub fn nest_proof(flat: &Value) -> Value {
	json!({
		"value": flat.get("value").cloned().unwrap_or(Value::Null),
		"hash": { "salt": flat.get("salt").cloned().unwrap_or(Value::Null) },
	})
}

/// Reshape a reference reader proof `{ value, hash: { salt } }` into the flat
/// binding `{ value, salt }`.
pub fn flatten_proof(nested: &Value) -> Value {
	json!({
		"value": nested.get("value").cloned().unwrap_or(Value::Null),
		"salt": nested.get("hash").and_then(|hash| hash.get("salt")).cloned().unwrap_or(Value::Null),
	})
}

/// The value of a `KEY=VALUE` sentinel line in captured stdout, if present.
pub fn sentinel<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
	stdout
		.lines()
		.find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
}

/// Locate the compiled KYC harness entry (`dist/kyc.js`).
pub fn harness_path() -> PathBuf {
	if let Ok(path) = std::env::var("KYC_HARNESS") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../../keetanetwork-anchor-client/node-harness/dist/kyc.js")
}

/// Locate the compiled `EncryptedContainer` harness entry (`dist/container.js`).
pub fn container_harness_path() -> PathBuf {
	if let Ok(path) = std::env::var("CONTAINER_HARNESS") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../../keetanetwork-anchor-client/node-harness/dist/container.js")
}

/// Spawn a JSON-lines node harness at `script` and consume its `ready` line.
fn spawn_harness(script: PathBuf) -> Result<(Child, ChildStdin, Lines<BufReader<ChildStdout>>), BoxError> {
	if !script.exists() {
		return Err(format!("harness not found at {} (run `make node-harness`)", script.display()).into());
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

	Ok((child, stdin, lines))
}

/// Send a `command` with object `params` over a JSON-lines harness and read the
/// response, surfacing an `error` field as a failure.
fn harness_request(
	stdin: &mut ChildStdin,
	lines: &mut Lines<BufReader<ChildStdout>>,
	command: &str,
	params: Value,
) -> Result<Value, BoxError> {
	let mut object = match params {
		Value::Object(map) => map,
		_ => Map::new(),
	};
	object.insert("cmd".to_string(), Value::String(command.to_string()));
	writeln!(stdin, "{}", Value::Object(object))?;
	stdin.flush()?;

	let line = lines.next().ok_or("harness ended before responding")??;
	let value: Value = serde_json::from_str(&line)?;
	if let Some(message) = value.get("error").and_then(Value::as_str) {
		return Err(format!("harness command `{command}` failed: {message}").into());
	}

	Ok(value)
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
		let (child, stdin, lines) = spawn_harness(harness_path())?;
		Ok(Self { child, stdin, lines })
	}

	/// Send a command with object params and return its response.
	pub fn request(&mut self, command: &str, params: Value) -> Result<Value, BoxError> {
		harness_request(&mut self.stdin, &mut self.lines, command, params)
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

/// A live `EncryptedContainer` reference harness driven over JSON lines.
pub struct ContainerHarness {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
}

impl ContainerHarness {
	/// Spawn `node dist/container.js` and wait for its `ready` line.
	pub fn start() -> Result<Self, BoxError> {
		let (child, stdin, lines) = spawn_harness(container_harness_path())?;
		Ok(Self { child, stdin, lines })
	}

	/// Send a command with object params and return its response.
	pub fn request(&mut self, command: &str, params: Value) -> Result<Value, BoxError> {
		harness_request(&mut self.stdin, &mut self.lines, command, params)
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(mut self) -> Result<(), BoxError> {
		self.request("shutdown", Value::Object(Map::new()))?;
		self.child.wait()?;
		Ok(())
	}
}

impl Drop for ContainerHarness {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

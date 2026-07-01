//! Shared JSON-lines driver for the live TypeScript node harnesses.
//!
//! Every harness (KYC, `EncryptedContainer`, asset-movement) speaks the same
//! `ready`/command/response protocol over stdio, so the P2 wasmtime e2e and the
//! bound-language e2e drive them all through one [`Harness`] type.

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
		} },
		{ "name": "documentPassport", "sensitive": true, "value": {
			"documentNumber": "X1234567",
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

/// The reference value a reader recovers for each issued attribute: a scalar is
/// its string, a `{ "__date": "<ISO>" }` is that ISO string, and a structured
/// value is its object unchanged.
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
		.filter_map(|entry| {
			entry
				.get("name")
				.and_then(Value::as_str)
				.map(str::to_string)
		})
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
	stdout.lines().find_map(|line| {
		line.strip_prefix(key)
			.and_then(|rest| rest.strip_prefix('='))
	})
}

/// Locate a compiled node-harness entry at `dist/<default_file>`, letting
/// `env_var` override the path when the build places it elsewhere.
pub fn harness_path(env_var: &str, default_file: &str) -> PathBuf {
	if let Ok(path) = std::env::var(env_var) {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join(format!("../../keetanetwork-anchor-client/node-harness/dist/{default_file}"))
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

/// A live node-harness anchor driven over JSON lines. Every harness speaks the
/// same protocol, so one type serves KYC, `EncryptedContainer`, and
/// asset-movement; the constructors differ only in which script they spawn.
pub struct Harness {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
}

impl Harness {
	/// Spawn the KYC harness (`dist/kyc.js`) and wait for its `ready` line.
	pub fn kyc() -> Result<Self, BoxError> {
		Self::spawn("KYC_HARNESS", "kyc.js")
	}

	/// Spawn the `EncryptedContainer` harness (`dist/container.js`).
	pub fn container() -> Result<Self, BoxError> {
		Self::spawn("CONTAINER_HARNESS", "container.js")
	}

	/// Spawn the asset-movement harness (`dist/asset.js`).
	pub fn asset() -> Result<Self, BoxError> {
		Self::spawn("ASSET_HARNESS", "asset.js")
	}

	/// Spawn the harness `default_file` (overridable via `env_var`) and consume
	/// its `ready` line.
	fn spawn(env_var: &str, default_file: &str) -> Result<Self, BoxError> {
		let (child, stdin, lines) = spawn_harness(harness_path(env_var, default_file))?;
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

impl Drop for Harness {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

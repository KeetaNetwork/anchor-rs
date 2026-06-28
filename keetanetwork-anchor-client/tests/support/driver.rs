//! Shared driver for the TypeScript interop harnesses.
//!
//! Spawns a harness entry (`node node-harness/dist/<name>.js`) and exchanges
//! one JSON object per line (request on stdin, response on stdout).

use std::io::{BufRead, BufReader, Lines, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use keetanetwork_anchor_client::ResolverError;
use serde_json::{Map, Value};
use snafu::Snafu;

/// Errors raised while resolving or driving a TypeScript harness.
#[derive(Debug, Snafu)]
pub enum HarnessError {
	/// The compiled harness entry was not found.
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

	/// Decoding the published metadata blob failed.
	#[snafu(display("metadata blob decode failed: {source}"), context(false))]
	Decode {
		/// The underlying resolver error.
		source: ResolverError,
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

/// A live TypeScript harness entry driven over JSON lines.
pub struct HarnessDriver {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
	ready: Value,
}

impl HarnessDriver {
	/// Spawn the `entry` harness (`dist/<entry>.js`) and wait for its `ready`
	/// line.
	pub fn spawn(entry: &str) -> Result<Self, HarnessError> {
		let script = script_path(entry)?;

		let mut child = Command::new("node")
			.arg(&script)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()?;

		let stdin = child.stdin.take().ok_or(HarnessError::UnexpectedEof)?;
		let stdout = child.stdout.take().ok_or(HarnessError::UnexpectedEof)?;
		let lines = BufReader::new(stdout).lines();

		let mut driver = Self { child, stdin, lines, ready: Value::Null };

		let ready = driver.read_response("start")?;
		if ready.get("event").and_then(Value::as_str) != Some("ready") {
			return Err(HarnessError::CommandFailed { command: "start".to_string(), message: ready.to_string() });
		}

		driver.ready = ready;
		Ok(driver)
	}

	/// A string field from the harness `ready` payload.
	pub fn ready_field(&self, field: &'static str) -> Result<&str, HarnessError> {
		field_str(&self.ready, field)
	}

	/// Send a command with object (or null) params and return its response.
	pub fn request(&mut self, command: &str, params: Value) -> Result<Value, HarnessError> {
		let mut object = match params {
			Value::Object(map) => map,
			_ => Map::new(),
		};

		object.insert("cmd".to_string(), Value::String(command.to_string()));
		writeln!(self.stdin, "{}", Value::Object(object))?;

		self.stdin.flush()?;
		self.read_response(command)
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(mut self) -> Result<(), HarnessError> {
		self.request("shutdown", Value::Object(Map::new()))?;
		self.child.wait()?;
		Ok(())
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

impl Drop for HarnessDriver {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

/// Read a required string field, or report it missing.
pub fn field_str<'v>(value: &'v Value, field: &'static str) -> Result<&'v str, HarnessError> {
	value
		.get(field)
		.and_then(Value::as_str)
		.ok_or(HarnessError::MissingField { field })
}

/// Read a required boolean field, or report it missing.
pub fn field_bool(value: &Value, field: &'static str) -> Result<bool, HarnessError> {
	value
		.get(field)
		.and_then(Value::as_bool)
		.ok_or(HarnessError::MissingField { field })
}

/// Read an optional array-of-strings field, treating `null` or absence as
/// [`None`].
pub fn optional_string_array(value: &Value, field: &str) -> Option<Vec<String>> {
	let entries = value.get(field)?.as_array()?;
	let collected = entries
		.iter()
		.filter_map(|item| item.as_str().map(str::to_string))
		.collect();
	Some(collected)
}

/// Map a `{ valid, account }` verification response into the account string on
/// success, or `None` when the harness reported the signature as invalid.
pub fn verified_account(response: &Value) -> Result<Option<String>, HarnessError> {
	let valid = field_bool(response, "valid")?;
	if !valid {
		return Ok(None);
	}

	Ok(Some(field_str(response, "account")?.to_string()))
}

/// Resolve a compiled harness entry inside this crate.
pub fn script_path(entry: &str) -> Result<PathBuf, HarnessError> {
	let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("node-harness/dist")
		.join(entry)
		.with_extension("js");

	if !script.exists() {
		return Err(HarnessError::ScriptNotFound { searched: script });
	}

	Ok(script)
}

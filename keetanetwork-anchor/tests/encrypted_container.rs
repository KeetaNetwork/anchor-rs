//! Cross-language `EncryptedContainer` conformance against the reference.
//!
//! The Rust core encodes blobs the reference opens and verifies, and decodes
//! blobs the reference produced. Principals and signers are derived from
//! shared seeds plus a key algorithm so both runtimes reproduce the same
//! accounts. Each signed case also confirms the recovered signer identity
//! matches the expected key.

use std::error::Error;
use std::io::{BufRead, BufReader, Lines, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use keetanetwork_account::{
	Account, AccountPublicKey, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPair,
	Keyable,
};
use keetanetwork_anchor::encrypted_container::{EncryptedContainer, FromPlaintextOptions};
use keetanetwork_crypto::prelude::IntoSecret;
use serde_json::{json, Map, Value};

/// A boxed, thread-safe error so the driver composes with each test's `?`.
type BoxError = Box<dyn Error + Send + Sync>;

/// The seed both runtimes derive the encryption principal from.
const PRINCIPAL_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// The seed the signing side derives its signer from.
const SIGNER_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A key algorithm exercised on both sides of the boundary. The name is the
/// token the harness maps back to its account key algorithm.
#[derive(Clone, Copy)]
enum Algorithm {
	Secp256k1,
	Ed25519,
	Secp256r1,
}

impl Algorithm {
	fn name(self) -> &'static str {
		match self {
			Algorithm::Secp256k1 => "secp256k1",
			Algorithm::Ed25519 => "ed25519",
			Algorithm::Secp256r1 => "secp256r1",
		}
	}
}

const ALGORITHMS: [Algorithm; 3] = [Algorithm::Secp256k1, Algorithm::Ed25519, Algorithm::Secp256r1];

/// One conformance case: the container shape plus the key algorithm used for its
/// principal (when encrypted) and signer (when signed).
struct Case {
	label: &'static str,
	encrypted: bool,
	signed: bool,
	algorithm: Algorithm,
}

impl Case {
	fn describe(&self) -> String {
		format!("{} ({})", self.label, self.algorithm.name())
	}

	fn payload(&self) -> Vec<u8> {
		self.describe().into_bytes()
	}
}

/// The matrix: one unsigned plaintext case (algorithm-independent), then signed
/// and encrypted variants across every key algorithm so signing is proven for
/// each curve, including the combined encrypted-and-signed shape.
fn cases() -> Vec<Case> {
	let mut cases = vec![Case { label: "plaintext", encrypted: false, signed: false, algorithm: Algorithm::Secp256k1 }];
	for algorithm in ALGORITHMS {
		cases.push(Case { label: "plaintext-signed", encrypted: false, signed: true, algorithm });
		cases.push(Case { label: "encrypted", encrypted: true, signed: false, algorithm });
		cases.push(Case { label: "encrypted-signed", encrypted: true, signed: true, algorithm });
	}

	cases
}

/// Derive a generic account (with private key) from a seed at index 0 for a
/// concrete key type. The macro keeps each typed `Account` construction in one
/// place while the type itself varies per algorithm arm.
macro_rules! generic_from_seed {
	($key:ty, $seed:expr) => {{
		let keyable = Keyable::HexSeed(($seed.to_string().into_secret(), 0));
		let accountable = Accountable::KeyAndType(keyable, <$key>::KEY_PAIR_TYPE);
		let account = Account::<$key>::try_from(accountable)?;
		let private_key = account
			.keypair
			.take_private_key()
			.ok_or("derived account is missing its private key")?;

		GenericAccount::try_from(private_key)?
	}};
}

/// A generic account (with private key) derived from `seed` at index 0 for the
/// given algorithm, reproducible across runtimes and across calls.
fn account_from_seed(seed: &str, algorithm: Algorithm) -> Result<Arc<GenericAccount>, BoxError> {
	let generic = match algorithm {
		Algorithm::Secp256k1 => generic_from_seed!(KeyECDSASECP256K1, seed),
		Algorithm::Ed25519 => generic_from_seed!(KeyED25519, seed),
		Algorithm::Secp256r1 => generic_from_seed!(KeyECDSASECP256R1, seed),
	};
	Ok(Arc::new(generic))
}

fn require_bool(value: &Value, field: &str) -> Result<bool, BoxError> {
	value
		.get(field)
		.and_then(Value::as_bool)
		.ok_or_else(|| format!("response missing bool `{field}`").into())
}

fn require_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, BoxError> {
	value
		.get(field)
		.and_then(Value::as_str)
		.ok_or_else(|| format!("response missing string `{field}`").into())
}

fn require_bytes(value: &Value, field: &str) -> Result<Vec<u8>, BoxError> {
	let decoded = STANDARD.decode(require_str(value, field)?)?;
	Ok(decoded)
}

#[test]
fn rust_encodes_reference_decodes() -> Result<(), BoxError> {
	let mut harness = ContainerHarness::start()?;
	for case in cases() {
		let payload = case.payload();
		let principals = match case.encrypted {
			true => Some(vec![account_from_seed(PRINCIPAL_SEED, case.algorithm)?]),
			false => None,
		};
		let signer = match case.signed {
			true => Some(account_from_seed(SIGNER_SEED, case.algorithm)?),
			false => None,
		};

		let options = FromPlaintextOptions { locked: Some(false), signer };
		let mut container = EncryptedContainer::from_plaintext(payload.clone(), principals, options);
		let encoded = container.get_encoded()?;

		let mut params = Map::new();
		params.insert("encoded".to_string(), Value::String(STANDARD.encode(&encoded)));

		if case.encrypted {
			params.insert("principalSeeds".to_string(), json!([PRINCIPAL_SEED]));
			params.insert("principalAlgorithm".to_string(), Value::String(case.algorithm.name().to_string()));
		}

		let response = harness.request("decode", Value::Object(params))?;
		assert_eq!(
			require_bytes(&response, "plaintext")?,
			payload,
			"reference plaintext mismatch for {}",
			case.describe()
		);
		assert_eq!(
			require_bool(&response, "encrypted")?,
			case.encrypted,
			"reference encrypted flag mismatch for {}",
			case.describe()
		);
		assert_eq!(
			require_bool(&response, "isSigned")?,
			case.signed,
			"reference signed flag mismatch for {}",
			case.describe()
		);

		if case.signed {
			assert!(require_bool(&response, "signatureValid")?, "reference rejected signature for {}", case.describe());

			let expected_signer = account_from_seed(SIGNER_SEED, case.algorithm)?;
			let expected_signer_key = hex::encode(expected_signer.to_public_key_with_type());
			assert_eq!(
				require_str(&response, "signerPublicKey")?,
				expected_signer_key,
				"reference recovered wrong signer for {}",
				case.describe()
			);
		}
	}

	harness.shutdown()
}

#[test]
fn reference_encodes_rust_decodes() -> Result<(), BoxError> {
	let mut harness = ContainerHarness::start()?;
	for case in cases() {
		let payload = case.payload();
		let command = match case.encrypted {
			true => "encodeEncrypted",
			false => "encodePlaintext",
		};

		let mut params = Map::new();
		params.insert("plaintext".to_string(), Value::String(STANDARD.encode(&payload)));

		if case.encrypted {
			params.insert("principalSeeds".to_string(), json!([PRINCIPAL_SEED]));
			params.insert("principalAlgorithm".to_string(), Value::String(case.algorithm.name().to_string()));
		}
		if case.signed {
			params.insert("signerSeed".to_string(), Value::String(SIGNER_SEED.to_string()));
			params.insert("signerAlgorithm".to_string(), Value::String(case.algorithm.name().to_string()));
		}

		let response = harness.request(command, Value::Object(params))?;
		let encoded = require_bytes(&response, "encoded")?;
		let principals = vec![account_from_seed(PRINCIPAL_SEED, case.algorithm)?];

		let mut container = match case.encrypted {
			true => EncryptedContainer::from_encrypted(&encoded, principals)?,
			false => EncryptedContainer::from_encoded(&encoded, None)?,
		};
		assert_eq!(container.get_plaintext()?, payload, "rust plaintext mismatch for {}", case.describe());
		assert_eq!(container.is_encrypted(), case.encrypted, "rust encrypted flag mismatch for {}", case.describe());
		assert_eq!(container.is_signed(), case.signed, "rust signed flag mismatch for {}", case.describe());

		if case.signed {
			assert!(container.verify_signature()?, "rust rejected reference signature for {}", case.describe());

			let recovered = container
				.signing_account()?
				.ok_or("rust recovered no signing account")?;

			let expected_signer = account_from_seed(SIGNER_SEED, case.algorithm)?;
			assert_eq!(
				recovered.to_public_key_with_type(),
				expected_signer.to_public_key_with_type(),
				"rust recovered wrong signer for {}",
				case.describe()
			);
		}
	}

	harness.shutdown()
}

/// Locate the compiled container harness entry (`dist/container.js`).
fn harness_path() -> PathBuf {
	if let Ok(path) = std::env::var("CONTAINER_HARNESS") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../keetanetwork-anchor-client/node-harness/dist/container.js")
}

/// The reference container harness driven over JSON lines.
struct ContainerHarness {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
}

impl ContainerHarness {
	/// Spawn `node dist/container.js` and wait for its `ready` line.
	fn start() -> Result<Self, BoxError> {
		let script = harness_path();
		if !script.exists() {
			return Err(format!("container harness not found at {} (run `make node-harness`)", script.display()).into());
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
	fn request(&mut self, command: &str, params: Value) -> Result<Value, BoxError> {
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
	fn shutdown(mut self) -> Result<(), BoxError> {
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

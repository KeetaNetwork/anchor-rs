//! C# `EncryptedContainer` SDK <-> TypeScript anchor conformance, both directions
//!
//! Using only the real C# SDK (over the P1 core module) and the reference
//! TypeScript `EncryptedContainer`, it covers the full cross-implementation
//! round trip for an encrypted, signed container:
//!   - TS encrypts + signs -> C# decrypts + verifies   (`TS_DECODE/VERIFY/SIGNER`)
//!   - C# encrypts + signs  -> TS decrypts + verifies   (`decode`)

mod common;
mod dotnet;

use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

use common::{sentinel, BoxError, ContainerHarness};
use dotnet::{dotnet_available, harness_dir, module_path};

/// The seed the encryption principal derives from on both sides.
const PRINCIPAL_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// The seed the signer derives from on both sides.
const SIGNER_SEED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// The TS-side key algorithm token; the C# side names the same curve
/// `ecdsa_secp256k1`, and both derive the identical account from a seed.
const TS_ALGORITHM: &str = "secp256k1";

#[test]
fn csharp_container_conforms_with_typescript_anchor() -> Result<(), BoxError> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# container conformance: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# container conformance: build the wasm32-wasip1 module first ({})", module.display());
		return Ok(());
	}

	let mut harness = ContainerHarness::start()?;

	// TS encrypts + signs a container our C# SDK must decrypt and verify.
	let ts_plaintext = STANDARD.encode(b"typescript encrypted and signed container");
	let ts_encoded = harness.request(
		"encodeEncrypted",
		json!({
			"plaintext": ts_plaintext,
			"principalSeeds": [PRINCIPAL_SEED],
			"principalAlgorithm": TS_ALGORITHM,
			"signerSeed": SIGNER_SEED,
			"signerAlgorithm": TS_ALGORITHM,
		}),
	)?;
	let ts_container = field_str(&ts_encoded, "encoded")?;

	// Run the C# SDK conformance: it decodes the TS container, then emits one of
	// its own for the TS reader to read back.
	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_CONTAINER_CONFORMANCE", "1")
		.env("KEETA_PRINCIPAL_SEED", PRINCIPAL_SEED)
		.env("KEETA_SIGNER_SEED", SIGNER_SEED)
		.env("KEETA_TS_CONTAINER", &ts_container)
		.env("KEETA_TS_PLAINTEXT", &ts_plaintext)
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	let context = || format!("STDOUT:\n{stdout}\nSTDERR:\n{stderr}");

	assert!(output.status.success(), "the C# container SDK must exit zero\n{}", context());
	assert!(stdout.contains("CONTAINER_CONFORMANCE_OK"), "the C# SDK must print the conformance sentinel\n{}", context());

	// TS encrypts + signs -> C# decrypts + verifies, recovering the right signer.
	assert_eq!(sentinel(&stdout, "TS_DECODE_OK"), Some("true"), "C# must decrypt the TS container\n{}", context());
	assert_eq!(sentinel(&stdout, "TS_VERIFY_OK"), Some("true"), "C# must verify the TS signature\n{}", context());
	assert_eq!(sentinel(&stdout, "TS_SIGNER_OK"), Some("true"), "C# must recover the TS signer\n{}", context());

	// C# encrypts + signs -> TS decrypts + verifies.
	let cs_container = sentinel(&stdout, "CS_CONTAINER").ok_or_else(|| format!("missing CS_CONTAINER\n{}", context()))?;
	let cs_plaintext = sentinel(&stdout, "CS_PLAINTEXT").ok_or_else(|| format!("missing CS_PLAINTEXT\n{}", context()))?;
	let cs_signer_key =
		sentinel(&stdout, "CS_SIGNER_KEY").ok_or_else(|| format!("missing CS_SIGNER_KEY\n{}", context()))?;

	let decoded = harness.request(
		"decode",
		json!({ "encoded": cs_container, "principalSeeds": [PRINCIPAL_SEED], "principalAlgorithm": TS_ALGORITHM }),
	)?;
	assert_eq!(field_str(&decoded, "plaintext")?, cs_plaintext, "the TS reader must recover the C# plaintext");
	assert!(field_bool(&decoded, "encrypted")?, "the TS reader must report the C# container as encrypted");
	assert!(field_bool(&decoded, "isSigned")?, "the TS reader must report the C# container as signed");
	assert!(field_bool(&decoded, "signatureValid")?, "the TS reader must validate the C# signature");
	assert_eq!(field_str(&decoded, "signerPublicKey")?, cs_signer_key, "the TS reader must recover the C# signer");

	harness.shutdown()?;
	Ok(())
}

/// Read a required string field from a harness response.
fn field_str(value: &Value, field: &str) -> Result<String, BoxError> {
	value
		.get(field)
		.and_then(Value::as_str)
		.map(str::to_string)
		.ok_or_else(|| format!("harness response missing string `{field}`").into())
}

/// Read a required boolean field from a harness response.
fn field_bool(value: &Value, field: &str) -> Result<bool, BoxError> {
	value
		.get(field)
		.and_then(Value::as_bool)
		.ok_or_else(|| format!("harness response missing bool `{field}`").into())
}

//! C# KYC SDK <-> TypeScript anchor compatibility, end-to-end over real services
//!
//! It covers the full cross-implementation matrix for KYC certificates, both
//! directions, using only the real anchor, the real C# SDK, and the real
//! reference TypeScript library:
//!   - TS issues (encrypts)   -> C# decrypts            (`ATTRIBUTES_OK`)
//!   - TS proves              -> C# validates           (`TS_PROOF_VALID/WRONG`)
//!   - C# issues (encrypts)   -> TS decrypts            (`decodeCertificate`)
//!   - C# proves              -> TS validates           (`validateProof`)

mod common;
mod dotnet;

use std::process::Command;

use serde_json::{json, Value};

use common::{
	attribute_names, expected_attributes, field_str, flatten_proof, issue_attributes, nest_proof, sentinel, BoxError,
	Harness, SUBJECT_SEED,
};
use dotnet::{dotnet_available, harness_dir, module_path};

/// The sensitive attribute proven in both directions, and a different sensitive
/// attribute a proof must not validate against.
const PROOF_NAME: &str = "email";
const WRONG_NAME: &str = "fullName";

#[test]
fn csharp_sdk_conforms_with_typescript_anchor() -> Result<(), BoxError> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# compatibility: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# compatibility: build the wasm32-wasip1 module first ({})", module.display());
		return Ok(());
	}

	let mut harness = Harness::kyc()?;

	// Boot the real KYC anchor advertising a signed, US-bound provider, with its
	// metadata published on-chain to a root account the SDK resolves over HTTP.
	let started = harness.request("startKycAnchor", json!({ "sign": true, "countryCodes": ["US"] }))?;
	let api = field_str(&started, "api")?;
	let root = field_str(&started, "root")?;
	let provider_id = field_str(&started, "providerId")?;

	// The anchor issues a populated leaf for our subject; capture the reference
	// values it reads back, so the C# SDK can prove its decode matches the TS
	// `getValue()` across scalars, a date, and structured `Address`/`EntityType`.
	let issued = harness
		.request("issueCertificate", json!({ "subjectSeed": SUBJECT_SEED, "attributes": issue_attributes() }))?;
	let anchor_leaf = field_str(&issued, "leaf")?;
	let issued_verification_id = field_str(&issued, "verificationID")?;
	let reference = issued
		.get("attributes")
		.ok_or("issued certificate is missing its attributes")?;
	let reference_json = serde_json::to_string(reference)?;

	// A two-record certificate chain published on-chain for a fresh holder, the
	// fixture the C# `GetAllCertificates` ledger read must serve back.
	let chain = harness.request("publishCertificateChain", json!({}))?;
	let chain_account = field_str(&chain, "account")?;
	let chain_ca = field_str(&chain, "ca")?;

	// The TypeScript reader proves an attribute on the anchor leaf; the C# SDK
	// must validate that proof (TS proves -> C# validates).
	let ts_proof = harness
		.request("proveAttribute", json!({ "leaf": anchor_leaf, "subjectSeed": SUBJECT_SEED, "name": PROOF_NAME }))?;
	let ts_proof_flat = flatten_proof(
		ts_proof
			.get("proof")
			.ok_or("proveAttribute response is missing its proof")?,
	);

	// Run the C# SDK end-to-end against the live anchor
	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_NODE_API", &api)
		.env("KEETA_ROOT", &root)
		.env("KEETA_PROVIDER_ID", &provider_id)
		.env("KEETA_LEAF_PEM", &anchor_leaf)
		.env("KEETA_ISSUED_VERIFICATION_ID", &issued_verification_id)
		.env("KEETA_CHAIN_ACCOUNT", &chain_account)
		.env("KEETA_CHAIN_CA", &chain_ca)
		.env("KEETA_ATTRIBUTES_JSON", &reference_json)
		.env("KEETA_SUBJECT_SEED", SUBJECT_SEED)
		.env("KEETA_COMPATIBILITY", "1")
		.env("KEETA_ISSUE_JSON", issue_attributes().to_string())
		.env("KEETA_TS_PROOF_JSON", ts_proof_flat.to_string())
		.env("KEETA_TS_PROOF_NAME", PROOF_NAME)
		.env("KEETA_TS_WRONG_NAME", WRONG_NAME)
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	let context = || format!("STDOUT:\n{stdout}\nSTDERR:\n{stderr}");

	assert!(output.status.success(), "the C# SDK must exit zero\n{}", context());
	for marker in ["KYC_OK", "ATTRIBUTES_OK", "COMPATIBILITY_OK"] {
		assert!(stdout.contains(marker), "the C# SDK must print `{marker}`\n{}", context());
	}

	// TS proves -> C# validates: the proof validates for its attribute and not
	// for a different one.
	assert_eq!(sentinel(&stdout, "TS_PROOF_VALID"), Some("true"), "C# must validate the TS proof\n{}", context());
	assert_eq!(
		sentinel(&stdout, "TS_PROOF_WRONG"),
		Some("false"),
		"a TS proof must not validate against a different attribute in C#\n{}",
		context()
	);

	// The C#-issued leaf and the proof it generated for it.
	let csharp_leaf = parse_csharp_leaf(&stdout).ok_or_else(|| format!("missing CS_LEAF\n{}", context()))?;
	let csharp_proof_flat: Value =
		serde_json::from_str(sentinel(&stdout, "CS_PROOF").ok_or_else(|| format!("missing CS_PROOF\n{}", context()))?)?;

	// C# issues (encrypts) -> TS decrypts: the reference reader recovers every
	// attribute the C# SDK embedded.
	let attribute_names = attribute_names();
	let names: Vec<&str> = attribute_names.iter().map(String::as_str).collect();
	let decoded = harness.decode_certificate(&csharp_leaf, SUBJECT_SEED, &names)?;
	let read_back = decoded
		.get("attributes")
		.and_then(Value::as_object)
		.ok_or("decode response is missing its attributes")?;
	assert_eq!(read_back, &expected_attributes(), "the TS reader must recover the C#-issued attributes");

	// C# proves -> TS validates: the proof validates for its attribute and not
	// for a different one.
	let csharp_proof = nest_proof(&csharp_proof_flat);
	assert!(
		validate_proof(&mut harness, &csharp_leaf, PROOF_NAME, &csharp_proof)?,
		"the TS reader must validate the C# proof"
	);
	assert!(
		!validate_proof(&mut harness, &csharp_leaf, WRONG_NAME, &csharp_proof)?,
		"a C# proof must not validate against a different attribute in TS"
	);

	harness.shutdown()?;
	Ok(())
}

impl Harness {
	/// Read `attributes` back from an externally issued `leaf` using `subject_seed`.
	fn decode_certificate(&mut self, leaf: &str, subject_seed: &str, attributes: &[&str]) -> Result<Value, BoxError> {
		self.request(
			"decodeCertificate",
			json!({ "leaf": leaf, "subjectSeed": subject_seed, "attributes": attributes }),
		)
	}
}

/// Validate a nested `proof` for sensitive attribute `name` on `leaf` through the
/// reference reader.
fn validate_proof(harness: &mut Harness, leaf: &str, name: &str, proof: &Value) -> Result<bool, BoxError> {
	let response = harness
		.request("validateProof", json!({ "leaf": leaf, "subjectSeed": SUBJECT_SEED, "name": name, "proof": proof }))?;
	response
		.get("valid")
		.and_then(Value::as_bool)
		.ok_or_else(|| "validateProof response is missing its `valid` flag".into())
}

/// Decode the C#-issued leaf from its `CS_LEAF=<json string>` sentinel line.
fn parse_csharp_leaf(stdout: &str) -> Option<String> {
	let encoded = sentinel(stdout, "CS_LEAF")?;
	serde_json::from_str(encoded).ok()
}

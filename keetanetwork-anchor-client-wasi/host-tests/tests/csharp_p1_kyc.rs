//! Bound C# KYC SDK networked end-to-end test.
//!
//! Boots the live TypeScript KYC anchor via the shared harness, then runs the
//! idiomatic C# SDK (`bindings/csharp`) against it through the .NET CLI. The SDK
//! loads the `wasm32-wasip1` core module on `wasmtime-dotnet` and performs node
//! I/O over `System.Net.Http`

mod common;
mod dotnet;

use std::process::Command;

use serde_json::json;

use common::{field_str, BoxError, KycHarness};
use dotnet::{dotnet_available, example_dir, module_path};

#[test]
#[ignore = "requires `make node-harness`, the wasm32-wasip1 module, and a .NET SDK"]
fn csharp_sdk_signs_against_live_anchor() -> Result<(), BoxError> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# e2e: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	assert!(module.exists(), "build the P1 module first (missing {})", module.display());

	let mut harness = KycHarness::start()?;

	// Boot the real KYC anchor advertising a signed, US-bound provider, with its
	// metadata published on-chain to a root account the SDK resolves over HTTP.
	let started = harness.request("startKycAnchor", json!({ "sign": true, "countryCodes": ["US"] }))?;
	let api = field_str(&started, "api")?;
	let root = field_str(&started, "root")?;
	let provider_id = field_str(&started, "providerId")?;

	// Run the C# example end-to-end. It drives discovery, SignedBody (create),
	// and SignedUrl (status, certificates) for every signing algorithm, printing
	// `KYC_OK` only when all succeed.
	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(example_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_NODE_API", &api)
		.env("KEETA_ROOT", &root)
		.env("KEETA_PROVIDER_ID", &provider_id)
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the C# example must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(
		stdout.contains("KYC_OK"),
		"the C# example must confirm the KYC round-trip\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);

	harness.shutdown()?;
	Ok(())
}

//! Offline C# `crypto` resources end-to-end test.
//!
//! Runs the C# SDK example in its `KEETA_CRYPTO_ONLY` mode against the P1 core
//! module: no node, no harness, no network.

mod dotnet;

use std::process::Command;

use dotnet::{dotnet_available, harness_dir, module_path};

#[test]
fn csharp_crypto_resources_round_trip() -> Result<(), Box<dyn std::error::Error>> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# crypto e2e: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# crypto e2e: build the wasm32-wasip1 module first ({})", module.display());
		return Ok(());
	}

	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_CRYPTO_ONLY", "1")
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the C# crypto example must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(
		stdout.contains("CRYPTO_OK"),
		"the C# crypto example must confirm the crypto round-trip\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);

	Ok(())
}

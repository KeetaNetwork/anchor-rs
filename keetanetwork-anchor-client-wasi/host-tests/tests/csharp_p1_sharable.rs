//! C# `sharable-certificate-attributes` end-to-end test.
//!
//! Runs the C# SDK harness in its `KEETA_SHARABLE_ONLY` mode against the P1 core
//! module: no node, no harness server, no network.

mod dotnet;

use std::process::Command;

use dotnet::{dotnet_available, harness_dir, module_path};

#[test]
fn csharp_sharable_attributes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# sharable e2e: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# sharable e2e: build the wasm32-wasip1 module first ({})", module.display());
		return Ok(());
	}

	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_SHARABLE_ONLY", "1")
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the C# sharable example must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(
		stdout.contains("SHARABLE_OK"),
		"the C# sharable example must confirm the disclosure round-trip\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);

	Ok(())
}

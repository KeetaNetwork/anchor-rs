//! Offline C# KYC builder end-to-end test.
//!
//! Runs the C# SDK example in its `KEETA_ISSUE_ONLY` mode against the P1 core
//! module: issue a leaf through the fluent builder, then read every attribute
//! shape back through the same module. No node, harness, or network.

mod dotnet;

use std::process::Command;

use dotnet::{dotnet_available, harness_dir, module_path};

#[test]
fn csharp_builder_issues_a_leaf_and_reads_it_back() -> Result<(), Box<dyn std::error::Error>> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# issue e2e: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# issue e2e: build the wasm32-wasip1 module first ({})", module.display());
		return Ok(());
	}

	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_ISSUE_ONLY", "1")
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the C# issue example must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(
		stdout.contains("ISSUE_OK"),
		"the C# issue example must confirm the issue round-trip\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);

	Ok(())
}

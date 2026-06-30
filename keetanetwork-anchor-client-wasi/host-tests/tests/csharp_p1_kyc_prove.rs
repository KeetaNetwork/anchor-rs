//! C# KYC proof end-to-end test.

mod dotnet;

use std::process::Command;

use dotnet::{dotnet_available, harness_dir, module_path};

#[test]
fn csharp_proves_and_validates_a_sensitive_attribute() {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# prove e2e: the .NET SDK was not found (set CI to require it)");
		return;
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# prove e2e: build the wasm32-wasip1 module first ({})", module.display());
		return;
	}

	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_PROVE_ONLY", "1")
		.output()
		.expect("the .NET CLI must run the prove example");

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the C# prove example must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(
		stdout.contains("PROVE_OK"),
		"the C# prove example must confirm the proof round-trip\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);
}

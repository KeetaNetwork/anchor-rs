//! Shared helpers for driving the C# SDK test harness through the .NET CLI.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Locate the prebuilt P1 core module.
pub fn module_path() -> PathBuf {
	if let Ok(path) = std::env::var("WASI_P1_MODULE") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../../target/wasm32-wasip1/debug/keetanetwork_anchor_client_wasi.wasm")
}

/// The C# SDK test-harness project directory.
pub fn harness_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bindings/csharp/KeetaNet.Anchor.Kyc.Harness")
}

/// Whether the .NET CLI is available on this machine.
pub fn dotnet_available() -> bool {
	Command::new("dotnet")
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|status| status.success())
		.unwrap_or(false)
}

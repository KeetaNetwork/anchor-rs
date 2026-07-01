//! C# asset-movement SDK <-> TypeScript anchor compatibility, over real services
//!
//! Boots the live reference asset-movement anchor and drives the C# SDK (over the
//! P1 core module's real HTTP shim) against it across signing algorithms.

mod common;
mod dotnet;

use std::process::Command;

use serde_json::json;

use common::{field_str, BoxError, Harness};
use dotnet::{dotnet_available, harness_dir, module_path};

#[test]
fn csharp_asset_sdk_conforms_with_typescript_anchor() -> Result<(), BoxError> {
	// Platform-specific: skip locally without the .NET SDK, but enforce in CI.
	if std::env::var_os("CI").is_none() && !dotnet_available() {
		eprintln!("skipping C# asset compatibility: the .NET SDK was not found (set CI to require it)");
		return Ok(());
	}

	let module = module_path();
	if !module.exists() {
		eprintln!("skipping C# asset compatibility: build the wasm32-wasip1 module first ({})", module.display());
		return Ok(());
	}

	let mut harness = Harness::asset()?;

	// Boot the real asset-movement anchor advertising a signed provider, with its
	// metadata published on-chain to a root account the SDK resolves over HTTP.
	let started = harness.request("startAssetAnchor", json!({ "sign": true }))?;
	let api = field_str(&started, "api")?;
	let root = field_str(&started, "root")?;
	let provider_id = field_str(&started, "providerId")?;
	let asset = field_str(&started, "asset")?;
	let signer = field_str(&started, "signer")?;
	let send_to = field_str(&started, "sendToAddress")?;

	// Run the C# SDK end-to-end against the live anchor.
	let output = Command::new("dotnet")
		.args(["run", "--project"])
		.arg(harness_dir())
		.args(["-c", "Release"])
		.env("KEETA_ANCHOR_P1_WASM", &module)
		.env("KEETA_ASSET", "1")
		.env("KEETA_NODE_API", &api)
		.env("KEETA_ROOT", &root)
		.env("KEETA_PROVIDER_ID", &provider_id)
		.env("KEETA_ASSET_ID", &asset)
		.env("KEETA_PROVIDER_ACCOUNT", &signer)
		.env("KEETA_SEND_TO", &send_to)
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	let context = || format!("STDOUT:\n{stdout}\nSTDERR:\n{stderr}");

	assert!(output.status.success(), "the C# asset SDK must exit zero\n{}", context());
	assert!(stdout.contains("ASSET_OK"), "the C# asset SDK must print `ASSET_OK`\n{}", context());

	harness.shutdown()?;
	Ok(())
}

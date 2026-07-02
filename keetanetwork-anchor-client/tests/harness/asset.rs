//! Driver for the asset-movement interop harness (`dist/asset.js`).

use serde_json::{Map, Value};

use super::driver::{field_str, HarnessDriver, HarnessError};

/// A live asset-movement anchor HTTP server started by the harness, with its
/// service metadata published on-chain to a root account.
pub struct AssetAnchor {
	/// The server base URL (`http://127.0.0.1:<port>`).
	pub url: String,
	/// The node API base URL the resolver reads the root account through.
	pub api: String,
	/// The root account whose on-chain `info.metadata` advertises the provider.
	pub root: String,
	/// The provider id (the key under `services.assetMovement`).
	pub provider_id: String,
	/// The canonical asset the provider moves (the chain's base token).
	pub asset: String,
	/// The resolved `KEETA_SEND` recipient the fixtures report.
	pub send_to_address: String,
	/// The metadata signer's `keeta_...` string, when the entry is signed.
	pub signer: Option<String>,
	/// The base64 `formatMetadata` blob, used to read operation URLs directly.
	pub blob: String,
}

/// A live asset-movement anchor harness driven over JSON lines.
pub struct AssetHarness {
	driver: HarnessDriver,
}

impl AssetHarness {
	/// Spawn the asset harness and wait for its `ready` line.
	pub fn start() -> Result<Self, HarnessError> {
		Ok(Self { driver: HarnessDriver::spawn("asset")? })
	}

	/// Start a live asset-movement anchor HTTP server, optionally signing its
	/// metadata entry.
	pub fn start_asset_anchor(&mut self, sign: bool) -> Result<AssetAnchor, HarnessError> {
		let mut request = Map::new();
		request.insert("sign".to_string(), Value::Bool(sign));

		let response = self
			.driver
			.request("startAssetAnchor", Value::Object(request))?;
		let url = field_str(&response, "url")?.to_string();
		let api = field_str(&response, "api")?.to_string();
		let root = field_str(&response, "root")?.to_string();
		let provider_id = field_str(&response, "providerId")?.to_string();
		let asset = field_str(&response, "asset")?.to_string();
		let send_to_address = field_str(&response, "sendToAddress")?.to_string();
		let blob = field_str(&response, "blob")?.to_string();
		let signer = response
			.get("signer")
			.and_then(Value::as_str)
			.map(str::to_string);

		Ok(AssetAnchor { url, api, root, provider_id, asset, send_to_address, signer, blob })
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(self) -> Result<(), HarnessError> {
		self.driver.shutdown()
	}
}

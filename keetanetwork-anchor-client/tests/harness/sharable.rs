//! Driver for the sharable-attributes interop harness (`dist/sharable.js`).

use serde_json::{json, Value};

use super::driver::{HarnessDriver, HarnessError};

/// The curve both sides derive the subject and recipient accounts on, so a
/// container one implementation seals opens with the other's recipient key.
pub const ALGORITHM: &str = "secp256k1";

/// A sharable-attributes harness driven over JSON lines.
pub struct SharableHarness {
	driver: HarnessDriver,
}

impl SharableHarness {
	/// Spawn the sharable harness and wait for its `ready` line.
	pub fn start() -> Result<Self, HarnessError> {
		Ok(Self { driver: HarnessDriver::spawn("sharable")? })
	}

	/// Issue a leaf for `subject_seed`, wrap `attributes` in a sharable bundle
	/// for `recipient_seed`, and return the response (`pem` and the reference's
	/// own `buffers` for each disclosed attribute).
	pub fn build_sharable(
		&mut self,
		subject_seed: &str,
		recipient_seed: &str,
		attributes: &Value,
	) -> Result<Value, HarnessError> {
		self.driver.request(
			"buildSharable",
			json!({
				"subjectSeed": subject_seed,
				"recipientSeed": recipient_seed,
				"attributes": attributes,
				"algorithm": ALGORITHM,
			}),
		)
	}

	/// Open a bundle exported elsewhere (e.g. by the Rust core) with the key for
	/// `recipient_seed`, returning the reference's `buffers` for each name.
	pub fn read_sharable(&mut self, pem: &str, recipient_seed: &str, names: &[&str]) -> Result<Value, HarnessError> {
		self.driver.request(
			"readSharable",
			json!({
				"pem": pem,
				"recipientSeed": recipient_seed,
				"names": names,
				"algorithm": ALGORITHM,
			}),
		)
	}

	/// Stop the harness and wait for it to exit.
	pub fn shutdown(self) -> Result<(), HarnessError> {
		self.driver.shutdown()
	}
}

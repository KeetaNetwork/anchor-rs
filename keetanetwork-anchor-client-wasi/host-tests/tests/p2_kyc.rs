//! wasmtime P2 KYC component end-to-end test.
//!
//! Boots the `KeetaNetKYCAnchorHTTPServer` via the TypeScript KYC harness,
//! serves the published service-metadata blob over a local HTTP endpoint, then
//! drives the exported `client` resource over `wasi:http`.

use std::io::{BufRead, BufReader, Lines, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

mod bindings {
	wasmtime::component::bindgen!({
		world: "keeta-anchor-kyc",
		path: "../wit",
		imports: { default: async | trappable },
		exports: { default: async },
	});
}

use bindings::exports::keeta::anchor::kyc::{
	CertificatesOutcome, CodedError, KycProvider, SignerSpec, StatusOutcome, VerificationOutcome,
};
use bindings::KeetaAnchorKyc;

/// Host state granting the component WASI + outbound `wasi:http`.
struct Host {
	ctx: WasiCtx,
	http: WasiHttpCtx,
	table: ResourceTable,
}

impl Default for Host {
	fn default() -> Self {
		let ctx = WasiCtx::builder().inherit_stdio().build();
		let http = WasiHttpCtx::new();
		let table = ResourceTable::new();
		Self { ctx, http, table }
	}
}

impl WasiView for Host {
	fn ctx(&mut self) -> WasiCtxView<'_> {
		WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
	}
}

impl WasiHttpView for Host {
	fn http(&mut self) -> WasiHttpCtxView<'_> {
		WasiHttpCtxView { ctx: &mut self.http, table: &mut self.table, hooks: Default::default() }
	}
}

/// Locate the prebuilt P2 component.
fn component_path() -> PathBuf {
	if let Ok(path) = std::env::var("WASI_P2_COMPONENT") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let relative = "../../target/wasm32-wasip2/debug/keetanetwork_anchor_client_wasi.wasm";
	manifest_dir.join(relative)
}

/// Locate the compiled KYC harness entry (`dist/kyc.js`).
fn harness_path() -> PathBuf {
	if let Ok(path) = std::env::var("KYC_HARNESS") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../../keetanetwork-anchor-client/node-harness/dist/kyc.js")
}

/// Project a guest [`CodedError`] into a host error for `?`.
fn coded(error: CodedError) -> wasmtime::Error {
	wasmtime::Error::msg(format!("{}: {}", error.code, error.message))
}

/// Read a required string field from a harness response.
fn field_str(value: &Value, field: &str) -> wasmtime::Result<String> {
	value
		.get(field)
		.and_then(Value::as_str)
		.map(str::to_string)
		.ok_or_else(|| wasmtime::Error::msg(format!("harness response missing field `{field}`")))
}

/// A live KYC anchor harness driven over JSON lines (a local copy of the
/// pattern in the client crate's test support; cross-crate test code cannot be
/// imported).
struct KycHarness {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
}

impl KycHarness {
	/// Spawn `node dist/kyc.js` and wait for its `ready` line.
	fn start() -> wasmtime::Result<Self> {
		let script = harness_path();
		if !script.exists() {
			return Err(wasmtime::Error::msg(format!(
				"KYC harness not found at {} (run `make node-harness`)",
				script.display()
			)));
		}

		let mut child = Command::new("node")
			.arg(&script)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()?;

		let stdin = child
			.stdin
			.take()
			.ok_or_else(|| wasmtime::Error::msg("harness stdin unavailable"))?;
		let stdout = child
			.stdout
			.take()
			.ok_or_else(|| wasmtime::Error::msg("harness stdout unavailable"))?;
		let mut lines = BufReader::new(stdout).lines();

		let ready = lines
			.next()
			.ok_or_else(|| wasmtime::Error::msg("harness ended before ready"))??;
		let ready: Value = serde_json::from_str(&ready)?;
		if ready.get("event").and_then(Value::as_str) != Some("ready") {
			return Err(wasmtime::Error::msg(format!("harness did not report ready: {ready}")));
		}

		Ok(Self { child, stdin, lines })
	}

	/// Send a command with object params and return its response.
	fn request(&mut self, command: &str, params: Value) -> wasmtime::Result<Value> {
		let mut object = match params {
			Value::Object(map) => map,
			_ => Map::new(),
		};
		object.insert("cmd".to_string(), Value::String(command.to_string()));
		writeln!(self.stdin, "{}", Value::Object(object))?;
		self.stdin.flush()?;

		let line = self
			.lines
			.next()
			.ok_or_else(|| wasmtime::Error::msg("harness ended before responding"))??;
		let value: Value = serde_json::from_str(&line)?;
		if let Some(message) = value.get("error").and_then(Value::as_str) {
			return Err(wasmtime::Error::msg(format!("harness command `{command}` failed: {message}")));
		}

		Ok(value)
	}

	/// Stop the harness and wait for it to exit.
	fn shutdown(mut self) -> wasmtime::Result<()> {
		self.request("shutdown", Value::Object(Map::new()))?;
		self.child.wait()?;
		Ok(())
	}
}

impl Drop for KycHarness {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

/// A local HTTP endpoint that serves one fixed metadata document for every GET,
/// standing in for the on-chain root the component resolves over `wasi:http`.
struct MetadataServer {
	url: String,
	server: Arc<tiny_http::Server>,
	worker: Option<JoinHandle<()>>,
}

impl MetadataServer {
	/// Serve `body` (the raw, post-base64 metadata bytes) on an ephemeral
	/// localhost port.
	fn serve(body: Vec<u8>) -> wasmtime::Result<Self> {
		let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| wasmtime::Error::msg(error.to_string()))?;
		let port = server
			.server_addr()
			.to_ip()
			.ok_or_else(|| wasmtime::Error::msg("metadata server bound a non-IP address"))?
			.port();
		let url = format!("http://127.0.0.1:{port}/");

		let server = Arc::new(server);
		let worker_server = server.clone();
		let worker = std::thread::spawn(move || {
			for request in worker_server.incoming_requests() {
				let response = tiny_http::Response::from_data(body.clone());
				let _ = request.respond(response);
			}
		});

		Ok(Self { url, server, worker: Some(worker) })
	}
}

impl Drop for MetadataServer {
	fn drop(&mut self) {
		self.server.unblock();
		if let Some(worker) = self.worker.take() {
			let _ = worker.join();
		}
	}
}

/// Instantiate the P2 component with WASI + outbound `wasi:http` granted.
async fn instantiate() -> wasmtime::Result<(Store<Host>, KeetaAnchorKyc)> {
	let engine = Engine::default();
	let component = Component::from_file(&engine, component_path())?;
	let mut linker: Linker<Host> = Linker::new(&engine);

	wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
	wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

	let mut store = Store::new(&engine, Host::default());
	let bindings = KeetaAnchorKyc::instantiate_async(&mut store, &component, &linker).await?;
	Ok((store, bindings))
}

#[tokio::test]
#[ignore = "requires `make node-harness` and the built wasm32-wasip2 component"]
async fn p2_kyc_signs_against_live_anchor() -> wasmtime::Result<()> {
	let mut harness = KycHarness::start()?;

	// Boot the real KYC anchor advertising a signed, US-bound provider.
	let started = harness.request("startKycAnchor", json!({ "sign": true, "countryCodes": ["US"] }))?;
	let provider_id = field_str(&started, "providerId")?;
	let blob = field_str(&started, "blob")?;

	// The component fetches metadata over wasi:http; serve the decoded blob
	// (parse_metadata inflates it) from a local endpoint.
	let raw = STANDARD
		.decode(blob.trim())
		.map_err(|error| wasmtime::Error::msg(error.to_string()))?;
	let metadata = MetadataServer::serve(raw)?;

	let (mut store, bindings) = instantiate().await?;
	let kyc = bindings.keeta_anchor_kyc();

	// Bind a signing client to a deterministic secp256k1 account derived from a
	// 32-byte seed.
	let spec = SignerSpec { seed: "11".repeat(32), index: 0, algorithm: "ecdsa_secp256k1".to_string() };
	let client = kyc
		.client()
		.call_with_signer(&mut store, &metadata.url, &spec)
		.await?
		.map_err(coded)?;

	// Discovery: exactly the one advertised provider must surface, proving the
	// metadata fetch and entry-signature verification match the TS reference.
	let countries = vec!["US".to_string()];
	let providers = kyc
		.client()
		.call_providers(&mut store, client, &countries)
		.await?
		.map_err(coded)?;
	assert_eq!(providers.len(), 1, "exactly one provider must serve the requested country");
	let provider: KycProvider = providers
		.into_iter()
		.next()
		.expect("the provider list is non-empty");
	assert_eq!(provider.id, provider_id, "the discovered provider id must match the harness");

	// SignedBody parity: the real TS server verifies the signature on the empty
	// `create-verification` payload, or the whole request is rejected.
	let outcome = kyc
		.client()
		.call_create_verification(&mut store, client, &provider, &countries, None)
		.await?
		.map_err(coded)?;
	let verification = match outcome {
		VerificationOutcome::Ready(verification) => verification,
		VerificationOutcome::Retry(after) => {
			panic!("create-verification must be ready, got retry after {after}ms")
		}
	};
	assert!(!verification.id.is_empty(), "the verification must carry an id");
	assert!(!verification.web_url.is_empty(), "the verification must carry a web url");

	// SignedUrl parity: status reads sign the request URL; the TS server must
	// accept it and report the harness-configured pending status.
	let status = kyc
		.client()
		.call_get_verification_status(&mut store, client, &provider, &verification.id)
		.await?
		.map_err(coded)?;
	let status = match status {
		StatusOutcome::Ready(status) => status,
		StatusOutcome::Retry(after) => panic!("status must be ready, got retry after {after}ms"),
	};
	assert!(!status.status.is_empty(), "the status must be non-empty");

	// SignedUrl parity on the certificate path: the server accepts the signed
	// request and returns either the issued certificates or a retry.
	let certificates = kyc
		.client()
		.call_get_certificates(&mut store, client, &provider, &verification.id)
		.await?
		.map_err(coded)?;
	assert!(
		matches!(certificates, CertificatesOutcome::Ready(_) | CertificatesOutcome::Retry(_)),
		"the certificate read must yield a ready or retry outcome"
	);

	drop(metadata);
	harness.shutdown()?;
	Ok(())
}

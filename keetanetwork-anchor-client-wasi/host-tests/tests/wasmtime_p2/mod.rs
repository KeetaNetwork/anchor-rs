//! Shared wasmtime host for the P2 component tests: the generated bindings, a
//! WASI + outbound `wasi:http` host state, and the instantiation helper. Both
//! the live KYC e2e and the `crypto` tests build on this.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

pub mod bindings {
	wasmtime::component::bindgen!({
		world: "keeta-anchor-kyc",
		path: "../wit",
		imports: { default: async | trappable },
		exports: { default: async },
	});
}

pub use bindings::exports::keeta::client::crypto::CodedError;
pub use bindings::KeetaAnchorKyc;

/// Host state granting the component WASI + outbound `wasi:http`.
pub struct Host {
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
pub fn component_path() -> PathBuf {
	if let Ok(path) = std::env::var("WASI_P2_COMPONENT") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest_dir.join("../../target/wasm32-wasip2/debug/keetanetwork_anchor_client_wasi.wasm")
}

/// Whether the prebuilt P2 component is present (needs `make build-wasi`).
pub fn component_built() -> bool {
	component_path().exists()
}

/// Project a guest [`CodedError`] into a host error for `?`.
pub fn coded(error: CodedError) -> wasmtime::Error {
	wasmtime::Error::msg(format!("{}: {}", error.code, error.message))
}

/// Parse a textual `keeta_…` public-key string into a guest `account`
/// resource for the component's `borrow<account>` parameters.
pub async fn account_from_public_key_string(
	store: &mut Store<Host>,
	bindings: &KeetaAnchorKyc,
	public_key_string: &str,
) -> wasmtime::Result<wasmtime::component::ResourceAny> {
	bindings
		.keeta_client_crypto()
		.account()
		.call_from_public_key_string(&mut *store, public_key_string)
		.await?
		.map_err(coded)
}

/// The engine, compiled component, and populated linker shared by every test
/// in a binary, so Cranelift compiles the large debug component once per
/// binary instead of once per test.
struct Compiled {
	engine: Engine,
	component: Component,
	linker: Linker<Host>,
}

/// Compile the component on first use, sharing the result across the binary.
fn compiled() -> wasmtime::Result<&'static Compiled> {
	static COMPILED: OnceLock<wasmtime::Result<Compiled>> = OnceLock::new();
	COMPILED
		.get_or_init(compile)
		.as_ref()
		.map_err(|error| wasmtime::Error::msg(error.to_string()))
}

fn compile() -> wasmtime::Result<Compiled> {
	let engine = super::common::cached_engine()?;
	let component = Component::from_file(&engine, component_path())?;
	let mut linker: Linker<Host> = Linker::new(&engine);

	wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
	wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

	Ok(Compiled { engine, component, linker })
}

/// Instantiate the P2 component with WASI + outbound `wasi:http` granted.
pub async fn instantiate() -> wasmtime::Result<(Store<Host>, KeetaAnchorKyc)> {
	let compiled = compiled()?;
	let mut store = Store::new(&compiled.engine, Host::default());
	let bindings = KeetaAnchorKyc::instantiate_async(&mut store, &compiled.component, &compiled.linker).await?;
	Ok((store, bindings))
}

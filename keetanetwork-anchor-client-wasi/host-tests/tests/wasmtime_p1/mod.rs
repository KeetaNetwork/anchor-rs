//! Shared wasmtime host for the P1 core-module tests: a WASI Preview 1 store
//! plus thin wrappers over the module's `keeta_*` C ABI (handles, linear-memory
//! buffers, and the `last_error` channel).

#![allow(dead_code)]

use wasmtime::{Caller, Engine, Instance, Linker, Memory, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

/// A P1 module instance with its store and exported linear memory.
pub struct P1 {
	store: Store<WasiP1Ctx>,
	instance: Instance,
	memory: Memory,
}

impl P1 {
	/// Instantiate the prebuilt P1 module with WASI Preview 1 granted.
	pub fn instantiate() -> wasmtime::Result<Self> {
		let engine = Engine::default();
		let module = Module::from_file(&engine, super::dotnet::module_path())?;
		let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);

		p1::add_to_linker_sync(&mut linker, |ctx| ctx)?;
		Self::stub_host_transport(&mut linker)?;

		let wasi = WasiCtxBuilder::new().inherit_stdio().build_p1();
		let mut store = Store::new(&engine, wasi);
		let instance = linker.instantiate(&mut store, &module)?;
		if let Ok(initialize) = instance.get_typed_func::<(), ()>(&mut store, "_initialize") {
			initialize.call(&mut store, ())?;
		}

		let memory = instance
			.get_memory(&mut store, "memory")
			.ok_or_else(|| wasmtime::Error::msg("the P1 module must export its linear memory"))?;

		Ok(Self { store, instance, memory })
	}

	/// Satisfy the module's `keeta:anchor/host` transport imports. KYC issuance
	/// is offline, so these stubs are never called; they only let the networked
	/// client portion of the module link.
	fn stub_host_transport(linker: &mut Linker<WasiP1Ctx>) -> wasmtime::Result<()> {
		linker.func_wrap(
			"keeta:anchor/host",
			"keeta_anchor_host_fetch",
			|_: Caller<'_, WasiP1Ctx>, _: u32, _: u32| 0u32,
		)?;
		linker.func_wrap("keeta:anchor/host", "keeta_anchor_host_take", |_: Caller<'_, WasiP1Ctx>, _: u32| {})?;
		linker.func_wrap("keeta:anchor/host", "keeta_anchor_host_sleep", |_: Caller<'_, WasiP1Ctx>, _: u64| {})?;
		Ok(())
	}

	/// Derive an account handle from a hex `seed` at `index` under `algorithm`.
	pub fn account_from_seed(&mut self, seed: &str, index: i32, algorithm: &str) -> wasmtime::Result<i32> {
		let (seed_ptr, seed_len) = self.write(seed.as_bytes())?;
		let (algorithm_ptr, algorithm_len) = self.write(algorithm.as_bytes())?;
		let handle = self.call5("keeta_account_from_seed", seed_ptr, seed_len, index, algorithm_ptr, algorithm_len)?;
		self.handle(handle)
	}

	/// Issue a leaf from the JSON `params` buffer; returns a leaf handle.
	pub fn issue(&mut self, subject: i32, issuer: i32, params: &[u8]) -> wasmtime::Result<i32> {
		let (params_ptr, params_len) = self.write(params)?;
		let handle = self.call4("keeta_kyc_certificate_issue", subject, issuer, params_ptr, params_len)?;
		self.handle(handle)
	}

	/// The leaf's PEM encoding.
	pub fn pem(&mut self, leaf: i32) -> wasmtime::Result<Vec<u8>> {
		let bytes = self.call1("keeta_kyc_certificate_pem", leaf)?;
		self.read_handle(bytes)
	}

	/// The plain value of attribute `name`.
	pub fn plain_attribute(&mut self, leaf: i32, name: &str) -> wasmtime::Result<Vec<u8>> {
		let (name_ptr, name_len) = self.write(name.as_bytes())?;
		let bytes = self.call3("keeta_kyc_certificate_plain_attribute", leaf, name_ptr, name_len)?;
		self.read_handle(bytes)
	}

	/// The decrypted value of sensitive attribute `name`, using `account`.
	pub fn decrypt_attribute(&mut self, leaf: i32, name: &str, account: i32) -> wasmtime::Result<Vec<u8>> {
		let (name_ptr, name_len) = self.write(name.as_bytes())?;
		let bytes = self.call4("keeta_kyc_certificate_decrypt_attribute", leaf, name_ptr, name_len, account)?;
		self.read_handle(bytes)
	}

	/// A proof for sensitive attribute `name`, as its `{ value, salt }` JSON.
	pub fn prove(&mut self, leaf: i32, name: &str, account: i32) -> wasmtime::Result<Vec<u8>> {
		let (name_ptr, name_len) = self.write(name.as_bytes())?;
		let bytes = self.call4("keeta_kyc_certificate_prove", leaf, name_ptr, name_len, account)?;
		self.read_handle(bytes)
	}

	/// Whether `proof` (JSON) validates for attribute `name`: `1`/`0`/`-1`.
	pub fn validate_proof(&mut self, leaf: i32, name: &str, account: i32, proof: &[u8]) -> wasmtime::Result<i32> {
		let (name_ptr, name_len) = self.write(name.as_bytes())?;
		let (proof_ptr, proof_len) = self.write(proof)?;
		self.call6("keeta_kyc_certificate_validate_proof", leaf, name_ptr, name_len, account, proof_ptr, proof_len)
	}

	/// Seal a bundle disclosing `names` from leaf `certificate`, proved with the
	/// `subject` account and bridged by the base-certificate `intermediates`.
	pub fn sharable_from_certificate(
		&mut self,
		certificate: i32,
		subject: i32,
		intermediates: &[i32],
		names: &[&str],
	) -> wasmtime::Result<i32> {
		let (intermediates_ptr, intermediates_len) = self.write_handles(intermediates)?;
		let labels = serde_json::to_vec(names)?;
		let (names_ptr, names_len) = self.write(&labels)?;
		let handle = self.call6(
			"keeta_sharable_from_certificate",
			certificate,
			subject,
			intermediates_ptr,
			intermediates_len,
			names_ptr,
			names_len,
		)?;

		self.handle(handle)
	}

	/// Open a bundle from its PEM envelope, resolved with `principals`.
	pub fn sharable_from_pem(&mut self, pem: &[u8], principals: &[i32]) -> wasmtime::Result<i32> {
		let (pem_ptr, pem_len) = self.write(pem)?;
		let (principals_ptr, principals_len) = self.write_handles(principals)?;

		let handle = self.call4("keeta_sharable_from_pem", pem_ptr, pem_len, principals_ptr, principals_len)?;
		self.handle(handle)
	}

	/// Grant `principals` access to the sealed bundle: `1`/`-1`.
	pub fn sharable_grant_access(&mut self, bundle: i32, principals: &[i32]) -> wasmtime::Result<i32> {
		let (principals_ptr, principals_len) = self.write_handles(principals)?;
		self.call3("keeta_sharable_grant_access", bundle, principals_ptr, principals_len)
	}

	/// The bundle's PEM envelope.
	pub fn sharable_to_pem(&mut self, bundle: i32) -> wasmtime::Result<Vec<u8>> {
		let bytes = self.call1("keeta_sharable_to_pem", bundle)?;
		self.read_handle(bytes)
	}

	/// The schema-decoded semantic value of disclosed attribute `name`.
	pub fn sharable_attribute_value(&mut self, bundle: i32, name: &str) -> wasmtime::Result<Vec<u8>> {
		let (name_ptr, name_len) = self.write(name.as_bytes())?;
		let bytes = self.call3("keeta_sharable_attribute_value", bundle, name_ptr, name_len)?;
		self.read_handle(bytes)
	}

	/// The bundle's disclosed attribute names, as a JSON string array.
	pub fn sharable_attribute_names(&mut self, bundle: i32) -> wasmtime::Result<Vec<u8>> {
		let bytes = self.call1("keeta_sharable_attribute_names", bundle)?;
		self.read_handle(bytes)
	}

	/// Reserve guest memory for a little-endian `i32` handle list, returning `(ptr, len)`.
	fn write_handles(&mut self, handles: &[i32]) -> wasmtime::Result<(i32, i32)> {
		let mut bytes = Vec::with_capacity(handles.len() * 4);
		for handle in handles {
			bytes.extend_from_slice(&handle.to_le_bytes());
		}

		self.write(&bytes)
	}

	/// Reserve guest memory and copy `data` into it, returning `(ptr, len)`.
	fn write(&mut self, data: &[u8]) -> wasmtime::Result<(i32, i32)> {
		let len = data.len() as i32;
		let ptr = self.call1("keeta_alloc", len)?;

		let memory = self.memory;
		memory.write(&mut self.store, ptr as usize, data)?;

		Ok((ptr, len))
	}

	/// Read a bytes handle's data, then release the handle.
	fn read_handle(&mut self, handle: i32) -> wasmtime::Result<Vec<u8>> {
		let handle = self.handle(handle)?;
		let ptr = self.call1("keeta_bytes_ptr", handle)?;
		let len = self.call1("keeta_bytes_len", handle)?;
		let mut buffer = vec![0u8; len as usize];

		let memory = self.memory;
		memory.read(&self.store, ptr as usize, &mut buffer)?;

		let free = self
			.instance
			.get_typed_func::<i32, ()>(&mut self.store, "keeta_bytes_free")?;
		free.call(&mut self.store, handle)?;

		Ok(buffer)
	}

	/// Treat `0` as failure, surfacing the module's last error message.
	fn handle(&mut self, handle: i32) -> wasmtime::Result<i32> {
		if handle != 0 {
			return Ok(handle);
		}

		let message = self.last_error_message()?;
		Err(wasmtime::Error::msg(message))
	}

	/// The module's last error message, or a placeholder when none is pending.
	fn last_error_message(&mut self) -> wasmtime::Result<String> {
		let handle = self.call0("keeta_last_error_message")?;
		if handle == 0 {
			return Ok("no error reported".to_string());
		}

		let ptr = self.call1("keeta_bytes_ptr", handle)?;
		let len = self.call1("keeta_bytes_len", handle)?;
		let mut buffer = vec![0u8; len as usize];

		let memory = self.memory;
		memory.read(&self.store, ptr as usize, &mut buffer)?;

		Ok(String::from_utf8_lossy(&buffer).into_owned())
	}

	fn call0(&mut self, name: &str) -> wasmtime::Result<i32> {
		let func = self
			.instance
			.get_typed_func::<(), i32>(&mut self.store, name)?;
		func.call(&mut self.store, ())
	}

	fn call1(&mut self, name: &str, a: i32) -> wasmtime::Result<i32> {
		let func = self
			.instance
			.get_typed_func::<i32, i32>(&mut self.store, name)?;
		func.call(&mut self.store, a)
	}

	fn call3(&mut self, name: &str, a: i32, b: i32, c: i32) -> wasmtime::Result<i32> {
		let func = self
			.instance
			.get_typed_func::<(i32, i32, i32), i32>(&mut self.store, name)?;
		func.call(&mut self.store, (a, b, c))
	}

	fn call4(&mut self, name: &str, a: i32, b: i32, c: i32, d: i32) -> wasmtime::Result<i32> {
		let func = self
			.instance
			.get_typed_func::<(i32, i32, i32, i32), i32>(&mut self.store, name)?;
		func.call(&mut self.store, (a, b, c, d))
	}

	fn call5(&mut self, name: &str, a: i32, b: i32, c: i32, d: i32, e: i32) -> wasmtime::Result<i32> {
		let func = self
			.instance
			.get_typed_func::<(i32, i32, i32, i32, i32), i32>(&mut self.store, name)?;
		func.call(&mut self.store, (a, b, c, d, e))
	}

	fn call6(&mut self, name: &str, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> wasmtime::Result<i32> {
		let func = self
			.instance
			.get_typed_func::<(i32, i32, i32, i32, i32, i32), i32>(&mut self.store, name)?;
		func.call(&mut self.store, (a, b, c, d, e, f))
	}
}

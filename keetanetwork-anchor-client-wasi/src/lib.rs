//! WASI bindings for the KeetaNet anchor client: two feature-selected flavors
//! over the shared offline core in [`keetanetwork_anchor_bindings::account`].
//!
//! - **`p2`** ([`wasm32-wasip2`]): a `wit-bindgen` component.
//! - **`p1`** ([`wasm32-wasip1`]): a core module over a flat C ABI.
//!
//! Exactly one of `p1`/`p2` is enabled per wasi build; off a wasi target both
//! compile out.
//!
//! [`wasm32-wasip1`]: https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip1.html
//! [`wasm32-wasip2`]: https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip2.html

#[cfg(all(target_os = "wasi", feature = "p1", feature = "p2"))]
compile_error!("enable exactly one of the `p1` or `p2` features for a wasi build");
#[cfg(all(target_os = "wasi", not(any(feature = "p1", feature = "p2"))))]
compile_error!("enable exactly one of the `p1` or `p2` features for a wasi build");

// P1 only: link the node WASI core module so its `keeta_*` crypto exports
// (accounts, certificates, ...) are emitted into this module.
#[cfg(all(feature = "p1", target_os = "wasi"))]
extern crate keetanetwork_client_wasi;

// The asset-movement JSON contract shared by both bindings.
#[cfg(all(target_os = "wasi", any(feature = "p1", feature = "p2")))]
mod asset_json;

#[cfg(all(feature = "p2", target_os = "wasi"))]
mod p2;

#[cfg(all(feature = "p1", target_os = "wasi"))]
mod p1;

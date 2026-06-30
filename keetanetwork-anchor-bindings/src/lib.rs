//! Shared, target-agnostic logic for the KeetaNet anchor binding crates.
//!
//! Every FFI boundary (wasm, wasi, native) repeats the same input parsing
//! and core-error reduction. Centralizing it here keeps the binding crates
//! thin and the error interface (`{code, message}`) identical across targets.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod account;
pub mod certificate;
pub mod encrypted_container;
pub mod error;
pub mod parse;

//! Anchor Rust Library

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub mod asn1;
pub mod certificates;
pub mod error;
pub mod generated;
pub mod iso20022;
pub mod kyc_schema;
pub mod sensitive_attributes;
pub mod utils;

#[cfg(feature = "signing")]
pub mod signing;

#[cfg(feature = "x509")]
pub mod trust;

#[cfg(feature = "std")]
#[doc(hidden)]
pub mod doc_utils;
#[cfg(feature = "std")]
#[doc(hidden)]
pub mod testing;

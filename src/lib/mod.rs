//! Anchor Rust Library

pub mod asn1;
pub mod certificates;
pub mod error;
pub mod kyc_schema;
pub mod sensitive_attributes;
pub mod testing;
pub mod utils;

// Include generated ASN.1 code directly
#[path = "../generated/kyc_attributes.rs"]
pub mod kyc_attributes_impl;
#[path = "../generated/sensitive_attributes.rs"]
pub mod sensitive_attributes_impl;

// Re-export main types from the generated modules
pub mod generated {
	pub use crate::kyc_attributes_impl::{Attribute, AttributeValue, KYCAttributes};
	pub use crate::sensitive_attributes_impl::{
		SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue,
	};
}

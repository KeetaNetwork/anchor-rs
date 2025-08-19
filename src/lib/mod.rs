//! Anchor Rust Library

pub mod asn1;
pub mod certificates;
pub mod error;
pub mod utils;

// Include generated ASN.1 code directly
#[path = "../generated/sensitive_attributes.rs"]
pub mod sensitive_attributes_impl;

#[path = "../generated/kyc_attributes.rs"]
pub mod kyc_attributes_impl;

// Re-export main types from the generated modules
pub use sensitive_attributes_impl::{SensitiveAttribute, SensitiveAttributeCipher, SensitiveAttributeHashedValue};

pub use kyc_attributes_impl::{Attribute, AttributeValue, KYCAttributes};

// For backward compatibility, create a generated module
pub mod generated {
	pub use crate::{
		Attribute, AttributeValue, KYCAttributes, SensitiveAttribute, SensitiveAttributeCipher,
		SensitiveAttributeHashedValue,
	};
}

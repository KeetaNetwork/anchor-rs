pub mod builder;
pub mod error;
pub mod utils;

// Re-export commonly used types
pub use builder::{Certificate, CertificateBuilder};
pub use error::CertificateError;

// Re-export generated types with extensions
pub use crate::generated::{Attribute as KycAttribute, AttributeValue as KycAttributeValue, KYCAttributes};

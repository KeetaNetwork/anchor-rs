
use std::borrow::Cow;
use std::collections::HashMap;
use rasn::types::ObjectIdentifier;

// Algorithm OID constants
pub const AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 1, 42]));
pub const AES_256_GCM: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 1, 46]));
pub const SHA2_256: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 2, 1]));
pub const SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 2, 8]));

// Plain attribute OID constants
/// Postal code OID
/// # References
/// - [https://oidref.com/2.5.5.17](https://oidref.com/2.5.5.17)
pub const ADDRESS_POSTAL_CODE: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 5, 17]));

pub mod keeta {
    use super::*;

    // Extension OID constants
    pub const KYC_ATTRIBUTES_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 0, 0]));

    // Sensitive attribute OID constants
    /// Physical address
    pub const ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 2]));
    /// Date of birth
    pub const DATE_OF_BIRTH: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 1]));
    /// Email address
    pub const EMAIL: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 3]));
    /// Person's full name
    pub const FULL_NAME: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 0]));
    /// Phone number
    pub const PHONE_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 4]));

    lazy_static::lazy_static! {
        /// OID database for sensitive certificate attributes.
        pub static ref SENSITIVE_ATTRIBUTES: HashMap<&'static str, ObjectIdentifier> = {
            [
                ("address", ADDRESS),
                ("dateOfBirth", DATE_OF_BIRTH),
                ("email", EMAIL),
                ("fullName", FULL_NAME),
                ("phoneNumber", PHONE_NUMBER),
            ]
            .iter()
            .cloned()
            .collect()
        };
    }
}

lazy_static::lazy_static! {
    /// OID database for sensitive attribute algorithms.
    pub static ref ALGORITHM_ATTRIBUTES: HashMap<&'static str, ObjectIdentifier> = {
        [
            ("aes-256-cbc", AES_256_CBC),
            ("aes-256-gcm", AES_256_GCM),
            ("sha2-256", SHA2_256),
            ("sha3-256", SHA3_256),
        ]
        .iter()
        .cloned()
        .collect()
    };
}

lazy_static::lazy_static! {
    /// OID database for plain certificate attributes.
    pub static ref PLAIN_ATTRIBUTES: HashMap<&'static str, ObjectIdentifier> = {
        [
            ("postalCode", ADDRESS_POSTAL_CODE),
        ]
        .iter()
        .cloned()
        .collect()
    };
}

use std::borrow::Cow;
use std::collections::HashMap;

use rasn::types::ObjectIdentifier;

// Compile-time OID constants for sensitive attributes
pub const AES_256_GCM_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 1, 46]));
pub const AES_256_CBC_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 1, 42]));
pub const SHA2_256_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 2, 1]));
pub const SHA3_256_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 2, 8]));

// Compile-time OID constants for certificate attributes
pub const FULL_NAME_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 0]));
pub const DATE_OF_BIRTH_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 1]));
pub const ADDRESS_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 2]));
pub const EMAIL_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 3]));
pub const PHONE_NUMBER_OID: ObjectIdentifier =
	ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 4, 1, 62675, 1, 4]));

lazy_static::lazy_static! {
	/// OID database for certificate attributes.
	pub static ref CERTIFICATE_ATTRIBUTE_OIDS: HashMap<&'static str, ObjectIdentifier> = {
		[
			("fullName", FULL_NAME_OID),
			("dateOfBirth", DATE_OF_BIRTH_OID),
			("address", ADDRESS_OID),
			("email", EMAIL_OID),
			("phoneNumber", PHONE_NUMBER_OID),
		]
		.iter()
		.cloned()
		.collect()
	};

	/// OID database for sensitive attribute algorithms.
	pub static ref SENSITIVE_ATTRIBUTE_OIDS: HashMap<&'static str, ObjectIdentifier> = {
		[
			("aes-256-gcm", AES_256_GCM_OID),
			("aes-256-cbc", AES_256_CBC_OID),
			("sha2-256", SHA2_256_OID),
			("sha3-256", SHA3_256_OID),
		]
		.iter()
		.cloned()
		.collect()
	};
}

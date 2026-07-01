#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
use rasn::prelude::*;
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum ContainerBox {
	#[rasn(tag(explicit(context, 0)))]
	encrypted(EncryptedBox),
	#[rasn(tag(explicit(context, 1)))]
	plaintext(PlaintextBox),
}
#[doc = " A self-describing encrypted (or plaintext) blob. The value is always"]
#[doc = " zlib-compressed; when encrypted, a per-principal asymmetrically-wrapped"]
#[doc = " symmetric key gates an AES-256-CBC body. An optional SignerInfo carries an"]
#[doc = " RFC 5652-style detached signature over the compressed bytes."]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ContainerPackage {
	pub version: Integer,
	pub container: ContainerBox,
	#[rasn(tag(explicit(context, 2)), identifier = "signerInfo")]
	pub signer_info: Option<SignerInfo>,
}
impl ContainerPackage {
	pub fn new(version: Integer, container: ContainerBox, signer_info: Option<SignerInfo>) -> Self {
		Self { version, container, signer_info }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptedBox {
	pub keys: SequenceOf<KeyStore>,
	#[rasn(identifier = "encryptionAlgorithm")]
	pub encryption_algorithm: ObjectIdentifier,
	#[rasn(identifier = "initializationVector")]
	pub initialization_vector: OctetString,
	#[rasn(identifier = "encryptedValue")]
	pub encrypted_value: OctetString,
}
impl EncryptedBox {
	pub fn new(
		keys: SequenceOf<KeyStore>,
		encryption_algorithm: ObjectIdentifier,
		initialization_vector: OctetString,
		encrypted_value: OctetString,
	) -> Self {
		Self { keys, encryption_algorithm, initialization_vector, encrypted_value }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KeyStore {
	#[rasn(identifier = "publicKey")]
	pub public_key: OctetString,
	#[rasn(identifier = "encryptedSymmetricKey")]
	pub encrypted_symmetric_key: OctetString,
}
impl KeyStore {
	pub fn new(public_key: OctetString, encrypted_symmetric_key: OctetString) -> Self {
		Self { public_key, encrypted_symmetric_key }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PlaintextBox {
	#[rasn(identifier = "plainValue")]
	pub plain_value: OctetString,
}
impl PlaintextBox {
	pub fn new(plain_value: OctetString) -> Self {
		Self { plain_value }
	}
}
#[doc = " RFC 5652 Section 5.3 SignerInfo, adapted: sid carries the signer's"]
#[doc = " type-prefixed public key, the digest is SHA3-256 over the compressed"]
#[doc = " value, and the signature is the raw fixed-width form for the key type."]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SignerInfo {
	pub version: Integer,
	#[rasn(tag(context, 0))]
	pub sid: OctetString,
	#[rasn(identifier = "digestAlgorithm")]
	pub digest_algorithm: ObjectIdentifier,
	#[rasn(identifier = "signatureAlgorithm")]
	pub signature_algorithm: ObjectIdentifier,
	pub signature: OctetString,
}
impl SignerInfo {
	pub fn new(
		version: Integer,
		sid: OctetString,
		digest_algorithm: ObjectIdentifier,
		signature_algorithm: ObjectIdentifier,
		signature: OctetString,
	) -> Self {
		Self { version, sid, digest_algorithm, signature_algorithm, signature }
	}
}

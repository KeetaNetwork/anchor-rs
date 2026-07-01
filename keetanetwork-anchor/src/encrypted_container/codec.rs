//! Transport codec for the encrypted container: zlib framing, AES-256-CBC body,
//! per-principal key wrapping, and RFC 5652-style detached signatures.
//!
//! [`EncryptedContainer`]: crate::encrypted_container::EncryptedContainer

use alloc::borrow::Cow;
use alloc::sync::Arc;
use alloc::vec::Vec;

use hex::FromHex;
use keetanetwork_account::account::{AccountPublicKey, AccountSigner, AccountVerifier};
use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_crypto::algorithms::aes_cbc::Aes256Cbc;
use keetanetwork_crypto::error::CryptoError;
use keetanetwork_crypto::operations::encryption::SymmetricEncryption;
use keetanetwork_crypto::operations::signature::SigningOptions;
use keetanetwork_crypto::prelude::{ExposeSecret, HashAlgorithm};
use keetanetwork_crypto::utils::generate_random_seed;
use num_bigint::BigInt;
use rasn::types::{Integer, ObjectIdentifier, OctetString};

use crate::asn1::oids;
use crate::encrypted_container::error::{EncryptedContainerError, OrDecryptionFailed, Result};
use crate::generated::{ContainerBox, ContainerPackage, EncryptedBox, KeyStore, PlaintextBox, SignerInfo};

/// Only container version accepted on transport.
const CONTAINER_VERSION: u64 = 1;
/// RFC 5652 `CMSVersion` for a `subjectKeyIdentifier`-addressed signer.
const SIGNER_VERSION: u64 = 3;
/// zlib compression level. The exact bytes need not match other
/// implementations: signatures bind to the stored compressed bytes, which a
/// verifier reads back without recompressing.
const ZLIB_LEVEL: u8 = 6;
/// AES-256-CBC initialization vector width.
const AES_IV_LEN: usize = 16;
/// AES-256 symmetric key width.
const AES_KEY_LEN: usize = 32;

const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 101, 112]));
const OID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 132, 0, 10]));
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10045, 3, 1, 7]));

/// A freshly generated AES key and IV for one encryption pass.
pub(crate) struct CipherMaterial {
	key: [u8; AES_KEY_LEN],
	iv: [u8; AES_IV_LEN],
}

impl CipherMaterial {
	/// Draw a random key and IV from the platform CSPRNG.
	pub(crate) fn random() -> Result<Self> {
		let key_seed = generate_random_seed()?;
		let iv_seed = generate_random_seed()?;

		let key = *key_seed.expose_secret();
		let iv = *iv_seed
			.expose_secret()
			.as_ref()
			.first_chunk::<AES_IV_LEN>()
			.ok_or(CryptoError::InvalidIvSize)?;

		Ok(Self { key, iv })
	}
}

/// The accounts gated to a container plus the symmetric material used to seal
/// its body.
pub(crate) struct Encryption<'a> {
	pub principals: &'a [Arc<GenericAccount>],
	pub material: &'a CipherMaterial,
}

/// The decoded body of a container before decryption.
pub(crate) enum ContainerBody {
	Plaintext { compressed: Vec<u8> },
	Encrypted(EncryptedBody),
}

/// The encrypted body: wrapped keys plus the AES parameters.
pub(crate) struct EncryptedBody {
	pub key_stores: Vec<KeyStore>,
	pub iv: Vec<u8>,
	pub ciphertext: Vec<u8>,
}

/// A container parsed far enough to inspect its shape and signer, but not yet
/// decrypted.
pub(crate) struct BareContainer {
	pub body: ContainerBody,
	pub signer_info: Option<SignerInfo>,
}

impl BareContainer {
	pub(crate) fn is_encrypted(&self) -> bool {
		matches!(self.body, ContainerBody::Encrypted(_))
	}
}

/// The compressed bytes exactly as stored (post-decryption) alongside the
/// inflated plaintext.
pub(crate) struct DecodedBody {
	pub compressed: Vec<u8>,
	pub plaintext: Vec<u8>,
}

/// Encode `plaintext` into a container, optionally sealing it to a principal
/// set and attaching a detached signature.
///
/// The signature covers the compressed (pre-encryption) bytes so it stays
/// verifiable after decryption.
pub(crate) fn encode(
	plaintext: &[u8],
	encryption: Option<Encryption<'_>>,
	signer: Option<&GenericAccount>,
) -> Result<Vec<u8>> {
	let compressed = compress(plaintext);
	let container = match encryption {
		Some(encryption) => seal_body(&compressed, encryption)?,
		None => {
			let compressed_octets = OctetString::from_slice(&compressed);
			let plaintext_box = PlaintextBox::new(compressed_octets);
			ContainerBox::plaintext(plaintext_box)
		}
	};
	let signer_info = match signer {
		Some(account) => Some(sign_compressed(&compressed, account)?),
		None => None,
	};

	let version = Integer::from(CONTAINER_VERSION);
	let package = ContainerPackage::new(version, container, signer_info);
	let der = rasn::der::encode(&package)?;
	Ok(der)
}

/// Parse a container's outer shape without decrypting it.
pub(crate) fn parse(encoded: &[u8]) -> Result<BareContainer> {
	let package: ContainerPackage = rasn::der::decode(encoded)?;
	let version_big = BigInt::from(package.version);
	let version = u64::try_from(version_big).unwrap_or(u64::MAX);
	if version != CONTAINER_VERSION {
		return Err(EncryptedContainerError::UnsupportedVersion { version });
	}

	let body = match package.container {
		ContainerBox::plaintext(plaintext) => ContainerBody::Plaintext { compressed: plaintext.plain_value.to_vec() },
		ContainerBox::encrypted(encrypted) => {
			assert_cipher_supported(&encrypted.encryption_algorithm)?;
			let encrypted_body = EncryptedBody {
				key_stores: encrypted.keys,
				iv: encrypted.initialization_vector.to_vec(),
				ciphertext: encrypted.encrypted_value.to_vec(),
			};
			ContainerBody::Encrypted(encrypted_body)
		}
	};

	Ok(BareContainer { body, signer_info: package.signer_info })
}

/// Recover the compressed bytes and inflated plaintext from a parsed container.
///
/// `principals` is consulted only for encrypted bodies; for those, one of the
/// accounts must both match a key-store entry and hold a private key.
pub(crate) fn decode_body(body: &ContainerBody, principals: &[Arc<GenericAccount>]) -> Result<DecodedBody> {
	let compressed = match body {
		ContainerBody::Plaintext { compressed } => compressed.clone(),
		ContainerBody::Encrypted(encrypted) => decrypt_body(encrypted, principals)?,
	};

	let plaintext = decompress(&compressed)?;
	Ok(DecodedBody { compressed, plaintext })
}

/// Reconstruct a public-key-only account from its type-prefixed transport form.
pub(crate) fn account_from_public_key(public_key_and_type: &[u8]) -> Result<GenericAccount> {
	let public_key_and_type_hex = hex::encode(public_key_and_type);
	let account = GenericAccount::from_hex(public_key_and_type_hex)?;
	Ok(account)
}

/// Verify a detached signature against the compressed bytes it should cover.
///
/// Returns `Ok(false)` for a structurally valid but incorrect signature, and an
/// error only when the algorithms are unsupported or the signer key is
/// unusable.
pub(crate) fn verify(signer_info: &SignerInfo, data: &[u8]) -> Result<bool> {
	assert_digest_supported(&signer_info.digest_algorithm)?;
	assert_signature_supported(&signer_info.signature_algorithm)?;

	let signer = account_from_public_key(signer_info.sid.as_ref())?;
	let message = HashAlgorithm::Sha3_256.hash(data);
	let options = Some(SigningOptions::raw());
	let outcome = signer.verify(&message, signer_info.signature.as_ref(), options);

	Ok(outcome.is_ok())
}

fn seal_body(compressed: &[u8], encryption: Encryption<'_>) -> Result<ContainerBox> {
	let aes = Aes256Cbc::new();
	let iv_and_ciphertext = aes.encrypt(encryption.material.key, Some(&encryption.material.iv), compressed)?;
	let ciphertext = iv_and_ciphertext
		.get(AES_IV_LEN..)
		.ok_or(CryptoError::EncryptionFailed)?
		.to_vec();

	let mut keys = Vec::with_capacity(encryption.principals.len());
	for principal in encryption.principals {
		let wrapped_key = principal.encrypt(encryption.material.key)?;
		let public_key = principal.to_public_key_with_type();
		let public_key_octets = OctetString::from_slice(&public_key);
		let wrapped_key_octets = OctetString::from_slice(&wrapped_key);

		keys.push(KeyStore::new(public_key_octets, wrapped_key_octets));
	}

	let initialization_vector = OctetString::from_slice(&encryption.material.iv);
	let encryption_algorithm = oids::AES_256_CBC;
	let encrypted_value = OctetString::from_slice(&ciphertext);

	let encrypted = EncryptedBox::new(keys, encryption_algorithm, initialization_vector, encrypted_value);
	Ok(ContainerBox::encrypted(encrypted))
}

/// Whether a type-erased signer carries the private key signing requires.
///
/// TODO: Update Account with an AccountPrivateKey trait
fn signer_has_private_key(signer: &GenericAccount) -> bool {
	match signer {
		GenericAccount::EcdsaSecp256k1(account) => account.has_private_key(),
		GenericAccount::EcdsaSecp256r1(account) => account.has_private_key(),
		GenericAccount::Ed25519(account) => account.has_private_key(),
		GenericAccount::Network(account) => account.has_private_key(),
		GenericAccount::Token(account) => account.has_private_key(),
		GenericAccount::Storage(account) => account.has_private_key(),
		GenericAccount::Multisig(account) => account.has_private_key(),
	}
}

fn sign_compressed(compressed: &[u8], signer: &GenericAccount) -> Result<SignerInfo> {
	if !signer_has_private_key(signer) {
		return Err(EncryptedContainerError::SignerRequiresPrivateKey);
	}

	let digest = HashAlgorithm::Sha3_256.hash(compressed);
	let signature = signer.sign(&digest, Some(SigningOptions::raw()))?;
	let sid = signer.to_public_key_with_type();
	let signature_algorithm = signature_algorithm_oid(signer)?;

	let version = Integer::from(SIGNER_VERSION);
	let sid = OctetString::from_slice(&sid);
	let digest_algorithm = oids::SHA3_256;
	let signature = OctetString::from_slice(&signature);

	let signer_info = SignerInfo::new(version, sid, digest_algorithm, signature_algorithm, signature);
	Ok(signer_info)
}

fn decrypt_body(encrypted: &EncryptedBody, principals: &[Arc<GenericAccount>]) -> Result<Vec<u8>> {
	if principals.is_empty() {
		return Err(EncryptedContainerError::NoKeysProvided);
	}

	let cipher_key = unwrap_symmetric_key(encrypted, principals)?;
	let aes = Aes256Cbc::new();
	let mut iv_and_ciphertext = Vec::with_capacity(encrypted.iv.len() + encrypted.ciphertext.len());

	iv_and_ciphertext.extend_from_slice(&encrypted.iv);
	iv_and_ciphertext.extend_from_slice(&encrypted.ciphertext);

	let compressed = aes
		.decrypt(&cipher_key, &iv_and_ciphertext)
		.or_decryption_failed()?;
	Ok(compressed)
}

fn unwrap_symmetric_key(encrypted: &EncryptedBody, principals: &[Arc<GenericAccount>]) -> Result<Vec<u8>> {
	for store in &encrypted.key_stores {
		let store_public_key = store.public_key.as_ref();
		for principal in principals {
			let principal_public_key = principal.to_public_key_with_type();
			let matches_principal = principal_public_key.as_slice() == store_public_key;
			if !matches_principal {
				continue;
			}

			// A public-key-only principal (reconstructed for another store's
			// recipient) cannot unwrap; skip it and keep searching rather than
			// treating its failure as a hard decryption error.
			if let Ok(cipher_key) = principal.decrypt(store.encrypted_symmetric_key.as_ref()) {
				return Ok(cipher_key);
			}
		}
	}
	Err(EncryptedContainerError::NoMatchingKey)
}

fn compress(plaintext: &[u8]) -> Vec<u8> {
	miniz_oxide::deflate::compress_to_vec_zlib(plaintext, ZLIB_LEVEL)
}

fn decompress(compressed: &[u8]) -> Result<Vec<u8>> {
	miniz_oxide::inflate::decompress_to_vec_zlib(compressed).map_err(|_| EncryptedContainerError::DecompressionFailed)
}

fn signature_algorithm_oid(account: &GenericAccount) -> Result<ObjectIdentifier> {
	let oid = match account.to_keypair_type() {
		KeyPairType::ECDSASECP256K1 => OID_SECP256K1,
		KeyPairType::ED25519 => OID_ED25519,
		KeyPairType::ECDSASECP256R1 => OID_SECP256R1,
		_ => return Err(EncryptedContainerError::UnsupportedKeyType),
	};
	Ok(oid)
}

/// Pass when `supported` holds, otherwise surface `error`.
fn require(supported: bool, error: EncryptedContainerError) -> Result<()> {
	if supported {
		Ok(())
	} else {
		Err(error)
	}
}

fn assert_cipher_supported(oid: &ObjectIdentifier) -> Result<()> {
	let supported = *oid == oids::AES_256_CBC;
	require(supported, EncryptedContainerError::UnsupportedCipherAlgorithm)
}

fn assert_digest_supported(oid: &ObjectIdentifier) -> Result<()> {
	let supported = *oid == oids::SHA3_256;
	require(supported, EncryptedContainerError::UnsupportedDigestAlgorithm)
}

fn assert_signature_supported(oid: &ObjectIdentifier) -> Result<()> {
	let supported = *oid == OID_ED25519 || *oid == OID_SECP256K1 || *oid == OID_SECP256R1;
	require(supported, EncryptedContainerError::UnsupportedSignatureAlgorithm)
}

#[cfg(test)]
mod tests {
	use keetanetwork_account::{Account, KeyPair};

	use super::*;
	use crate::test_all_key_types;

	/// Build a private-key-backed generic account so the same value can encrypt,
	/// decrypt, and sign within a test.
	fn to_generic(account: Account<impl KeyPair>) -> GenericAccount {
		let private_key = account
			.keypair
			.take_private_key()
			.expect("test account holds a private key");
		GenericAccount::try_from(private_key).expect("generic account from private key")
	}

	test_all_key_types!(plaintext_round_trips, |account: Account<_>| {
		let _ = &account;
		let payload = b"plaintext-roundtrip-payload";
		let encoded = encode(payload, None, None).expect("encode plaintext");
		let bare = parse(&encoded).expect("parse plaintext");
		assert!(!bare.is_encrypted());

		let decoded = decode_body(&bare.body, &[]).expect("decode plaintext");
		assert_eq!(decoded.plaintext, payload);
	});

	test_all_key_types!(encrypted_round_trips, |account: Account<_>| {
		let payload = b"encrypted-roundtrip-payload";
		let principals = [Arc::new(to_generic(account))];
		let material = CipherMaterial::random().expect("material");
		let encryption = Encryption { principals: &principals, material: &material };
		let encoded = encode(payload, Some(encryption), None).expect("encode encrypted");

		let bare = parse(&encoded).expect("parse encrypted");
		assert!(bare.is_encrypted());

		let decoded = decode_body(&bare.body, &principals).expect("decode encrypted");
		assert_eq!(decoded.plaintext, payload);
	});

	test_all_key_types!(decrypt_without_keys_is_rejected, |account: Account<_>| {
		let payload = b"needs-a-key";
		let principals = [Arc::new(to_generic(account))];
		let material = CipherMaterial::random().expect("material");
		let encryption = Encryption { principals: &principals, material: &material };
		let encoded = encode(payload, Some(encryption), None).expect("encode encrypted");
		let bare = parse(&encoded).expect("parse encrypted");

		let outcome = decode_body(&bare.body, &[]);
		assert!(matches!(outcome, Err(EncryptedContainerError::NoKeysProvided)));
	});

	test_all_key_types!(signature_round_trips_and_detects_tamper, |account: Account<_>| {
		let payload = b"signed-payload";
		let signer = to_generic(account);
		let encoded = encode(payload, None, Some(&signer)).expect("encode signed");
		let bare = parse(&encoded).expect("parse signed");
		let signer_info = bare.signer_info.expect("signer info present");
		let decoded = decode_body(&bare.body, &[]).expect("decode signed");

		let valid = verify(&signer_info, &decoded.compressed).expect("verify");
		assert!(valid);

		let mut tampered = decoded.compressed.clone();
		tampered.push(0);

		let invalid = verify(&signer_info, &tampered).expect("verify tampered");
		assert!(!invalid);
	});

	test_all_key_types!(signing_requires_a_private_key, |account: Account<_>| {
		let signer = to_generic(account);
		let public_only = account_from_public_key(&signer.to_public_key_with_type()).expect("public-only signer");

		let outcome = encode(b"unsigned-without-key", None, Some(&public_only));
		assert!(matches!(outcome, Err(EncryptedContainerError::SignerRequiresPrivateKey)));
	});

	test_all_key_types!(tampered_ciphertext_is_rejected, |account: Account<_>| {
		let payload = b"sealed-but-corrupted";
		let principals = [Arc::new(to_generic(account))];
		let material = CipherMaterial::random().expect("material");
		let encryption = Encryption { principals: &principals, material: &material };
		let encoded = encode(payload, Some(encryption), None).expect("encode encrypted");

		let bare = parse(&encoded).expect("parse encrypted");
		let ContainerBody::Encrypted(mut body) = bare.body else {
			panic!("expected an encrypted body");
		};

		let last = body.ciphertext.len() - 1;
		body.ciphertext[last] ^= 0xFF;

		let outcome = decode_body(&ContainerBody::Encrypted(body), &principals);
		assert!(matches!(
			outcome,
			Err(EncryptedContainerError::DecryptionFailed | EncryptedContainerError::DecompressionFailed)
		));
	});

	test_all_key_types!(unsupported_version_is_rejected, |account: Account<_>| {
		let _ = &account;
		let package = ContainerPackage::new(
			Integer::from(2u64),
			ContainerBox::plaintext(PlaintextBox::new(OctetString::from_slice(&compress(b"x")))),
			None,
		);

		let encoded = rasn::der::encode(&package).expect("encode v2");
		let outcome = parse(&encoded);
		assert!(matches!(outcome, Err(EncryptedContainerError::UnsupportedVersion { version: 2 })));
	});
}

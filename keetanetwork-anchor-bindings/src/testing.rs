//! Shared reference-bearing certificate fixtures for the binding op tests.

use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_anchor::certificates::KycCertificate;
use keetanetwork_anchor::doc_utils::{create_secp256k1_test_account, create_test_certificate_builder};
use keetanetwork_crypto::prelude::{HashAlgorithm, IntoSecret};

use crate::encrypted_container as ec_ops;

/// The referenced blob's plaintext, digest-certified by the fixture reference.
pub(crate) const BLOB_PLAINTEXT: &[u8] = b"NOT REALLY A PNG";
/// The attribute carrying the fixture's external reference.
pub(crate) const LICENSE: &str = "documentDriversLicense";

/// Issue a leaf whose sensitive drivers-license value carries an external blob
/// reference, returning the certificate, the erased subject able to decrypt
/// it, and the uppercase-hex reference id.
pub(crate) fn document_certificate() -> (KycCertificate, Arc<GenericAccount>, String) {
	let subject = create_secp256k1_test_account(Some(0));
	let issuer = create_secp256k1_test_account(Some(1));
	let digest = HashAlgorithm::Sha3_256.hash(BLOB_PLAINTEXT);
	let id = hex::encode_upper(&digest);

	let license = serde_json::json!({
		"documentNumber": "DL-7",
		"front": {
			"external": { "url": "data:application/octet-string;base64,AAAA", "contentType": "image/png" },
			"digest": { "digestAlgorithm": "sha3-256", "digest": { "type": "Buffer", "data": digest } },
			"encryptionAlgorithm": "1.3.6.1.4.1.62675.2",
		},
	});

	let license_bytes = serde_json::to_vec(&license).expect("license json encodes");
	let certificate = create_test_certificate_builder(&subject)
		.with_sensitive_attribute(LICENSE, license_bytes.into_secret())
		.build(&subject.keypair, &issuer.keypair)
		.expect("fixture certificate builds");

	(certificate, Arc::new(GenericAccount::EcdsaSecp256k1(subject)), id)
}

/// Seal `plaintext` to `subject` through the container ops, producing the raw
/// stored form a fetched reference blob arrives in.
pub(crate) fn seal_blob(plaintext: &[u8], subject: &Arc<GenericAccount>) -> Vec<u8> {
	let principals = [Arc::clone(subject)];
	let mut container = ec_ops::from_plaintext(plaintext.to_vec(), Some(&principals), Some(true), None);

	ec_ops::get_encoded(&mut container).expect("sealed blob encodes")
}

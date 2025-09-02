use keetanetwork_account::{Account, AccountError, Accountable, KeyPair};
use keetanetwork_crypto::prelude::{CryptoSignerWithOptions, SignatureEncoding};

use keetanetwork_anchor::asn1::oids;
use keetanetwork_anchor::generated::KYCAttributes;

mod common;
use common::{
	create_kyc_from_attributes, create_kyc_with_attributes, create_plain_attribute, create_sensitive_attribute,
	test_attribute_properties, test_kyc_count, test_mixed_attribute_counts, test_oids_exist, test_oids_not_exist,
	TestData,
};

/// Test KYC schema builder functionality with actual API
fn test_kyc_attributes_builder_basic<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let test_data = TestData::standard();

	// Test empty KYC attributes
	let empty_kyc = create_kyc_with_attributes::<String>(&[], &[]);
	assert!(test_kyc_count(&empty_kyc, 0).is_ok());

	// Test single plain attribute
	let plain_kyc = create_kyc_with_attributes(&[(oids::keeta::FULL_NAME, test_data.full_name.as_bytes())], &[]);
	assert!(test_kyc_count(&plain_kyc, 1).is_ok());

	// Test multiple sensitive attributes
	let sensitive_kyc = create_kyc_with_attributes(
		&[],
		&[(oids::keeta::FULL_NAME, test_data.full_name.as_bytes()), (oids::keeta::EMAIL, test_data.email.as_bytes())],
	);
	assert!(test_kyc_count(&sensitive_kyc, 2).is_ok());

	// Test mixed attributes
	let mixed_kyc = create_kyc_with_attributes(
		&[(oids::ADDRESS_POSTAL_CODE, test_data.postal_code.as_bytes())],
		&[
			(oids::keeta::FULL_NAME, test_data.full_name.as_bytes()),
			(oids::keeta::EMAIL, test_data.email.as_bytes()),
			(oids::keeta::PHONE_NUMBER, test_data.phone_number.as_bytes()),
		],
	);
	assert!(test_kyc_count(&mixed_kyc, 4).is_ok());
}

/// Test KYC attributes iteration and access
fn test_kyc_attributes_access<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let test_data = TestData::standard();
	let kyc_attributes = create_kyc_with_attributes(
		&[(oids::ADDRESS_POSTAL_CODE, test_data.postal_code.as_bytes())],
		&[(oids::keeta::FULL_NAME, test_data.full_name.as_bytes()), (oids::keeta::EMAIL, test_data.email.as_bytes())],
	);

	// Test finding attributes by OID
	assert!(test_oids_exist(&kyc_attributes, &[oids::ADDRESS_POSTAL_CODE, oids::keeta::FULL_NAME, oids::keeta::EMAIL])
		.is_ok());
	// Test non-existent attribute
	assert!(test_oids_not_exist(&kyc_attributes, &["1.2.3.4.5"]).is_ok());
	// Test iteration and counts
	assert!(test_mixed_attribute_counts(&kyc_attributes, 1, 2).is_ok());

	// Verify specific attribute types
	let postal_attr = kyc_attributes
		.find_by_oid(oids::ADDRESS_POSTAL_CODE.to_string())
		.expect("ADDRESS_POSTAL_CODE attribute should exist");
	assert!(test_attribute_properties(postal_attr, test_data.postal_code.as_bytes(), false).is_ok());

	let name_attr = kyc_attributes
		.find_by_oid(oids::keeta::FULL_NAME.to_string())
		.expect("FULL_NAME attribute should exist");
	assert!(test_attribute_properties(name_attr, test_data.full_name.as_bytes(), true).is_ok());
}

/// Test KYC attributes serialization
fn test_kyc_attributes_serialization<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let test_data = TestData::standard();
	let original_kyc = create_kyc_with_attributes(
		&[(oids::ADDRESS_POSTAL_CODE, test_data.postal_code.as_bytes())],
		&[(oids::keeta::EMAIL, test_data.email.as_bytes())],
	);

	// Test DER encoding/decoding
	let der_bytes = original_kyc.to_der().expect("Failed to encode KYC to DER");
	assert!(!der_bytes.is_empty());

	// Verify decoded attributes match original
	let decoded_kyc = KYCAttributes::try_from(der_bytes).expect("Failed to decode KYC from DER");
	assert!(test_kyc_count(&decoded_kyc, 2).is_ok());
	assert!(test_oids_exist(&decoded_kyc, &[oids::ADDRESS_POSTAL_CODE, oids::keeta::EMAIL]).is_ok());
}

/// Test individual attribute builder
fn test_attribute_builder<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let test_data = TestData::standard();

	// Test plain attribute creation
	let plain_attr = create_plain_attribute(oids::ADDRESS_POSTAL_CODE, test_data.postal_code.as_bytes());
	assert!(test_attribute_properties(&plain_attr, test_data.postal_code.as_bytes(), false).is_ok());

	// Test sensitive attribute creation
	let sensitive_attr = create_sensitive_attribute(oids::keeta::FULL_NAME, test_data.full_name.as_bytes());
	assert!(test_attribute_properties(&sensitive_attr, test_data.full_name.as_bytes(), true).is_ok());

	// Test using pre-built attributes in KYC builder
	let kyc_attributes = create_kyc_from_attributes(vec![plain_attr, sensitive_attr]);
	assert!(test_kyc_count(&kyc_attributes, 2).is_ok());
}

#[cfg(feature = "serde")]
/// Test JSON serialization if serde feature is enabled
fn test_kyc_json_serialization<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let test_data = TestData::standard();
	let kyc_attributes = create_kyc_with_attributes(
		&[(oids::ADDRESS_POSTAL_CODE, test_data.postal_code.as_bytes())],
		&[(oids::keeta::EMAIL, test_data.email.as_bytes())],
	);

	// Test JSON serialization
	let json_str = serde_json::to_string(&kyc_attributes).expect("Failed to serialize KYC to JSON");
	assert!(!json_str.is_empty());

	// Test JSON deserialization
	let deserialized: KYCAttributes = serde_json::from_str(&json_str).expect("Failed to deserialize JSON to KYC");
	// Verify deserialized data matches original
	assert!(test_kyc_count(&deserialized, 2).is_ok());
	assert!(test_oids_exist(&deserialized, &[oids::ADDRESS_POSTAL_CODE, oids::keeta::EMAIL]).is_ok());
}

// Run tests across all key types
keetanetwork_anchor::test_all_key_types!(test_kyc_builder_basic, test_kyc_attributes_builder_basic);
keetanetwork_anchor::test_all_key_types!(test_kyc_access, test_kyc_attributes_access);
keetanetwork_anchor::test_all_key_types!(test_kyc_serialization, test_kyc_attributes_serialization);
keetanetwork_anchor::test_all_key_types!(test_attr_builder, test_attribute_builder);

#[cfg(feature = "serde")]
keetanetwork_anchor::test_all_key_types!(test_kyc_json, test_kyc_json_serialization);

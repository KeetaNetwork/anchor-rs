mod common;

use keetanetwork_account::{Account, AccountError, Accountable, KeyPair};
use keetanetwork_anchor::certificates::{KycCertificate, KycCertificateBuilder};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::prelude::{CryptoSignerWithOptions, IntoSecret, SignatureEncoding};
use keetanetwork_x509::utils::create_dn;
use keetanetwork_x509::SerialNumber;

use common::{
	test_certificate_attributes, test_certificate_issued_by, test_get_kyc_attribute_value, test_has_kyc_attributes,
	test_plain_attributes,
};
use common::{TestAccounts, TestData};

/// KycCertificate test scenario builder
pub struct KycCertificateTestBuilder<T: KeyPair>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	accounts: TestAccounts<T>,
	test_data: TestData,
	ca_certificate: Option<KycCertificate>,
	intermediate_certificate: Option<KycCertificate>,
}

impl<T: KeyPair> Default for KycCertificateTestBuilder<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	fn default() -> Self {
		Self::new()
	}
}

impl<T: KeyPair> KycCertificateTestBuilder<T>
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
{
	/// Create a new test builder with standard accounts and data
	pub fn new() -> Self {
		Self {
			accounts: TestAccounts::new(),
			test_data: TestData::standard(),
			ca_certificate: None,
			intermediate_certificate: None,
		}
	}

	/// Create a test builder with custom seeds
	pub fn with_seeds(issuer_seed: u32, subject_seed: u32) -> Self {
		Self {
			accounts: TestAccounts::with_seeds(issuer_seed, subject_seed),
			test_data: TestData::standard(),
			ca_certificate: None,
			intermediate_certificate: None,
		}
	}

	/// Use sensitive attribute test data
	pub fn with_sensitive_data(mut self) -> Self {
		self.test_data = TestData::sensitive_attribute();
		self
	}

	/// Create a CA certificate and store it in the builder
	pub fn create_ca_certificate<S>(&mut self) -> Result<KycCertificate, Box<dyn std::error::Error>>
	where
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		let ca_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test CA Root")])?;
		let ca_public_key_info = SubjectPublicKeyInfo::try_from(&self.accounts.issuer)?;

		let certificate = KycCertificateBuilder::for_ca()
			.with_subject_dn(ca_dn.clone())
			.with_issuer_dn(ca_dn) // Self-signed
			.with_serial_number(SerialNumber::from(3u64))
			.with_validity_days(3650)
			.with_subject_public_key(ca_public_key_info)
			.with_basic_constraints(true, Some(5))
			.build(&self.accounts.issuer.keypair, &self.accounts.issuer.keypair)?;

		self.ca_certificate = Some(certificate.clone());
		Ok(certificate)
	}

	/// Create an intermediate certificate signed by the CA
	pub fn create_intermediate_certificate<S>(&mut self) -> Result<KycCertificate, Box<dyn std::error::Error>>
	where
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// Ensure we have a CA certificate first
		if self.ca_certificate.is_none() {
			self.create_ca_certificate::<S>()?;
		}

		let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Intermediate CA")])?;
		let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test CA Root")])?; // Signed by CA
		let subject_public_key_info = SubjectPublicKeyInfo::try_from(&self.accounts.subject)?;

		let certificate = KycCertificateBuilder::for_ca()
			.with_subject_dn(subject_dn)
			.with_issuer_dn(issuer_dn)
			.with_serial_number(SerialNumber::from(6u64))
			.with_validity_days(1825) // 5 years
			.with_subject_public_key(subject_public_key_info)
			.with_basic_constraints(true, Some(0)) // Path length 0 for intermediate
			.build(&self.accounts.subject.keypair, &self.accounts.issuer.keypair)?;

		self.intermediate_certificate = Some(certificate.clone());
		Ok(certificate)
	}

	/// Create a user certificate with KYC attributes signed by the CA
	pub fn create_user_certificate<S>(&mut self) -> Result<KycCertificate, Box<dyn std::error::Error>>
	where
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// Ensure we have a CA certificate first
		if self.ca_certificate.is_none() {
			self.create_ca_certificate::<S>()?;
		}

		let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test Subject")])?;
		let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test CA Root")])?;
		let subject_public_key_info = SubjectPublicKeyInfo::try_from(&self.accounts.subject)?;

		let certificate = KycCertificateBuilder::for_end_entity()
			.with_subject_dn(subject_dn)
			.with_issuer_dn(issuer_dn)
			.with_serial_number(SerialNumber::from(4u64))
			.with_validity_days(365)
			.with_subject_public_key(subject_public_key_info)
			.with_sensitive_attribute("fullName", self.test_data.full_name.as_bytes().to_vec().into_secret())
			.with_sensitive_attribute("email", self.test_data.email.as_bytes().to_vec().into_secret())
			.with_sensitive_attribute(
				"phoneNumber",
				self.test_data
					.phone_number
					.as_bytes()
					.to_vec()
					.into_secret(),
			)
			.with_sensitive_attribute("address", self.test_data.address.as_bytes().to_vec().into_secret())
			.with_sensitive_attribute(
				"dateOfBirth",
				self.test_data
					.date_of_birth
					.as_bytes()
					.to_vec()
					.into_secret(),
			)
			.build(&self.accounts.subject.keypair, &self.accounts.issuer.keypair)?;

		Ok(certificate)
	}

	/// Create a user certificate with mixed plain and sensitive attributes signed by the CA
	pub fn create_mixed_certificate<S>(&mut self) -> Result<KycCertificate, Box<dyn std::error::Error>>
	where
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// Ensure we have a CA certificate first
		if self.ca_certificate.is_none() {
			self.create_ca_certificate::<S>()?;
		}

		let subject_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Mixed Test")])?;
		let issuer_dn = create_dn(&[(keetanetwork_x509::oids::CN, "Test CA Root")])?;
		let subject_public_key_info = SubjectPublicKeyInfo::try_from(&self.accounts.subject)?;

		let certificate = KycCertificateBuilder::for_end_entity()
			.with_subject_dn(subject_dn)
			.with_issuer_dn(issuer_dn)
			.with_serial_number(SerialNumber::from(5u64))
			.with_validity_days(365)
			.with_subject_public_key(subject_public_key_info)
			// Plain text attribute
			.with_plain_attribute("postalCode", self.test_data.postal_code)
			// Sensitive attributes
			.with_sensitive_attribute("fullName", self.test_data.full_name.as_bytes().to_vec().into_secret())
			.with_sensitive_attribute("email", self.test_data.email.as_bytes().to_vec().into_secret())
			.build(&self.accounts.subject.keypair, &self.accounts.issuer.keypair)?;

		Ok(certificate)
	}

	/// Get reference to test accounts
	pub fn accounts(&self) -> &TestAccounts<T> {
		&self.accounts
	}

	/// Get reference to test data
	pub fn test_data(&self) -> &TestData {
		&self.test_data
	}

	/// Get the stored CA certificate
	pub fn ca_certificate(&self) -> Option<&KycCertificate> {
		self.ca_certificate.as_ref()
	}

	/// Get the stored intermediate certificate
	pub fn intermediate_certificate(&self) -> Option<&KycCertificate> {
		self.intermediate_certificate.as_ref()
	}

	/// Get the issuer certificate for user certificate validation
	/// Returns intermediate if available, otherwise CA
	pub fn issuer_certificate(&self) -> Option<&KycCertificate> {
		self.intermediate_certificate
			.as_ref()
			.or(self.ca_certificate.as_ref())
	}
}

/// Test certificate creation workflow
fn test_certificate_workflow<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let mut builder = KycCertificateTestBuilder::<T>::new();

	let ca_certificate = builder
		.create_ca_certificate::<S>()
		.expect("Failed to create CA certificate");
	assert!(test_has_kyc_attributes(&ca_certificate, 0, "CA cert").is_ok());

	let user_certificate = builder
		.create_user_certificate::<S>()
		.expect("Failed to create user certificate");
	assert!(test_has_kyc_attributes(&user_certificate, 5, "User cert").is_ok());
	assert!(test_certificate_issued_by(&user_certificate, &ca_certificate).is_ok());

	// Get references after mutations are complete
	let accounts = builder.accounts();
	let test_data = builder.test_data();
	assert!(test_certificate_attributes::<T, S>(&user_certificate, accounts, test_data).is_ok());
}

/// Test certificate with mixed plain and sensitive attributes
fn test_mixed_certificate_attributes<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let mut builder = KycCertificateTestBuilder::<T>::new();

	// Create certificate with both plain and sensitive attributes
	let mixed_certificate = builder
		.create_mixed_certificate::<S>()
		.expect("Failed to create mixed certificate");
	assert!(test_has_kyc_attributes(&mixed_certificate, 3, "Mixed cert").is_ok());

	// Get references after mutations are complete
	let accounts = builder.accounts();
	let test_data = builder.test_data();
	assert!(test_plain_attributes(&mixed_certificate, test_data).is_ok());
	assert!(test_certificate_attributes::<T, S>(&mixed_certificate, accounts, test_data).is_ok());
}

/// Test certificate builder with different configurations
fn test_certificate_builder_configurations<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let mut builder = KycCertificateTestBuilder::<T>::new();
	// Test basic CA certificate without KYC attributes
	let ca_cert = builder
		.create_ca_certificate::<S>()
		.expect("Failed to create CA certificate");
	assert!(test_has_kyc_attributes(&ca_cert, 0, "CA cert").is_ok());

	// Test user certificate with mixed attributes
	let user_cert = builder
		.create_user_certificate::<S>()
		.expect("Failed to create user certificate");
	assert!(test_has_kyc_attributes(&user_cert, 5, "User cert").is_ok());

	// Test certificate with only mixed attributes
	let mixed_cert = builder
		.create_mixed_certificate::<S>()
		.expect("Failed to create mixed certificate");
	assert!(test_has_kyc_attributes(&mixed_cert, 3, "Mixed cert").is_ok());
}

/// Test certificate error handling and edge cases
fn test_certificate_error_handling<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let accounts = TestAccounts::<T>::new();
	// Create a test certificate for error testing
	let mut builder = KycCertificateTestBuilder::<T>::new();
	let test_cert = builder
		.create_mixed_certificate::<S>()
		.expect("Failed to create test certificate");
	// Test accessing plain attribute without keypair (should work)
	assert!(test_get_kyc_attribute_value::<T>(&test_cert, "postalCode", None).is_ok());
	// Test with correct keypair (should work)
	assert!(test_get_kyc_attribute_value::<T>(&test_cert, "fullName", Some(&accounts.subject.keypair)).is_ok());
	// Test accessing non-existent attributes using helper
	assert!(test_get_kyc_attribute_value::<T>(&test_cert, "nonExistent", None).is_err());
	// Test accessing sensitive attribute without keypair (should fail)
	assert!(test_get_kyc_attribute_value::<T>(&test_cert, "fullName", None).is_err());
	// Test with wrong keypair (should fail)
	assert!(test_get_kyc_attribute_value(&test_cert, "fullName", Some(&accounts.wrong_account.keypair)).is_err());
}

/// Test certificate attribute access without private key
fn test_certificate_without_private_key<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let mut builder = KycCertificateTestBuilder::<T>::new();

	// Test that attributes exist but can't be decrypted without the private key
	let user_certificate = builder
		.create_user_certificate::<S>()
		.expect("Failed to create user certificate");
	assert!(test_get_kyc_attribute_value::<T>(&user_certificate, "fullName", None).is_err());
	assert!(test_get_kyc_attribute_value::<T>(&user_certificate, "email", None).is_err());

	// Get references after mutations are complete
	let accounts = builder.accounts();
	// Test that decryption fails with public-only account
	let keypair = Some(&accounts.subject_public_only.keypair);
	assert!(test_get_kyc_attribute_value::<T>(&user_certificate, "fullName", keypair).is_err());
}

/// Test CA certificate creation and properties
fn test_ca_certificate_creation<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	// Create CA certificate with proper extensions using builder
	let ca_cert = KycCertificateTestBuilder::<T>::new()
		.create_ca_certificate::<S>()
		.expect("Failed to create CA certificate");
	// Verify CA certificate properties
	assert!(test_has_kyc_attributes(&ca_cert, 0, "CA").is_ok());

	// Verify we can access the underlying X.509 certificate
	let x509_cert = ca_cert.to_x509();
	let serial_number = x509_cert.to_serial_number();
	assert!(!serial_number.as_bytes().is_empty(), "Should have serial number");
}

/// Test certificate builder validation and constraints  
fn test_certificate_builder_validation<T, S>(_account: Account<T>)
where
	Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	T: KeyPair + CryptoSignerWithOptions<S> + 'static,
	S: SignatureEncoding,
{
	let mut builder = KycCertificateTestBuilder::<T>::new();
	// Test builder creates valid certificates
	let valid_cert = builder
		.create_user_certificate::<S>()
		.expect("Should create valid certificate");
	assert!(test_has_kyc_attributes(&valid_cert, 5, "Valid cert").is_ok());
}

keetanetwork_anchor::test_all_key_types!(test_certificates_workflow, test_certificate_workflow);
keetanetwork_anchor::test_all_key_types!(test_mixed_attributes, test_mixed_certificate_attributes);
keetanetwork_anchor::test_all_key_types!(test_builder_configs, test_certificate_builder_configurations);
keetanetwork_anchor::test_all_key_types!(test_cert_errors, test_certificate_error_handling);
keetanetwork_anchor::test_all_key_types!(test_no_private_key, test_certificate_without_private_key);
keetanetwork_anchor::test_all_key_types!(test_ca_creation, test_ca_certificate_creation);
keetanetwork_anchor::test_all_key_types!(test_builder_validation, test_certificate_builder_validation);

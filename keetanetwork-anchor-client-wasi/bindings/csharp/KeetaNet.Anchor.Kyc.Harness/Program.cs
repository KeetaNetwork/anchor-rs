// Test harness for the C# KYC binding, exercised by the Rust host-tests
// `csharp_p1_kyc.rs` (networked) and `p1_crypto.rs` (crypto only). Each env-var
// mode runs assertions and prints a sentinel the host-tests check for.

using KeetaNet.Anchor.Kyc;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Account = KeetaNet.Anchor.Kyc.Crypto.Account;
using AttributeProof = KeetaNet.Anchor.Kyc.Crypto.AttributeProof;
using CryptoCertificate = KeetaNet.Anchor.Kyc.Crypto.Certificate;
using EncryptedContainer = KeetaNet.Anchor.Kyc.Crypto.EncryptedContainer;
using KycCertificate = KeetaNet.Anchor.Kyc.Crypto.KycCertificate;
using KycCertificateBuilder = KeetaNet.Anchor.Kyc.Crypto.KycCertificateBuilder;
using SharableCertificateAttributes = KeetaNet.Anchor.Kyc.Crypto.SharableCertificateAttributes;

string wasmPath = RequireEnv("KEETA_ANCHOR_P1_WASM");

using var runtime = WasmRuntime.Load(wasmPath);

// Exercise the `crypto` resources only, needing no node or harness.
if (Environment.GetEnvironmentVariable("KEETA_CRYPTO_ONLY") is not null)
{
	CryptoSelfTest(runtime);
	Console.WriteLine("CRYPTO_OK");
	return;
}

// Issue a leaf through the builder, then read it back.
if (Environment.GetEnvironmentVariable("KEETA_ISSUE_ONLY") is not null)
{
	IssueSelfTest(runtime);
	Console.WriteLine("ISSUE_OK");
	return;
}

// Issue a leaf, then prove and validate a sensitive attribute.
if (Environment.GetEnvironmentVariable("KEETA_PROVE_ONLY") is not null)
{
	ProveSelfTest(runtime);
	Console.WriteLine("PROVE_OK");
	return;
}

// Build, encode, decode, sign, and re-key an encrypted container.
if (Environment.GetEnvironmentVariable("KEETA_CONTAINER_ONLY") is not null)
{
	ContainerSelfTest(runtime);
	Console.WriteLine("CONTAINER_OK");
	return;
}

// Seal a subset of a leaf's attributes for a recipient, then open
// the PEM envelope and read the disclosed values back.
if (Environment.GetEnvironmentVariable("KEETA_SHARABLE_ONLY") is not null)
{
	SharableSelfTest(runtime);
	Console.WriteLine("SHARABLE_OK");
	return;
}

// Cross-implementation compatibility against the reference TypeScript anchor:
// decode and verify a TS-produced container, then emit a C#-produced one for the
// TS reader to decode and verify.
if (Environment.GetEnvironmentVariable("KEETA_CONTAINER_COMPATIBILITY") is not null)
{
	ContainerCompatibility(runtime);
	Console.WriteLine("CONTAINER_COMPATIBILITY_OK");
	return;
}

string nodeApi = RequireEnv("KEETA_NODE_API");
string root = RequireEnv("KEETA_ROOT");
string providerId = RequireEnv("KEETA_PROVIDER_ID");
string seed = Environment.GetEnvironmentVariable("KEETA_SEED") ?? new string('1', 64);

string[] algorithms = { "ed25519", "ecdsa_secp256k1", "ecdsa_secp256r1" };
string[] countries = { "US" };

foreach (string algorithm in algorithms)
{
	// Build the signer as a `crypto` account, then bind the client over it,
	// exercising the account-handle path end-to-end.
	using Account signer = Account.FromSeed(runtime, seed, 0, algorithm);
	using var client = KycClient.WithAccount(runtime, nodeApi, root, signer);

	IReadOnlyList<KycProvider> providers = client.Providers(countries);
	Require(providers.Count == 1, $"{algorithm}: expected exactly one provider, got {providers.Count}");

	KycProvider provider = providers[0];
	Require(provider.Id == providerId, $"{algorithm}: provider id mismatch ({provider.Id} != {providerId})");

	VerificationOutcome verification = client.CreateVerification(provider, countries);
	Require(verification.Ready is not null, $"{algorithm}: create-verification was not ready");
	Require(!string.IsNullOrEmpty(verification.Ready!.Id), $"{algorithm}: verification id was empty");
	Require(!string.IsNullOrEmpty(verification.Ready!.WebUrl), $"{algorithm}: verification web url was empty");

	StatusOutcome status = client.GetVerificationStatus(provider, verification.Ready!.Id);
	Require(status.Ready is not null, $"{algorithm}: status was not ready");
	Require(!string.IsNullOrEmpty(status.Ready!.Status), $"{algorithm}: status was empty");

	CertificatesOutcome certificates = client.GetCertificates(provider, verification.Ready!.Id);
	Require(
		certificates.Ready is not null || certificates.RetryAfterMs is not null,
		$"{algorithm}: certificates were neither ready nor a retry");

	Console.WriteLine($"{algorithm}: OK");
}

Console.WriteLine("KYC_OK");

if (Environment.GetEnvironmentVariable("KEETA_LEAF_PEM") is { } leafPem)
{
	CheckAttributes(runtime, leafPem, RequireEnv("KEETA_ATTRIBUTES_JSON"), RequireEnv("KEETA_SUBJECT_SEED"));
	Console.WriteLine("ATTRIBUTES_OK");
}

// Cross-implementation compatibility against the live TypeScript anchor: validate
// a TS-produced proof for the anchor leaf, then issue a leaf and prove an
// attribute on the C# side for the TS reader to read back and validate.
if (Environment.GetEnvironmentVariable("KEETA_COMPATIBILITY") is not null)
{
	Compatibility(runtime);
	Console.WriteLine("COMPATIBILITY_OK");
}

// Decrypt and decode every attribute of an issued leaf, asserting each matches
// the reference values.
static void CheckAttributes(WasmRuntime runtime, string leafPem, string attributesJson, string subjectSeed)
{
	using Account subject = Account.FromSeed(runtime, subjectSeed, 0, "ecdsa_secp256k1");
	using KycCertificate leaf = KycCertificate.Parse(runtime, leafPem);

	using JsonDocument attributes = JsonDocument.Parse(attributesJson);
	foreach (JsonProperty entry in attributes.RootElement.EnumerateObject())
	{
		if (entry.Value.ValueKind == JsonValueKind.String)
		{
			Require(leaf.GetText(entry.Name, subject) == entry.Value.GetString(), $"scalar attribute `{entry.Name}` must match the reference value");
			continue;
		}

		Require(JsonEqual(leaf.GetJson(entry.Name, subject), entry.Value), $"structured attribute `{entry.Name}` must match the reference value");
	}
}

// Cross-implementation compatibility against the live TypeScript anchor:
//  1. validate a proof the TS reader produced for the anchor-issued leaf,
//  2. issue a leaf on the C# side and prove an attribute on it, emitting both
//     for the Rust orchestrator to hand to the TS reader to read and validate.
static void Compatibility(WasmRuntime runtime)
{
	string subjectSeed = RequireEnv("KEETA_SUBJECT_SEED");
	string proveName = RequireEnv("KEETA_TS_PROOF_NAME");
	string wrongName = RequireEnv("KEETA_TS_WRONG_NAME");

	using Account subject = Account.FromSeed(runtime, subjectSeed, 0, "ecdsa_secp256k1");

	// 1. Validate a proof the TypeScript reader produced for the anchor leaf: it
	// validates for its attribute and not for a different one.
	using KycCertificate anchorLeaf = KycCertificate.Parse(runtime, RequireEnv("KEETA_LEAF_PEM"));
	AttributeProof tsProof = JsonSerializer.Deserialize<AttributeProof>(RequireEnv("KEETA_TS_PROOF_JSON"), Camel())
		?? throw new InvalidOperationException("the TypeScript proof JSON was empty");
	Console.WriteLine($"TS_PROOF_VALID={Bool(anchorLeaf.ValidateProof(proveName, subject, tsProof))}");
	Console.WriteLine($"TS_PROOF_WRONG={Bool(anchorLeaf.ValidateProof(wrongName, subject, tsProof))}");

	// 2. Issue a leaf on the C# side for the TypeScript reader to read back. The
	// subject shares the anchor's seed so the TS reader decrypts with one key.
	using Account issuer = Account.FromSeed(runtime, new string('2', 64), 0, "ecdsa_secp256k1");
	KycCertificateBuilder builder = KycCertificate.Builder(runtime)
		.Subject(subject)
		.Issuer(issuer)
		.SubjectName("Subject")
		.IssuerName("Issuer")
		.Serial(11)
		.Validity(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
	ApplyAttributes(builder, RequireEnv("KEETA_ISSUE_JSON"));
	using KycCertificate issued = builder.Issue();
	Console.WriteLine($"CS_LEAF={JsonSerializer.Serialize(issued.Pem())}");

	// 3. Prove an attribute on the C# leaf for the TypeScript reader to validate.
	AttributeProof csProof = issued.Prove(proveName, subject);
	Console.WriteLine($"CS_PROOF={JsonSerializer.Serialize(csProof, Camel())}");
}

// Embed each attribute from a raw issue document, mapping its JSON value to the
// builder's typed setters: a string scalar, a `{ "__date": "<ISO>" }` date, or
// an arbitrary structured value.
static void ApplyAttributes(KycCertificateBuilder builder, string issueJson)
{
	using JsonDocument document = JsonDocument.Parse(issueJson);
	foreach (JsonElement entry in document.RootElement.EnumerateArray())
	{
		string name = entry.GetProperty("name").GetString()!;
		bool sensitive = entry.GetProperty("sensitive").GetBoolean();
		JsonElement value = entry.GetProperty("value");

		switch (value.ValueKind)
		{
			case JsonValueKind.String:
				builder.SetAttribute(name, sensitive, value.GetString()!);
				break;
			case JsonValueKind.Object when value.TryGetProperty("__date", out JsonElement date):
				builder.SetAttribute(name, sensitive,
					DateTimeOffset.Parse(date.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));
				break;
			default:
				builder.SetAttribute(name, sensitive, value);
				break;
		}
	}
}

static JsonSerializerOptions Camel() => new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

static string Bool(bool value) => value ? "true" : "false";

// Structural JSON equality: objects compare by key set regardless of order,
// arrays element-wise in order, scalars by value.
static bool JsonEqual(JsonElement left, JsonElement right)
{
	if (left.ValueKind != right.ValueKind)
	{
		return false;
	}

	switch (left.ValueKind)
	{
		case JsonValueKind.Object:
			Dictionary<string, JsonElement> rightProps = right.EnumerateObject().ToDictionary(property => property.Name, property => property.Value);
			int leftCount = 0;
			foreach (JsonProperty property in left.EnumerateObject())
			{
				leftCount++;
				if (!rightProps.TryGetValue(property.Name, out JsonElement value) || !JsonEqual(property.Value, value))
				{
					return false;
				}
			}
			return leftCount == rightProps.Count;
		case JsonValueKind.Array:
			JsonElement[] leftItems = left.EnumerateArray().ToArray();
			JsonElement[] rightItems = right.EnumerateArray().ToArray();
			return leftItems.Length == rightItems.Length
				&& leftItems.Zip(rightItems, JsonEqual).All(equal => equal);
		case JsonValueKind.String:
			return left.GetString() == right.GetString();
		case JsonValueKind.Number:
			return left.GetRawText() == right.GetRawText();
		default:
			return true;
	}
}

// Exercise the offline `crypto` resources against the embedded KYC fixture: an
// account round-trip, certificate validity, and KYC attribute reads/decryption.
static void CryptoSelfTest(WasmRuntime runtime)
{
	// The seed `doc_utils` derives its subject from; the fixture is issued to the
	// secp256k1 account at index 0 of this seed.
	const string subjectSeed = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";
	const string algorithm = "ecdsa_secp256k1";
	DateTimeOffset validAt = DateTimeOffset.FromUnixTimeSeconds(1_797_292_800);
	DateTimeOffset beforeValidity = DateTimeOffset.FromUnixTimeSeconds(0);

	const string pem =
		"""
		-----BEGIN CERTIFICATE-----
		MIIDzTCCA3SgAwIBAgICMDkwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxYLVGVzdCBJ
		c3N1ZXIwIhgPMjAyNjA2MjgyMzIwNDVaGA8yMDI3MDYyODIzMjA0NVowFzEVMBMG
		A1UEAxYMVGVzdCBTdWJqZWN0MDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACpkFiKH+5
		y+/csZUSPRIZwON061asGjraczszX1LL2HujggLOMIICyjAOBgNVHQ8BAf8EBAMC
		AMAwggK2BgorBgEEAYPpUwAABIICpjCCAqIwggFKBgorBgEEAYPpUwEDgYIBOjCC
		ATYCAQAwga0GCWCGSAFlAwQBLgQMfrJEYqEtjXoXFJrDBIGRBFEOgNX6ho8+Fil3
		91HDLYxx5u/l5UuOQFnJizMqoBkD/64XdrGWeURzt5ERG33SBxNJLaIbGLfU+w+a
		mu8HII50cSOjYYGalY7HbfAxqp0QStJZC9FTnr5+jHXQLSrfLnViXjPSz9sk7+xq
		eptUlXaromEIBaKAzavrUB8xlayBDh6hXNEToOjxmSai5f4khTBfBDD4fEMxz1aM
		wJbcmH5fi75NVNQH//2775k63qU3kWwuGu4yMrwa0TVvAd274S0xbC8GCWCGSAFl
		AwQCCAQgEj0cBCSSIdCPXWPhbdFGvSuSbegC0XhbAG82dmNRkbIEIA87wpxepdKD
		7qOY7UUEd9YUxIeSSBFwM2KPhO30zl+DMIIBQgYKKwYBBAGD6VMBAIGCATIwggEu
		AgEAMIGtBglghkgBZQMEAS4EDKznmG0IQycoVdJ9VQSBkQT/6Qumd90HGs1cof3u
		5derYnULnG3pbLxExHPqdzIwnOcXyFvGR8DDgBXYmUCspHjH3AQN6wYDfQ0IQ89F
		uakNlpGpGMWy152544+VG3fbrJmPkRhxKHPpYmQfiUGMqF0kGE7tLwzbC7cLx0ni
		jkkXUwlX5/UV3kJT3wBQciD1gKgl4euhYNxAfuyLtkZaZhkwXwQwJXrikAzhMr8q
		kKtaDkAohxfngm3mLEzsE+MmuI7hobUEIm59Uze8K3JG35L7OfVABglghkgBZQME
		AggEIGJ8nq65ul0UKAY3UL84Mg0Iddj9VYVNBa3oTnANZXYfBBgqlBgcLrd4of/W
		Hu4NJE0IKwCL+Gnbok4wDAYDVQURgAUxMjM0NTAKBggqhkjOPQQDAgNHADBEAiBY
		mcOwl1yNkItpFWeWby4gqa0rHOw7U0bHxpk9kYWHbgIgVbO0xyOAB7ByOqMO40Qh
		or6z8/Cbh+JIKGADPmGawrE=
		-----END CERTIFICATE-----
		""";

	using Account account = Account.FromSeed(runtime, subjectSeed, 0, algorithm);
	Require(account.Algorithm == algorithm, "account algorithm mismatch");
	Require(account.Address.StartsWith("keeta_", StringComparison.Ordinal), "account address was not a keeta address");

	byte[] message = Encoding.UTF8.GetBytes("crypto over p1");
	byte[] signature = account.Sign(message);
	Require(signature.Length > 0, "signature was empty");
	Require(account.Verify(message, signature), "the account must verify its own signature");
	Require(!account.Verify(Encoding.UTF8.GetBytes("tampered"), signature), "a tampered message must not verify");

	// The reusable account: encrypt-to-self and mnemonic
	// derivation both resolve to the same signer behavior.
	byte[] secret = Encoding.UTF8.GetBytes("for my eyes only");
	Require(Encoding.UTF8.GetString(account.Decrypt(account.Encrypt(secret))) == "for my eyes only", "encrypt/decrypt must round-trip");

	IReadOnlyList<string> mnemonic = Account.GeneratePassphrase(runtime);
	Require(mnemonic.Count is 12 or 24, "a generated mnemonic must be 12 or 24 words");
	using Account fromWords = Account.FromPassphrase(runtime, mnemonic, 0, "ed25519");
	byte[] mnemonicSignature = fromWords.Sign(message);
	Require(fromWords.Verify(message, mnemonicSignature), "a mnemonic-derived account must verify its own signature");

	using CryptoCertificate certificate = CryptoCertificate.Parse(runtime, pem);
	Require(certificate.Pem().Contains("BEGIN CERTIFICATE"), "the certificate must encode to PEM");
	Require(certificate.ValidAt(validAt), "the certificate must be valid inside its window");
	Require(!certificate.ValidAt(beforeValidity), "the certificate must be invalid before its window");

	Require(certificate.Subject.Contains("Test Subject"), "the subject DN must name the fixture subject");
	Require(certificate.Issuer.Contains("Test Issuer"), "the issuer DN must name the fixture issuer");
	Require(certificate.Serial == "12345", "the serial must decode to its base-10 form");
	Require(certificate.NotBefore < certificate.NotAfter, "the validity window must be ordered");
	Require(
		certificate.NotBefore <= validAt && validAt <= certificate.NotAfter,
		"the in-window moment must fall inside the reported validity window");
	Require(
		certificate.SubjectPublicKey == account.PublicKey,
		"the subject public key must equal the subject account's public key");

	using KycCertificate kyc = KycCertificate.Parse(runtime, pem);
	IReadOnlyList<KeetaNet.Anchor.Kyc.Crypto.KycAttribute> attributes = kyc.Attributes();
	Require(attributes.Count == 3, "the fixture carries three KYC attributes");
	int sensitive = attributes.Count(attribute => attribute.Sensitive);
	Require(sensitive == 2, "two of the fixture's attributes are sensitive");

	Require(Encoding.UTF8.GetString(kyc.PlainAttribute("postalCode")) == "12345", "the plain postal code must read back");

	using CryptoCertificate baseCertificate = kyc.Base();
	Require(baseCertificate.Pem().Contains("BEGIN CERTIFICATE"), "the base certificate must encode to PEM");

	using CryptoCertificate trustRoot = CryptoCertificate.Parse(runtime, pem);
	Require(
		kyc.Verify(new[] { trustRoot }, Array.Empty<CryptoCertificate>(), validAt),
		"the leaf must chain to its own certificate as a trusted root");
	Require(
		!kyc.Verify(Array.Empty<CryptoCertificate>(), Array.Empty<CryptoCertificate>(), validAt),
		"the leaf must not verify with an empty trust set");

	byte[] email = kyc.DecryptAttribute("email", account);
	Require(Encoding.UTF8.GetString(email) == "john@example.com", "the decrypted email must match the issued claim");
}

// Issue a leaf through the fluent builder across distinct subject/issuer
// algorithms, then read every shape back through the same module: a plain scalar,
// a decrypted scalar, a decrypted date, and a decrypted structured value.
static void IssueSelfTest(WasmRuntime runtime)
{
	const string subjectSeed = "1111111111111111111111111111111111111111111111111111111111111111";
	const string issuerSeed = "2222222222222222222222222222222222222222222222222222222222222222";

	using Account subject = Account.FromSeed(runtime, subjectSeed, 0, "ed25519");
	using Account issuer = Account.FromSeed(runtime, issuerSeed, 0, "ecdsa_secp256k1");

	JsonElement address = JsonSerializer.Deserialize<JsonElement>(
		"""{"addressType":"HOME","postalCode":"34677","townName":"Oldsmar"}""");

	using KycCertificate leaf = KycCertificate.Builder(runtime)
		.Subject(subject)
		.Issuer(issuer)
		.SubjectName("Subject")
		.IssuerName("Issuer")
		.Serial(7)
		.Validity(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), DateTimeOffset.FromUnixTimeSeconds(1_900_000_000))
		.SetAttribute("postalCode", sensitive: false, "12345")
		.SetAttribute("email", sensitive: true, "user@example.com")
		.SetAttribute("dateOfBirth", sensitive: true, DateTimeOffset.FromUnixTimeSeconds(315_532_800))
		.SetAttribute("address", sensitive: true, address)
		.Issue();

	string pem = leaf.Pem();
	Require(pem.Contains("BEGIN CERTIFICATE"), "the issued leaf must encode to PEM");

	using KycCertificate parsed = KycCertificate.Parse(runtime, pem);
	Require(Encoding.UTF8.GetString(parsed.PlainAttribute("postalCode")) == "12345", "the plain postal code must read back");
	Require(parsed.GetText("email", subject) == "user@example.com", "the sensitive email must decrypt to the issued value");
	Require(parsed.GetText("dateOfBirth", subject) == "1980-01-01T00:00:00.000Z", "the sensitive date must decrypt to its ISO form");
	Require(
		parsed.GetJson("address", subject).GetProperty("postalCode").GetString() == "34677",
		"the sensitive structured address must decrypt to its JSON value");
}

// Issue a leaf, then prove a sensitive attribute and validate the proof against
// the leaf using only the subject account: a proof for the attribute validates,
// a proof for a different attribute does not.
static void ProveSelfTest(WasmRuntime runtime)
{
	const string subjectSeed = "1111111111111111111111111111111111111111111111111111111111111111";
	const string issuerSeed = "2222222222222222222222222222222222222222222222222222222222222222";

	using Account subject = Account.FromSeed(runtime, subjectSeed, 0, "ed25519");
	using Account issuer = Account.FromSeed(runtime, issuerSeed, 0, "ecdsa_secp256k1");

	using KycCertificate leaf = KycCertificate.Builder(runtime)
		.Subject(subject)
		.Issuer(issuer)
		.SubjectName("Subject")
		.IssuerName("Issuer")
		.Serial(7)
		.Validity(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), DateTimeOffset.FromUnixTimeSeconds(1_900_000_000))
		.SetAttribute("email", sensitive: true, "user@example.com")
		.SetAttribute("fullName", sensitive: true, "Test User")
		.Issue();

	AttributeProof proof = leaf.Prove("email", subject);
	Require(proof.Value.Length > 0 && proof.Salt.Length > 0, "the proof must carry a value and salt");
	Require(leaf.ValidateProof("email", subject, proof), "the attribute proof must validate against the leaf");

	AttributeProof other = leaf.Prove("fullName", subject);
	Require(!leaf.ValidateProof("email", subject, other), "a proof for a different attribute must not validate");
}

// Exercise the offline encrypted-container surface: a plaintext round-trip
// through its encoding, an encrypted round-trip opened by a private-keyed
// principal, a signed container that verifies and recovers its signer, and a
// grant/revoke cycle over the principal set.
static void ContainerSelfTest(WasmRuntime runtime)
{
	const string ownerSeed = "1111111111111111111111111111111111111111111111111111111111111111";
	const string signerSeed = "2222222222222222222222222222222222222222222222222222222222222222";
	const string readerSeed = "3333333333333333333333333333333333333333333333333333333333333333";
	byte[] payload = Encoding.UTF8.GetBytes("container over p1");

	using (EncryptedContainer plain = EncryptedContainer.FromPlaintext(runtime, payload))
	{
		byte[] encoded = plain.Encoded();
		using EncryptedContainer restored = EncryptedContainer.FromEncoded(runtime, encoded);
		Require(restored.Plaintext().SequenceEqual(payload), "the plaintext must round-trip through its encoding");
		Require(!restored.IsEncrypted, "a plaintext container must not report as encrypted");
	}

	using (Account owner = Account.FromSeed(runtime, ownerSeed, 0, "ecdsa_secp256k1"))
	{
		byte[] encoded;
		using (EncryptedContainer encrypted = EncryptedContainer.FromPlaintext(runtime, payload, new[] { owner }, locked: false))
		{
			Require(encrypted.IsEncrypted, "a container with principals must report as encrypted");
			encoded = encrypted.Encoded();
		}

		using EncryptedContainer opened = EncryptedContainer.FromEncrypted(runtime, encoded, new[] { owner });
		Require(opened.Plaintext().SequenceEqual(payload), "the principal must decrypt the sealed payload");
		Require(opened.IsEncrypted, "a decoded encrypted container must report as encrypted");
	}

	using (Account signer = Account.FromSeed(runtime, signerSeed, 0, "ed25519"))
	{
		byte[] encoded;
		using (EncryptedContainer signed = EncryptedContainer.FromPlaintext(runtime, payload, locked: false, signer: signer))
		{
			encoded = signed.Encoded();
		}

		using EncryptedContainer restored = EncryptedContainer.FromEncoded(runtime, encoded);
		Require(restored.IsSigned, "a signed container must report as signed");
		Require(restored.VerifySignature(), "the detached signature must verify");

		byte[]? recovered = restored.SigningAccount();
		Require(recovered is not null, "a signed container must recover its signer");
		Require(
			Convert.ToHexString(recovered!).Equals(signer.PublicKey, StringComparison.OrdinalIgnoreCase),
			"the recovered signer key must match the signing account");
	}

	using (Account owner = Account.FromSeed(runtime, ownerSeed, 0, "ecdsa_secp256k1"))
	using (Account reader = Account.FromSeed(runtime, readerSeed, 0, "ecdsa_secp256k1"))
	using (EncryptedContainer container = EncryptedContainer.FromPlaintext(runtime, payload, new[] { owner }, locked: false))
	{
		container.GrantAccess(new[] { reader });
		Require(container.Principals().Count == 2, "granting access must add a principal");

		container.RevokeAccess(Convert.FromHexString(reader.PublicKey));
		Require(container.Principals().Count == 1, "revoking access must remove a principal");
	}
}

// Exercise the offline sharable-attributes surface: issue a leaf, seal a subset
// of its attributes for a recipient, reject an export with no recipient, then
// open the PEM envelope and read the disclosed values, embedded leaf, principal
// set, and disclosed names back.
static void SharableSelfTest(WasmRuntime runtime)
{
	const string subjectSeed = "1111111111111111111111111111111111111111111111111111111111111111";
	const string issuerSeed = "2222222222222222222222222222222222222222222222222222222222222222";
	const string recipientSeed = "3333333333333333333333333333333333333333333333333333333333333333";
	const string algorithm = "ecdsa_secp256k1";

	using Account subject = Account.FromSeed(runtime, subjectSeed, 0, algorithm);
	using Account issuer = Account.FromSeed(runtime, issuerSeed, 0, algorithm);
	using Account recipient = Account.FromSeed(runtime, recipientSeed, 0, algorithm);

	using KycCertificate leaf = KycCertificate.Builder(runtime)
		.Subject(subject)
		.Issuer(issuer)
		.SubjectName("Subject")
		.IssuerName("Issuer")
		.Serial(7)
		.Validity(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), DateTimeOffset.FromUnixTimeSeconds(1_900_000_000))
		.SetAttribute("postalCode", sensitive: false, "12345")
		.SetAttribute("email", sensitive: true, "john@example.com")
		.Issue();

	// Sealing binds the disclosure, but exporting without a recipient is rejected.
	using (SharableCertificateAttributes noRecipient =
		SharableCertificateAttributes.FromCertificate(runtime, leaf, subject, names: new[] { "email" }))
	{
		bool rejected = false;
		try
		{
			noRecipient.Export();
		}
		catch (KeetaException)
		{
			rejected = true;
		}

		Require(rejected, "exporting a bundle with no recipient must be rejected");
	}

	// Seal both attributes for the recipient, then export the PEM envelope.
	using SharableCertificateAttributes bundle =
		SharableCertificateAttributes.FromCertificate(runtime, leaf, subject, names: new[] { "postalCode", "email" });
	bundle.GrantAccess(new[] { recipient });
	string pem = bundle.ToPem();

	// The recipient opens the envelope and reads both disclosed values back.
	using SharableCertificateAttributes opened = SharableCertificateAttributes.FromPem(runtime, pem, new[] { recipient });
	Require(
		Encoding.UTF8.GetString(opened.AttributeValue("postalCode")!) == "12345",
		"the recipient must read the disclosed plain attribute");
	Require(
		Encoding.UTF8.GetString(opened.AttributeValue("email")!) == "john@example.com",
		"the recipient must read the disclosed sensitive attribute");
	Require(opened.AttributeBuffer("doesNotExist") is null, "a missing attribute must disclose nothing");

	// The embedded leaf, principal set, and disclosed names survive the round trip.
	using KycCertificate embedded = opened.LeafCertificate();
	Require(embedded.Pem().Contains("BEGIN CERTIFICATE"), "the embedded leaf must encode to PEM");

	IReadOnlyList<byte[]> principals = opened.Principals();
	Require(principals.Count == 1, "the granted recipient must be the sole principal");
	Require(
		Convert.ToHexString(principals[0]).Equals(recipient.PublicKey, StringComparison.OrdinalIgnoreCase),
		"the sole principal must be the granted recipient");

	Require(opened.AttributeNames().Count == 2, "the bundle must disclose exactly two attributes");
}

// Cross-implementation compatibility against the reference TypeScript anchor,
// both directions, for the encrypted container:
//  1. TS encrypts and signs -> C# decrypts and verifies (`TS_DECODE/VERIFY/SIGNER`),
//  2. C# encrypts and signs -> emit the blob for the TS reader to decode and
//     verify (`CS_CONTAINER`, `CS_PLAINTEXT`, `CS_SIGNER_KEY`).
static void ContainerCompatibility(WasmRuntime runtime)
{
	const string algorithm = "ecdsa_secp256k1";
	using Account principal = Account.FromSeed(runtime, RequireEnv("KEETA_PRINCIPAL_SEED"), 0, algorithm);
	using Account signer = Account.FromSeed(runtime, RequireEnv("KEETA_SIGNER_SEED"), 0, algorithm);

	// 1. Decode and verify the TS-produced encrypted, signed container.
	byte[] tsContainer = Convert.FromBase64String(RequireEnv("KEETA_TS_CONTAINER"));
	byte[] expectedPlaintext = Convert.FromBase64String(RequireEnv("KEETA_TS_PLAINTEXT"));
	using EncryptedContainer decoded = EncryptedContainer.FromEncrypted(runtime, tsContainer, new[] { principal });
	Console.WriteLine($"TS_DECODE_OK={Bool(decoded.Plaintext().SequenceEqual(expectedPlaintext))}");
	Console.WriteLine($"TS_VERIFY_OK={Bool(decoded.IsSigned && decoded.VerifySignature())}");

	byte[]? recovered = decoded.SigningAccount();
	bool signerOk = recovered is not null
		&& Convert.ToHexString(recovered).Equals(signer.PublicKey, StringComparison.OrdinalIgnoreCase);
	Console.WriteLine($"TS_SIGNER_OK={Bool(signerOk)}");

	// 2. Produce an encrypted, signed container for the TS reader to read back.
	byte[] payload = Encoding.UTF8.GetBytes("c-sharp encrypted and signed container");
	using EncryptedContainer produced =
		EncryptedContainer.FromPlaintext(runtime, payload, new[] { principal }, locked: false, signer: signer);
	Console.WriteLine($"CS_CONTAINER={Convert.ToBase64String(produced.Encoded())}");
	Console.WriteLine($"CS_PLAINTEXT={Convert.ToBase64String(payload)}");
	Console.WriteLine($"CS_SIGNER_KEY={signer.PublicKey}");
}

static string RequireEnv(string name) =>
	Environment.GetEnvironmentVariable(name)
	?? throw new InvalidOperationException($"missing required environment variable `{name}`");

static void Require(bool condition, string message)
{
	if (!condition)
	{
		throw new InvalidOperationException(message);
	}
}

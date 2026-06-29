// Proof-of-concept driver for the C# KYC binding, exercised by the Rust
// host-tests `csharp_p1_kyc.rs` (networked) and `p1_crypto.rs` (offline crypto).

using KeetaNet.Anchor.Kyc;
using System.Text;
using System.Text.Json;
using Account = KeetaNet.Anchor.Kyc.Crypto.Account;
using CryptoCertificate = KeetaNet.Anchor.Kyc.Crypto.Certificate;
using KycCertificate = KeetaNet.Anchor.Kyc.Crypto.KycCertificate;

string wasmPath = RequireEnv("KEETA_ANCHOR_P1_WASM");

using var runtime = WasmRuntime.Load(wasmPath);

// Offline mode: exercise the `crypto` resources only, needing no node or harness.
if (Environment.GetEnvironmentVariable("KEETA_CRYPTO_ONLY") is not null)
{
	CryptoSelfTest(runtime);
	Console.WriteLine("CRYPTO_OK");
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
	OracleCheck(runtime, leafPem, RequireEnv("KEETA_ORACLE_JSON"), RequireEnv("KEETA_SUBJECT_SEED"));
	Console.WriteLine("ORACLE_OK");
}

// Decrypt and decode every attribute of an issued leaf, asserting each matches
// the reference oracle. The issued leaf is sensitive throughout, so every value
// is decrypted with the subject's key; scalars (and dates) compare as text,
// structured types as order-insensitive JSON.
static void OracleCheck(WasmRuntime runtime, string leafPem, string oracleJson, string subjectSeed)
{
	using Account subject = Account.FromSeed(runtime, subjectSeed, 0, "ecdsa_secp256k1");
	using KycCertificate leaf = KycCertificate.Parse(runtime, leafPem);

	using JsonDocument oracle = JsonDocument.Parse(oracleJson);
	foreach (JsonProperty entry in oracle.RootElement.EnumerateObject())
	{
		if (entry.Value.ValueKind == JsonValueKind.String)
		{
			Require(leaf.GetText(entry.Name, subject) == entry.Value.GetString(), $"scalar attribute `{entry.Name}` must match the oracle");
			continue;
		}

		Require(JsonEqual(leaf.GetJson(entry.Name, subject), entry.Value), $"structured attribute `{entry.Name}` must match the oracle");
	}
}

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

using System.Text;
using System.Text.Json;

namespace KeetaNet.Anchor.Kyc.Crypto;

/// <summary>
/// A Keeta account: a signer derived from a seed, or a read-only account parsed
/// from an address. The key material lives inside the wasm core; this wrapper
/// holds only the handle and releases it on <see cref="Dispose"/>.
/// </summary>
public sealed class Account : IDisposable
{
	private readonly WasmRuntime _runtime;
	private bool _disposed;

	/// <summary>The core-module handle backing this account.</summary>
	internal int Handle { get; }

	private Account(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		Handle = handle;
	}

	/// <summary>Derive a signing account from a hex <paramref name="seed"/>.</summary>
	/// <remarks><paramref name="algorithm"/> is <c>ed25519</c>, <c>ecdsa_secp256k1</c>, or <c>ecdsa_secp256r1</c>.</remarks>
	public static Account FromSeed(WasmRuntime runtime, string seed, uint index, string algorithm) =>
		new(runtime, runtime.AccountFromSeed(seed, index, algorithm));

	/// <summary>Build a read-only account from its textual address.</summary>
	public static Account FromAddress(WasmRuntime runtime, string address) =>
		new(runtime, runtime.AccountFromAddress(address));

	/// <summary>Derive a signing account from a hex <paramref name="privateKey"/>.</summary>
	/// <remarks><paramref name="algorithm"/> is <c>ed25519</c>, <c>ecdsa_secp256k1</c>, or <c>ecdsa_secp256r1</c>.</remarks>
	public static Account FromPrivateKey(WasmRuntime runtime, string privateKey, string algorithm) =>
		new(runtime, runtime.AccountFromPrivateKey(privateKey, algorithm));

	/// <summary>Derive a signing account from a BIP39 mnemonic <paramref name="words"/>.</summary>
	public static Account FromPassphrase(WasmRuntime runtime, IEnumerable<string> words, uint index, string algorithm) =>
		new(runtime, runtime.AccountFromPassphrase(string.Join('\n', words), index, algorithm));

	/// <summary>Build a read-only account from a hex <paramref name="publicKey"/>.</summary>
	public static Account FromPublicKey(WasmRuntime runtime, string publicKey, string algorithm) =>
		new(runtime, runtime.AccountFromPublicKey(publicKey, algorithm));

	/// <summary>Generate a random hex seed.</summary>
	public static string GenerateSeed(WasmRuntime runtime) => runtime.AccountGenerateSeed();

	/// <summary>Generate a random BIP39 mnemonic.</summary>
	public static IReadOnlyList<string> GeneratePassphrase(WasmRuntime runtime) =>
		runtime.AccountGeneratePassphrase().Split('\n', StringSplitOptions.RemoveEmptyEntries);

	/// <summary>The account's textual <c>keeta_...</c> address.</summary>
	public string Address => _runtime.AccountAddress(Handle);

	/// <summary>The account's algorithm name.</summary>
	public string Algorithm => _runtime.AccountAlgorithm(Handle);

	/// <summary>The account's type-prefixed public key (hex).</summary>
	public string PublicKey => _runtime.AccountPublicKey(Handle);

	/// <summary>Sign <paramref name="message"/> with the account's private key.</summary>
	public byte[] Sign(byte[] message) => _runtime.AccountSign(Handle, message);

	/// <summary>Verify <paramref name="signature"/> over <paramref name="message"/>.</summary>
	public bool Verify(byte[] message, byte[] signature) => _runtime.AccountVerify(Handle, message, signature);

	/// <summary>Encrypt <paramref name="plaintext"/> to the account's public key.</summary>
	public byte[] Encrypt(byte[] plaintext) => _runtime.AccountEncrypt(Handle, plaintext);

	/// <summary>Decrypt <paramref name="ciphertext"/> with the account's private key.</summary>
	public byte[] Decrypt(byte[] ciphertext) => _runtime.AccountDecrypt(Handle, ciphertext);

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.AccountFree(Handle);
	}
}

/// <summary>
/// A base X.509 certificate: a provider CA, a trust root, or an intermediate.
/// </summary>
public sealed class Certificate : IDisposable
{
	private readonly WasmRuntime _runtime;
	private bool _disposed;

	/// <summary>The core-module handle backing this certificate.</summary>
	internal int Handle { get; }

	internal Certificate(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		Handle = handle;
	}

	/// <summary>Parse a PEM-encoded certificate.</summary>
	public static Certificate Parse(WasmRuntime runtime, string pem) =>
		new(runtime, runtime.CertificateParse(pem));

	/// <summary>Parse a DER-encoded certificate.</summary>
	public static Certificate ParseDer(WasmRuntime runtime, byte[] der) =>
		new(runtime, runtime.CertificateParseDer(der));

	/// <summary>The PEM encoding of the certificate.</summary>
	public string Pem() => _runtime.CertificatePem(Handle);

	/// <summary>The DER encoding of the certificate.</summary>
	public byte[] Der() => _runtime.CertificateDer(Handle);

	/// <summary>Whether the certificate is valid at <paramref name="moment"/>.</summary>
	public bool ValidAt(DateTimeOffset moment) => _runtime.CertificateValidAt(Handle, moment.ToUnixTimeMilliseconds());

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.CertificateFree(Handle);
	}
}

/// <summary>One KYC attribute: its OID <see cref="Name"/> and whether its value is encrypted.</summary>
public sealed record KycAttribute(string Name, bool Sensitive);

/// <summary>
/// A KYC leaf certificate: a base certificate plus parsed KYC attributes, some
/// plain and some encrypted to the subject.
/// </summary>
public sealed class KycCertificate : IDisposable
{
	private static readonly JsonSerializerOptions Json = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
	};

	private readonly WasmRuntime _runtime;
	private bool _disposed;

	/// <summary>The core-module handle backing this certificate.</summary>
	internal int Handle { get; }

	private KycCertificate(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		Handle = handle;
	}

	/// <summary>Parse a PEM-encoded KYC certificate.</summary>
	public static KycCertificate Parse(WasmRuntime runtime, string pem) =>
		new(runtime, runtime.KycCertificateParse(pem));

	/// <summary>The base certificate, as an independently owned certificate object.</summary>
	public Certificate Base() => new(_runtime, _runtime.KycCertificateBase(Handle));

	/// <summary>Whether the certificate is valid at <paramref name="moment"/>.</summary>
	public bool ValidAt(DateTimeOffset moment) => _runtime.KycCertificateValidAt(Handle, moment.ToUnixTimeMilliseconds());

	/// <summary>
	/// Whether the certificate chains to one of <paramref name="trustedRoots"/> at
	/// <paramref name="moment"/>, using <paramref name="intermediates"/> to bridge the path.
	/// </summary>
	public bool Verify(
		IEnumerable<Certificate> trustedRoots,
		IEnumerable<Certificate> intermediates,
		DateTimeOffset moment)
	{
		int[] roots = trustedRoots.Select(certificate => certificate.Handle).ToArray();
		int[] bridges = intermediates.Select(certificate => certificate.Handle).ToArray();
		return _runtime.KycCertificateVerify(Handle, roots, bridges, moment.ToUnixTimeMilliseconds());
	}

	/// <summary>The KYC attributes the certificate carries.</summary>
	public IReadOnlyList<KycAttribute> Attributes()
	{
		byte[] payload = _runtime.KycCertificateAttributes(Handle);
		return JsonSerializer.Deserialize<List<KycAttribute>>(payload, Json) ?? new List<KycAttribute>();
	}

	/// <summary>A plain (unencrypted) attribute by <paramref name="name"/>.</summary>
	public byte[] PlainAttribute(string name) => _runtime.KycCertificatePlainAttribute(Handle, name);

	/// <summary>Decrypt a sensitive attribute by <paramref name="name"/> using <paramref name="subject"/>.</summary>
	public byte[] DecryptAttribute(string name, Account subject) =>
		_runtime.KycCertificateDecryptAttribute(Handle, name, subject.Handle);

	/// <summary>
	/// A plain scalar attribute decoded as text. Scalar and date attributes
	/// decode to a UTF-8 string (dates as an ISO-8601 timestamp).
	/// </summary>
	public string GetText(string name) => Encoding.UTF8.GetString(PlainAttribute(name));

	/// <summary>
	/// A sensitive scalar attribute decrypted with <paramref name="subject"/> and
	/// decoded as text (dates as an ISO-8601 timestamp).
	/// </summary>
	public string GetText(string name, Account subject) =>
		Encoding.UTF8.GetString(DecryptAttribute(name, subject));

	/// <summary>
	/// A plain structured attribute decoded as JSON. Structured attributes
	/// (e.g. address, entity type) decode to a JSON object or array matching the
	/// TypeScript client's value shape.
	/// </summary>
	public JsonElement GetJson(string name) => ParseJson(PlainAttribute(name));

	/// <summary>
	/// A sensitive structured attribute decrypted with <paramref name="subject"/>
	/// and decoded as JSON.
	/// </summary>
	public JsonElement GetJson(string name, Account subject) =>
		ParseJson(DecryptAttribute(name, subject));

	private static JsonElement ParseJson(byte[] payload)
	{
		using var document = JsonDocument.Parse(payload);
		return document.RootElement.Clone();
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.KycCertificateFree(Handle);
	}
}

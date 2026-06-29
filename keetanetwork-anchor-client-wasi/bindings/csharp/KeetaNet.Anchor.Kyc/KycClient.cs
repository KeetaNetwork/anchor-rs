using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// A KYC anchor client bound to a signer and a metadata root. Discovery, request
/// signing, retries, and polling all run inside the wasm core.
/// </summary>
public sealed class KycClient : IDisposable
{
	private static readonly JsonSerializerOptions Json = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	};

	private readonly WasmRuntime _runtime;
	private readonly int _handle;
	private bool _disposed;

	private KycClient(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		_handle = handle;
	}

	/// <summary>
	/// Build a client signed by an existing <paramref name="account"/> from the
	/// <c>crypto</c> surface, resolving providers from <paramref name="root"/>'s
	/// on-chain service metadata read via the node API at <paramref name="nodeUrl"/>.
	/// </summary>
	public static KycClient WithAccount(WasmRuntime runtime, string nodeUrl, string root, Crypto.Account account)
	{
		int handle = runtime.KycWithAccount(nodeUrl, root, account.Handle);
		return new KycClient(runtime, handle);
	}

	/// <summary>Every provider that serves all <paramref name="countries"/> (ISO codes).</summary>
	public IReadOnlyList<KycProvider> Providers(IEnumerable<string> countries)
	{
		string countriesJson = JsonSerializer.Serialize(countries.ToArray(), Json);
		byte[] payload = _runtime.KycProviders(_handle, countriesJson);
		return JsonSerializer.Deserialize<List<KycProvider>>(payload, Json) ?? new List<KycProvider>();
	}

	/// <summary>
	/// Begin a verification with <paramref name="provider"/> for
	/// <paramref name="countries"/>, optionally redirecting the user to
	/// <paramref name="redirect"/> when the flow ends.
	/// </summary>
	public VerificationOutcome CreateVerification(
		KycProvider provider,
		IEnumerable<string> countries,
		string? redirect = null)
	{
		string providerJson = JsonSerializer.Serialize(provider, Json);
		string countriesJson = JsonSerializer.Serialize(countries.ToArray(), Json);
		byte[] payload = _runtime.KycCreateVerification(_handle, providerJson, countriesJson, redirect ?? "");

		return ParseOutcome<Verification, VerificationOutcome>(
			payload, "verification", ready => new VerificationOutcome(ready, null), retry => new VerificationOutcome(null, retry));
	}

	/// <summary>Fetch the certificates issued for verification <paramref name="id"/>.</summary>
	public CertificatesOutcome GetCertificates(KycProvider provider, string id)
	{
		string providerJson = JsonSerializer.Serialize(provider, Json);
		byte[] payload = _runtime.KycGetCertificates(_handle, providerJson, id);

		return ParseOutcome<Certificates, CertificatesOutcome>(
			payload, "certificates", ready => new CertificatesOutcome(ready, null), retry => new CertificatesOutcome(null, retry));
	}

	/// <summary>Parse <paramref name="provider"/>'s advertised issuer CA certificate.</summary>
	/// <remarks>Use it as a trusted root when verifying an issued <see cref="Crypto.KycCertificate"/>.</remarks>
	public Crypto.Certificate ProviderCertificate(KycProvider provider) =>
		Crypto.Certificate.Parse(_runtime, provider.Ca);

	/// <summary>Read the status of verification <paramref name="id"/>.</summary>
	public StatusOutcome GetVerificationStatus(KycProvider provider, string id)
	{
		string providerJson = JsonSerializer.Serialize(provider, Json);
		byte[] payload = _runtime.KycGetVerificationStatus(_handle, providerJson, id);

		return ParseOutcome<VerificationStatus, StatusOutcome>(
			payload, "status", ready => new StatusOutcome(ready, null), retry => new StatusOutcome(null, retry));
	}

	/// <summary>
	/// Shape a pending-or-ready outcome: a <c>retry</c> object yields
	/// <paramref name="retry"/> with its delay, otherwise the <paramref name="readyProperty"/>
	/// value is deserialized and passed to <paramref name="ready"/>.
	/// </summary>
	private static TOutcome ParseOutcome<TReady, TOutcome>(
		byte[] payload,
		string readyProperty,
		Func<TReady, TOutcome> ready,
		Func<uint, TOutcome> retry)
	{
		using var document = JsonDocument.Parse(payload);
		JsonElement root = document.RootElement;
		if (root.GetProperty("type").GetString() == "retry")
		{
			return retry(root.GetProperty("afterMs").GetUInt32());
		}

		return ready(root.GetProperty(readyProperty).Deserialize<TReady>(Json)!);
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.KycFree(_handle);
	}
}

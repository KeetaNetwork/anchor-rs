using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// A KYC anchor client bound to a signer and a metadata root. Discovery, request
/// signing, retries, and polling all run inside the wasm core.
/// </summary>
/// <remarks>
/// Discovery returns <see cref="KycProvider"/> handles carrying the resolved
/// metadata; every operation lives on the handle. A stored
/// <see cref="KycProviderInfo"/> snapshot rebinds through <see cref="Provider"/>.
/// </remarks>
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

	internal WasmRuntime Runtime => _runtime;

	internal int Handle => _handle;

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
		List<KycProviderInfo> infos =
			JsonSerializer.Deserialize<List<KycProviderInfo>>(payload, Json) ?? new List<KycProviderInfo>();
		return infos.ConvertAll(info => new KycProvider(this, info));
	}

	/// <summary>
	/// Bind a stored <see cref="KycProviderInfo"/> snapshot back to this client,
	/// yielding the operation-carrying <see cref="KycProvider"/> handle.
	/// </summary>
	public KycProvider Provider(KycProviderInfo info) => new(this, info);

	internal static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);

	/// <summary>
	/// Shape a pending-or-ready outcome: a <c>retry</c> object yields
	/// <paramref name="retry"/> with its delay, otherwise the <paramref name="readyProperty"/>
	/// value is deserialized and passed to <paramref name="ready"/>.
	/// </summary>
	internal static TOutcome ParseOutcome<TReady, TOutcome>(
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

/// <summary>
/// A discovered KYC provider bound to its client: every operation lives here,
/// and the resolved metadata snapshot is exposed as <see cref="Info"/>.
/// </summary>
/// <remarks>
/// The handle holds no wasm resource of its own so it needs no disposal and
/// rebinds cheaply from a stored snapshot via
/// <see cref="KycClient.Provider"/>.
/// </remarks>
public sealed class KycProvider
{
	private readonly KycClient _client;

	internal KycProvider(KycClient client, KycProviderInfo info)
	{
		_client = client;
		Info = info;
	}

	/// <summary>The resolved metadata snapshot.</summary>
	public KycProviderInfo Info { get; }

	/// <summary>The provider id (the key under <c>services.kyc</c>).</summary>
	public string Id => Info.Id;

	/// <summary>
	/// Begin a verification for <paramref name="countries"/>, optionally
	/// redirecting the user to <paramref name="redirect"/> when the flow ends.
	/// </summary>
	public VerificationOutcome CreateVerification(IEnumerable<string> countries, string? redirect = null)
	{
		string countriesJson = KycClient.Serialize(countries.ToArray());
		byte[] payload = _client.Runtime.KycCreateVerification(
			_client.Handle, KycClient.Serialize(Info), countriesJson, redirect ?? "");

		return KycClient.ParseOutcome<Verification, VerificationOutcome>(
			payload, "verification", ready => new VerificationOutcome(ready, null), retry => new VerificationOutcome(null, retry));
	}

	/// <summary>Fetch the certificates issued for verification <paramref name="id"/>.</summary>
	public CertificatesOutcome GetCertificates(string id)
	{
		byte[] payload = _client.Runtime.KycGetCertificates(_client.Handle, KycClient.Serialize(Info), id);

		return KycClient.ParseOutcome<Certificates, CertificatesOutcome>(
			payload, "certificates", ready => new CertificatesOutcome(ready, null), retry => new CertificatesOutcome(null, retry));
	}

	/// <summary>Parse the provider's advertised issuer CA certificate.</summary>
	/// <remarks>Use it as a trusted root when verifying an issued <see cref="Crypto.KycCertificate"/>.</remarks>
	public Crypto.Certificate ProviderCertificate() => Crypto.Certificate.Parse(_client.Runtime, Info.Ca);

	/// <summary>Read the status of verification <paramref name="id"/>.</summary>
	public StatusOutcome GetVerificationStatus(string id)
	{
		byte[] payload = _client.Runtime.KycGetVerificationStatus(_client.Handle, KycClient.Serialize(Info), id);

		return KycClient.ParseOutcome<VerificationStatus, StatusOutcome>(
			payload, "status", ready => new StatusOutcome(ready, null), retry => new StatusOutcome(null, retry));
	}
}

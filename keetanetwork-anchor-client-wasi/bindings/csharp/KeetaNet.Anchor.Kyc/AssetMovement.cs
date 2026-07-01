using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// An asset-movement anchor client bound to a signer and a metadata root.
/// Discovery, request signing, retries, and the account-status blocker fold all
/// run inside the wasm core.
/// </summary>
public sealed class AssetMovementClient : IDisposable
{
	private static readonly JsonSerializerOptions Json = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
		Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
	};

	private readonly WasmRuntime _runtime;
	private readonly int _handle;
	private bool _disposed;

	private AssetMovementClient(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		_handle = handle;
	}

	/// <summary>
	/// Build a client signed by an existing <paramref name="account"/> from the
	/// <c>crypto</c> surface, resolving providers from <paramref name="root"/>'s
	/// on-chain service metadata read via the node API at <paramref name="nodeUrl"/>.
	/// </summary>
	public static AssetMovementClient WithAccount(WasmRuntime runtime, string nodeUrl, string root, Crypto.Account account)
	{
		int handle = runtime.AssetWithAccount(nodeUrl, root, account.Handle);
		return new AssetMovementClient(runtime, handle);
	}

	/// <summary>Every advertised provider.</summary>
	public IReadOnlyList<AssetProvider> Providers()
	{
		byte[] payload = _runtime.AssetProviders(_handle);
		return JsonSerializer.Deserialize<List<AssetProvider>>(payload, Json) ?? new List<AssetProvider>();
	}

	/// <summary>The provider with <paramref name="id"/>, or null when none advertises it.</summary>
	public AssetProvider? ProviderById(string id) => ParseOptionalProvider(_runtime.AssetProviderById(_handle, id));

	/// <summary>The provider signed by <paramref name="account"/>, or null when absent.</summary>
	public AssetProvider? ProviderByAccount(string account) =>
		ParseOptionalProvider(_runtime.AssetProviderByAccount(_handle, account));

	/// <summary>Simulate a transfer, returning its instruction choices.</summary>
	public AssetSimulatedTransfer SimulateTransfer(AssetProvider provider, AssetTransferRequest request) =>
		Read<AssetSimulatedTransfer>(_runtime.AssetSimulateTransfer(_handle, Serialize(provider), Serialize(request)));

	/// <summary>Initiate a transfer. The request's recipient is required.</summary>
	public AssetTransfer InitiateTransfer(AssetProvider provider, AssetTransferRequest request) =>
		Read<AssetTransfer>(_runtime.AssetInitiateTransfer(_handle, Serialize(provider), Serialize(request)));

	/// <summary>Execute a pull instruction for a transfer.</summary>
	public AssetTransferStatus ExecuteTransfer(AssetProvider provider, AssetExecuteRequest request) =>
		Read<AssetTransferStatus>(_runtime.AssetExecuteTransfer(_handle, Serialize(provider), Serialize(request)));

	/// <summary>Read the status of transfer <paramref name="id"/>.</summary>
	public AssetTransferStatus TransferStatus(AssetProvider provider, string id) =>
		Read<AssetTransferStatus>(_runtime.AssetTransferStatus(_handle, Serialize(provider), id));

	/// <summary>Read whether the signer's account is ready to use this provider.</summary>
	public AssetAccountStatus AccountStatus(AssetProvider provider) =>
		Read<AssetAccountStatus>(_runtime.AssetAccountStatus(_handle, Serialize(provider)));

	/// <summary>Open a persistent-forwarding template session.</summary>
	public AssetTemplateSession InitiateForwardingTemplate(AssetProvider provider, AssetInitiateTemplateRequest request) =>
		Read<AssetTemplateSession>(
			_runtime.AssetInitiateForwardingTemplate(_handle, Serialize(provider), Serialize(request)));

	/// <summary>Create a persistent-forwarding template.</summary>
	public AssetForwardingTemplate CreateForwardingTemplate(AssetProvider provider, AssetCreateTemplateRequest request) =>
		Read<AssetForwardingTemplate>(
			_runtime.AssetCreateForwardingTemplate(_handle, Serialize(provider), Serialize(request)));

	/// <summary>List persistent-forwarding templates.</summary>
	public AssetTemplatePage ListForwardingTemplates(AssetProvider provider, AssetListTemplatesRequest request) =>
		Read<AssetTemplatePage>(_runtime.AssetListForwardingTemplates(_handle, Serialize(provider), Serialize(request)));

	/// <summary>Create a persistent-forwarding address, returning its (obfuscated) details.</summary>
	public JsonElement CreateForwardingAddress(AssetProvider provider, AssetCreateAddressRequest request) =>
		Read<JsonElement>(_runtime.AssetCreateForwardingAddress(_handle, Serialize(provider), Serialize(request)));

	/// <summary>List persistent-forwarding addresses.</summary>
	public AssetAddressPage ListForwardingAddresses(AssetProvider provider, AssetListAddressesRequest request) =>
		Read<AssetAddressPage>(_runtime.AssetListForwardingAddresses(_handle, Serialize(provider), Serialize(request)));

	/// <summary>Deactivate a persistent-forwarding template by id.</summary>
	public void DeactivateForwardingTemplate(AssetProvider provider, string id) =>
		_runtime.AssetDeactivateForwardingTemplate(_handle, Serialize(provider), id);

	/// <summary>Deactivate a persistent-forwarding address by id.</summary>
	public void DeactivateForwardingAddress(AssetProvider provider, string id) =>
		_runtime.AssetDeactivateForwardingAddress(_handle, Serialize(provider), id);

	/// <summary>List asset-movement transactions.</summary>
	public AssetTransactionPage ListTransactions(AssetProvider provider, AssetListTransactionsRequest request) =>
		Read<AssetTransactionPage>(_runtime.AssetListTransactions(_handle, Serialize(provider), Serialize(request)));

	/// <summary>
	/// Share KYC attributes with the provider. When the outcome is pending, poll
	/// its promise URL until it completes.
	/// </summary>
	public AssetShareKycOutcome ShareKyc(AssetProvider provider, AssetShareKycRequest request) =>
		Read<AssetShareKycOutcome>(_runtime.AssetShareKyc(_handle, Serialize(provider), Serialize(request)));

	private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);

	private static T Read<T>(byte[] payload) =>
		JsonSerializer.Deserialize<T>(payload, Json)
		?? throw new KeetaException("DECODE", $"could not decode a {typeof(T).Name} from the asset-movement response");

	/// <summary>Parse a provider payload, mapping a JSON <c>null</c> body to null.</summary>
	private static AssetProvider? ParseOptionalProvider(byte[] payload)
	{
		using var document = JsonDocument.Parse(payload);
		if (document.RootElement.ValueKind == JsonValueKind.Null)
		{
			return null;
		}

		return document.RootElement.Deserialize<AssetProvider>(Json);
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.AssetFree(_handle);
	}
}

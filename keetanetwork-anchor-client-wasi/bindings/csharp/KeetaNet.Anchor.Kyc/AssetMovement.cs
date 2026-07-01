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

	/// <summary>
	/// Every provider whose advertised <c>supportedAssets</c> satisfies
	/// <paramref name="search"/> (asset, endpoints, and directional rails).
	/// </summary>
	public IReadOnlyList<AssetProvider> GetProvidersForTransfer(AssetProviderSearch search)
	{
		byte[] payload = _runtime.AssetProvidersForTransfer(_handle, Serialize(search));
		return JsonSerializer.Deserialize<List<AssetProvider>>(payload, Json) ?? new List<AssetProvider>();
	}

	/// <summary>
	/// Whether <paramref name="provider"/> advertises the
	/// <paramref name="operation"/> endpoint (e.g. <c>initiateTransfer</c>,
	/// <c>createPersistentForwarding</c>).
	/// </summary>
	public bool IsOperationSupported(AssetProvider provider, string operation) =>
		provider.Operations.ContainsKey(operation);

	/// <summary>The provider's advertised legal disclaimers, or null when none.</summary>
	public JsonElement? GetLegalDisclaimers(AssetProvider provider) => provider.Legal;

	/// <summary>
	/// The legal disclaimers advertised by the provider with
	/// <paramref name="id"/>, or null when the provider or its disclaimers are
	/// absent.
	/// </summary>
	public JsonElement? GetProviderLegalDisclaimersById(string id) => ProviderById(id)?.Legal;

	/// <summary>
	/// The provider's display metadata for <paramref name="asset"/> (an external
	/// chain asset id) at <paramref name="location"/> (a canonical location
	/// string), or null when the provider advertises none.
	/// </summary>
	public JsonElement? GetAssetMetadataForLocation(AssetProvider provider, string location, string asset)
	{
		if (provider.LocationMetadata is not { } metadata || metadata.ValueKind != JsonValueKind.Object)
		{
			return null;
		}

		if (!metadata.TryGetProperty(location, out JsonElement forLocation)
			|| forLocation.ValueKind != JsonValueKind.Object
			|| !forLocation.TryGetProperty("assets", out JsonElement assets)
			|| assets.ValueKind != JsonValueKind.Object)
		{
			return null;
		}

		return assets.TryGetProperty(asset, out JsonElement found) ? found : null;
	}

	/// <summary>Simulate a transfer, returning a fluent handle over its instruction choices.</summary>
	public AssetSimulatedTransfer SimulateTransfer(AssetProvider provider, AssetTransferRequest request)
	{
		var wire = Read<AssetSimulatedTransferWire>(
			_runtime.AssetSimulateTransfer(_handle, Serialize(provider), Serialize(request)));
		return new AssetSimulatedTransfer(this, provider, request, wire.InstructionChoices);
	}

	/// <summary>Initiate a transfer, returning a fluent handle. The request's recipient is required.</summary>
	public AssetTransfer InitiateTransfer(AssetProvider provider, AssetTransferRequest request)
	{
		var wire = Read<AssetTransferWire>(
			_runtime.AssetInitiateTransfer(_handle, Serialize(provider), Serialize(request)));
		return new AssetTransfer(this, provider, wire.Id, wire.InstructionChoices);
	}

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
	/// Share KYC attributes with the provider, returning the outcome verbatim.
	/// A pending outcome carries the promise URL the caller must poll; use
	/// <see cref="ShareKycAndWait"/> to poll it automatically.
	/// </summary>
	public AssetShareKycOutcome ShareKyc(AssetProvider provider, AssetShareKycRequest request) =>
		Read<AssetShareKycOutcome>(_runtime.AssetShareKyc(_handle, Serialize(provider), Serialize(request)));

	/// <summary>
	/// Share KYC attributes and, when the outcome is pending with a promise URL,
	/// poll that URL inside the core until it resolves.
	/// </summary>
	public AssetShareKycOutcome ShareKycAndWait(
		AssetProvider provider,
		AssetShareKycRequest request,
		TimeSpan? pollInterval = null,
		TimeSpan? timeout = null) =>
		Read<AssetShareKycOutcome>(_runtime.AssetShareKycAwait(
			_handle,
			Serialize(provider),
			Serialize(request),
			ToWholeMilliseconds(pollInterval),
			ToWholeMilliseconds(timeout)));

	/// <summary>A bound as whole milliseconds, with 0 selecting the core default.</summary>
	private static int ToWholeMilliseconds(TimeSpan? bound) =>
		bound is { } value && value > TimeSpan.Zero
			? (int)Math.Min(value.TotalMilliseconds, int.MaxValue)
			: 0;

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

/// <summary>
/// A simulated transfer: the instruction choices a caller can inspect, plus the
/// fluent step to promote the simulation into a real, managed transfer with the
/// same provider and request.
/// </summary>
public sealed class AssetSimulatedTransfer
{
	private readonly AssetMovementClient _client;
	private readonly AssetProvider _provider;
	private readonly AssetTransferRequest _request;

	internal AssetSimulatedTransfer(
		AssetMovementClient client,
		AssetProvider provider,
		AssetTransferRequest request,
		IReadOnlyList<JsonElement> instructionChoices)
	{
		_client = client;
		_provider = provider;
		_request = request;
		InstructionChoices = instructionChoices;
	}

	/// <summary>The candidate instructions that would complete this transfer.</summary>
	public IReadOnlyList<JsonElement> InstructionChoices { get; }

	/// <summary>
	/// Initiate the simulated transfer with the same provider and request.
	/// A simulation may omit the recipient; supply <paramref name="recipient"/>
	/// here to complete the destination before initiating.
	/// </summary>
	public AssetTransfer CreateTransfer(object? recipient = null, string? depositMessage = null)
	{
		AssetTransferDestination to = _request.To with
		{
			Recipient = recipient ?? _request.To.Recipient,
			DepositMessage = depositMessage ?? _request.To.DepositMessage,
		};
		return _client.InitiateTransfer(_provider, _request with { To = to });
	}
}

/// <summary>
/// An initiated transfer bound to its provider: inspect the instruction
/// choices, poll its status, or execute a chosen pull instruction, without
/// re-threading the provider or id.
/// </summary>
public sealed class AssetTransfer
{
	private readonly AssetMovementClient _client;
	private readonly AssetProvider _provider;

	internal AssetTransfer(
		AssetMovementClient client,
		AssetProvider provider,
		string id,
		IReadOnlyList<JsonElement> instructionChoices)
	{
		_client = client;
		_provider = provider;
		Id = id;
		InstructionChoices = instructionChoices;
	}

	/// <summary>The transfer id assigned by the provider.</summary>
	public string Id { get; }

	/// <summary>The candidate instructions that complete this transfer.</summary>
	public IReadOnlyList<JsonElement> InstructionChoices { get; }

	/// <summary>Read this transfer's current status.</summary>
	public AssetTransferStatus GetStatus() => _client.TransferStatus(_provider, Id);

	/// <summary>Execute a fiat pull <paramref name="instruction"/> for this transfer.</summary>
	public AssetTransferStatus Execute(AssetPullInstruction instruction) =>
		_client.ExecuteTransfer(_provider, new AssetExecuteRequest(Id, instruction));
}

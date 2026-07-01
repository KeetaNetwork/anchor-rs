using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// The authentication an asset-movement operation endpoint requires. Serialized
/// in its lowercase wire form (<c>none</c>/<c>optional</c>/<c>required</c>) by the
/// camelCase enum converter the asset-movement options register.
/// </summary>
public enum AssetEndpointAuth
{
	/// <summary>The endpoint is unauthenticated.</summary>
	None,
	/// <summary>The endpoint accepts, but does not require, a signature.</summary>
	Optional,
	/// <summary>The endpoint requires a signature.</summary>
	Required,
}

/// <summary>One advertised asset-movement operation endpoint.</summary>
public sealed record AssetEndpoint(string Url, AssetEndpointAuth Auth);

/// <summary>
/// An asset-movement provider discovered from on-chain service metadata. The
/// polymorphic <see cref="SupportedAssets"/>, <see cref="LocationMetadata"/>, and
/// <see cref="Legal"/> members are carried as raw JSON so the value round-trips
/// unchanged when handed back to an operation.
/// </summary>
public sealed record AssetProvider(
	string Id,
	IReadOnlyDictionary<string, AssetEndpoint> Operations,
	IReadOnlyList<JsonElement>? SupportedAssets = null,
	JsonElement? LocationMetadata = null,
	JsonElement? Legal = null,
	string? Account = null);

/// <summary>Pagination bounds shared by the list operations.</summary>
public sealed record AssetPagination(uint? Limit = null, uint? Offset = null);

/// <summary>The source of a transfer: a location and an optional provider-specific source.</summary>
public sealed record AssetTransferSource(string Location, object? Source = null);

/// <summary>
/// The destination of a transfer: a location, an optional recipient, and an
/// optional deposit message.
/// </summary>
public sealed record AssetTransferDestination(string Location, object? Recipient = null, string? DepositMessage = null);

/// <summary>
/// A request to simulate or initiate a transfer. <paramref name="Asset"/> is a
/// canonical asset string or a <c>{ from, to }</c> pair.
/// </summary>
public sealed record AssetTransferRequest(
	object Asset,
	AssetTransferSource From,
	AssetTransferDestination To,
	string Value,
	IReadOnlyList<string>? AllowedRails = null);

/// <summary>A request to execute a pull instruction for a transfer.</summary>
public sealed record AssetExecuteRequest(string Id, object Instruction);

/// <summary>A request to open a persistent-forwarding template session.</summary>
public sealed record AssetInitiateTemplateRequest(object Asset, string Location);

/// <summary>
/// A request to create a persistent-forwarding template: either a direct
/// template (<paramref name="Asset"/>, <paramref name="Location"/>, and
/// <paramref name="Address"/>) or the completion of a session (<paramref name="Data"/>).
/// </summary>
public sealed record AssetCreateTemplateRequest(
	object? Asset = null,
	string? Location = null,
	object? Address = null,
	string? Id = null,
	object? Data = null);

/// <summary>A request to list persistent-forwarding templates.</summary>
public sealed record AssetListTemplatesRequest(
	IReadOnlyList<string>? Asset = null,
	IReadOnlyList<string>? Location = null);

/// <summary>A request to create a persistent-forwarding address.</summary>
public sealed record AssetCreateAddressRequest(
	string SourceLocation,
	object Asset,
	string? OutgoingRail = null,
	string? IncomingRail = null,
	string? DestinationLocation = null,
	object? DestinationAddress = null,
	string? PersistentAddressTemplateId = null);

/// <summary>One filter over persistent-forwarding addresses.</summary>
public sealed record AssetAddressFilter(
	string? SourceLocation = null,
	string? DestinationLocation = null,
	string? Asset = null,
	string? DestinationAddress = null,
	string? PersistentAddressTemplateId = null);

/// <summary>A request to list persistent-forwarding addresses.</summary>
public sealed record AssetListAddressesRequest(
	IReadOnlyList<AssetAddressFilter>? Search = null,
	AssetPagination? Pagination = null);

/// <summary>A persistent-address filter for listing transactions.</summary>
public sealed record AssetPersistentAddressFilter(
	string Location,
	string? PersistentAddress = null,
	string? PersistentAddressTemplate = null);

/// <summary>A source/destination endpoint filter for listing transactions.</summary>
public sealed record AssetEndpointFilter(string Location, string? UserAddress = null, string? Asset = null);

/// <summary>A specific-transaction filter for listing transactions.</summary>
public sealed record AssetTransactionRef(string Location, object Transaction);

/// <summary>A request to list asset-movement transactions.</summary>
public sealed record AssetListTransactionsRequest(
	IReadOnlyList<AssetPersistentAddressFilter>? PersistentAddresses = null,
	AssetEndpointFilter? From = null,
	AssetEndpointFilter? To = null,
	IReadOnlyList<AssetTransactionRef>? Transactions = null,
	AssetPagination? Pagination = null);

/// <summary>A request to share KYC attributes with the provider.</summary>
public sealed record AssetShareKycRequest(string Attributes, object? TosAgreement = null);

/// <summary>An initiated transfer: its id and the instruction choices to complete it.</summary>
public sealed record AssetTransfer(string Id, IReadOnlyList<JsonElement> InstructionChoices);

/// <summary>A simulated transfer: the instruction choices, without an id.</summary>
public sealed record AssetSimulatedTransfer(IReadOnlyList<JsonElement> InstructionChoices);

/// <summary>A transfer's status: the underlying transaction record.</summary>
public sealed record AssetTransferStatus(JsonElement Transaction);

/// <summary>A persistent-forwarding template session opened by an initiate call.</summary>
public sealed record AssetTemplateSession(string Id, string ExpiresAt, JsonElement Data);

/// <summary>A created persistent-forwarding template.</summary>
public sealed record AssetForwardingTemplate(string Id, JsonElement Location, JsonElement Asset, JsonElement Address);

/// <summary>A page of persistent-forwarding templates.</summary>
public sealed record AssetTemplatePage(IReadOnlyList<JsonElement> Templates, string Total);

/// <summary>A page of persistent-forwarding addresses.</summary>
public sealed record AssetAddressPage(IReadOnlyList<JsonElement> Addresses, string Total);

/// <summary>A page of asset-movement transactions.</summary>
public sealed record AssetTransactionPage(IReadOnlyList<JsonElement> Transactions, string Total);

/// <summary>The outcome of a share-KYC request.</summary>
public sealed record AssetShareKycOutcome(
	bool IsPending,
	[property: JsonPropertyName("promiseURL")] string? PromiseUrl);

/// <summary>
/// The signer's readiness with a provider: <see cref="ActionRequired"/> and, when
/// set, the polymorphic <see cref="Blockers"/> the caller must resolve first.
/// </summary>
public sealed record AssetAccountStatus(bool ActionRequired, IReadOnlyList<JsonElement>? Blockers = null);

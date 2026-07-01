namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// The networked asset-movement surface of the P1 core module: discover
/// providers, then move assets, manage persistent forwarding, and share KYC.
/// Provider and request payloads cross as JSON strings.
/// </summary>
public sealed partial class WasmRuntime
{
	internal int AssetWithAccount(string nodeUrl, string root, int accountHandle)
	{
		var owned = new List<Argument>();
		try
		{
			Argument node = Write(nodeUrl, owned);
			Argument anchor = Write(root, owned);
			return TakeHandle(Invoke<int, int, int, int, int, int>(
				"keeta_asset_with_account", node.Pointer, node.Length, anchor.Pointer, anchor.Length, accountHandle));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] AssetProviders(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_asset_providers", handle));

	internal byte[] AssetProviderById(int handle, string id) =>
		WithHandleAndText("keeta_asset_provider_by_id", handle, id);

	internal byte[] AssetProviderByAccount(int handle, string account) =>
		WithHandleAndText("keeta_asset_provider_by_account", handle, account);

	internal byte[] AssetProvidersForTransfer(int handle, string searchJson) =>
		WithHandleAndText("keeta_asset_providers_for_transfer", handle, searchJson);

	internal byte[] AssetSimulateTransfer(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_simulate_transfer", handle, providerJson, requestJson);

	internal byte[] AssetInitiateTransfer(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_initiate_transfer", handle, providerJson, requestJson);

	internal byte[] AssetExecuteTransfer(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_execute_transfer", handle, providerJson, requestJson);

	internal byte[] AssetTransferStatus(int handle, string providerJson, string id) =>
		WithProviderAndArg("keeta_asset_transfer_status", handle, providerJson, id);

	internal byte[] AssetAccountStatus(int handle, string providerJson)
	{
		var owned = new List<Argument>();
		try
		{
			Argument provider = Write(providerJson, owned);
			return TakeBytes(Invoke<int, int, int, int>(
				"keeta_asset_account_status", handle, provider.Pointer, provider.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] AssetInitiateForwardingTemplate(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_initiate_forwarding_template", handle, providerJson, requestJson);

	internal byte[] AssetCreateForwardingTemplate(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_create_forwarding_template", handle, providerJson, requestJson);

	internal byte[] AssetListForwardingTemplates(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_list_forwarding_templates", handle, providerJson, requestJson);

	internal byte[] AssetCreateForwardingAddress(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_create_forwarding_address", handle, providerJson, requestJson);

	internal byte[] AssetListForwardingAddresses(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_list_forwarding_addresses", handle, providerJson, requestJson);

	internal byte[] AssetDeactivateForwardingTemplate(int handle, string providerJson, string id) =>
		WithProviderAndArg("keeta_asset_deactivate_forwarding_template", handle, providerJson, id);

	internal byte[] AssetDeactivateForwardingAddress(int handle, string providerJson, string id) =>
		WithProviderAndArg("keeta_asset_deactivate_forwarding_address", handle, providerJson, id);

	internal byte[] AssetListTransactions(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_list_transactions", handle, providerJson, requestJson);

	internal byte[] AssetShareKyc(int handle, string providerJson, string requestJson) =>
		WithProviderAndArg("keeta_asset_share_kyc", handle, providerJson, requestJson);

	internal byte[] AssetShareKycAwait(int handle, string providerJson, string requestJson, int intervalMs, int timeoutMs)
	{
		var owned = new List<Argument>();
		try
		{
			Argument provider = Write(providerJson, owned);
			Argument request = Write(requestJson, owned);
			return TakeBytes(Invoke<int, int, int, int, int, int, int, int>(
				"keeta_asset_share_kyc_await",
				handle,
				provider.Pointer, provider.Length,
				request.Pointer, request.Length,
				intervalMs, timeoutMs));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void AssetFree(int handle) => Free("keeta_asset_free", handle);

	/// <summary>Drive an export taking a client handle and one UTF-8 argument.</summary>
	private byte[] WithHandleAndText(string export, int handle, string value)
	{
		var owned = new List<Argument>();
		try
		{
			Argument argument = Write(value, owned);
			return TakeBytes(Invoke<int, int, int, int>(export, handle, argument.Pointer, argument.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	/// <summary>Drive an export taking a client handle, a provider, and one argument.</summary>
	private byte[] WithProviderAndArg(string export, int handle, string providerJson, string argument)
	{
		var owned = new List<Argument>();
		try
		{
			Argument provider = Write(providerJson, owned);
			Argument value = Write(argument, owned);
			return TakeBytes(Invoke<int, int, int, int, int, int>(
				export, handle, provider.Pointer, provider.Length, value.Pointer, value.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}
}

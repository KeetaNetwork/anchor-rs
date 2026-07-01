using System.Text.Json;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// The sharable certificate-attributes surface of the P1 core module: a sealed,
/// selectively disclosed subset of a leaf's attributes, handle-based. Leaf,
/// account, and base-certificate handles are reused from the shared
/// <c>crypto</c> and KYC registries.
/// </summary>
public sealed partial class WasmRuntime
{
	internal int SharableFromCertificate(int certificateHandle, int subjectHandle, int[] intermediates, string[] names)
	{
		var owned = new List<Argument>();
		try
		{
			Argument bridges = WriteHandles(intermediates, owned);
			Argument labels = WriteBytes(JsonSerializer.SerializeToUtf8Bytes(names), owned);
			return TakeHandle(Invoke<int, int, int, int, int, int, int>(
				"keeta_sharable_from_certificate",
				certificateHandle, subjectHandle, bridges.Pointer, bridges.Length, labels.Pointer, labels.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int SharableFromEncoded(byte[] data, int[] principals) =>
		SharableFrom("keeta_sharable_from_encoded", data, principals);

	internal int SharableFromPem(string pem, int[] principals)
	{
		var owned = new List<Argument>();
		try
		{
			Argument envelope = Write(pem, owned);
			Argument keys = WriteHandles(principals, owned);
			return TakeHandle(Invoke<int, int, int, int, int>(
				"keeta_sharable_from_pem", envelope.Pointer, envelope.Length, keys.Pointer, keys.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	private int SharableFrom(string export, byte[] data, int[] principals)
	{
		var owned = new List<Argument>();
		try
		{
			Argument payload = WriteBytes(data, owned);
			Argument keys = WriteHandles(principals, owned);
			return TakeHandle(Invoke<int, int, int, int, int>(
				export, payload.Pointer, payload.Length, keys.Pointer, keys.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void SharableGrantAccess(int handle, int[] principals)
	{
		var owned = new List<Argument>();
		try
		{
			Argument keys = WriteHandles(principals, owned);
			TakeFlag(Invoke<int, int, int, int>("keeta_sharable_grant_access", handle, keys.Pointer, keys.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void SharableRevokeAccess(int handle, byte[] publicKey)
	{
		var owned = new List<Argument>();
		try
		{
			Argument key = WriteBytes(publicKey, owned);
			TakeFlag(Invoke<int, int, int, int>("keeta_sharable_revoke_access", handle, key.Pointer, key.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] SharablePrincipals(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_sharable_principals", handle));

	internal byte[] SharableExport(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_sharable_export", handle));

	internal string SharableToPem(int handle) =>
		Text(Invoke<int, int>("keeta_sharable_to_pem", handle));

	internal int SharableCertificate(int handle) =>
		TakeHandle(Invoke<int, int>("keeta_sharable_certificate", handle));

	internal byte[] SharableIntermediates(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_sharable_intermediates", handle));

	internal byte[] SharableAttributeNames(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_sharable_attribute_names", handle));

	internal byte[] SharableAttributeBuffer(int handle, string name) =>
		SharableAttribute("keeta_sharable_attribute_buffer", handle, name);

	internal byte[] SharableAttributeValue(int handle, string name) =>
		SharableAttribute("keeta_sharable_attribute_value", handle, name);

	private byte[] SharableAttribute(string export, int handle, string name)
	{
		var owned = new List<Argument>();
		try
		{
			Argument label = Write(name, owned);
			return TakeBytes(Invoke<int, int, int, int>(export, handle, label.Pointer, label.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void SharableFree(int handle) => Free("keeta_sharable_free", handle);
}

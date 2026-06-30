namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// The encrypted-container surface of the P1 core module: handle-based,
/// optionally encrypted and signed blobs. Principal sets and signers are passed
/// as account handles from the shared <c>crypto</c> registry.
/// </summary>
public sealed partial class WasmRuntime
{
	internal int EncryptedContainerFromPlaintext(byte[] data, int[] principals, int locked, int signerHandle)
	{
		var owned = new List<Argument>();
		try
		{
			Argument payload = WriteBytes(data, owned);
			Argument keys = WriteHandles(principals, owned);
			return TakeHandle(Invoke<int, int, int, int, int, int, int>(
				"keeta_encrypted_container_from_plaintext",
				payload.Pointer, payload.Length, keys.Pointer, keys.Length, locked, signerHandle));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int EncryptedContainerFromEncoded(byte[] data, int[] principals) =>
		EncryptedContainerFrom("keeta_encrypted_container_from_encoded", data, principals);

	internal int EncryptedContainerFromEncrypted(byte[] data, int[] principals) =>
		EncryptedContainerFrom("keeta_encrypted_container_from_encrypted", data, principals);

	private int EncryptedContainerFrom(string export, byte[] data, int[] principals)
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

	internal byte[] EncryptedContainerGetPlaintext(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_encrypted_container_get_plaintext", handle));

	internal byte[] EncryptedContainerGetEncoded(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_encrypted_container_get_encoded", handle));

	internal bool EncryptedContainerIsEncrypted(int handle) =>
		TakeFlag(Invoke<int, int>("keeta_encrypted_container_is_encrypted", handle));

	internal bool EncryptedContainerIsSigned(int handle) =>
		TakeFlag(Invoke<int, int>("keeta_encrypted_container_is_signed", handle));

	internal bool EncryptedContainerVerifySignature(int handle) =>
		TakeFlag(Invoke<int, int>("keeta_encrypted_container_verify_signature", handle));

	internal byte[] EncryptedContainerSigningAccount(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_encrypted_container_signing_account", handle));

	internal byte[] EncryptedContainerPrincipals(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_encrypted_container_principals", handle));

	internal void EncryptedContainerGrantAccess(int handle, int[] principals)
	{
		var owned = new List<Argument>();
		try
		{
			Argument keys = WriteHandles(principals, owned);
			TakeFlag(Invoke<int, int, int, int>(
				"keeta_encrypted_container_grant_access", handle, keys.Pointer, keys.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void EncryptedContainerRevokeAccess(int handle, byte[] publicKey)
	{
		var owned = new List<Argument>();
		try
		{
			Argument key = WriteBytes(publicKey, owned);
			TakeFlag(Invoke<int, int, int, int>(
				"keeta_encrypted_container_revoke_access", handle, key.Pointer, key.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void EncryptedContainerFree(int handle) => Free("keeta_encrypted_container_free", handle);
}

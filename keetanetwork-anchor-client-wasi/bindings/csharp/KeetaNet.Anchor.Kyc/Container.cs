using System.Text.Json;

namespace KeetaNet.Anchor.Kyc.Crypto;

/// <summary>
/// A hybrid-encrypted, optionally signed container. The blob and its derived
/// state live inside the wasm core; this wrapper holds only the handle and
/// releases it on <see cref="Dispose"/>.
/// </summary>
public sealed class EncryptedContainer : IDisposable
{
	private readonly WasmRuntime _runtime;
	private bool _disposed;

	/// <summary>The core-module handle backing this container.</summary>
	internal int Handle { get; }

	private EncryptedContainer(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		Handle = handle;
	}

	/// <summary>
	/// Build a plaintext container. A non-empty <paramref name="principals"/> set
	/// seals it to those accounts; <paramref name="signer"/> attaches a detached
	/// signature; <paramref name="locked"/> overrides the default plaintext policy.
	/// </summary>
	public static EncryptedContainer FromPlaintext(
		WasmRuntime runtime,
		byte[] data,
		IEnumerable<Account>? principals = null,
		bool? locked = null,
		Account? signer = null)
	{
		int[] handles = Handles(principals);
		int lockedFlag = locked is null ? -1 : locked.Value ? 1 : 0;
		int signerHandle = signer?.Handle ?? 0;
		return new(runtime, runtime.EncryptedContainerFromPlaintext(data, handles, lockedFlag, signerHandle));
	}

	/// <summary>
	/// Build a container from an encoded blob that may be plaintext or encrypted,
	/// resolving an encrypted blob with the optional <paramref name="principals"/>.
	/// </summary>
	public static EncryptedContainer FromEncoded(
		WasmRuntime runtime,
		byte[] data,
		IEnumerable<Account>? principals = null) =>
		new(runtime, runtime.EncryptedContainerFromEncoded(data, Handles(principals)));

	/// <summary>
	/// Build a container from a blob that must be encrypted, opened by one of
	/// <paramref name="principals"/>.
	/// </summary>
	public static EncryptedContainer FromEncrypted(WasmRuntime runtime, byte[] data, IEnumerable<Account> principals) =>
		new(runtime, runtime.EncryptedContainerFromEncrypted(data, Handles(principals)));

	/// <summary>The decrypted, decompressed plaintext.</summary>
	public byte[] Plaintext() => _runtime.EncryptedContainerGetPlaintext(Handle);

	/// <summary>The container's DER encoding.</summary>
	public byte[] Encoded() => _runtime.EncryptedContainerGetEncoded(Handle);

	/// <summary>Whether the container is sealed to a principal set.</summary>
	public bool IsEncrypted => _runtime.EncryptedContainerIsEncrypted(Handle);

	/// <summary>Whether a signer is attached or a signature is present.</summary>
	public bool IsSigned => _runtime.EncryptedContainerIsSigned(Handle);

	/// <summary>Verify the detached signature over the compressed payload.</summary>
	public bool VerifySignature() => _runtime.EncryptedContainerVerifySignature(Handle);

	/// <summary>
	/// The type-prefixed public key of the signing account, or <c>null</c> when
	/// the container is unsigned.
	/// </summary>
	public byte[]? SigningAccount()
	{
		byte[] key = _runtime.EncryptedContainerSigningAccount(Handle);
		return key.Length == 0 ? null : key;
	}

	/// <summary>The type-prefixed public keys of the accounts that can open it.</summary>
	public IReadOnlyList<byte[]> Principals()
	{
		byte[] payload = _runtime.EncryptedContainerPrincipals(Handle);
		int[][] raw = JsonSerializer.Deserialize<int[][]>(payload) ?? Array.Empty<int[]>();
		return raw.Select(values => Array.ConvertAll(values, value => (byte)value)).ToList();
	}

	/// <summary>Grant <paramref name="accounts"/> access, invalidating the encoded form.</summary>
	public void GrantAccess(IEnumerable<Account> accounts) =>
		_runtime.EncryptedContainerGrantAccess(Handle, Handles(accounts));

	/// <summary>Revoke the account identified by its type-prefixed <paramref name="publicKey"/>.</summary>
	public void RevokeAccess(byte[] publicKey) => _runtime.EncryptedContainerRevokeAccess(Handle, publicKey);

	private static int[] Handles(IEnumerable<Account>? accounts) =>
		(accounts ?? Enumerable.Empty<Account>()).Select(account => account.Handle).ToArray();

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.EncryptedContainerFree(Handle);
	}
}

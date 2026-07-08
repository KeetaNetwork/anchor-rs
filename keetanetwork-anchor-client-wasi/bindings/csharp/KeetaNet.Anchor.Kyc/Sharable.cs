using System.Text.Json;

namespace KeetaNet.Anchor.Kyc.Crypto;

/// <summary>
/// A sealed, selectively disclosed subset of a KYC certificate's attributes.
/// The bundle and its derived state live inside the wasm core; this wrapper
/// holds only the handle and releases it on <see cref="Dispose"/>.
/// </summary>
public sealed class SharableCertificateAttributes : IDisposable
{
	private readonly WasmRuntime _runtime;
	private bool _disposed;

	/// <summary>The core-module handle backing this bundle.</summary>
	internal int Handle { get; }

	private SharableCertificateAttributes(WasmRuntime runtime, int handle)
	{
		_runtime = runtime;
		Handle = handle;
	}

	/// <summary>
	/// Prove or copy each attribute in <paramref name="names"/> from
	/// <paramref name="certificate"/> using the <paramref name="subject"/> account,
	/// bridging the trust chain with <paramref name="intermediates"/>, and seal the
	/// result. Grant a recipient before exporting.
	/// </summary>
	public static SharableCertificateAttributes FromCertificate(
		WasmRuntime runtime,
		KycCertificate certificate,
		Account subject,
		IEnumerable<Certificate>? intermediates = null,
		IEnumerable<string>? names = null)
	{
		int[] bridges = Handles(intermediates);
		string[] labels = (names ?? Enumerable.Empty<string>()).ToArray();
		return new(runtime, runtime.SharableFromCertificate(certificate.Handle, subject.Handle, bridges, labels));
	}

	/// <summary>
	/// Build like <see cref="FromCertificate"/>, additionally ingesting the
	/// caller-fetched external <paramref name="blobs"/> (raw fetched bytes keyed
	/// by reference id).
	/// </summary>
	public static SharableCertificateAttributes FromCertificateWithReferences(
		WasmRuntime runtime,
		KycCertificate certificate,
		Account subject,
		IReadOnlyDictionary<string, byte[]> blobs,
		IEnumerable<Certificate>? intermediates = null,
		IEnumerable<string>? names = null)
	{
		int[] bridges = Handles(intermediates);
		string[] labels = (names ?? Enumerable.Empty<string>()).ToArray();
		return new(runtime, runtime.SharableFromCertificateWithReferences(
			certificate.Handle, subject.Handle, bridges, labels, blobs));
	}

	/// <summary>Open a bundle from encoded container bytes, resolved with <paramref name="principals"/>.</summary>
	public static SharableCertificateAttributes FromEncoded(
		WasmRuntime runtime,
		byte[] data,
		IEnumerable<Account>? principals = null) =>
		new(runtime, runtime.SharableFromEncoded(data, AccountHandles(principals)));

	/// <summary>Open a bundle from a PEM envelope, resolved with <paramref name="principals"/>.</summary>
	public static SharableCertificateAttributes FromPem(
		WasmRuntime runtime,
		string pem,
		IEnumerable<Account>? principals = null) =>
		new(runtime, runtime.SharableFromPem(pem, AccountHandles(principals)));

	/// <summary>Grant <paramref name="accounts"/> access, invalidating the encoded form.</summary>
	public void GrantAccess(IEnumerable<Account> accounts) =>
		_runtime.SharableGrantAccess(Handle, AccountHandles(accounts));

	/// <summary>Revoke the account identified by its type-prefixed <paramref name="publicKey"/>.</summary>
	public void RevokeAccess(byte[] publicKey) => _runtime.SharableRevokeAccess(Handle, publicKey);

	/// <summary>The type-prefixed public keys of the accounts that can open the bundle.</summary>
	public IReadOnlyList<byte[]> Principals()
	{
		byte[] payload = _runtime.SharablePrincipals(Handle);
		int[][] raw = JsonSerializer.Deserialize<int[][]>(payload) ?? Array.Empty<int[]>();
		return raw.Select(values => Array.ConvertAll(values, value => (byte)value)).ToList();
	}

	/// <summary>The bundle's DER-encoded container bytes, requiring a granted recipient.</summary>
	public byte[] Export() => _runtime.SharableExport(Handle);

	/// <summary>The bundle exported as a PEM envelope.</summary>
	public string ToPem() => _runtime.SharableToPem(Handle);

	/// <summary>The embedded leaf certificate, as an independently owned object.</summary>
	public KycCertificate LeafCertificate() => KycCertificate.Adopt(_runtime, _runtime.SharableCertificate(Handle));

	/// <summary>The embedded intermediate certificate chain, as owned objects.</summary>
	public IReadOnlyList<Certificate> Intermediates()
	{
		byte[] payload = _runtime.SharableIntermediates(Handle);
		string[] pems = JsonSerializer.Deserialize<string[]>(payload) ?? Array.Empty<string>();
		return pems.Select(pem => Certificate.Parse(_runtime, pem)).ToList();
	}

	/// <summary>The names of the disclosed attributes.</summary>
	public IReadOnlyList<string> AttributeNames()
	{
		byte[] payload = _runtime.SharableAttributeNames(Handle);
		return JsonSerializer.Deserialize<string[]>(payload) ?? Array.Empty<string>();
	}

	/// <summary>The validated raw disclosed value for <paramref name="name"/>, or <c>null</c> when not disclosed.</summary>
	public byte[]? AttributeBuffer(string name)
	{
		byte[] value = _runtime.SharableAttributeBuffer(Handle, name);
		return value.Length == 0 ? null : value;
	}

	/// <summary>The schema-decoded semantic value for <paramref name="name"/>, or <c>null</c> when not disclosed.</summary>
	public byte[]? AttributeValue(string name)
	{
		byte[] value = _runtime.SharableAttributeValue(Handle, name);
		return value.Length == 0 ? null : value;
	}

	/// <summary>
	/// The inlined, digest-verified blob for reference <paramref name="id"/> on
	/// the disclosed attribute <paramref name="name"/>, or <c>null</c> when the
	/// attribute, entry, or matching reference node is absent.
	/// </summary>
	public byte[]? ReferenceBlob(string name, string id)
	{
		byte[] value = _runtime.SharableReferenceBlob(Handle, name, id);
		return value.Length == 0 ? null : value;
	}

	private static int[] Handles(IEnumerable<Certificate>? certificates) =>
		(certificates ?? Enumerable.Empty<Certificate>()).Select(certificate => certificate.Handle).ToArray();

	private static int[] AccountHandles(IEnumerable<Account>? accounts) =>
		(accounts ?? Enumerable.Empty<Account>()).Select(account => account.Handle).ToArray();

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_runtime.SharableFree(Handle);
	}
}

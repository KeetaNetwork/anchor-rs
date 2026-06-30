using System.Buffers.Binary;
using System.Text;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// The offline <c>crypto</c> surface of the P1 core module: handle-based account,
/// base certificate, and KYC certificate objects.
/// </summary>
public sealed partial class WasmRuntime
{
	// -----------------------------------------------------------------------
	// account
	// -----------------------------------------------------------------------

	internal int AccountFromSeed(string seed, uint index, string algorithm)
	{
		var owned = new List<Argument>();
		try
		{
			Argument secret = Write(seed, owned);
			Argument algo = Write(algorithm, owned);
			return TakeHandle(Invoke<int, int, int, int, int, int>(
				"keeta_account_from_seed", secret.Pointer, secret.Length, (int)index, algo.Pointer, algo.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int AccountFromAddress(string address)
	{
		var owned = new List<Argument>();
		try
		{
			Argument value = Write(address, owned);
			return TakeHandle(Invoke<int, int, int>("keeta_account_from_address", value.Pointer, value.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int AccountFromPrivateKey(string privateKey, string algorithm)
	{
		var owned = new List<Argument>();
		try
		{
			Argument key = Write(privateKey, owned);
			Argument algo = Write(algorithm, owned);
			return TakeHandle(Invoke<int, int, int, int, int>(
				"keeta_account_from_private_key", key.Pointer, key.Length, algo.Pointer, algo.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int AccountFromPassphrase(string words, uint index, string algorithm)
	{
		var owned = new List<Argument>();
		try
		{
			Argument mnemonic = Write(words, owned);
			Argument algo = Write(algorithm, owned);
			return TakeHandle(Invoke<int, int, int, int, int, int>(
				"keeta_account_from_passphrase", mnemonic.Pointer, mnemonic.Length, (int)index, algo.Pointer, algo.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int AccountFromPublicKey(string publicKey, string algorithm)
	{
		var owned = new List<Argument>();
		try
		{
			Argument key = Write(publicKey, owned);
			Argument algo = Write(algorithm, owned);
			return TakeHandle(Invoke<int, int, int, int, int>(
				"keeta_account_from_public_key", key.Pointer, key.Length, algo.Pointer, algo.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal string AccountGenerateSeed() =>
		Text(Invoke<int>("keeta_generate_seed"));

	internal string AccountGeneratePassphrase() =>
		Text(Invoke<int>("keeta_generate_passphrase"));

	internal byte[] AccountEncrypt(int handle, byte[] plaintext) =>
		AccountTransform("keeta_account_encrypt", handle, plaintext);

	internal byte[] AccountDecrypt(int handle, byte[] ciphertext) =>
		AccountTransform("keeta_account_decrypt", handle, ciphertext);

	private byte[] AccountTransform(string export, int handle, byte[] input)
	{
		var owned = new List<Argument>();
		try
		{
			Argument body = WriteBytes(input, owned);
			return TakeBytes(Invoke<int, int, int, int>(export, handle, body.Pointer, body.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal string AccountAddress(int handle) =>
		Text(Invoke<int, int>("keeta_account_address", handle));

	internal string AccountAlgorithm(int handle) =>
		Text(Invoke<int, int>("keeta_account_algorithm", handle));

	internal string AccountPublicKey(int handle) =>
		Text(Invoke<int, int>("keeta_account_public_key", handle));

	internal byte[] AccountSign(int handle, byte[] message)
	{
		var owned = new List<Argument>();
		try
		{
			Argument body = WriteBytes(message, owned);
			return TakeBytes(Invoke<int, int, int, int>("keeta_account_sign", handle, body.Pointer, body.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal bool AccountVerify(int handle, byte[] message, byte[] signature)
	{
		var owned = new List<Argument>();
		try
		{
			Argument body = WriteBytes(message, owned);
			Argument sig = WriteBytes(signature, owned);
			return Invoke<int, int, int, int, int, int>(
				"keeta_account_verify", handle, body.Pointer, body.Length, sig.Pointer, sig.Length) != 0;
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal void AccountFree(int handle) => Free("keeta_account_free", handle);

	// -----------------------------------------------------------------------
	// certificate
	// -----------------------------------------------------------------------

	internal int CertificateParse(string pem) => ParseText("keeta_certificate_parse", pem);

	internal int CertificateParseDer(byte[] der) => ParseBytes("keeta_certificate_parse_der", der);

	internal string CertificatePem(int handle) =>
		Text(Invoke<int, int>("keeta_certificate_pem", handle));

	internal byte[] CertificateDer(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_certificate_der", handle));

	internal bool CertificateValidAt(int handle, long unixMillis) =>
		TakeFlag(Invoke<int, long, int>("keeta_certificate_valid_at", handle, unixMillis));

	internal string CertificateSubject(int handle) =>
		Text(Invoke<int, int>("keeta_certificate_subject", handle));

	internal string CertificateIssuer(int handle) =>
		Text(Invoke<int, int>("keeta_certificate_issuer", handle));

	internal string CertificateSerial(int handle) =>
		Text(Invoke<int, int>("keeta_certificate_serial", handle));

	internal long CertificateNotBefore(int handle) =>
		InvokeLong("keeta_certificate_not_before", handle);

	internal long CertificateNotAfter(int handle) =>
		InvokeLong("keeta_certificate_not_after", handle);

	internal string CertificateSubjectPublicKey(int handle) =>
		Text(Invoke<int, int>("keeta_certificate_subject_public_key", handle));

	internal void CertificateFree(int handle) => Free("keeta_certificate_free", handle);

	// -----------------------------------------------------------------------
	// kyc-certificate
	// -----------------------------------------------------------------------

	internal int KycCertificateParse(string pem) => ParseText("keeta_kyc_certificate_parse", pem);

	internal int KycCertificateBase(int handle) =>
		TakeHandle(Invoke<int, int>("keeta_kyc_certificate_base", handle));

	internal bool KycCertificateValidAt(int handle, long unixMillis) =>
		TakeFlag(Invoke<int, long, int>("keeta_kyc_certificate_valid_at", handle, unixMillis));

	internal bool KycCertificateVerify(int handle, int[] trustedRoots, int[] intermediates, long unixMillis)
	{
		var owned = new List<Argument>();
		try
		{
			Argument roots = WriteHandles(trustedRoots, owned);
			Argument bridges = WriteHandles(intermediates, owned);
			return TakeFlag(Invoke<int, int, int, int, int, long, int>(
				"keeta_kyc_certificate_verify",
				handle, roots.Pointer, roots.Length, bridges.Pointer, bridges.Length, unixMillis));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] KycCertificateAttributes(int handle) =>
		TakeBytes(Invoke<int, int>("keeta_kyc_certificate_attributes", handle));

	internal byte[] KycCertificatePlainAttribute(int handle, string name)
	{
		var owned = new List<Argument>();
		try
		{
			Argument label = Write(name, owned);
			return TakeBytes(Invoke<int, int, int, int>(
				"keeta_kyc_certificate_plain_attribute", handle, label.Pointer, label.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] KycCertificateDecryptAttribute(int handle, string name, int accountHandle)
	{
		var owned = new List<Argument>();
		try
		{
			Argument label = Write(name, owned);
			return TakeBytes(Invoke<int, int, int, int, int>(
				"keeta_kyc_certificate_decrypt_attribute", handle, label.Pointer, label.Length, accountHandle));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] KycCertificateProve(int handle, string name, int accountHandle)
	{
		var owned = new List<Argument>();
		try
		{
			Argument label = Write(name, owned);
			return TakeBytes(Invoke<int, int, int, int, int>(
				"keeta_kyc_certificate_prove", handle, label.Pointer, label.Length, accountHandle));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal bool KycCertificateValidateProof(int handle, string name, int accountHandle, string proof)
	{
		var owned = new List<Argument>();
		try
		{
			Argument label = Write(name, owned);
			Argument document = Write(proof, owned);
			return TakeFlag(Invoke<int, int, int, int, int, int, int>(
				"keeta_kyc_certificate_validate_proof",
				handle, label.Pointer, label.Length, accountHandle, document.Pointer, document.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal int KycCertificateIssue(int subjectHandle, int issuerHandle, string parameters)
	{
		var owned = new List<Argument>();
		try
		{
			Argument args = Write(parameters, owned);
			return TakeHandle(Invoke<int, int, int, int, int>(
				"keeta_kyc_certificate_issue", subjectHandle, issuerHandle, args.Pointer, args.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal string KycCertificatePem(int handle) =>
		Text(Invoke<int, int>("keeta_kyc_certificate_pem", handle));

	internal void KycCertificateFree(int handle) => Free("keeta_kyc_certificate_free", handle);

	// -----------------------------------------------------------------------
	// kyc client over an account handle
	// -----------------------------------------------------------------------

	internal int KycWithAccount(string nodeUrl, string root, int accountHandle)
	{
		var owned = new List<Argument>();
		try
		{
			Argument node = Write(nodeUrl, owned);
			Argument anchor = Write(root, owned);
			return TakeHandle(Invoke<int, int, int, int, int, int>(
				"keeta_kyc_with_account", node.Pointer, node.Length, anchor.Pointer, anchor.Length, accountHandle));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	// -----------------------------------------------------------------------
	// Shared marshaling helpers
	// -----------------------------------------------------------------------

	/// <summary>Parse a UTF-8 textual argument into an object, returning its handle.</summary>
	private int ParseText(string export, string value)
	{
		var owned = new List<Argument>();
		try
		{
			Argument argument = Write(value, owned);
			return TakeHandle(Invoke<int, int, int>(export, argument.Pointer, argument.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	/// <summary>Parse a binary argument into an object, returning its handle.</summary>
	private int ParseBytes(string export, byte[] value)
	{
		var owned = new List<Argument>();
		try
		{
			Argument argument = WriteBytes(value, owned);
			return TakeHandle(Invoke<int, int, int>(export, argument.Pointer, argument.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	/// <summary>The UTF-8 text a bytes handle carries.</summary>
	private string Text(int handle) => Encoding.UTF8.GetString(TakeBytes(handle));

	/// <summary>Copy raw bytes into a fresh guest buffer.</summary>
	private Argument WriteBytes(byte[] value, List<Argument> owned)
	{
		int pointer = _alloc(value.Length);
		if (value.Length > 0)
		{
			value.AsSpan().CopyTo(_memory.GetSpan(pointer, value.Length));
		}

		var argument = new Argument(pointer, value.Length);
		owned.Add(argument);
		return argument;
	}

	/// <summary>Copy a list of handles into a fresh guest buffer of little-endian i32.</summary>
	private Argument WriteHandles(int[] handles, List<Argument> owned)
	{
		byte[] buffer = new byte[handles.Length * sizeof(int)];
		for (int index = 0; index < handles.Length; index++)
		{
			BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(index * sizeof(int)), handles[index]);
		}

		return WriteBytes(buffer, owned);
	}

	private int Invoke<TResult>(string export) =>
		(int)(object)Required(export, _instance.GetFunction<TResult>(export))()!;

	private int Invoke<T1, TResult>(string export, T1 arg1) =>
		(int)(object)Required(export, _instance.GetFunction<T1, TResult>(export))(arg1)!;

	private long InvokeLong<T1>(string export, T1 arg1) =>
		Required(export, _instance.GetFunction<T1, long>(export))(arg1);

	private int Invoke<T1, T2, TResult>(string export, T1 arg1, T2 arg2) =>
		(int)(object)Required(export, _instance.GetFunction<T1, T2, TResult>(export))(arg1, arg2)!;

	private int Invoke<T1, T2, T3, TResult>(string export, T1 arg1, T2 arg2, T3 arg3) =>
		(int)(object)Required(export, _instance.GetFunction<T1, T2, T3, TResult>(export))(arg1, arg2, arg3)!;

	private int Invoke<T1, T2, T3, T4, TResult>(string export, T1 arg1, T2 arg2, T3 arg3, T4 arg4) =>
		(int)(object)Required(export, _instance.GetFunction<T1, T2, T3, T4, TResult>(export))(arg1, arg2, arg3, arg4)!;

	private int Invoke<T1, T2, T3, T4, T5, TResult>(string export, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5) =>
		(int)(object)Required(export, _instance.GetFunction<T1, T2, T3, T4, T5, TResult>(export))(arg1, arg2, arg3, arg4, arg5)!;

	private int Invoke<T1, T2, T3, T4, T5, T6, TResult>(
		string export, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6) =>
		(int)(object)Required(export, _instance.GetFunction<T1, T2, T3, T4, T5, T6, TResult>(export))(
			arg1, arg2, arg3, arg4, arg5, arg6)!;

	private int Invoke<T1, T2, T3, T4, T5, T6, T7, TResult>(
		string export, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7) =>
		(int)(object)Required(export, _instance.GetFunction<T1, T2, T3, T4, T5, T6, T7, TResult>(export))(
			arg1, arg2, arg3, arg4, arg5, arg6, arg7)!;

	private void Free(string export, int handle) =>
		Required(export, _instance.GetAction<int>(export))(handle);
}

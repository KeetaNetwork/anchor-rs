using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Wasmtime;

namespace KeetaNet.Anchor.Kyc;

/// <summary>
/// Loads the P1 <c>wasm32-wasip1</c> core module and satisfies its host imports
/// with .NET HTTP and timers. The anchor logic runs inside the module; this type
/// owns only the wasm engine, memory marshaling, and the I/O shim.
/// </summary>
public sealed partial class WasmRuntime : IDisposable
{
	private const string HostModule = "keeta:anchor/host";
	private const string MemoryExport = "memory";

	private static readonly JsonSerializerOptions HostJson = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	};

	private readonly Engine _engine;
	private readonly Module _module;
	private readonly Linker _linker;
	private readonly Store _store;
	private readonly Instance _instance;
	private readonly Memory _memory;
	private readonly HttpClient _http = new();

	private readonly Func<int, int> _alloc;
	private readonly Action<int, int> _dealloc;
	private readonly Func<int, int> _bytesPtr;
	private readonly Func<int, int> _bytesLen;
	private readonly Action<int> _bytesFree;
	private readonly Func<int> _lastErrorCode;
	private readonly Func<int> _lastErrorMessage;

	private byte[] _pending = Array.Empty<byte>();

	private WasmRuntime(string wasmPath)
	{
		_engine = new Engine();
		_module = Module.FromFile(_engine, wasmPath);
		_linker = new Linker(_engine);
		_store = new Store(_engine);

		_linker.DefineWasi();
		_store.SetWasiConfiguration(new WasiConfiguration()
			.WithInheritedStandardOutput()
			.WithInheritedStandardError());

		DefineHostImports();

		_instance = _linker.Instantiate(_store, _module);
		_instance.GetAction("_initialize")?.Invoke();

		Memory? memory = _instance.GetMemory(MemoryExport);
		_memory = memory ?? throw new KeetaException("WASM", "module exports no memory");
		_alloc = Required("keeta_alloc", _instance.GetFunction<int, int>("keeta_alloc"));
		_dealloc = Required("keeta_dealloc", _instance.GetAction<int, int>("keeta_dealloc"));
		_bytesPtr = Required("keeta_bytes_ptr", _instance.GetFunction<int, int>("keeta_bytes_ptr"));
		_bytesLen = Required("keeta_bytes_len", _instance.GetFunction<int, int>("keeta_bytes_len"));
		_bytesFree = Required("keeta_bytes_free", _instance.GetAction<int>("keeta_bytes_free"));
		_lastErrorCode = Required("keeta_last_error_code", _instance.GetFunction<int>("keeta_last_error_code"));
		_lastErrorMessage =
			Required("keeta_last_error_message", _instance.GetFunction<int>("keeta_last_error_message"));
	}

	/// <summary>Load the core module from a filesystem path.</summary>
	public static WasmRuntime Load(string wasmPath) => new(wasmPath);

	// -----------------------------------------------------------------------
	// KYC exports (ABI marshaling only; JSON shaping lives in KycClient)
	// -----------------------------------------------------------------------

	internal byte[] KycProviders(int handle, string countriesJson)
	{
		var owned = new List<Argument>();
		try
		{
			Argument countries = Write(countriesJson, owned);
			return TakeBytes(Invoke<int, int, int, int>(
				"keeta_kyc_providers", handle, countries.Pointer, countries.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] KycCreateVerification(int handle, string providerJson, string countriesJson, string redirect)
	{
		var owned = new List<Argument>();
		try
		{
			Argument provider = Write(providerJson, owned);
			Argument countries = Write(countriesJson, owned);
			Argument target = Write(redirect, owned);
			return TakeBytes(Invoke<int, int, int, int, int, int, int, int>(
				"keeta_kyc_create_verification",
				handle,
				provider.Pointer, provider.Length,
				countries.Pointer, countries.Length,
				target.Pointer, target.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	internal byte[] KycGetCertificates(int handle, string providerJson, string id) =>
		WithProviderAndId("keeta_kyc_get_certificates", handle, providerJson, id);

	internal byte[] KycGetVerificationStatus(int handle, string providerJson, string id) =>
		WithProviderAndId("keeta_kyc_get_verification_status", handle, providerJson, id);

	internal void KycFree(int handle) => Free("keeta_kyc_free", handle);

	/// <summary>Drive an export taking a provider and a verification id.</summary>
	private byte[] WithProviderAndId(string export, int handle, string providerJson, string id)
	{
		var owned = new List<Argument>();
		try
		{
			Argument provider = Write(providerJson, owned);
			Argument identifier = Write(id, owned);
			return TakeBytes(Invoke<int, int, int, int, int, int>(
				export, handle, provider.Pointer, provider.Length, identifier.Pointer, identifier.Length));
		}
		finally
		{
			FreeAll(owned);
		}
	}

	// -----------------------------------------------------------------------
	// Host imports
	// -----------------------------------------------------------------------

	private void DefineHostImports()
	{
		_linker.DefineFunction(HostModule, "keeta_anchor_host_fetch", (CallerFunc<int, int, int>)HostFetch);
		_linker.DefineFunction(HostModule, "keeta_anchor_host_take", (CallerAction<int>)HostTake);
		_linker.DefineFunction(HostModule, "keeta_anchor_host_sleep", (Action<long>)HostSleep);
	}

	/// <summary>Perform the buffered request and return the response byte length.</summary>
	private int HostFetch(Caller caller, int requestPtr, int requestLen)
	{
		Memory memory = caller.GetMemory(MemoryExport)!;
		byte[] request = memory.GetSpan((uint)requestPtr, requestLen).ToArray();
		_pending = PerformHttp(request);
		return _pending.Length;
	}

	/// <summary>Copy the buffered response into guest memory.</summary>
	private void HostTake(Caller caller, int responsePtr)
	{
		Memory memory = caller.GetMemory(MemoryExport)!;
		_pending.AsSpan().CopyTo(memory.GetSpan((uint)responsePtr, _pending.Length));
	}

	private static void HostSleep(long millis)
	{
		if (millis > 0)
		{
			Thread.Sleep((int)Math.Min(millis, int.MaxValue));
		}
	}

	/// <summary>Run one HTTP request, projecting the result (or failure) to response JSON.</summary>
	private byte[] PerformHttp(byte[] requestJson)
	{
		try
		{
			HostRequest request = JsonSerializer.Deserialize<HostRequest>(requestJson, HostJson)
				?? throw new KeetaException("HOST", "empty host request");

			using var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Url);
			if (request.Body is not null)
			{
				message.Content = new ByteArrayContent(Convert.FromBase64String(request.Body));
				message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
			}

			message.Headers.Accept.ParseAdd("application/json");

			using HttpResponseMessage response = _http.Send(message);
			byte[] body = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
			string? retryAfter = response.Headers.TryGetValues("Retry-After", out IEnumerable<string>? values)
				? values.FirstOrDefault()
				: null;

			var payload = new HostResponse
			{
				Status = (ushort)(int)response.StatusCode,
				Body = Convert.ToBase64String(body),
				RetryAfter = retryAfter,
			};

			return JsonSerializer.SerializeToUtf8Bytes(payload, HostJson);
		}
		catch (Exception error)
		{
			var payload = new HostResponse { Error = error.Message };
			return JsonSerializer.SerializeToUtf8Bytes(payload, HostJson);
		}
	}

	// -----------------------------------------------------------------------
	// Memory marshaling
	// -----------------------------------------------------------------------

	/// <summary>Copy a UTF-8 string into a fresh guest buffer.</summary>
	private Argument Write(string value, List<Argument> owned)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(value);
		int pointer = _alloc(bytes.Length);
		if (bytes.Length > 0)
		{
			bytes.AsSpan().CopyTo(_memory.GetSpan(pointer, bytes.Length));
		}

		var argument = new Argument(pointer, bytes.Length);
		owned.Add(argument);
		return argument;
	}

	/// <summary>
	/// Resolve a bytes-handle result: <c>0</c> signals failure (raise the pending
	/// last error), otherwise copy the bytes out and release the handle.
	/// </summary>
	private byte[] TakeBytes(int handle)
	{
		if (handle == 0)
		{
			throw LastError();
		}

		return ReadAndFreeBytes(handle);
	}

	/// <summary>
	/// Resolve an object-handle result: <c>0</c> signals failure (raise the
	/// pending last error), otherwise return the live handle.
	/// </summary>
	private int TakeHandle(int handle) => handle != 0 ? handle : throw LastError();

	/// <summary>
	/// Resolve a tri-state predicate result (<c>1</c>/<c>0</c>/<c>-1</c>): a
	/// negative value signals failure (raise the pending last error).
	/// </summary>
	private bool TakeFlag(int result) => result < 0 ? throw LastError() : result != 0;

	/// <summary>Copy a bytes handle's payload into a managed array and free it.</summary>
	private byte[] ReadAndFreeBytes(int handle)
	{
		int pointer = _bytesPtr(handle);
		int length = _bytesLen(handle);
		byte[] data = length > 0 ? _memory.GetSpan(pointer, length).ToArray() : Array.Empty<byte>();
		_bytesFree(handle);
		return data;
	}

	/// <summary>Build an exception from the module's pending <c>code</c>/<c>message</c>.</summary>
	private KeetaException LastError()
	{
		string code = ReadErrorPart(_lastErrorCode());
		string message = ReadErrorPart(_lastErrorMessage());
		return new KeetaException(code.Length > 0 ? code : "UNKNOWN", message.Length > 0 ? message : "operation failed");
	}

	/// <summary>Read one optional last-error part (an empty string when absent).</summary>
	private string ReadErrorPart(int handle) =>
		handle == 0 ? string.Empty : Encoding.UTF8.GetString(ReadAndFreeBytes(handle));

	private void FreeAll(List<Argument> owned)
	{
		foreach (Argument argument in owned)
		{
			_dealloc(argument.Pointer, argument.Length);
		}
	}

	private static T Required<T>(string name, T? value) where T : class =>
		value ?? throw new KeetaException("WASM", $"module export `{name}` not found");

	public void Dispose()
	{
		_http.Dispose();
		_store.Dispose();
		_linker.Dispose();
		_module.Dispose();
		_engine.Dispose();
	}

	/// <summary>A guest buffer the host owns until it frees it.</summary>
	private readonly record struct Argument(int Pointer, int Length);

	private sealed class HostRequest
	{
		public string Method { get; set; } = "GET";
		public string Url { get; set; } = "";
		public string? Body { get; set; }
	}

	private sealed class HostResponse
	{
		public ushort Status { get; set; }
		public string Body { get; set; } = "";
		public string? RetryAfter { get; set; }
		public string? Error { get; set; }
	}
}

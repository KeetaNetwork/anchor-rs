using System.Text.Json.Serialization;

namespace KeetaNet.Anchor.Kyc;

/// <summary>The KYC operation endpoint templates a provider advertises.</summary>
public sealed record KycOperations(
	string? CreateVerification,
	string? GetCertificates,
	string? GetVerificationStatus,
	string? CheckLocality,
	string? GetEstimate);

/// <summary>A KYC provider discovered from on-chain service metadata.</summary>
/// <remarks><see cref="CountryCodes"/> is null for a worldwide provider.</remarks>
public sealed record KycProvider(
	string Id,
	string Ca,
	KycOperations Operations,
	IReadOnlyList<string>? CountryCodes);

/// <summary>
/// The cost a provider expects to charge for a verification: a <see cref="Token"/>
/// and the <see cref="Min"/>/<see cref="Max"/> bounds, decimal strings in that token's units.
/// </summary>
public sealed record ExpectedCost(string Min, string Max, string Token);

/// <summary>An in-progress verification, the URL where the user completes it, and its expected cost.</summary>
public sealed record Verification(string Id, string WebUrl, ExpectedCost ExpectedCost);

/// <summary>
/// The provider-reported status of a verification, and whether the provider
/// requires a manual review to complete (null when not reported).
/// </summary>
public sealed record VerificationStatus(string Status, bool? RequiresManualVerification = null);

/// <summary>One issued, PEM-encoded certificate and the intermediates bridging it to a trust root.</summary>
public sealed record Certificate(
	[property: JsonPropertyName("certificate")] string Value,
	IReadOnlyList<string> Intermediates);

/// <summary>The certificates issued for a verification.</summary>
public sealed record Certificates(IReadOnlyList<Certificate> Results);

/// <summary>
/// A result the provider may report as pending: either <see cref="Ready"/> with a
/// value, or <see cref="RetryAfterMs"/> milliseconds before retrying.
/// </summary>
public sealed record VerificationOutcome(Verification? Ready, uint? RetryAfterMs);

/// <summary>A status result, ready or retry-after-millis.</summary>
public sealed record StatusOutcome(VerificationStatus? Ready, uint? RetryAfterMs);

/// <summary>A certificates result, ready or retry-after-millis.</summary>
public sealed record CertificatesOutcome(Certificates? Ready, uint? RetryAfterMs);

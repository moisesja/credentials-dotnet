namespace Credentials.Verification;

/// <summary>Per-call options for credential verification. Unset members fall back to engine defaults.</summary>
public sealed record CredentialVerificationOptions
{
    /// <summary>The instant to evaluate the validity window and proof <c>expires</c> against. Defaults to now.</summary>
    public DateTimeOffset? VerificationTime { get; init; }

    /// <summary>Tolerance applied to validity-window checks to absorb clock skew. Default: 2 minutes.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// The proof purpose the proof is required to declare. Defaults to <c>assertionMethod</c> when not
    /// set (the purpose under which a credential is issued).
    /// </summary>
    public string? ExpectedProofPurpose { get; init; }

    /// <summary>Whether to accept VCDM 1.1 credentials on the verification path (D8). Default: <see langword="true"/>.</summary>
    public bool AcceptVcdm11 { get; init; } = true;

    /// <summary>The decision-composition policy. Defaults to fail-closed.</summary>
    public VerificationPolicy Policy { get; init; } = new();
}

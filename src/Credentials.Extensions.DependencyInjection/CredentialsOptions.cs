namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Engine-wide defaults for credential verification, configured via
/// <see cref="CredentialsBuilder.Configure"/>. Per-call options (set on a specific verify request)
/// override these.
/// </summary>
public sealed class CredentialsOptions
{
    /// <summary>
    /// The tolerance applied to validity-window checks (<c>validFrom</c> / <c>validUntil</c>) to absorb
    /// small clock differences between issuer, holder, and verifier. Default: 2 minutes.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Whether the verifier accepts VCDM 1.1 credentials (issuance is always VCDM 2.0 only — D8).
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool AcceptVcdm11 { get; set; } = true;
}

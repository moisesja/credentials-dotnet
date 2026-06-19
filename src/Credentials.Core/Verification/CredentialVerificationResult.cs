namespace Credentials.Verification;

/// <summary>
/// The structured outcome of verifying a credential (FR-043): an overall <see cref="Decision"/> plus
/// the per-check results, the detected <see cref="Version"/>, and the securing <see cref="Mechanism"/>.
/// Effectively immutable and safe to share across threads (NFR-003). Verification is side-effect free
/// and reports failures here rather than throwing (FR-045).
/// </summary>
public sealed class CredentialVerificationResult
{
    internal CredentialVerificationResult(
        VerificationDecision decision,
        IReadOnlyList<CheckResult> checks,
        VcdmVersion version,
        SecuringState mechanism)
    {
        Decision = decision;
        Checks = checks;
        Version = version;
        Mechanism = mechanism;
    }

    /// <summary>The overall decision.</summary>
    public VerificationDecision Decision { get; }

    /// <summary>True if the decision is <see cref="VerificationDecision.Accepted"/>.</summary>
    public bool IsAccepted => Decision == VerificationDecision.Accepted;

    /// <summary>The per-check results, in evaluation order.</summary>
    public IReadOnlyList<CheckResult> Checks { get; }

    /// <summary>The detected VCDM version of the verified credential.</summary>
    public VcdmVersion Version { get; }

    /// <summary>The securing mechanism the credential used.</summary>
    public SecuringState Mechanism { get; }

    /// <summary>Returns the result for a given check kind (see <see cref="CheckKinds"/>), or <see langword="null"/>.</summary>
    public CheckResult? Check(string kind) => Checks.FirstOrDefault(c => c.Kind == kind);

    /// <summary>A one-line, secret-free summary suitable for logging.</summary>
    public override string ToString()
    {
        var summary = string.Join(", ", Checks.Select(c => $"{c.Kind}={c.Status}"));
        return $"{Decision} [{summary}]";
    }
}

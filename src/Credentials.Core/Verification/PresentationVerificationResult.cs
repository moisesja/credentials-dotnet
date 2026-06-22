namespace Credentials.Verification;

/// <summary>
/// The structured outcome of verifying a Verifiable Presentation (FR-041): an overall
/// <see cref="Decision"/>, the holder-binding and structure checks, and a per-contained-credential
/// verification result. A presentation is only <see cref="VerificationDecision.Accepted"/> when its
/// holder binding (when required), its structure, and every contained credential are accepted.
/// Effectively immutable; side-effect free (FR-045).
/// </summary>
public sealed class PresentationVerificationResult
{
    internal PresentationVerificationResult(
        VerificationDecision decision,
        IReadOnlyList<CheckResult> checks,
        IReadOnlyList<CredentialVerificationResult> credentials,
        VcdmVersion version,
        SecuringState mechanism)
    {
        Decision = decision;
        Checks = checks;
        Credentials = credentials;
        Version = version;
        Mechanism = mechanism;
    }

    /// <summary>The overall decision.</summary>
    public VerificationDecision Decision { get; }

    /// <summary>True if the decision is <see cref="VerificationDecision.Accepted"/>.</summary>
    public bool IsAccepted => Decision == VerificationDecision.Accepted;

    /// <summary>The presentation-level checks (holder binding, structure), in evaluation order.</summary>
    public IReadOnlyList<CheckResult> Checks { get; }

    /// <summary>The verification result of each contained credential, in presentation order.</summary>
    public IReadOnlyList<CredentialVerificationResult> Credentials { get; }

    /// <summary>The detected VCDM version of the presentation.</summary>
    public VcdmVersion Version { get; }

    /// <summary>The securing mechanism the presentation binding used.</summary>
    public SecuringState Mechanism { get; }

    /// <summary>Returns the presentation-level result for a given check kind (see <see cref="CheckKinds"/>), or <see langword="null"/>.</summary>
    public CheckResult? Check(string kind) => Checks.FirstOrDefault(c => c.Kind == kind);

    /// <summary>A one-line, secret-free summary suitable for logging.</summary>
    public override string ToString()
    {
        var summary = string.Join(", ", Checks.Select(c => $"{c.Kind}={c.Status}"));
        return $"{Decision} [{summary}, credentials={Credentials.Count}]";
    }
}

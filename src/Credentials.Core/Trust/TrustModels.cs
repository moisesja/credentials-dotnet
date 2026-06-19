using System.Text.Json;
using Credentials.Verification;

namespace Credentials.Trust;

/// <summary>
/// The context handed to an <see cref="IIssuerTrustPolicy"/>. Carries only identity material — the
/// proof-verified issuer, the verification method(s) the proof actually used (so a policy may pin a key),
/// the credential's types, securing mechanism, and id — never credential claims or key material (NFR-008).
/// </summary>
public sealed class IssuerTrustContext
{
    /// <summary>Creates an issuer-trust context.</summary>
    public IssuerTrustContext(
        string issuerId,
        IReadOnlyList<string> credentialTypes,
        IReadOnlyList<string> verificationMethods,
        SecuringState mechanism,
        string? credentialId,
        DateTimeOffset evaluatedAt,
        JsonElement document)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuerId);
        IssuerId = issuerId;
        CredentialTypes = credentialTypes ?? [];
        VerificationMethods = verificationMethods ?? [];
        Mechanism = mechanism;
        CredentialId = credentialId;
        EvaluatedAt = evaluatedAt;
        Document = document;
    }

    /// <summary>The issuer identifier the proof authenticated (the base DID of the proof's verification method).</summary>
    public string IssuerId { get; }

    /// <summary>The credential's <c>type</c> values.</summary>
    public IReadOnlyList<string> CredentialTypes { get; }

    /// <summary>The proof-verified verification-method identifiers (DID URLs) the signatures used.</summary>
    public IReadOnlyList<string> VerificationMethods { get; }

    /// <summary>The securing mechanism the credential used.</summary>
    public SecuringState Mechanism { get; }

    /// <summary>The credential <c>id</c>, if present.</summary>
    public string? CredentialId { get; }

    /// <summary>When the trust evaluation is taking place.</summary>
    public DateTimeOffset EvaluatedAt { get; }

    /// <summary>A read-only view of the credential document (for policies that inspect more than the basics).</summary>
    public JsonElement Document { get; }
}

/// <summary>An issuer-trust decision.</summary>
public enum IssuerTrustDecision
{
    /// <summary>The issuer is trusted.</summary>
    Trusted,

    /// <summary>The issuer is explicitly not trusted (a definitive negative ⇒ the credential is rejected).</summary>
    Untrusted,

    /// <summary>Trust could not be determined.</summary>
    Indeterminate,
}

/// <summary>The structured result of an <see cref="IIssuerTrustPolicy"/> evaluation: a decision plus reason.</summary>
public sealed record IssuerTrustResult
{
    private IssuerTrustResult(IssuerTrustDecision decision, string reasonCode, string reason, IReadOnlyList<CheckDiagnostic> diagnostics)
    {
        Decision = decision;
        ReasonCode = reasonCode;
        Reason = reason;
        Diagnostics = diagnostics;
    }

    /// <summary>The trust decision.</summary>
    public IssuerTrustDecision Decision { get; }

    /// <summary>A short, stable reason code.</summary>
    public string ReasonCode { get; }

    /// <summary>A human-readable reason.</summary>
    public string Reason { get; }

    /// <summary>Optional secret-free diagnostics.</summary>
    public IReadOnlyList<CheckDiagnostic> Diagnostics { get; }

    /// <summary>A trusted result.</summary>
    public static IssuerTrustResult Trusted(string reasonCode = "trusted", string reason = "The issuer is trusted.") =>
        new(IssuerTrustDecision.Trusted, reasonCode, reason, []);

    /// <summary>An untrusted result (⇒ the credential is rejected).</summary>
    public static IssuerTrustResult Untrusted(string reasonCode, string reason) =>
        new(IssuerTrustDecision.Untrusted, reasonCode, reason, [new CheckDiagnostic(reasonCode, reason, DiagnosticSeverity.Error)]);

    /// <summary>An indeterminate result.</summary>
    public static IssuerTrustResult Indeterminate(string reasonCode, string reason) =>
        new(IssuerTrustDecision.Indeterminate, reasonCode, reason, [new CheckDiagnostic(reasonCode, reason, DiagnosticSeverity.Error)]);
}

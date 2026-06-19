using System.Text.Json;
using NetCrypto;

namespace Credentials.Securing;

/// <summary>The neutral outcome status of a securing-mechanism verification.</summary>
internal enum SecuringVerificationStatus
{
    /// <summary>The proof is present and cryptographically valid.</summary>
    Verified,

    /// <summary>The proof is present but invalid (e.g. a bad signature) — a definitive negative.</summary>
    Invalid,

    /// <summary>A verification method could not be resolved, so validity is unknown.</summary>
    Unresolvable,

    /// <summary>No securing proof was found on the document.</summary>
    NoProof,
}

/// <summary>A neutral securing problem (mapped from the substrate, secret-free).</summary>
internal sealed record SecuringProblem(string Code, string? Message);

/// <summary>
/// The neutral result of a securing-mechanism verification (no substrate types leak out). On a
/// verified result, <see cref="VerificationMethods"/> carries the verification-method DID URLs whose
/// signatures were confirmed, so the verifier can bind their base DIDs to the credential's issuer.
/// These are the proof's own <c>verificationMethod</c> identifiers (the keys actually used), not any
/// resolver-supplied, attacker-spoofable <c>controller</c> field.
/// </summary>
internal sealed record SecuringVerificationResult(
    SecuringVerificationStatus Status,
    IReadOnlyList<SecuringProblem> Problems,
    IReadOnlyList<string> VerificationMethods)
{
    public static SecuringVerificationResult NoProof { get; } =
        new(SecuringVerificationStatus.NoProof, [], []);

    public static SecuringVerificationResult Verified(IReadOnlyList<string> verificationMethods) =>
        new(SecuringVerificationStatus.Verified, [], verificationMethods);

    public static SecuringVerificationResult Invalid(IReadOnlyList<SecuringProblem> problems) =>
        new(SecuringVerificationStatus.Invalid, problems, []);

    public static SecuringVerificationResult Unresolvable(string code, string? message = null) =>
        new(SecuringVerificationStatus.Unresolvable, [new SecuringProblem(code, message)], []);
}

/// <summary>A neutral request to secure a document with a proof.</summary>
internal sealed record SecureRequest
{
    public required JsonElement Document { get; init; }
    public required string Cryptosuite { get; init; }
    public required ISigner Signer { get; init; }
    public required string VerificationMethod { get; init; }
    public required string ProofPurpose { get; init; }
    public DateTimeOffset? Created { get; init; }
}

/// <summary>The neutral outcome of securing a document: the secured document.</summary>
internal sealed record SecureOutcome(JsonElement SecuredDocument);

/// <summary>A neutral request to verify a secured document.</summary>
internal sealed record VerifyRequest
{
    public required JsonElement Document { get; init; }
    public string? ExpectedProofPurpose { get; init; }
    public DateTimeOffset? VerificationTime { get; init; }
}

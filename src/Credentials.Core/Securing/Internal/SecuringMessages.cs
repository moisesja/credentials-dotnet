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
/// resolver-supplied, attacker-spoofable <c>controller</c> field. For the enveloping forms the
/// identifier is the JWS/COSE <c>kid</c> the key was resolved under.
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

    public static SecuringVerificationResult Invalid(string code, string? message = null) =>
        new(SecuringVerificationStatus.Invalid, [new SecuringProblem(code, message)], []);

    public static SecuringVerificationResult Unresolvable(string code, string? message = null) =>
        new(SecuringVerificationStatus.Unresolvable, [new SecuringProblem(code, message)], []);
}

/// <summary>
/// A neutral request to secure a document with a proof. The <see cref="Document"/> drives the embedded
/// Data Integrity path (the pipeline strips/attaches <c>proof</c>); <see cref="Payload"/> carries the
/// exact UTF-8 bytes the enveloping (JOSE/COSE) forms sign verbatim. <see cref="Cryptosuite"/>,
/// <see cref="ProofPurpose"/> and <see cref="Created"/> are Data-Integrity-only.
/// </summary>
internal sealed record SecureRequest
{
    public required JsonElement Document { get; init; }
    public required ISigner Signer { get; init; }
    public required string VerificationMethod { get; init; }

    /// <summary>The exact UTF-8 payload bytes for the enveloping forms (signed verbatim, never re-serialized).</summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    /// <summary>The Data Integrity cryptosuite name. Null for the enveloping forms.</summary>
    public string? Cryptosuite { get; init; }

    /// <summary>The Data Integrity proof purpose.</summary>
    public string ProofPurpose { get; init; } = Credentials.ProofPurpose.AssertionMethod;

    /// <summary>The Data Integrity proof <c>created</c> timestamp.</summary>
    public DateTimeOffset? Created { get; init; }
}

/// <summary>
/// The neutral outcome of securing a document. Exactly one shape is populated per form: a secured JSON
/// <see cref="Document"/> (Data Integrity), a compact JWS string (<see cref="Jose"/>), or COSE_Sign1
/// bytes (<see cref="Cose"/>). No substrate type leaks out.
/// </summary>
internal sealed class SecureOutcome
{
    private readonly JsonElement _document;
    private readonly string? _jose;
    private readonly ReadOnlyMemory<byte> _cose;

    private SecureOutcome(SecuringForm form, JsonElement document, string? jose, ReadOnlyMemory<byte> cose)
    {
        Form = form;
        _document = document;
        _jose = jose;
        _cose = cose;
    }

    /// <summary>Which securing form produced this outcome.</summary>
    public SecuringForm Form { get; }

    /// <summary>The secured JSON document (Data Integrity).</summary>
    public JsonElement Document => _document;

    /// <summary>The compact JWS string (JOSE enveloping).</summary>
    public string Jose => _jose ?? throw new InvalidOperationException("This outcome is not a JOSE envelope.");

    /// <summary>The COSE_Sign1 bytes (COSE enveloping).</summary>
    public ReadOnlyMemory<byte> Cose => _cose;

    public static SecureOutcome ForDocument(JsonElement securedDocument) =>
        new(SecuringForm.DataIntegrity, securedDocument, null, default);

    public static SecureOutcome ForJose(string compactJws) =>
        new(SecuringForm.Jose, default, compactJws, default);

    public static SecureOutcome ForCose(ReadOnlyMemory<byte> coseBytes) =>
        new(SecuringForm.Cose, default, null, coseBytes);
}

/// <summary>
/// A neutral request to verify a secured document. <see cref="Document"/> is the JSON document for the
/// embedded Data Integrity path; <see cref="Envelope"/> carries the verbatim secured wire bytes (the
/// compact JWS as UTF-8, or the COSE_Sign1 bytes) for the enveloping forms.
/// </summary>
internal sealed record VerifyRequest
{
    public required JsonElement Document { get; init; }

    /// <summary>The verbatim secured wire bytes for the enveloping forms.</summary>
    public ReadOnlyMemory<byte>? Envelope { get; init; }

    /// <summary>
    /// For the enveloping forms, the exact inner-credential bytes the downstream verification stages
    /// will validate. The mechanism asserts the substrate-verified payload equals these bytes, so the
    /// credential whose claims are checked is provably the one the signature covers — independent of how
    /// the substrate decodes the payload internally (defence in depth for sign-exact-bytes).
    /// </summary>
    public ReadOnlyMemory<byte>? ExpectedPayload { get; init; }

    public string? ExpectedProofPurpose { get; init; }
    public DateTimeOffset? VerificationTime { get; init; }
}

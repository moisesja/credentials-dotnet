using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Roles;
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

/// <summary>Whether a securing operation targets a credential or a presentation (selects the JOSE <c>typ</c>: <c>vc+jwt</c> vs <c>vp+jwt</c>).</summary>
internal enum SecuringDocumentKind
{
    Credential,
    Presentation,
}

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
/// <para>
/// <b>Invariant — the two representations are NOT interchangeable.</b> For the enveloping forms (JOSE/COSE)
/// <see cref="Payload"/> is the <em>sole</em> authority for the signed bytes; <see cref="Document"/> is
/// ignored on that path (it is still <c>required</c> only because the embedded path needs it). When a caller
/// mutates the bytes before signing — e.g. the holder injecting a presentation <c>nonce</c>/<c>aud</c> for
/// replay defence (F1) — it MUST apply the mutation to <see cref="Payload"/>, and <see cref="Document"/> and
/// <see cref="Payload"/> may then legitimately diverge. An enveloping mechanism reading <see cref="Document"/>
/// instead of <see cref="Payload"/> would silently sign the wrong (e.g. freshness-stripped) bytes; the
/// enveloping mechanisms therefore assert <see cref="Payload"/> is non-empty so that footgun fails loudly.
/// </para>
/// </summary>
internal sealed record SecureRequest
{
    public required JsonElement Document { get; init; }
    public required ISigner Signer { get; init; }
    public required string VerificationMethod { get; init; }

    /// <summary>
    /// The exact UTF-8 payload bytes for the enveloping forms (signed verbatim, never re-serialized).
    /// Required and authoritative for JOSE/COSE; ignored by the embedded Data Integrity form (which signs
    /// <see cref="Document"/>).
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    /// <summary>The Data Integrity cryptosuite name. Null for the enveloping forms.</summary>
    public string? Cryptosuite { get; init; }

    /// <summary>The Data Integrity proof purpose.</summary>
    public string ProofPurpose { get; init; } = Credentials.ProofPurpose.AssertionMethod;

    /// <summary>The Data Integrity proof <c>created</c> timestamp.</summary>
    public DateTimeOffset? Created { get; init; }

    /// <summary>Whether this secures a credential or a presentation — selects the JOSE <c>typ</c> (<c>vc+jwt</c> vs <c>vp+jwt</c>).</summary>
    public SecuringDocumentKind Kind { get; init; } = SecuringDocumentKind.Credential;

    /// <summary>The Data Integrity proof <c>challenge</c> (presentation authentication binding).</summary>
    public string? Challenge { get; init; }

    /// <summary>The Data Integrity proof <c>domain</c> (presentation authentication binding).</summary>
    public string? Domain { get; init; }

    // ---- SD-JWT VC only (FR-013); null/ignored by the other forms. ----

    /// <summary>The SD-JWT VC claims set (the VCDM document clone the issuer hands to the SD-JWT mechanism).</summary>
    public JsonObject? Claims { get; init; }

    /// <summary>The SD-JWT VC type claim (<c>vct</c>).</summary>
    public string? Vct { get; init; }

    /// <summary>The claims to mark selectively disclosable.</summary>
    public IReadOnlyList<DisclosureSelector>? Disclosable { get; init; }

    /// <summary>The holder confirmation key (<c>cnf</c>), or null for no holder binding.</summary>
    public HolderBindingKey? HolderBinding { get; init; }

    /// <summary>The SD-JWT disclosure-digest hash algorithm.</summary>
    public SdHashName? SdHash { get; init; }

    /// <summary>The number of decoy digests to add.</summary>
    public int DecoyDigestCount { get; init; }
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
    private readonly string? _sdJwt;

    private SecureOutcome(SecuringForm form, JsonElement document, string? jose, ReadOnlyMemory<byte> cose, string? sdJwt)
    {
        Form = form;
        _document = document;
        _jose = jose;
        _cose = cose;
        _sdJwt = sdJwt;
    }

    /// <summary>Which securing form produced this outcome.</summary>
    public SecuringForm Form { get; }

    /// <summary>The secured JSON document (Data Integrity).</summary>
    public JsonElement Document => Form == SecuringForm.DataIntegrity
        ? _document
        : throw new InvalidOperationException("This outcome is not a Data Integrity document.");

    /// <summary>The compact JWS string (JOSE enveloping).</summary>
    public string Jose => _jose ?? throw new InvalidOperationException("This outcome is not a JOSE envelope.");

    /// <summary>The COSE_Sign1 bytes (COSE enveloping).</summary>
    public ReadOnlyMemory<byte> Cose => Form == SecuringForm.Cose
        ? _cose
        : throw new InvalidOperationException("This outcome is not a COSE envelope.");

    /// <summary>The compact SD-JWT VC serialization (SD-JWT VC).</summary>
    public string SdJwt => _sdJwt ?? throw new InvalidOperationException("This outcome is not an SD-JWT VC.");

    public static SecureOutcome ForDocument(JsonElement securedDocument) =>
        new(SecuringForm.DataIntegrity, securedDocument, null, default, null);

    public static SecureOutcome ForJose(string compactJws) =>
        new(SecuringForm.Jose, default, compactJws, default, null);

    public static SecureOutcome ForCose(ReadOnlyMemory<byte> coseBytes) =>
        new(SecuringForm.Cose, default, null, coseBytes, null);

    public static SecureOutcome ForSdJwt(string compactSdJwt) =>
        new(SecuringForm.SdJwtVc, default, null, default, compactSdJwt);
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

    // ---- Holder binding (SD-JWT VC Key Binding JWT; Data Integrity / JOSE presentation binding). ----

    /// <summary>Require a holder binding (KB-JWT for SD-JWT VC) to be present and valid.</summary>
    public bool RequireHolderBinding { get; init; }

    /// <summary>The expected holder-binding audience (KB-JWT <c>aud</c>) / presentation audience.</summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>The expected holder-binding nonce (KB-JWT <c>nonce</c>) / presentation nonce.</summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>The maximum holder-binding age (KB-JWT <c>iat</c> freshness); <see langword="null"/> disables it.</summary>
    public TimeSpan? MaxHolderBindingAge { get; init; }

    /// <summary>The expected Data Integrity proof <c>challenge</c> (VP authentication binding).</summary>
    public string? ExpectedChallenge { get; init; }

    /// <summary>The expected Data Integrity proof <c>domain</c> (VP authentication binding).</summary>
    public string? ExpectedDomain { get; init; }

    /// <summary>Whether this verifies a credential or a presentation — selects the JOSE <c>typ</c> expected (<c>vc+jwt</c> vs <c>vp+jwt</c>).</summary>
    public SecuringDocumentKind Kind { get; init; } = SecuringDocumentKind.Credential;
}

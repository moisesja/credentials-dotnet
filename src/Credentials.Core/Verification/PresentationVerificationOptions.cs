namespace Credentials.Verification;

/// <summary>
/// Per-call options for verifying a Verifiable Presentation (FR-041). Carries the holder-binding
/// expectations (audience / challenge / domain / nonce) and the per-contained-credential options.
/// </summary>
public sealed record PresentationVerificationOptions
{
    /// <summary>
    /// The options applied to each contained credential's verification. The presentation's
    /// <see cref="ExpectedAudience"/> / <see cref="ExpectedNonce"/> are additionally threaded into each
    /// SD-JWT VC child's Key Binding JWT check.
    /// </summary>
    public CredentialVerificationOptions CredentialOptions { get; init; } = new();

    /// <summary>
    /// Require the presentation to be bound to its holder key (proof of possession). Default:
    /// <see langword="true"/>. When <see langword="false"/>, an unbound presentation's holder-binding check
    /// is <see cref="CheckStatus.Skipped"/>; when <see langword="true"/>, an absent/invalid binding fails.
    /// </summary>
    /// <remarks>
    /// Deliberately defaults to <see langword="true"/>, unlike
    /// <see cref="CredentialVerificationOptions.RequireHolderBinding"/> (default <see langword="false"/>). The
    /// two are NOT the same knob: this one governs the <em>presentation's own</em> proof of possession (the
    /// whole point of a VP — a holder proving control to a verifier), whereas the credential-level flag
    /// governs a standalone credential's SD-JWT VC Key Binding JWT, which a bare issuer-signed credential need
    /// not carry. Per-contained-credential holder binding is additionally enabled whenever
    /// <see cref="ExpectedAudience"/> is supplied (see the verifier's contained-options derivation), so a
    /// verifier that names itself still enforces each child's KB-JWT without changing the credential-level default.
    /// <para>
    /// SCOPE OF HOLDER BINDING. A passing holder-binding check proves only <em>possession of the binding key</em>
    /// and <em>freshness</em> (the presentation's authentication proof verified and its challenge/domain matched
    /// the verifier's). It deliberately does <strong>not</strong> prove that the presenter is the
    /// <c>credentialSubject</c> of the contained credentials — the engine performs no holder↔subject linkage.
    /// A party who obtains a credential can present it in a presentation signed with their <em>own</em> key and
    /// the presentation composes to <see cref="VerificationDecision.Accepted"/>. Binding the presenter to the
    /// credential subject (and any holder-identity policy) is the verifying application's responsibility; do not
    /// read <see cref="VerificationDecision.Accepted"/> as "presented by the subject". (Per VCDM 2.0, <c>holder</c>
    /// itself is optional: a signed presentation with no <c>holder</c> still passes binding on possession alone.)
    /// </para>
    /// </remarks>
    public bool RequireHolderBinding { get; init; } = true;

    /// <summary>The challenge the Data Integrity authentication binding must declare (replay defence).</summary>
    public string? ExpectedChallenge { get; init; }

    /// <summary>The domain the Data Integrity authentication binding must declare.</summary>
    public string? ExpectedDomain { get; init; }

    /// <summary>The audience an SD-JWT VC child's Key Binding JWT (<c>aud</c>) must equal — the verifier's identifier.</summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>The nonce an SD-JWT VC child's Key Binding JWT (<c>nonce</c>) must equal.</summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// Require the presentation to contain at least one credential (FR-033). Default: <see langword="true"/>.
    /// When <see langword="true"/>, an empty/absent <c>verifiableCredential</c> is a structure failure — so
    /// an <see cref="VerificationDecision.Accepted"/> decision implies a credential was actually presented.
    /// </summary>
    public bool RequireAtLeastOneCredential { get; init; } = true;

    /// <summary>The instant to evaluate validity and freshness against. Defaults to now.</summary>
    public DateTimeOffset? VerificationTime { get; init; }

    /// <summary>The decision-composition policy. Defaults to fail-closed.</summary>
    public VerificationPolicy Policy { get; init; } = new();
}

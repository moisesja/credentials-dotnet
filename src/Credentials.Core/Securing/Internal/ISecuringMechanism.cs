namespace Credentials.Securing;

/// <summary>
/// A securing mechanism — the single internal adapter that maps a securing form (+ cryptosuite) to the
/// concrete substrate operations, and the <em>only</em> place its securing substrate is imported
/// (FR-050). Role services call through this seam and never touch a substrate type.
/// </summary>
internal interface ISecuringMechanism
{
    /// <summary>The securing form this mechanism implements.</summary>
    SecuringForm Form { get; }

    /// <summary>The cryptosuite names this mechanism supports (e.g. the Data Integrity suites); empty for the enveloping forms.</summary>
    IReadOnlyCollection<string> SuiteNames { get; }

    /// <summary>Whether this mechanism is usable in the current runtime (e.g. a native dependency is present).</summary>
    bool IsAvailable { get; }

    /// <summary>Secures a document, returning the secured document.</summary>
    Task<SecureOutcome> SecureAsync(SecureRequest request, CancellationToken cancellationToken);

    /// <summary>Verifies a secured document, returning a neutral tri-state result (never throws for an invalid proof).</summary>
    Task<SecuringVerificationResult> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Implemented by the enveloping mechanisms (JOSE/COSE): materializes the inner credential from a
/// secured envelope's bytes. The mechanism is the single place that decodes its substrate's envelope
/// (FR-050), so the verifier never imports a JOSE/COSE type to ingest enveloped input.
/// </summary>
internal interface IEnvelopeIngest
{
    /// <summary>
    /// Decodes the (unverified) inner credential from a secured envelope, returning a frozen
    /// <see cref="Credential"/> that retains the verbatim <paramref name="envelope"/> for the proof
    /// stage to verify. Throws <see cref="CredentialFormatException"/> if the envelope cannot be decoded.
    /// </summary>
    Credential Ingest(ReadOnlyMemory<byte> envelope);
}

/// <summary>
/// Implemented by the SD-JWT VC mechanism: produces a holder presentation of an issued SD-JWT VC,
/// revealing a chosen subset of disclosures and appending a Key Binding JWT bound to the verifier's
/// audience and nonce (FR-032). The mechanism is the single place the SD-JWT holder substrate is called.
/// </summary>
internal interface ISdJwtPresenter
{
    /// <summary>Builds an SD-JWT VC presentation (issuer-JWT~chosen disclosures~KB-JWT) for the request.</summary>
    /// <exception cref="CredentialFormatException">The issued SD-JWT is malformed.</exception>
    Task<string> PresentAsync(SdJwtPresentRequest request, CancellationToken cancellationToken);
}

/// <summary>A neutral request to present an issued SD-JWT VC with a Key Binding JWT.</summary>
internal sealed record SdJwtPresentRequest
{
    /// <summary>The full issued SD-JWT VC (carrying all disclosures).</summary>
    public required string IssuedCompact { get; init; }

    /// <summary>The claim names to reveal (their disclosures are kept; the rest are withheld).</summary>
    public required IReadOnlyList<string> DiscloseClaims { get; init; }

    /// <summary>The holder's signer (its public key must equal the issuer-set <c>cnf</c>).</summary>
    public required NetCrypto.ISigner HolderSigner { get; init; }

    /// <summary>The holder verification method (the KB-JWT <c>kid</c>).</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>The intended verifier (KB-JWT <c>aud</c>).</summary>
    public required string Audience { get; init; }

    /// <summary>The verifier-supplied freshness/replay nonce (KB-JWT <c>nonce</c>).</summary>
    public required string Nonce { get; init; }
}

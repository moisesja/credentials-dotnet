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

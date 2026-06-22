namespace Credentials.Roles;

/// <summary>
/// A credential a holder has received and holds (FR-030). It wraps the ingested, frozen
/// <see cref="Credentials.Credential"/> (with its detected securing form), ready to be inspected,
/// presented (SD-JWT VC), or placed into a <see cref="VerifiablePresentation"/>. Obtained from
/// <see cref="IHolder.Ingest"/>.
/// </summary>
public sealed class HeldCredential
{
    internal HeldCredential(Credential credential) =>
        Credential = credential ?? throw new ArgumentNullException(nameof(credential));

    /// <summary>The held credential.</summary>
    public Credential Credential { get; }

    /// <summary>How the held credential is secured.</summary>
    public SecuringState Securing => Credential.Securing;

    /// <summary>
    /// The verbatim compact serialization for a token-format credential (JOSE <c>vc+jwt</c> or SD-JWT VC),
    /// or <see langword="null"/> for a JSON-object / COSE credential. Used as the input to an SD-JWT VC
    /// presentation (which selects disclosures from, and re-emits, this exact token).
    /// </summary>
    public string? Compact => Credential.CompactEnvelope;
}

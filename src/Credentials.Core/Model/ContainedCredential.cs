namespace Credentials;

/// <summary>
/// A credential contained in a <see cref="VerifiablePresentation"/>'s <c>verifiableCredential</c>
/// member. It is either an <see cref="Embedded"/> JSON-object credential (structure-faithful) or an
/// <see cref="Enveloped"/> credential carried as a verbatim compact serialization (a JOSE or SD-JWT
/// token — kept byte-for-byte, since touching a signed ASCII token would break it).
/// </summary>
public sealed class ContainedCredential
{
    private readonly Credential? _embedded;
    private readonly string? _envelopedCompact;

    private ContainedCredential(Credential? embedded, string? envelopedCompact)
    {
        _embedded = embedded;
        _envelopedCompact = envelopedCompact;
    }

    /// <summary>Wraps an embedded JSON-object credential.</summary>
    public static ContainedCredential Embedded(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return new ContainedCredential(credential, null);
    }

    /// <summary>Wraps an enveloped credential carried as a verbatim compact serialization.</summary>
    public static ContainedCredential Enveloped(string compactSerialization)
    {
        ArgumentException.ThrowIfNullOrEmpty(compactSerialization);
        return new ContainedCredential(null, compactSerialization);
    }

    /// <summary>True if this is an embedded JSON-object credential.</summary>
    public bool IsEmbedded => _embedded is not null;

    /// <summary>The embedded credential, or <see langword="null"/> if this is an enveloped credential.</summary>
    public Credential? AsEmbedded => _embedded;

    /// <summary>The verbatim compact serialization, or <see langword="null"/> if this is an embedded credential.</summary>
    public string? AsEnvelopedCompact => _envelopedCompact;
}

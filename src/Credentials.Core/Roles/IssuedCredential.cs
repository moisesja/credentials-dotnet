namespace Credentials.Roles;

/// <summary>
/// The result of issuing (securing) a credential. <see cref="Credential"/> is always the secured
/// credential — an embedded Data Integrity credential, or an enveloped (JOSE/COSE) credential that
/// retains its verbatim envelope and can be re-verified directly. For the enveloping forms the raw wire
/// serialization is also exposed (<see cref="CompactJws"/> for JOSE, <see cref="CoseBytes"/> for COSE)
/// for transmission.
/// </summary>
public sealed class IssuedCredential
{
    private readonly string? _compactJws;
    private readonly ReadOnlyMemory<byte> _coseBytes;

    private IssuedCredential(
        SecuringState form,
        Credential credential,
        string mediaType,
        string? compactJws,
        ReadOnlyMemory<byte> coseBytes)
    {
        Form = form;
        Credential = credential;
        MediaType = mediaType;
        _compactJws = compactJws;
        _coseBytes = coseBytes;
    }

    /// <summary>The securing form of the issued credential.</summary>
    public SecuringState Form { get; }

    /// <summary>The secured credential (with its embedded proof, or carrying its enveloped serialization).</summary>
    public Credential Credential { get; }

    /// <summary>The media type of the issued credential.</summary>
    public string MediaType { get; }

    /// <summary>The compact JWS serialization for a JOSE-enveloped credential, or <see langword="null"/> otherwise.</summary>
    public string? CompactJws => _compactJws;

    /// <summary>The COSE_Sign1 bytes for a COSE-enveloped credential, or <see langword="null"/> otherwise.</summary>
    public ReadOnlyMemory<byte>? CoseBytes => Form == SecuringState.Cose ? _coseBytes : null;

    /// <summary>Creates an embedded Data Integrity issued-credential result.</summary>
    public static IssuedCredential DataIntegrity(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return new IssuedCredential(SecuringState.DataIntegrity, credential, "application/vc+ld+json", null, default);
    }

    /// <summary>Creates an enveloping VC-JOSE issued-credential result (media type <c>application/vc+jwt</c>).</summary>
    public static IssuedCredential Jose(Credential enveloped, string compactJws)
    {
        ArgumentNullException.ThrowIfNull(enveloped);
        ArgumentException.ThrowIfNullOrEmpty(compactJws);
        return new IssuedCredential(SecuringState.Jose, enveloped, "application/vc+jwt", compactJws, default);
    }

    /// <summary>Creates an enveloping VC-COSE issued-credential result (media type <c>application/vc+cose</c>).</summary>
    public static IssuedCredential Cose(Credential enveloped, ReadOnlyMemory<byte> coseBytes)
    {
        ArgumentNullException.ThrowIfNull(enveloped);
        return new IssuedCredential(SecuringState.Cose, enveloped, "application/vc+cose", null, coseBytes);
    }
}

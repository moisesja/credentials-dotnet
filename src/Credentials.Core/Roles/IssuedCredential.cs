namespace Credentials.Roles;

/// <summary>
/// The result of issuing (securing) a credential. In M1 this wraps the embedded Data Integrity
/// credential; later milestones add the enveloping (string/bytes) and SD-JWT VC payload shapes.
/// </summary>
public sealed class IssuedCredential
{
    private IssuedCredential(SecuringState form, Credential credential, string mediaType)
    {
        Form = form;
        Credential = credential;
        MediaType = mediaType;
    }

    /// <summary>The securing form of the issued credential.</summary>
    public SecuringState Form { get; }

    /// <summary>The secured credential (with its embedded proof).</summary>
    public Credential Credential { get; }

    /// <summary>The media type of the issued credential.</summary>
    public string MediaType { get; }

    /// <summary>Creates an embedded Data Integrity issued-credential result.</summary>
    public static IssuedCredential DataIntegrity(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return new IssuedCredential(SecuringState.DataIntegrity, credential, "application/vc+ld+json");
    }
}

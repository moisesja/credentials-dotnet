namespace Credentials.Validation;

/// <summary>Which VCDM document role a structural check is being run against.</summary>
public enum VcRole
{
    /// <summary>A Verifiable Credential.</summary>
    Credential,

    /// <summary>A Verifiable Presentation.</summary>
    Presentation,
}

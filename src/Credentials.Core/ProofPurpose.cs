namespace Credentials;

/// <summary>
/// The W3C proof-purpose values, exposed as credentials-dotnet constants so callers never reach for a
/// substrate type. A credential proof is normally issued for <see cref="AssertionMethod"/>.
/// </summary>
public static class ProofPurpose
{
    /// <summary>The issuer asserts the claims (the default purpose for a credential proof).</summary>
    public const string AssertionMethod = "assertionMethod";

    /// <summary>Authentication (e.g. a holder binding a presentation).</summary>
    public const string Authentication = "authentication";

    /// <summary>Invoking an authorization capability.</summary>
    public const string CapabilityInvocation = "capabilityInvocation";

    /// <summary>Delegating an authorization capability.</summary>
    public const string CapabilityDelegation = "capabilityDelegation";

    /// <summary>Key agreement.</summary>
    public const string KeyAgreement = "keyAgreement";
}

namespace Credentials.Verification;

/// <summary>
/// The stable string identifiers for the verification checks. Strings (not an enum) so the set is
/// additive — later milestones add checks without a breaking enum change.
/// </summary>
public static class CheckKinds
{
    /// <summary>The securing-proof check (Data Integrity / enveloping / SD-JWT VC signature).</summary>
    public const string Proof = "proof";

    /// <summary>VCDM structural conformance.</summary>
    public const string Structure = "structure";

    /// <summary>The validity window (<c>validFrom</c> / <c>validUntil</c>) against the verification time.</summary>
    public const string Validity = "validity";

    /// <summary>Credential status (e.g. Bitstring Status List). Evaluated from M2.</summary>
    public const string Status = "status";

    /// <summary>Credential schema validation. Evaluated from M2.</summary>
    public const string Schema = "schema";

    /// <summary>The caller-supplied issuer-trust policy. Evaluated when a policy is configured.</summary>
    public const string IssuerTrust = "issuerTrust";

    /// <summary>The presentation holder binding (proof of possession). Evaluated from M6.</summary>
    public const string HolderBinding = "holderBinding";
}

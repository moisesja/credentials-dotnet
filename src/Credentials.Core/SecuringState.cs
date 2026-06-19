namespace Credentials;

/// <summary>
/// How a <see cref="Credential"/> or <see cref="VerifiablePresentation"/> is secured — i.e. which
/// securing mechanism (if any) currently protects the document. An unsecured credential carries no
/// proof; the issuer's securing step transitions it to one of the secured states.
/// </summary>
public enum SecuringState
{
    /// <summary>No securing proof is present (a freshly built or proof-stripped credential).</summary>
    Unsecured,

    /// <summary>An embedded W3C Data Integrity proof lives inside the credential JSON (the <c>proof</c> member).</summary>
    DataIntegrity,

    /// <summary>An enveloping VC-JOSE proof — the credential is the payload of a JWS compact serialization.</summary>
    Jose,

    /// <summary>An enveloping VC-COSE proof — the credential is the payload of a COSE_Sign1 message.</summary>
    Cose,

    /// <summary>An SD-JWT VC (<c>application/dc+sd-jwt</c>) — a selectively disclosable token-format credential.</summary>
    SdJwtVc,
}

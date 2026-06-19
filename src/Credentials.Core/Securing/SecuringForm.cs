namespace Credentials;

/// <summary>
/// The family of securing mechanism used to protect a credential. M1 implements
/// <see cref="DataIntegrity"/>; the enveloping and SD-JWT VC forms arrive in later milestones.
/// </summary>
public enum SecuringForm
{
    /// <summary>Embedded W3C Data Integrity proof (an in-document <c>proof</c>).</summary>
    DataIntegrity,

    /// <summary>Enveloping VC-JOSE proof (JWS compact serialization). M3.</summary>
    Jose,

    /// <summary>Enveloping VC-COSE proof (COSE_Sign1). M3.</summary>
    Cose,

    /// <summary>SD-JWT VC token. M4.</summary>
    SdJwtVc,
}

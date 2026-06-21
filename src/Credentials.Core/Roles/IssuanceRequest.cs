using NetCrypto;

namespace Credentials.Roles;

/// <summary>
/// The base of a securing request handed to <see cref="IIssuer.IssueAsync"/>. Closed to this assembly
/// (only the built-in form requests derive from it), so the issuer can exhaustively handle each form.
/// </summary>
public abstract record IssuanceRequest
{
    private protected IssuanceRequest()
    {
    }
}

/// <summary>
/// Requests an embedded W3C Data Integrity proof (FR-011). The cryptosuite is an opaque string, so a
/// new suite surfaced by the proofs layer is selectable with no API change (FR-053). Signing goes
/// through the <see cref="Signer"/> abstraction — the engine never handles raw private keys (FR-015).
/// </summary>
public sealed record DataIntegrityIssuanceRequest : IssuanceRequest
{
    /// <summary>The Data Integrity cryptosuite name (e.g. <c>eddsa-jcs-2022</c>, <c>ecdsa-rdfc-2019</c>).</summary>
    public required string Cryptosuite { get; init; }

    /// <summary>The signer for the issuer key (a <c>NetCrypto.ISigner</c>; never raw key material).</summary>
    public required ISigner Signer { get; init; }

    /// <summary>The <c>verificationMethod</c> DID URL the proof references (e.g. <c>did:key:z6Mk…#z6Mk…</c>).</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>The proof purpose. Defaults to <see cref="ProofPurpose.AssertionMethod"/>.</summary>
    public string ProofPurpose { get; init; } = Credentials.ProofPurpose.AssertionMethod;

    /// <summary>The proof <c>created</c> timestamp. Defaults to the time of issuance when not set.</summary>
    public DateTimeOffset? Created { get; init; }
}

/// <summary>
/// Requests an enveloping VC-JOSE proof (FR-012): the credential's exact bytes are signed into a compact
/// JWS (<c>typ=vc+jwt</c>). The signature algorithm is derived from the signer's key type; the
/// <see cref="VerificationMethod"/> becomes the JWS <c>kid</c> the verifier binds the issuer to. Signing
/// goes through the <see cref="Signer"/> abstraction — the engine never handles raw private keys (FR-015).
/// </summary>
public sealed record JoseEnvelopeIssuanceRequest : IssuanceRequest
{
    /// <summary>The signer for the issuer key (a <c>NetCrypto.ISigner</c>; never raw key material).</summary>
    public required ISigner Signer { get; init; }

    /// <summary>The <c>verificationMethod</c> DID URL used as the JWS <c>kid</c> (e.g. <c>did:key:z6Mk…#z6Mk…</c>).</summary>
    public required string VerificationMethod { get; init; }
}

/// <summary>
/// Requests an enveloping VC-COSE proof (FR-012): the credential's exact bytes are signed into a tagged
/// COSE_Sign1 message (<c>typ=application/vc+cose</c>, <c>content-type=application/vc</c>). The COSE
/// algorithm is derived from the signer's key type (EdDSA / ES256 / ES384 / ES256K); the
/// <see cref="VerificationMethod"/> becomes the COSE <c>kid</c> the verifier binds the issuer to.
/// </summary>
public sealed record CoseEnvelopeIssuanceRequest : IssuanceRequest
{
    /// <summary>The signer for the issuer key (a <c>NetCrypto.ISigner</c>; never raw key material).</summary>
    public required ISigner Signer { get; init; }

    /// <summary>The <c>verificationMethod</c> DID URL used as the COSE <c>kid</c> (e.g. <c>did:key:z6Mk…#z6Mk…</c>).</summary>
    public required string VerificationMethod { get; init; }
}

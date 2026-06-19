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

using NetCrypto;

namespace Credentials.Roles;

/// <summary>
/// A holder's request to present an issued SD-JWT VC (FR-032): which claims to reveal, the holder's
/// signing key (for the Key Binding JWT), and the verifier's audience + nonce the binding is bound to.
/// The holder's signing key MUST be the one whose public key the issuer set as the credential's <c>cnf</c>
/// confirmation key at issuance — otherwise the Key Binding JWT will not verify.
/// </summary>
public sealed record SdJwtPresentationRequest
{
    /// <summary>
    /// The claim names to selectively reveal (their disclosures are kept; the rest are withheld). Empty
    /// reveals only the always-clear claims. Names not present as disclosable claims are ignored.
    /// </summary>
    public IReadOnlyList<string> DiscloseClaims { get; init; } = [];

    /// <summary>The holder's signer (a <c>NetCrypto.ISigner</c>; never raw key material). Its public key must equal the issuer-set <c>cnf</c>.</summary>
    public required ISigner HolderSigner { get; init; }

    /// <summary>The holder's verification method DID URL (the KB-JWT <c>kid</c>).</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>The intended verifier (the KB-JWT <c>aud</c>).</summary>
    public required string Audience { get; init; }

    /// <summary>The verifier-supplied freshness/replay nonce (the KB-JWT <c>nonce</c>).</summary>
    public required string Nonce { get; init; }
}

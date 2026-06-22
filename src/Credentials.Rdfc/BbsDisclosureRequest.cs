namespace Credentials.Rdfc;

/// <summary>
/// A holder's selective-disclosure request for a <c>bbs-2023</c> base credential (FR-031): the
/// RFC 6901 JSON Pointers to reveal <em>in addition to</em> the issuer's always-revealed mandatory
/// group. A draft-free type — no <c>DataProofsDotnet.Rdfc</c> / CBOR / dotNetRDF type appears here
/// (NFR-005); the engine translates it to a substrate derivation internally.
/// </summary>
public sealed record BbsDisclosureRequest
{
    /// <summary>
    /// The RFC 6901 JSON Pointers (e.g. <c>/credentialSubject/gpa</c>) to selectively reveal. The
    /// issuer's mandatory group (chosen at base-proof creation) is always revealed regardless of this
    /// list; an empty list reveals only the mandatory group. A pointer that does not address anything in
    /// the credential simply reveals nothing extra; a syntactically malformed pointer (no leading
    /// <c>/</c>, a <see langword="null"/> element, …) is rejected with a <c>CredentialFormatException</c>.
    /// Note that withholding a verification-critical claim the issuer left out of the mandatory group
    /// (e.g. <c>validUntil</c>, <c>credentialStatus</c>) is undetectable to a verifier — see
    /// <see cref="IBbsDeriver"/> for the issuer's mandatory-group obligation.
    /// </summary>
    public IReadOnlyList<string> RevealPointers { get; init; } = [];
}

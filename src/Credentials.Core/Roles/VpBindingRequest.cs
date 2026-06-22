using NetCrypto;

namespace Credentials.Roles;

/// <summary>
/// A holder's request to bind a <see cref="VerifiablePresentation"/> to its holder key (FR-034) — proof
/// of possession over the presentation. For Data Integrity binding the proof is an <c>authentication</c>
/// proof carrying <see cref="Challenge"/> / <see cref="Domain"/>; for JOSE binding the presentation is
/// signed into a compact <c>vp+jwt</c>. The holder signs through a <c>NetCrypto.ISigner</c> — never raw
/// key material — and the verifier binds the signing key's base DID to the presentation's <c>holder</c>.
/// </summary>
public sealed record VpBindingRequest
{
    /// <summary>The holder's signer (a <c>NetCrypto.ISigner</c>; never raw key material).</summary>
    public required ISigner HolderSigner { get; init; }

    /// <summary>The holder's <c>verificationMethod</c> DID URL (the proof VM / JWS <c>kid</c>).</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>The verifier-supplied challenge/nonce bound into a Data Integrity authentication proof (replay defence).</summary>
    public string? Challenge { get; init; }

    /// <summary>The verifier domain bound into a Data Integrity authentication proof.</summary>
    public string? Domain { get; init; }

    /// <summary>
    /// The Data Integrity cryptosuite for the binding proof (e.g. <c>eddsa-jcs-2022</c>). Ignored by JOSE
    /// binding, whose algorithm is derived from the signer's key type.
    /// </summary>
    public string Cryptosuite { get; init; } = "eddsa-jcs-2022";
}

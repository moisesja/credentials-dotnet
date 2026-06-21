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

/// <summary>
/// Requests an SD-JWT VC (FR-013, <c>application/dc+sd-jwt</c>): the credential's claims are issued as a
/// selectively disclosable SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-16, behind the stable surface — D12). The
/// VCDM 2.0 credential is carried as the SD-JWT VC claims set with the required <see cref="Vct"/> added in
/// the clear and an <c>iss</c> claim mirroring the credential issuer (the issuer-binding anchor); the
/// caller-chosen <see cref="Disclosable"/> claims are marked selectively disclosable. The signature
/// algorithm is derived from the signer's key type; the <see cref="VerificationMethod"/> becomes the
/// issuer-JWT <c>kid</c> the verifier binds the issuer to. No draft-version type appears here (FR-051).
/// </summary>
public sealed record SdJwtVcIssuanceRequest : IssuanceRequest
{
    /// <summary>The REQUIRED SD-JWT VC type claim (<c>vct</c>), a non-empty string kept in the clear.</summary>
    public required string Vct { get; init; }

    /// <summary>The signer for the issuer key (a <c>NetCrypto.ISigner</c>; never raw key material).</summary>
    public required ISigner Signer { get; init; }

    /// <summary>The <c>verificationMethod</c> DID URL used as the issuer-JWT <c>kid</c> (e.g. <c>did:key:z6Mk…#z6Mk…</c>).</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>
    /// Which credential claims to make selectively disclosable. May not target a VCDM structural member
    /// (<c>@context</c>, <c>type</c>, <c>issuer</c>, <c>id</c>, or <c>credentialSubject</c> as a whole);
    /// disclose <c>credentialSubject</c> sub-properties with <see cref="DisclosureSelector.ObjectProperties"/>.
    /// Empty means a non-selective SD-JWT VC (all claims in the clear).
    /// </summary>
    public IReadOnlyList<DisclosureSelector> Disclosable { get; init; } = [];

    /// <summary>
    /// The holder's public key to bind the credential to (the <c>cnf</c> confirmation key), enabling a
    /// later holder presentation to prove possession with a Key Binding JWT. <see langword="null"/> for an
    /// SD-JWT VC without holder binding.
    /// </summary>
    public HolderBindingKey? HolderBinding { get; init; }

    /// <summary>The disclosure-digest hash algorithm (the <c>_sd_alg</c>). Defaults to <see cref="SdHashName.Sha256"/>.</summary>
    public SdHashName SdHash { get; init; } = SdHashName.Sha256;

    /// <summary>
    /// The number of decoy digests to add (privacy: hides the true number of selectively disclosable
    /// claims). Defaults to 0. Must be non-negative.
    /// </summary>
    public int DecoyDigestCount { get; init; }
}

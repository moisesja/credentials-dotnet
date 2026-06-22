using Credentials;

namespace Credentials.Rdfc;

/// <summary>
/// Derives a minimally-disclosing <c>bbs-2023</c> credential from a held base credential (FR-031): a
/// holder-side, zero-knowledge selective disclosure that reveals the issuer's mandatory group plus the
/// holder's chosen claims, without any issuer interaction and without the holder ever seeing a private
/// key. The derived credential is an ordinary embedded Data Integrity credential (cryptosuite
/// <c>bbs-2023</c>) that verifies through the standard <see cref="Credentials.Roles.IVerifier"/> path.
///
/// <para>This is the focused selective-disclosure entry point; the broader holder role (ingest,
/// presentations, SD-JWT presentation) arrives with <c>IHolder</c> in a later milestone. The wire
/// mechanics (BBS derivation, the CBOR derived proof) are owned by <c>DataProofsDotnet</c> (FR-050);
/// no draft-version type appears on this surface (NFR-005). Available only when the opt-in
/// <c>UseBbs2023()</c> registration and the BBS native library are present.</para>
///
/// <para><b>Issuer contract — verification-critical claims MUST be mandatory.</b> A holder can withhold
/// any claim the issuer did <em>not</em> place in the base proof's mandatory group, and the BBS proof
/// stays valid over the reduced disclosure — the verifier cannot distinguish an issuer that never set a
/// claim from a holder that hid it. So a conformant <c>bbs-2023</c> issuer MUST put every claim a verifier
/// relies on — <c>issuer</c>, <c>@context</c>, <c>type</c>, <c>id</c>, <c>validFrom</c>, <c>validUntil</c>,
/// <c>credentialStatus</c>, <c>credentialSchema</c> — in the mandatory group (the same set this engine keeps
/// non-disclosable for SD-JWT VC). Otherwise a holder can derive away an expiry or a revocation reference
/// and the credential still verifies. This engine does not yet issue <c>bbs-2023</c> bases (issuance is
/// gated), so the mandatory-group choice is the third-party issuer's responsibility; this engine will
/// enforce it when bbs-2023 issuance ships. Mandatory claims, by contrast, cannot be dropped or altered —
/// that is cryptographically enforced.</para>
/// </summary>
public interface IBbsDeriver
{
    /// <summary>
    /// Derives a selectively-disclosed credential from <paramref name="baseCredential"/> (a credential
    /// secured with a <c>bbs-2023</c> base proof), revealing the mandatory group plus
    /// <see cref="BbsDisclosureRequest.RevealPointers"/>. Each call uses a fresh random presentation
    /// header, so repeated derivations of the same base are unlinkable.
    /// </summary>
    /// <param name="baseCredential">A credential carrying a <c>bbs-2023</c> base proof.</param>
    /// <param name="request">Which additional claims to reveal.</param>
    /// <param name="cancellationToken">Cancels the derivation.</param>
    /// <returns>The derived (minimally-disclosing) credential, ready to present.</returns>
    /// <exception cref="CredentialFormatException">The base credential is not a valid <c>bbs-2023</c> base, or the pointers are invalid.</exception>
    /// <exception cref="System.NotSupportedException">The BBS native library is unavailable on this host.</exception>
    Task<Credential> DeriveAsync(Credential baseCredential, BbsDisclosureRequest request, CancellationToken cancellationToken = default);
}

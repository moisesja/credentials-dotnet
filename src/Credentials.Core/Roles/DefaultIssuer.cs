using System.Text;
using Credentials.Securing;

namespace Credentials.Roles;

/// <summary>The default <see cref="IIssuer"/>: secures a credential through the securing seam.</summary>
internal sealed class DefaultIssuer : IIssuer
{
    private readonly SecuringMechanismRegistry _registry;

    public DefaultIssuer(SecuringMechanismRegistry registry) =>
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));

    public async Task<IssuedCredential> IssueAsync(
        Credential credential,
        IssuanceRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (credential.Securing != SecuringState.Unsecured)
        {
            throw new InvalidOperationException("The credential is already secured.");
        }

        // D8 / FR-044: this engine VERIFIES VCDM 1.1 but ISSUES VCDM 2.0 only. The builder always seals 2.0,
        // but a caller can hand us a parsed non-2.0 (or unknown-context) credential — reject it here, at the
        // role boundary, so the 2.0-only contract is enforced for every securing form (DI/JOSE/COSE/SD-JWT),
        // not merely assumed from how the document was constructed.
        if (credential.Version != VcdmVersion.V2_0)
        {
            throw new InvalidOperationException(
                "Issuance is VCDM 2.0 only (D8): this credential is not VCDM 2.0, so it cannot be issued. " +
                "VCDM 1.1 is supported on the verification path only.");
        }

        switch (request)
        {
            case DataIntegrityIssuanceRequest dataIntegrity:
            {
                var mechanism = _registry.ResolveForIssue(SecuringForm.DataIntegrity, dataIntegrity.Cryptosuite);
                var secureRequest = new SecureRequest
                {
                    Document = credential.AsElement(),
                    Cryptosuite = dataIntegrity.Cryptosuite,
                    Signer = dataIntegrity.Signer,
                    VerificationMethod = dataIntegrity.VerificationMethod,
                    ProofPurpose = dataIntegrity.ProofPurpose,
                    Created = dataIntegrity.Created,
                };

                var outcome = await mechanism.SecureAsync(secureRequest, cancellationToken).ConfigureAwait(false);
                var securedDocument = CredentialDocument.FromElement(outcome.Document, DocumentOrigin.Built);
                var secured = Credential.FromDocument(securedDocument, SecuringState.DataIntegrity);
                return IssuedCredential.DataIntegrity(secured);
            }

            case JoseEnvelopeIssuanceRequest jose:
            {
                var mechanism = _registry.ResolveForIssue(SecuringForm.Jose, cryptosuite: null);
                var secureRequest = new SecureRequest
                {
                    Document = credential.AsElement(),
                    Payload = credential.AsUtf8(),
                    Signer = jose.Signer,
                    VerificationMethod = jose.VerificationMethod,
                };

                var outcome = await mechanism.SecureAsync(secureRequest, cancellationToken).ConfigureAwait(false);
                var enveloped = Credential.FromEnvelope(
                    credential.Document, SecuringState.Jose, Encoding.UTF8.GetBytes(outcome.Jose));
                return IssuedCredential.Jose(enveloped, outcome.Jose);
            }

            case CoseEnvelopeIssuanceRequest cose:
            {
                var mechanism = _registry.ResolveForIssue(SecuringForm.Cose, cryptosuite: null);
                var secureRequest = new SecureRequest
                {
                    Document = credential.AsElement(),
                    Payload = credential.AsUtf8(),
                    Signer = cose.Signer,
                    VerificationMethod = cose.VerificationMethod,
                };

                var outcome = await mechanism.SecureAsync(secureRequest, cancellationToken).ConfigureAwait(false);
                var coseBytes = outcome.Cose;
                var enveloped = Credential.FromEnvelope(credential.Document, SecuringState.Cose, coseBytes);
                return IssuedCredential.Cose(enveloped, coseBytes);
            }

            case SdJwtVcIssuanceRequest sdJwt:
            {
                var mechanism = _registry.ResolveForIssue(SecuringForm.SdJwtVc, cryptosuite: null);
                var secureRequest = new SecureRequest
                {
                    Document = credential.AsElement(),
                    Claims = credential.AsClaimsObject(),
                    Vct = sdJwt.Vct,
                    Disclosable = sdJwt.Disclosable,
                    HolderBinding = sdJwt.HolderBinding,
                    SdHash = sdJwt.SdHash,
                    DecoyDigestCount = sdJwt.DecoyDigestCount,
                    Signer = sdJwt.Signer,
                    VerificationMethod = sdJwt.VerificationMethod,
                };

                var outcome = await mechanism.SecureAsync(secureRequest, cancellationToken).ConfigureAwait(false);
                var enveloped = Credential.FromEnvelope(
                    credential.Document, SecuringState.SdJwtVc, Encoding.UTF8.GetBytes(outcome.SdJwt));
                return IssuedCredential.SdJwtVc(enveloped, outcome.SdJwt);
            }

            default:
                throw new NotSupportedException(
                    $"Issuance request '{request.GetType().Name}' is not supported in this milestone.");
        }
    }
}

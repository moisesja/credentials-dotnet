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

            default:
                throw new NotSupportedException(
                    $"Issuance request '{request.GetType().Name}' is not supported in this milestone.");
        }
    }
}

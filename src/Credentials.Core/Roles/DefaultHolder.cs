using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Securing;

namespace Credentials.Roles;

/// <summary>The default <see cref="IHolder"/>: ingests credentials and presents SD-JWT VCs through the securing seam.</summary>
internal sealed class DefaultHolder : IHolder
{
    private readonly SecuringMechanismRegistry _registry;

    public DefaultHolder(SecuringMechanismRegistry registry) =>
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));

    public HeldCredential Ingest(ReadOnlyMemory<byte> credentialWireBytes) =>
        new(EnvelopeIngest.Ingest(credentialWireBytes, _registry));

    public SdJwtInspection InspectSdJwt(HeldCredential held)
    {
        ArgumentNullException.ThrowIfNull(held);
        RequireSdJwt(held);

        return new SdJwtInspection
        {
            Vct = ReadString(held.Credential, "vct"),
            DisclosableClaims = SdJwtVcMechanism.DisclosableClaimNames(held.Compact!),
            SupportsHolderBinding = held.Credential.GetMember("cnf") is not null,
        };
    }

    public async Task<string> PresentSdJwtAsync(
        HeldCredential held, SdJwtPresentationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(held);
        ArgumentNullException.ThrowIfNull(request);
        RequireSdJwt(held);

        var presenter = _registry.GetMechanism(SecuringForm.SdJwtVc) as ISdJwtPresenter
            ?? throw new NotSupportedException("No SD-JWT VC securing mechanism is registered.");

        return await presenter.PresentAsync(
            new SdJwtPresentRequest
            {
                IssuedCompact = held.Compact!,
                DiscloseClaims = request.DiscloseClaims,
                HolderSigner = request.HolderSigner,
                VerificationMethod = request.VerificationMethod,
                Audience = request.Audience,
                Nonce = request.Nonce,
            },
            cancellationToken).ConfigureAwait(false);
    }

    public VerifiablePresentation BuildPresentation(VpAssemblyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var builder = VerifiablePresentation.Build();
        if (request.Holder is { Length: > 0 } holder)
        {
            builder.WithHolder(holder);
        }

        if (request.Id is { Length: > 0 } id)
        {
            builder.WithId(id);
        }

        foreach (var contained in request.Credentials)
        {
            if (contained.IsEmbedded)
            {
                builder.AddCredential(contained.AsEmbedded!);
            }
            else
            {
                builder.AddEnvelopedCredential(contained.AsEnvelopedCompact!);
            }
        }

        return builder.Seal();
    }

    public async Task<VerifiablePresentation> BindWithDataIntegrityAsync(
        VerifiablePresentation presentation, VpBindingRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(request);

        var mechanism = _registry.ResolveForIssue(SecuringForm.DataIntegrity, request.Cryptosuite);
        var outcome = await mechanism.SecureAsync(
            new SecureRequest
            {
                Document = presentation.AsElement(),
                Cryptosuite = request.Cryptosuite,
                Signer = request.HolderSigner,
                VerificationMethod = request.VerificationMethod,
                ProofPurpose = ProofPurpose.Authentication,
                Challenge = request.Challenge,
                Domain = request.Domain,
                Kind = SecuringDocumentKind.Presentation,
            },
            cancellationToken).ConfigureAwait(false);

        var securedDocument = CredentialDocument.FromElement(outcome.Document, DocumentOrigin.Built);
        return VerifiablePresentation.FromDocument(securedDocument, SecuringState.DataIntegrity);
    }

    public async Task<string> BindWithJoseEnvelopeAsync(
        VerifiablePresentation presentation, VpBindingRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(request);

        var mechanism = _registry.GetMechanism(SecuringForm.Jose)
            ?? throw new NotSupportedException("No JOSE securing mechanism is registered.");

        var outcome = await mechanism.SecureAsync(
            new SecureRequest
            {
                Document = presentation.AsElement(),
                Payload = presentation.AsUtf8(),
                Signer = request.HolderSigner,
                VerificationMethod = request.VerificationMethod,
                Kind = SecuringDocumentKind.Presentation,
            },
            cancellationToken).ConfigureAwait(false);

        return outcome.Jose;
    }

    private static void RequireSdJwt(HeldCredential held)
    {
        if (held.Securing != SecuringState.SdJwtVc || held.Compact is null)
        {
            throw new InvalidOperationException("The held credential is not an SD-JWT VC.");
        }
    }

    private static string? ReadString(Credential credential, string member) =>
        credential.GetMember(member) is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;
}

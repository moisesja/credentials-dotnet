using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetDid.Core;
using NetDid.Core.Model;

namespace Credentials.Resolution;

/// <summary>
/// Bridges NetDid resolution to the Data Integrity pipeline (FR-080): given a proof's
/// <c>verificationMethod</c> DID URL, it resolves the DID through NetDid, dereferences the
/// verification method, extracts its public key, and reports which verification relationships it
/// participates in. Returns <see langword="null"/> when the method cannot be resolved (which the
/// caller maps to an Indeterminate result, never a cryptographic failure).
/// </summary>
internal sealed class NetDidVerificationMethodResolver : IVerificationMethodResolver
{
    private static readonly (Func<DidDocument, IReadOnlyList<VerificationRelationshipEntry>?> Selector, string Purpose)[] Relationships =
    [
        (d => d.AssertionMethod, ProofPurpose.AssertionMethod),
        (d => d.Authentication, ProofPurpose.Authentication),
        (d => d.CapabilityInvocation, ProofPurpose.CapabilityInvocation),
        (d => d.CapabilityDelegation, ProofPurpose.CapabilityDelegation),
        (d => d.KeyAgreement, ProofPurpose.KeyAgreement),
    ];

    private readonly IDidResolver _didResolver;

    public NetDidVerificationMethodResolver(IDidResolver didResolver) =>
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));

    public async Task<ResolvedVerificationMethod?> ResolveAsync(
        string verificationMethodUrl,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(verificationMethodUrl))
        {
            return null;
        }

        var hashIndex = verificationMethodUrl.IndexOf('#');

        // The base DID is everything before the first '?' (query) or '#' (fragment) per DID Core.
        var cut = verificationMethodUrl.Length;
        var queryIndex = verificationMethodUrl.IndexOf('?');
        if (queryIndex >= 0)
        {
            cut = queryIndex;
        }

        if (hashIndex >= 0 && hashIndex < cut)
        {
            cut = hashIndex;
        }

        var baseDid = verificationMethodUrl[..cut];

        var resolution = await _didResolver.ResolveAsync(baseDid, options: null, cancellationToken).ConfigureAwait(false);
        if (resolution.DidDocument is null || resolution.ResolutionMetadata.Error is not null)
        {
            return null;
        }

        var document = resolution.DidDocument;
        var methods = document.VerificationMethod;
        if (methods is null || methods.Count == 0)
        {
            return null;
        }

        var method = hashIndex < 0
            ? methods[0]
            : methods.FirstOrDefault(m => string.Equals(m.Id, verificationMethodUrl, StringComparison.Ordinal));
        if (method is null)
        {
            return null;
        }

        PublicKeyMaterial publicKey;
        try
        {
            publicKey = method switch
            {
                { PublicKeyMultibase: { Length: > 0 } multibase } => PublicKeyMaterial.FromMultikey(multibase),
                { PublicKeyJwk: { } jwk } => PublicKeyMaterial.FromJsonWebKey(jwk),
                _ => throw new InvalidOperationException("The verification method has no public key material."),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }

        var controller = string.IsNullOrEmpty(method.Controller.Value) ? baseDid : method.Controller.Value;

        return new ResolvedVerificationMethod
        {
            Id = method.Id,
            Controller = controller,
            PublicKey = publicKey,
            Relationships = CollectRelationships(document, method.Id),
            ControllerControlsMethod = true,
        };
    }

    private static IReadOnlySet<string> CollectRelationships(DidDocument document, string methodId)
    {
        var purposes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (selector, purpose) in Relationships)
        {
            var entries = selector(document);
            if (entries is null)
            {
                continue;
            }

            foreach (var entry in entries)
            {
                var referencedId = entry.IsReference ? entry.Reference : entry.EmbeddedMethod?.Id;
                if (string.Equals(referencedId, methodId, StringComparison.Ordinal))
                {
                    purposes.Add(purpose);
                    break;
                }
            }
        }

        return purposes;
    }
}

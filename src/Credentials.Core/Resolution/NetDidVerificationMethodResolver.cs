using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetDid.Core;
using NetDid.Core.Model;

namespace Credentials.Resolution;

/// <summary>
/// Bridges NetDid resolution to the Data Integrity pipeline (FR-080): given a proof's
/// <c>verificationMethod</c> DID URL, it resolves the DID through NetDid, dereferences the
/// verification method, extracts its public key, and reports which verification relationships it
/// participates in. Returns a tri-state (<see cref="IVerificationMethodTriResolver"/>) so the caller can
/// honour F7: a DID that cannot be resolved at all is
/// <see cref="VerificationMethodResolutionStatus.DidUnresolvable"/> (→ Indeterminate), while a DID that
/// resolves but does not publish the referenced verification method (or whose key is unusable) is
/// <see cref="VerificationMethodResolutionStatus.MethodNotFound"/> (→ Failed) — the two must not be
/// conflated, or an attacker could mangle a tampered credential's fragment to downgrade a definitive
/// failure to Indeterminate. Mirrors <see cref="NetDidEnvelopeKeyResolver"/> for the enveloping forms.
/// </summary>
internal sealed class NetDidVerificationMethodResolver : IVerificationMethodTriResolver
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

    public async Task<VerificationMethodResolution> ResolveAsync(
        string verificationMethodUrl,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(verificationMethodUrl))
        {
            // An attacker-chosen empty/absent verification method authorizes no key — a definitive failure.
            return VerificationMethodResolution.MethodNotFound;
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
            // The DID itself could not be resolved (IO/network/unknown method) — unknown validity.
            return VerificationMethodResolution.DidUnresolvable;
        }

        // From here the DID resolved: a missing verification method / unusable key is a definitive failure
        // (the published key set does not authorize this verificationMethod), NOT an Indeterminate outcome.
        var document = resolution.DidDocument;
        var methods = document.VerificationMethod;
        if (methods is null || methods.Count == 0)
        {
            return VerificationMethodResolution.MethodNotFound;
        }

        var method = hashIndex < 0
            ? methods[0]
            : methods.FirstOrDefault(m => string.Equals(m.Id, verificationMethodUrl, StringComparison.Ordinal));
        if (method is null)
        {
            return VerificationMethodResolution.MethodNotFound;
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
            // The resolved VM's key material is malformed/unusable — a property of the published document,
            // so a definitive failure rather than an unknown-resolution outcome.
            return VerificationMethodResolution.MethodNotFound;
        }

        var controller = string.IsNullOrEmpty(method.Controller.Value) ? baseDid : method.Controller.Value;

        return VerificationMethodResolution.Resolved(new ResolvedVerificationMethod
        {
            Id = method.Id,
            Controller = controller,
            PublicKey = publicKey,
            Relationships = CollectRelationships(document, method.Id),
            ControllerControlsMethod = true,
        });
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

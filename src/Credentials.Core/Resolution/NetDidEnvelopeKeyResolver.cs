using DataProofsDotnet;
using NetDid.Core;

namespace Credentials.Resolution;

/// <summary>
/// Resolves an enveloping proof's <c>kid</c> through NetDid (FR-080): it dereferences the base DID,
/// finds the referenced verification method, and extracts its public key as neutral NetCrypto material
/// (<see cref="EnvelopeKey"/>). It mirrors <see cref="NetDidVerificationMethodResolver"/> but returns
/// substrate-free key material so the JOSE, COSE and SD-JWT VC mechanisms — which need a JWK and a raw
/// key respectively — all consume one DID resolution. The tri-state result keeps F7 honest: a DID that
/// fails to resolve is <see cref="EnvelopeKeyResolutionStatus.DidUnresolvable"/> (→ Indeterminate),
/// while a DID that resolves but does not publish the referenced verification method (e.g. an
/// attacker-mangled <c>kid</c> fragment over a still-resolvable base DID) is
/// <see cref="EnvelopeKeyResolutionStatus.MethodNotFound"/> (→ Failed) — a tampered/forged credential
/// can never be downgraded to Indeterminate by choosing a bogus fragment.
/// </summary>
internal sealed class NetDidEnvelopeKeyResolver : IEnvelopeKeyResolver
{
    private readonly IDidResolver _didResolver;

    public NetDidEnvelopeKeyResolver(IDidResolver didResolver) =>
        _didResolver = didResolver ?? throw new ArgumentNullException(nameof(didResolver));

    public async Task<EnvelopeKeyResolution> ResolveAsync(string kid, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(kid))
        {
            return EnvelopeKeyResolution.MethodNotFound;
        }

        var hashIndex = kid.IndexOf('#');

        // The base DID is everything before the first '?' (query) or '#' (fragment) per DID Core.
        var cut = kid.Length;
        var queryIndex = kid.IndexOf('?');
        if (queryIndex >= 0)
        {
            cut = queryIndex;
        }

        if (hashIndex >= 0 && hashIndex < cut)
        {
            cut = hashIndex;
        }

        var baseDid = kid[..cut];

        var resolution = await _didResolver.ResolveAsync(baseDid, options: null, cancellationToken).ConfigureAwait(false);
        if (resolution.DidDocument is null || resolution.ResolutionMetadata.Error is not null)
        {
            // The DID itself could not be resolved (IO/network/unknown method) — unknown validity.
            return EnvelopeKeyResolution.DidUnresolvable;
        }

        // From here the DID resolved: a missing verification method / unusable key is a definitive
        // failure (the published key set does not authorize this kid), NOT an Indeterminate outcome.
        var methods = resolution.DidDocument.VerificationMethod;
        if (methods is null || methods.Count == 0)
        {
            return EnvelopeKeyResolution.MethodNotFound;
        }

        // No fragment ⇒ the first method; otherwise the method whose id matches the full kid exactly.
        var method = hashIndex < 0
            ? methods[0]
            : methods.FirstOrDefault(m => string.Equals(m.Id, kid, StringComparison.Ordinal));
        if (method is null)
        {
            return EnvelopeKeyResolution.MethodNotFound;
        }

        try
        {
            var material = method switch
            {
                { PublicKeyMultibase: { Length: > 0 } multibase } => PublicKeyMaterial.FromMultikey(multibase),
                { PublicKeyJwk: { } jwk } => PublicKeyMaterial.FromJsonWebKey(jwk),
                _ => (PublicKeyMaterial?)null,
            };

            if (material is not { } pk)
            {
                return EnvelopeKeyResolution.MethodNotFound;
            }

            // Prefer the VM's own multibase; otherwise derive one so the JOSE path can build the JWK
            // via JwkConversion.FromMultikey (which handles EC point encoding).
            var multikey = method.PublicKeyMultibase is { Length: > 0 } existing ? existing : pk.ToMultikey();
            return EnvelopeKeyResolution.Resolved(new EnvelopeKey(pk.KeyType, pk.KeyBytes, multikey));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The resolved VM's key material is malformed/unusable — a property of the published document,
            // so a definitive failure rather than an unknown-resolution outcome.
            return EnvelopeKeyResolution.MethodNotFound;
        }
    }
}

using NetCrypto;

namespace Credentials.Resolution;

/// <summary>
/// Resolves an enveloping proof's <c>kid</c> (a verification-method DID URL) to the issuer's public
/// key material. JOSE verify wants a JWK while COSE verify wants a raw public key plus its
/// <see cref="KeyType"/> — both are derived from this one neutral, substrate-free result, so a single
/// DID resolution serves both enveloping forms (and the SD-JWT VC form). The tri-state
/// <see cref="EnvelopeKeyResolution"/> lets the caller honour F7: a DID that genuinely cannot be
/// resolved (IO/network/unknown method) is Indeterminate, while a DID that resolves but whose document
/// does not contain the referenced verification method is a definitive proof failure (the issuer's
/// published key set does not authorize that <c>kid</c>) — the two must not be conflated.
/// </summary>
internal interface IEnvelopeKeyResolver
{
    Task<EnvelopeKeyResolution> ResolveAsync(string kid, CancellationToken cancellationToken = default);
}

/// <summary>The outcome class of an <see cref="IEnvelopeKeyResolver"/> resolution.</summary>
internal enum EnvelopeKeyResolutionStatus
{
    /// <summary>The verification method was found and its public key extracted.</summary>
    Resolved,

    /// <summary>The DID could not be resolved at all (IO/network/unknown method) — unknown validity (→ Indeterminate).</summary>
    DidUnresolvable,

    /// <summary>
    /// The DID resolved but its document does not contain the referenced verification method (or its key
    /// is unusable) — a definitive negative (→ Failed): the published key set does not authorize this kid.
    /// </summary>
    MethodNotFound,
}

/// <summary>
/// The tri-state result of resolving an enveloping proof's <c>kid</c>. The <see cref="Key"/> is
/// meaningful only when <see cref="Status"/> is <see cref="EnvelopeKeyResolutionStatus.Resolved"/>.
/// </summary>
internal readonly record struct EnvelopeKeyResolution
{
    private EnvelopeKeyResolution(EnvelopeKeyResolutionStatus status, EnvelopeKey key)
    {
        Status = status;
        Key = key;
    }

    /// <summary>The resolution outcome class.</summary>
    public EnvelopeKeyResolutionStatus Status { get; }

    /// <summary>The resolved key material (only when <see cref="Status"/> is <see cref="EnvelopeKeyResolutionStatus.Resolved"/>).</summary>
    public EnvelopeKey Key { get; }

    /// <summary>A successful resolution carrying the verification method's public key.</summary>
    public static EnvelopeKeyResolution Resolved(EnvelopeKey key) => new(EnvelopeKeyResolutionStatus.Resolved, key);

    /// <summary>The DID could not be resolved (→ Indeterminate).</summary>
    public static EnvelopeKeyResolution DidUnresolvable { get; } = new(EnvelopeKeyResolutionStatus.DidUnresolvable, default);

    /// <summary>The DID resolved but the referenced verification method / usable key is absent (→ Failed).</summary>
    public static EnvelopeKeyResolution MethodNotFound { get; } = new(EnvelopeKeyResolutionStatus.MethodNotFound, default);
}

/// <summary>
/// The neutral public-key material for an enveloping verification: a NetCrypto <see cref="KeyType"/>,
/// the raw public-key bytes (consumed directly by COSE verify), and the multibase multikey form (used
/// to build the JOSE JWK so EC point encoding is handled by the substrate). Carries no JOSE/COSE type.
/// </summary>
internal readonly record struct EnvelopeKey(KeyType KeyType, ReadOnlyMemory<byte> PublicKey, string? Multibase);

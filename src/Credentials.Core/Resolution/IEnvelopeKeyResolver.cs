using NetCrypto;

namespace Credentials.Resolution;

/// <summary>
/// Resolves an enveloping proof's <c>kid</c> (a verification-method DID URL) to the issuer's public
/// key material. JOSE verify wants a JWK while COSE verify wants a raw public key plus its
/// <see cref="KeyType"/> — both are derived from this one neutral, substrate-free result, so a single
/// DID resolution serves both enveloping forms. Returns <see langword="null"/> when the method cannot
/// be resolved (which the caller maps to an Indeterminate result, never a cryptographic failure).
/// </summary>
internal interface IEnvelopeKeyResolver
{
    Task<EnvelopeKey?> ResolveAsync(string kid, CancellationToken cancellationToken = default);
}

/// <summary>
/// The neutral public-key material for an enveloping verification: a NetCrypto <see cref="KeyType"/>,
/// the raw public-key bytes (consumed directly by COSE verify), and the multibase multikey form (used
/// to build the JOSE JWK so EC point encoding is handled by the substrate). Carries no JOSE/COSE type.
/// </summary>
internal readonly record struct EnvelopeKey(KeyType KeyType, ReadOnlyMemory<byte> PublicKey, string? Multibase);

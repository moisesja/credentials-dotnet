namespace Credentials.Cryptography;

/// <summary>
/// The engine's cryptographically-secure randomness seam (FR-052). The engine generates salts,
/// nonces, and other random material for SD-JWT disclosures, BBS presentation headers, and
/// holder-binding challenges; every such draw goes through this single seam.
/// </summary>
/// <remarks>
/// The default implementation, <see cref="BclRandomSource"/>, wraps the BCL
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> because <c>NetCrypto</c> 1.1.0
/// exposes no public RNG abstraction. If <c>NetCrypto</c> later adds one, swap the default here with
/// no change to callers.
/// </remarks>
public interface IRandomSource
{
    /// <summary>Fills <paramref name="destination"/> with cryptographically-secure random bytes.</summary>
    void Fill(Span<byte> destination);

    /// <summary>Returns <paramref name="count"/> cryptographically-secure random bytes.</summary>
    byte[] GetBytes(int count);
}

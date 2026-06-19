namespace Credentials.Cryptography;

/// <summary>
/// The engine's hashing seam (FR-052). The credentials engine performs some cryptographic
/// operations itself — for example SD-JWT disclosure digests, status-list integrity checks, and
/// <c>digestSRI</c> verification — and routes all of them through this single seam so the underlying
/// primitive comes from <c>NetCrypto</c> rather than being hand-rolled. The default implementation is
/// <see cref="NetCryptoDigestService"/>.
/// </summary>
public interface IDigestService
{
    /// <summary>Computes the SHA-256 digest of <paramref name="data"/> (32 bytes).</summary>
    byte[] Sha256(ReadOnlySpan<byte> data);

    /// <summary>Computes the SHA-384 digest of <paramref name="data"/> (48 bytes).</summary>
    byte[] Sha384(ReadOnlySpan<byte> data);

    /// <summary>Computes the SHA-512 digest of <paramref name="data"/> (64 bytes).</summary>
    byte[] Sha512(ReadOnlySpan<byte> data);
}

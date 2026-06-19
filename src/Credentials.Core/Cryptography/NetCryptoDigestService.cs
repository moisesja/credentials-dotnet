namespace Credentials.Cryptography;

/// <summary>
/// The default <see cref="IDigestService"/>: a thin, stateless, thread-safe adapter over
/// <c>NetCrypto.Hash</c>, satisfying FR-052 (engine digests come from <c>NetCrypto</c>, not the BCL
/// directly and never hand-rolled).
/// </summary>
public sealed class NetCryptoDigestService : IDigestService
{
    /// <inheritdoc />
    public byte[] Sha256(ReadOnlySpan<byte> data) => global::NetCrypto.Hash.Sha256(data);

    /// <inheritdoc />
    public byte[] Sha384(ReadOnlySpan<byte> data) => global::NetCrypto.Hash.Sha384(data);

    /// <inheritdoc />
    public byte[] Sha512(ReadOnlySpan<byte> data) => global::NetCrypto.Hash.Sha512(data);
}

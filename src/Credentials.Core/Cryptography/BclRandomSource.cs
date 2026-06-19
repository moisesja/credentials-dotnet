using System.Security.Cryptography;

namespace Credentials.Cryptography;

/// <summary>
/// The default <see cref="IRandomSource"/>: a stateless, thread-safe adapter over the BCL
/// <see cref="RandomNumberGenerator"/>. Used because <c>NetCrypto</c> 1.1.0 exposes no RNG seam (see
/// <see cref="IRandomSource"/>); the BCL CSPRNG is the same primitive <c>NetCrypto</c> uses internally.
/// </summary>
public sealed class BclRandomSource : IRandomSource
{
    /// <inheritdoc />
    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    /// <inheritdoc />
    public byte[] GetBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        var bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}

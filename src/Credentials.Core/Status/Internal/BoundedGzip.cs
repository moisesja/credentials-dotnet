using System.IO;
using System.IO.Compression;

namespace Credentials.Status;

/// <summary>
/// GZIP (RFC 1952) compression/decompression with a hard cap on the number of bytes produced by
/// decompression — the defense against a decompression bomb (a tiny status list that inflates to
/// gigabytes). The Bitstring Status List spec sets a 16 KiB <em>minimum</em> but no maximum, so the
/// engine imposes its own upper bound. The cap is applied to bytes <em>produced</em> by the inflate
/// (never to the compressed input length, which an attacker controls cheaply).
/// </summary>
internal static class BoundedGzip
{
    /// <summary>Compresses <paramref name="data"/> with GZIP.</summary>
    public static byte[] Compress(ReadOnlySpan<byte> data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(data);
        }

        return output.ToArray();
    }

    /// <summary>
    /// Decompresses GZIP <paramref name="compressed"/>, refusing to produce more than
    /// <paramref name="maxBytes"/> bytes.
    /// </summary>
    /// <exception cref="InvalidDataException">
    /// The stream is not valid GZIP, or it would inflate beyond <paramref name="maxBytes"/>.
    /// </exception>
    public static byte[] Decompress(byte[] compressed, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(compressed);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);

        using var input = new MemoryStream(compressed, writable: false);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();

        var buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = gzip.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                throw new InvalidDataException(
                    $"The GZIP-compressed status list inflates beyond the {maxBytes}-byte limit.");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }
}

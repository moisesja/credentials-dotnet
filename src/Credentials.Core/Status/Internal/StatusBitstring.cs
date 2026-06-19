using System.IO;
using NetCid;

namespace Credentials.Status;

/// <summary>
/// The Bitstring Status List v1.0 codec — the bit/encoding core the status subsystem owns
/// (canonicalization and proofs are delegated elsewhere; this is pure bit math + transport encoding).
///
/// <para>
/// Wire form of <c>encodedList</c>: the raw bitstring is GZIP-compressed (RFC 1952) <em>first</em>, then
/// Multibase base64url-encoded (the <c>u</c> prefix, unpadded) — decoding reverses that order. Bits are
/// <strong>MSB-first</strong>: index 0 is the left-most (most-significant) bit of byte 0, so bit
/// <c>position</c> lives in byte <c>position / 8</c> at mask <c>0x80 >> (position % 8)</c>. Getting the
/// order wrong silently misreports revoked-vs-valid (the spec's §7.1 warning), so the round-trip and
/// MSB-first behaviour are pinned by tests.
/// </para>
/// </summary>
internal static class StatusBitstring
{
    /// <summary>The spec minimum bitstring length, in bits (16 KiB), for herd privacy.</summary>
    public const int MinimumBits = 131_072;

    /// <summary>The spec minimum bitstring length, in bytes (16 KiB).</summary>
    public const int MinimumBytes = MinimumBits / 8;

    /// <summary>
    /// The default cap on bytes produced by decompressing a fetched <c>encodedList</c> (decompression-bomb
    /// defense). 16 MiB ⇒ ~134 million single-bit entries — generous for real lists, bounded against abuse.
    /// </summary>
    public const long DefaultMaxInflatedBytes = 16L * 1024 * 1024;

    /// <summary>
    /// Encodes a raw bitstring to the <c>encodedList</c> wire form (GZIP then Multibase base64url, <c>u</c>
    /// prefix, unpadded).
    /// </summary>
    public static string Encode(ReadOnlySpan<byte> bitstring)
    {
        var compressed = BoundedGzip.Compress(bitstring);
        return Multibase.Encode(compressed, MultibaseEncoding.Base64Url);
    }

    /// <summary>
    /// Decodes an <c>encodedList</c> wire string back to the raw bitstring: Multibase-decode (asserting
    /// base64url), then bounded GZIP-inflate, then a minimum-length floor check.
    /// </summary>
    /// <param name="encodedList">The Multibase-base64url, GZIP-compressed bitstring.</param>
    /// <param name="maxInflatedBytes">The cap on decompressed bytes (default
    /// <see cref="DefaultMaxInflatedBytes"/>).</param>
    /// <returns>The raw, decompressed bitstring bytes (≥ <see cref="MinimumBytes"/>).</returns>
    /// <exception cref="FormatException">
    /// The string is not Multibase base64url, is not valid GZIP, exceeds the inflate cap, or decodes to
    /// fewer than <see cref="MinimumBits"/> bits.
    /// </exception>
    public static byte[] Decode(string encodedList, long maxInflatedBytes = DefaultMaxInflatedBytes)
    {
        ArgumentNullException.ThrowIfNull(encodedList);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxInflatedBytes, MinimumBytes);

        // NetCid's DefaultMaxInputLength (4096) bounds the ENCODED TEXT length and is far too small for a
        // real list; pass an explicit bound derived from the inflate cap. base64url expands bytes ~4/3, so
        // a compressed blob of up to maxInflatedBytes encodes to at most ~ceil(maxInflatedBytes*4/3)+pad
        // characters; anything larger cannot inflate within the cap, so we reject it before decoding.
        var maxEncodedChars = checked((int)Math.Min(int.MaxValue, (maxInflatedBytes / 3 + 1) * 4 + 8));

        byte[] compressed;
        try
        {
            if (!Multibase.TryDecode(encodedList, out compressed, out var encoding, maxEncodedChars)
                || encoding != MultibaseEncoding.Base64Url)
            {
                throw new FormatException("The encodedList is not a Multibase base64url string.");
            }
        }
        catch (ArgumentOutOfRangeException ex)
        {
            // Defensive: maxEncodedChars < 1 cannot happen given the guard above, but never leak a raw fault.
            throw new FormatException("The encodedList could not be decoded.", ex);
        }

        byte[] bitstring;
        try
        {
            bitstring = BoundedGzip.Decompress(compressed, maxInflatedBytes);
        }
        catch (InvalidDataException ex)
        {
            throw new FormatException("The encodedList is not valid GZIP or exceeds the size limit.", ex);
        }

        if (bitstring.Length < MinimumBytes)
        {
            throw new FormatException(
                $"The status list bitstring is {bitstring.Length * 8} bits; the minimum is {MinimumBits}.");
        }

        return bitstring;
    }

    /// <summary>
    /// Reads the status bit at <paramref name="position"/> (MSB-first). <paramref name="position"/> is the
    /// already-computed bit position (<c>statusListIndex * statusSize</c> for the first bit of an entry).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The position is outside the bitstring (RANGE error).</exception>
    public static bool GetBit(byte[] bitstring, long position)
    {
        ArgumentNullException.ThrowIfNull(bitstring);
        var totalBits = (long)bitstring.Length * 8;
        if (position < 0 || position >= totalBits)
        {
            throw new ArgumentOutOfRangeException(nameof(position), position,
                "The status index is outside the status list bitstring.");
        }

        var byteIndex = (int)(position / 8);
        var mask = (byte)(0x80 >> (int)(position % 8));
        return (bitstring[byteIndex] & mask) != 0;
    }

    /// <summary>Sets or clears the status bit at <paramref name="position"/> (MSB-first).</summary>
    /// <exception cref="ArgumentOutOfRangeException">The position is outside the bitstring.</exception>
    public static void SetBit(byte[] bitstring, long position, bool value)
    {
        ArgumentNullException.ThrowIfNull(bitstring);
        var totalBits = (long)bitstring.Length * 8;
        if (position < 0 || position >= totalBits)
        {
            throw new ArgumentOutOfRangeException(nameof(position), position,
                "The status index is outside the status list bitstring.");
        }

        var byteIndex = (int)(position / 8);
        var mask = (byte)(0x80 >> (int)(position % 8));
        if (value)
        {
            bitstring[byteIndex] |= mask;
        }
        else
        {
            bitstring[byteIndex] = (byte)(bitstring[byteIndex] & ~mask);
        }
    }

    /// <summary>Reads a multi-bit (<paramref name="statusSize"/>) value starting at the given bit
    /// position, MSB-first (the most-significant status bit first). Used for <c>statusSize &gt; 1</c>.</summary>
    public static long GetValue(byte[] bitstring, long position, int statusSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(statusSize, 1);
        if (statusSize > 62)
        {
            throw new ArgumentOutOfRangeException(nameof(statusSize), statusSize,
                "statusSize larger than 62 bits is not supported.");
        }

        long value = 0;
        for (var i = 0; i < statusSize; i++)
        {
            value = (value << 1) | (GetBit(bitstring, position + i) ? 1L : 0L);
        }

        return value;
    }

    /// <summary>Allocates a fresh, all-zero bitstring of <paramref name="lengthBits"/> bits
    /// (rounded up to a whole byte; never below the spec minimum).</summary>
    public static byte[] CreateEmpty(int lengthBits = MinimumBits)
    {
        if (lengthBits < MinimumBits)
        {
            lengthBits = MinimumBits;
        }

        var bytes = (lengthBits + 7) / 8;
        return new byte[bytes];
    }
}

using System;
using Credentials.Status;
using FluentAssertions;
using NetCid;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// The Bitstring Status List codec: MSB-first bit order, GZIP-then-multibase round-trip, the explicit
/// multibase length bound (NetCid's 4096 default is too small), the decompression-bomb cap, and the
/// 131,072-bit minimum-length floor. Getting the bit order or compression order wrong silently
/// misreports revoked-vs-valid, so these are pinned hard.
/// </summary>
public sealed class StatusBitstringTests
{
    [Fact]
    public void Encode_produces_a_multibase_base64url_string_unpadded()
    {
        var encoded = StatusBitstring.Encode(StatusBitstring.CreateEmpty());

        encoded.Should().StartWith("u", "Bitstring Status List uses multibase base64url (the 'u' prefix)");
        encoded.Should().NotContain("=", "base64url here is unpadded");
    }

    [Fact]
    public void Encode_then_Decode_round_trips_a_populated_bitstring()
    {
        var bits = StatusBitstring.CreateEmpty();
        StatusBitstring.SetBit(bits, 0, true);
        StatusBitstring.SetBit(bits, 94_567, true);
        StatusBitstring.SetBit(bits, StatusBitstring.MinimumBits - 1, true);

        var decoded = StatusBitstring.Decode(StatusBitstring.Encode(bits));

        decoded.Should().Equal(bits);
        StatusBitstring.GetBit(decoded, 0).Should().BeTrue();
        StatusBitstring.GetBit(decoded, 94_567).Should().BeTrue();
        StatusBitstring.GetBit(decoded, StatusBitstring.MinimumBits - 1).Should().BeTrue();
        StatusBitstring.GetBit(decoded, 1).Should().BeFalse();
    }

    [Theory]
    [InlineData(0, 0, 0x80)] // index 0 → most-significant bit of byte 0
    [InlineData(1, 0, 0x40)]
    [InlineData(7, 0, 0x01)] // index 7 → least-significant bit of byte 0
    [InlineData(8, 1, 0x80)] // index 8 → most-significant bit of byte 1
    [InlineData(15, 1, 0x01)]
    public void SetBit_is_MSB_first(int index, int expectedByte, int expectedMask)
    {
        var bits = StatusBitstring.CreateEmpty();
        StatusBitstring.SetBit(bits, index, true);

        bits[expectedByte].Should().Be((byte)expectedMask, "index {0} must be MSB-first within its byte", index);
        StatusBitstring.GetBit(bits, index).Should().BeTrue();
    }

    [Fact]
    public void SetBit_false_clears_the_bit()
    {
        var bits = StatusBitstring.CreateEmpty();
        StatusBitstring.SetBit(bits, 42, true);
        StatusBitstring.GetBit(bits, 42).Should().BeTrue();

        StatusBitstring.SetBit(bits, 42, false);
        StatusBitstring.GetBit(bits, 42).Should().BeFalse();
    }

    [Fact]
    public void GetBit_out_of_range_throws()
    {
        var bits = StatusBitstring.CreateEmpty();
        var act = () => StatusBitstring.GetBit(bits, StatusBitstring.MinimumBits);
        act.Should().Throw<ArgumentOutOfRangeException>();

        var negative = () => StatusBitstring.GetBit(bits, -1);
        negative.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Decode_rejects_a_bitstring_below_the_131072_bit_minimum()
    {
        // GZIP+multibase a deliberately too-short bitstring, then assert the floor check rejects it.
        var tooShort = new byte[100];
        var encoded = StatusBitstring.Encode(tooShort);

        var act = () => StatusBitstring.Decode(encoded);
        act.Should().Throw<FormatException>().WithMessage("*minimum*");
    }

    [Fact]
    public void Decode_passes_an_explicit_length_bound_so_a_large_list_does_not_spuriously_fail()
    {
        // An incompressible 16 KiB bitstring encodes to > 4096 chars — NetCid's DEFAULT decode bound (4096)
        // would reject it. Our codec must pass an explicit larger bound and round-trip successfully.
        var bits = StatusBitstring.CreateEmpty();
        new Random(42).NextBytes(bits);
        var encoded = StatusBitstring.Encode(bits);

        encoded.Length.Should().BeGreaterThan(4096, "an incompressible list exceeds NetCid's default 4096-char bound");

        // The naive default-bound NetCid path fails — this is exactly the trap the codec avoids.
        var naive = () => Multibase.Decode(encoded);
        naive.Should().Throw<CidFormatException>();

        // Our codec round-trips it.
        StatusBitstring.Decode(encoded).Should().Equal(bits);
    }

    [Fact]
    public void Decode_caps_decompression_to_defeat_a_gzip_bomb()
    {
        // A 2×-minimum all-zero bitstring compresses tiny but inflates to 32 KiB; decoding with a cap at the
        // 16 KiB minimum must refuse to inflate past the cap (decompression-bomb defense), not OOM.
        var big = StatusBitstring.CreateEmpty(StatusBitstring.MinimumBits * 2);
        var encoded = StatusBitstring.Encode(big);

        var act = () => StatusBitstring.Decode(encoded, maxInflatedBytes: StatusBitstring.MinimumBytes);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Decode_rejects_a_non_base64url_multibase_string()
    {
        // A base58btc multibase string (prefix 'z') is well-formed multibase but the wrong base for encodedList.
        var base58 = Multibase.Encode(new byte[] { 1, 2, 3 }, MultibaseEncoding.Base58Btc);

        var act = () => StatusBitstring.Decode(base58);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Decode_rejects_garbage_that_is_not_valid_gzip()
    {
        // Valid multibase base64url, but the bytes are not GZIP.
        var notGzip = Multibase.Encode(new byte[] { 1, 2, 3, 4, 5 }, MultibaseEncoding.Base64Url);

        var act = () => StatusBitstring.Decode(notGzip);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Decode_with_a_huge_inflate_cap_does_not_overflow()
    {
        // Hardening (adversarial finding): a near-long.MaxValue cap must not throw OverflowException in the
        // maxEncodedChars arithmetic — it clamps to a valid bound and still round-trips a real list.
        var bits = StatusBitstring.CreateEmpty();
        StatusBitstring.SetBit(bits, 7, true);
        var encoded = StatusBitstring.Encode(bits);

        var act = () => StatusBitstring.Decode(encoded, maxInflatedBytes: long.MaxValue);
        act.Should().NotThrow<OverflowException>();
        StatusBitstring.Decode(encoded, maxInflatedBytes: long.MaxValue).Should().Equal(bits);
    }

    [Fact]
    public void CreateEmpty_rejects_an_oversized_length_without_overflowing()
    {
        // Hardening: int.MaxValue bits must not overflow (lengthBits+7)/8 into a negative allocation;
        // it is rejected with a clear ArgumentOutOfRangeException.
        var act = () => StatusBitstring.CreateEmpty(int.MaxValue);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void GetValue_reads_a_multi_bit_value_msb_first()
    {
        var bits = StatusBitstring.CreateEmpty();
        // statusSize 2, entry index 1 ⇒ position 2; write value 0b10 (MSB-first): bit 2 set, bit 3 clear.
        StatusBitstring.SetBit(bits, 2, true);
        StatusBitstring.SetBit(bits, 3, false);

        StatusBitstring.GetValue(bits, position: 2, statusSize: 2).Should().Be(0b10);
    }
}

using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Securing;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// Unit tests for the M3 envelope routing primitives: <see cref="EnvelopeDetector"/> (byte-level form
/// classification before any parse/decode) and <see cref="CompactJws"/> (substrate-free header/payload
/// reading). These guard the verifier's bytes-overload routing and the JOSE kid/payload extraction.
/// </summary>
public sealed class M3EnvelopeDetectionTests
{
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void Detect_json_object_returns_null()
    {
        EnvelopeDetector.Detect(Utf8("{\"@context\":[]}")).Should().BeNull();
        EnvelopeDetector.Detect(Utf8("   \n\t {\"a\":1}")).Should().BeNull(); // leading whitespace skipped
    }

    [Fact]
    public void Detect_json_array_and_unknown_return_null()
    {
        EnvelopeDetector.Detect(Utf8("[1,2,3]")).Should().BeNull();
        EnvelopeDetector.Detect(Utf8("hello world!")).Should().BeNull(); // space ⇒ not base64url
        EnvelopeDetector.Detect(Utf8("nodotshere")).Should().BeNull();    // no '.' ⇒ not a compact JWS
        EnvelopeDetector.Detect([]).Should().BeNull();
    }

    [Fact]
    public void Detect_compact_jws_returns_jose()
    {
        EnvelopeDetector.Detect(Utf8("eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ.c2ln")).Should().Be(SecuringForm.Jose);
    }

    [Fact]
    public void Detect_rejects_non_two_dot_tokens()
    {
        EnvelopeDetector.Detect(Utf8("aaa.bbb.ccc.ddd")).Should().BeNull(); // JWE-shaped (4+ segments)
        EnvelopeDetector.Detect(Utf8("aaa.bbb")).Should().BeNull();        // only one '.'
    }

    [Theory]
    [InlineData(new byte[] { 0xD2, 0x84, 0x40 })]       // CBOR tag 18 (COSE_Sign1)
    [InlineData(new byte[] { 0x84, 0x40, 0xA0, 0x40 })] // untagged 4-element array
    [InlineData(new byte[] { 0xD8, 0x12, 0x84 })]       // tag 18 in 1-byte-arg encoding
    public void Detect_cose_returns_cose(byte[] bytes)
    {
        EnvelopeDetector.Detect(bytes).Should().Be(SecuringForm.Cose);
    }

    [Fact]
    public void ReadKid_reads_the_protected_header_kid()
    {
        var compact = Fabricate(new JsonObject { ["alg"] = "EdDSA", ["kid"] = "did:key:zABC#zABC" }, [1, 2, 3]);
        CompactJws.ReadKid(compact).Should().Be("did:key:zABC#zABC");
    }

    [Fact]
    public void ReadKid_returns_null_when_absent_or_malformed()
    {
        CompactJws.ReadKid(Fabricate(new JsonObject { ["alg"] = "EdDSA" }, [1, 2, 3])).Should().BeNull();
        CompactJws.ReadKid("not-a-jws").Should().BeNull();
        CompactJws.ReadKid("only.two").Should().BeNull();
    }

    [Fact]
    public void DecodePayload_round_trips()
    {
        var payload = Utf8("{\"hello\":\"world\"}");
        var compact = Fabricate(new JsonObject { ["alg"] = "EdDSA" }, payload);
        CompactJws.DecodePayload(compact).Should().Equal(payload);
    }

    [Fact]
    public void DecodePayload_throws_on_non_compact_jws()
    {
        var act = () => CompactJws.DecodePayload("only.two");
        act.Should().Throw<CredentialFormatException>();
    }

    private static string Fabricate(JsonObject header, byte[] payload)
    {
        var h = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = Base64Url.EncodeToString(payload);
        return $"{h}.{p}.{Base64Url.EncodeToString(new byte[8])}";
    }
}

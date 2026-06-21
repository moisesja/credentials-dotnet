using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Roles;
using Credentials.Securing;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// M4 envelope routing for SD-JWT VC: the <see cref="EnvelopeDetector"/> must classify a compact SD-JWT
/// (<c>issuer-JWS~D1~…~</c>) as <see cref="SecuringForm.SdJwtVc"/> — and must do so BEFORE the plain
/// compact-JWS branch, since an SD-JWT's first segment is itself a compact JWS. A plain compact JWS (no
/// <c>~</c>) must still be classified as <see cref="SecuringForm.Jose"/>.
/// </summary>
public sealed class M4SdJwtDetectionTests
{
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static string Jwt() => Fabricate(new JsonObject { ["alg"] = "EdDSA", ["typ"] = "dc+sd-jwt" }, Utf8("{\"vct\":\"x\"}"));

    [Fact]
    public void Detect_sd_jwt_without_disclosures_returns_sdjwtvc()
    {
        // issuerJwt~  (no disclosures, trailing '~')
        EnvelopeDetector.Detect(Utf8(Jwt() + "~")).Should().Be(SecuringForm.SdJwtVc);
    }

    [Fact]
    public void Detect_sd_jwt_with_disclosures_returns_sdjwtvc()
    {
        var disclosure = Base64Url.EncodeToString(Utf8("[\"salt\",\"given_name\",\"Alice\"]"));
        EnvelopeDetector.Detect(Utf8($"{Jwt()}~{disclosure}~")).Should().Be(SecuringForm.SdJwtVc);
    }

    [Fact]
    public void Detect_sd_jwt_with_key_binding_returns_sdjwtvc()
    {
        var disclosure = Base64Url.EncodeToString(Utf8("[\"salt\",\"given_name\",\"Alice\"]"));
        var kb = Fabricate(new JsonObject { ["alg"] = "EdDSA", ["typ"] = "kb+jwt" }, Utf8("{\"nonce\":\"n\"}"));
        EnvelopeDetector.Detect(Utf8($"{Jwt()}~{disclosure}~{kb}")).Should().Be(SecuringForm.SdJwtVc);
    }

    [Fact]
    public void Detect_sd_jwt_is_not_misrouted_to_jose()
    {
        EnvelopeDetector.Detect(Utf8(Jwt() + "~")).Should().NotBe(SecuringForm.Jose);
    }

    [Fact]
    public void Detect_plain_compact_jws_still_returns_jose()
    {
        // No '~' ⇒ a plain compact JWS, not an SD-JWT.
        EnvelopeDetector.Detect(Utf8(Jwt())).Should().Be(SecuringForm.Jose);
        EnvelopeDetector.Detect(Utf8("eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ.c2ln")).Should().Be(SecuringForm.Jose);
    }

    [Fact]
    public void Detect_json_object_with_tilde_in_a_value_is_not_sdjwt()
    {
        // A JSON-object credential starts with '{' ⇒ null, even if a value contains '~'.
        EnvelopeDetector.Detect(Utf8("{\"note\":\"a~b\"}")).Should().BeNull();
    }

    [Fact]
    public void Detect_leading_tilde_is_not_sdjwt()
    {
        // '~' is not a base64url first char ⇒ not classified as an SD-JWT (the issuer JWT must come first).
        EnvelopeDetector.Detect(Utf8("~abc~")).Should().BeNull();
    }

    private static string Fabricate(JsonObject header, byte[] payload)
    {
        var h = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = Base64Url.EncodeToString(payload);
        return $"{h}.{p}.{Base64Url.EncodeToString(new byte[8])}";
    }

    [Fact]
    public void DisclosureSelector_arrayElements_dedupes_indices()
    {
        // Duplicate indices are a usage trap, not a meaningful request — they are de-duplicated, preserving
        // first-seen order, so a given array element is disclosable at most once.
        DisclosureSelector.ArrayElements("tags", 0, 1, 0, 1, 2).Indices.Should().Equal(0, 1, 2);
    }
}

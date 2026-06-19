using System.Text.Json.Nodes;
using Credentials;
using Credentials.Validation;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>D1: positive version detection from the exact <c>@context[0]</c> base URL.</summary>
public sealed class VersionProjectionTests
{
    [Fact]
    public void Detects_v2_from_array()
    {
        var root = (JsonObject)JsonNode.Parse("""{ "@context": ["https://www.w3.org/ns/credentials/v2"] }""")!;
        VersionProjection.Detect(root).Should().Be(VcdmVersion.V2_0);
    }

    [Fact]
    public void Detects_v1_from_array()
    {
        var root = (JsonObject)JsonNode.Parse("""{ "@context": ["https://www.w3.org/2018/credentials/v1"] }""")!;
        VersionProjection.Detect(root).Should().Be(VcdmVersion.V1_1);
    }

    [Fact]
    public void Detects_from_bare_string_context()
    {
        var root = (JsonObject)JsonNode.Parse("""{ "@context": "https://www.w3.org/ns/credentials/v2" }""")!;
        VersionProjection.Detect(root).Should().Be(VcdmVersion.V2_0);
    }

    [Fact]
    public void Unrecognized_base_url_is_unknown_not_a_fallback()
    {
        var root = (JsonObject)JsonNode.Parse("""{ "@context": ["https://example.com/other"] }""")!;
        VersionProjection.Detect(root).Should().Be(VcdmVersion.Unknown);
    }

    [Fact]
    public void Missing_context_is_unknown()
    {
        var root = (JsonObject)JsonNode.Parse("""{ "type": ["VerifiableCredential"] }""")!;
        VersionProjection.Detect(root).Should().Be(VcdmVersion.Unknown);
    }
}

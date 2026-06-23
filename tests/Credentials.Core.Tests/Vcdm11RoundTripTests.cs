using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// M7 "no upgrade" rule (FR-044 / D8): a parsed VCDM 1.1 document stays 1.1 across a serialize→re-parse cycle
/// — the engine verifies 1.1, it never rewrites it toward 2.0 (no @context swap, no validFrom/validUntil
/// introduced, version still detected as 1.1).
/// </summary>
public sealed class Vcdm11RoundTripTests
{
    private static string Context0(JsonNode? root) =>
        root!.AsObject()["@context"]!.AsArray()[0]!.GetValue<string>();

    [Fact]
    public void V1_credential_survives_a_round_trip_without_upgrade()
    {
        var original = TestVectors.ValidV1Credential();
        var credential = Credential.Parse(original.ToJsonString());
        credential.Version.Should().Be(VcdmVersion.V1_1);

        var reparsed = Credential.Parse(credential.ToBytes());

        reparsed.Version.Should().Be(VcdmVersion.V1_1);
        var root = JsonNode.Parse(reparsed.ToBytes())!.AsObject();
        Context0(root).Should().Be("https://www.w3.org/2018/credentials/v1");
        root["issuanceDate"].Should().NotBeNull();           // 1.1 member preserved
        root.Should().NotContainKey("validFrom");            // no upgrade to 2.0 members
        root.Should().NotContainKey("validUntil");
    }

    [Fact]
    public void V1_presentation_survives_a_round_trip_without_upgrade()
    {
        var original = TestVectors.ValidV1Presentation();
        var presentation = VerifiablePresentation.Parse(original.ToJsonString());
        presentation.Version.Should().Be(VcdmVersion.V1_1);

        var reparsed = VerifiablePresentation.Parse(presentation.ToBytes());

        reparsed.Version.Should().Be(VcdmVersion.V1_1);
        Context0(JsonNode.Parse(reparsed.ToBytes())).Should().Be("https://www.w3.org/2018/credentials/v1");
    }
}

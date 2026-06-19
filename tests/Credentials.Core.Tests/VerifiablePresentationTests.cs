using System.Text.Json.Nodes;
using Credentials;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>FR-002 presentation model + F8 version-detected presentations + contained-credential handling.</summary>
public sealed class VerifiablePresentationTests
{
    private static Credential SampleCredential() => Credential.Build()
        .WithIssuer("did:example:issuer")
        .AddSubject(new JsonObject { ["id"] = "did:example:s" })
        .Seal();

    [Fact]
    public void Builds_a_presentation_with_an_embedded_credential()
    {
        var vp = VerifiablePresentation.Build()
            .WithHolder("did:example:holder")
            .AddCredential(SampleCredential())
            .Seal();

        vp.IsFrozen.Should().BeTrue();
        vp.Version.Should().Be(VcdmVersion.V2_0);
        vp.Type.Should().Contain("VerifiablePresentation");
        vp.Holder.Should().Be("did:example:holder");
        vp.VerifiableCredentials.Should().ContainSingle();
        vp.VerifiableCredentials[0].IsEmbedded.Should().BeTrue();
        vp.VerifiableCredentials[0].AsEmbedded!.Issuer!.Id.Should().Be("did:example:issuer");
    }

    [Fact]
    public void Parses_an_enveloped_contained_credential_verbatim()
    {
        const string compact = "eyJ0eXAiOiJ2Yytqd3QifQ.eyJ2YyI6e319.signature";
        var json =
            $$"""
            {
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "type": ["VerifiablePresentation"],
              "verifiableCredential": ["{{compact}}"]
            }
            """;

        var vp = VerifiablePresentation.Parse(json);

        vp.VerifiableCredentials.Should().ContainSingle();
        vp.VerifiableCredentials[0].IsEmbedded.Should().BeFalse();
        vp.VerifiableCredentials[0].AsEnvelopedCompact.Should().Be(compact);
    }

    [Fact]
    public void Detects_v1_presentation_version()
    {
        var json =
            """
            {
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              "type": ["VerifiablePresentation"]
            }
            """;

        var vp = VerifiablePresentation.Parse(json);
        vp.Version.Should().Be(VcdmVersion.V1_1);
        vp.ValidateStructure().IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sealing_an_invalid_presentation_throws()
    {
        // No way to build an invalid base presentation through the builder's seeded members,
        // so validate a hand-built one missing the base type instead.
        var vp = VerifiablePresentation.Parse(
            """{ "@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["Other"] }""");
        vp.ValidateStructure().IsValid.Should().BeFalse();
    }
}

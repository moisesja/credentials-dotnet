using System.Text.Json.Nodes;
using Credentials;
using Credentials.TestSupport;
using Credentials.Validation;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>FR-001/004/010 building + the A2 base-member protection.</summary>
public sealed class CredentialBuilderTests
{
    private static Credential BuildMinimal() => Credential.Build()
        .WithId("urn:uuid:1")
        .WithIssuer("did:example:issuer")
        .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["name"] = "Alice" })
        .Seal();

    [Fact]
    public void Seals_a_minimal_valid_credential()
    {
        var credential = BuildMinimal();

        credential.IsFrozen.Should().BeTrue();
        credential.Securing.Should().Be(SecuringState.Unsecured);
        credential.Version.Should().Be(VcdmVersion.V2_0);
        credential.Id.Should().Be("urn:uuid:1");
        credential.Issuer!.Id.Should().Be("did:example:issuer");
    }

    [Fact]
    public void Seeds_base_context_and_type_at_index_zero()
    {
        var credential = BuildMinimal();
        credential.Context[0].Should().Be("https://www.w3.org/ns/credentials/v2");
        credential.Type[0].Should().Be("VerifiableCredential");
    }

    [Fact]
    public void AddContext_appends_without_displacing_index_zero()
    {
        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddContext("https://www.w3.org/ns/credentials/examples/v2")
            .AddSubject(new JsonObject { ["id"] = "did:example:s" })
            .Seal();

        credential.Context[0].Should().Be("https://www.w3.org/ns/credentials/v2");
        credential.Context.Should().Contain("https://www.w3.org/ns/credentials/examples/v2");
    }

    [Fact]
    public void AddType_appends_additional_type()
    {
        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddType("UniversityDegreeCredential")
            .AddSubject(new JsonObject { ["id"] = "did:example:s" })
            .Seal();

        credential.Type.Should().ContainInOrder("VerifiableCredential", "UniversityDegreeCredential");
    }

    [Fact]
    [FrTag("FR-010")]
    public void Multiple_subjects_are_promoted_to_an_array()
    {
        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddSubject(new JsonObject { ["id"] = "did:example:a" })
            .AddSubject(new JsonObject { ["id"] = "did:example:b" })
            .Seal();

        credential.CredentialSubjects.Should().HaveCount(2);
        credential.CredentialSubjects.Select(s => s.Id).Should().ContainInOrder("did:example:a", "did:example:b");
    }

    [Fact]
    public void Validity_window_round_trips_through_typed_accessors()
    {
        var from = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var until = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddSubject(new JsonObject { ["id"] = "did:example:s" })
            .WithValidFrom(from)
            .WithValidUntil(until)
            .Seal();

        credential.ValidFrom.Should().Be(from);
        credential.ValidUntil.Should().Be(until);
    }

    [Fact]
    public void SetMember_rejects_protected_context_member()
    {
        var act = () => Credential.Build().SetMember("@context", new JsonArray("https://evil.example/"));
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void SetMember_carries_arbitrary_members_through()
    {
        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddSubject(new JsonObject { ["id"] = "did:example:s" })
            .SetMember("termsOfUse", new JsonObject { ["type"] = "IssuerPolicy" })
            .Seal();

        credential.GetMember("termsOfUse").Should().NotBeNull();
    }

    [Fact]
    public void Seal_throws_on_structurally_invalid_credential()
    {
        // Missing credentialSubject and issuer.
        var act = () => Credential.Build().Seal();
        act.Should().Throw<CredentialStructureException>()
            .Which.Problems.Select(p => p.Code).Should().Contain("subject.missing");
    }

    [Fact]
    public void Builder_cannot_be_reused_after_seal()
    {
        var builder = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddSubject(new JsonObject { ["id"] = "did:example:s" });
        builder.Seal();

        var act = () => builder.WithId("urn:uuid:2");
        act.Should().Throw<InvalidOperationException>();
    }
}

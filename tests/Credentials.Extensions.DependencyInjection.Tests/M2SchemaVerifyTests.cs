using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Schema;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NSubstitute;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>M2 end-to-end credential-schema verification (FR-070) with a mocked <see cref="ICredentialSchemaResolver"/>.</summary>
public sealed class M2SchemaVerifyTests
{
    private const string SchemaUrl = "https://schema.example/person";

    private const string PersonSchema =
        """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "properties": {
            "credentialSubject": {
              "type": "object",
              "properties": { "name": { "type": "string" } },
              "required": ["name"]
            }
          },
          "required": ["credentialSubject"]
        }
        """;

    private static readonly byte[] PersonSchemaBytes = Encoding.UTF8.GetBytes(PersonSchema);

    private static ServiceProvider BuildProvider(ICredentialSchemaResolver? resolver) =>
        new ServiceCollection()
            .AddCredentials(b =>
            {
                b.UseNetDid();
                if (resolver is not null)
                {
                    b.UseSchemaResolver(resolver);
                }
            })
            .BuildServiceProvider();

    private static ICredentialSchemaResolver ResolverReturning(byte[] schemaBytes, string type = "JsonSchema")
    {
        var resolver = Substitute.For<ICredentialSchemaResolver>();
        resolver.ResolveAsync(Arg.Any<SchemaReference>(), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.Found(new ResolvedSchema(SchemaUrl, SchemaDialect.JsonSchema2020_12, schemaBytes)));
        return resolver;
    }

    private static async Task<Credential> IssueSubjectAsync(IIssuer issuer, TestKey key, string name = "Ada", string? digestSri = null, string type = "JsonSchema")
    {
        var schemaRef = new JsonObject { ["id"] = SchemaUrl, ["type"] = type };
        if (digestSri is not null)
        {
            schemaRef["digestSRI"] = digestSri;
        }

        var builder = Credential.Build()
            .WithIssuer(key.Did)
            .AddSchema(schemaRef);

        builder = name.Length == 0
            ? builder.AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            : builder.AddSubject(new JsonObject { ["id"] = "did:example:subject", ["name"] = name });

        var issued = await issuer.IssueAsync(builder.Seal(),
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
        return issued.Credential;
    }

    [Fact]
    public async Task Conforming_credential_passes_schema()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, name: "Ada");

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Passed, result.ToString());
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task Non_conforming_credential_fails_schema_and_rejects()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, name: ""); // no name

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Failed);
        result.Check(CheckKinds.Schema)!.Diagnostics.Should().NotBeEmpty();
        result.Decision.Should().Be(VerificationDecision.Rejected);
    }

    [Fact]
    public async Task DigestSri_match_passes()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var sri = "sha256-" + Convert.ToBase64String(SHA256.HashData(PersonSchemaBytes));
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, digestSri: sri);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task DigestSri_mismatch_fails()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var wrongSri = "sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("a different schema")));
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, digestSri: wrongSri);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var schema = result.Check(CheckKinds.Schema)!;
        schema.Status.Should().Be(CheckStatus.Failed);
        schema.Diagnostics.Should().Contain(d => d.Code == "schema.digest_mismatch");
    }

    [Fact]
    public async Task Unresolvable_schema_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var resolver = Substitute.For<ICredentialSchemaResolver>();
        resolver.ResolveAsync(Arg.Any<SchemaReference>(), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.NotFound("unresolvable"));
        using var provider = BuildProvider(resolver);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Indeterminate);
        result.Decision.Should().Be(VerificationDecision.Rejected); // fail-closed
    }

    [Fact]
    public async Task Unknown_schema_type_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes, type: "ShaclValidator2025"));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, type: "ShaclValidator2025");

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var schema = result.Check(CheckKinds.Schema)!;
        schema.Status.Should().Be(CheckStatus.Indeterminate);
        schema.Diagnostics.Should().Contain(d => d.Code == "schema.unknown_type");
    }

    [Fact]
    public async Task No_resolver_configured_skips_schema()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(resolver: null);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Skipped);
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task CheckSchema_false_skips_schema()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, name: ""); // would fail

        var result = await provider.GetRequiredService<IVerifier>()
            .VerifyCredentialAsync(subject, new CredentialVerificationOptions { CheckSchema = false });
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Skipped);
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }
}

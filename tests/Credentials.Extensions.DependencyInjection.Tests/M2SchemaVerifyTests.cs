using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Schema;
using Credentials.TestSupport;
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
    [FrTag("FR-070")]
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
    public async Task DigestSri_accepts_a_base64url_encoded_value()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        // base64url (unpadded, -/_ alphabet) of the schema's SHA-256.
        var sri = "sha256-" + Convert.ToBase64String(SHA256.HashData(PersonSchemaBytes))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        using var provider = BuildProvider(ResolverReturning(PersonSchemaBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, digestSri: sri);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Passed, "a correct base64url digest must not be falsely rejected");
    }

    [Fact]
    public async Task Multiple_schemas_aggregate_to_the_worst_outcome()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        // Two schema entries: one the credential satisfies, one it violates (requires an absent member).
        const string strictSchema =
            """
            { "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "required": ["nonexistent"] }
            """;
        var resolver = Substitute.For<ICredentialSchemaResolver>();
        resolver.ResolveAsync(Arg.Is<SchemaReference>(r => r.Id == "https://schema.example/ok"), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.Found(new ResolvedSchema("https://schema.example/ok", SchemaDialect.JsonSchema2020_12, PersonSchemaBytes)));
        resolver.ResolveAsync(Arg.Is<SchemaReference>(r => r.Id == "https://schema.example/strict"), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.Found(new ResolvedSchema("https://schema.example/strict", SchemaDialect.JsonSchema2020_12, Encoding.UTF8.GetBytes(strictSchema))));

        using var provider = BuildProvider(resolver);
        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSchema(new JsonObject { ["id"] = "https://schema.example/ok", ["type"] = "JsonSchema" })
            .AddSchema(new JsonObject { ["id"] = "https://schema.example/strict", ["type"] = "JsonSchema" })
            .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["name"] = "Ada" })
            .Seal();
        var issued = await provider.GetRequiredService<IIssuer>().IssueAsync(unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(issued.Credential);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Failed, "one of two schemas fails");
    }

    // ── JsonSchemaCredential (schema wrapped in its own VC) ──

    private static async Task<byte[]> IssueSchemaCredentialAsync(IIssuer issuer, TestKey key, string schemaJson)
    {
        var wrapper = Credential.Build()
            .WithIssuer(key.Did)
            .AddType("JsonSchemaCredential")
            .AddSubject(new JsonObject
            {
                ["id"] = SchemaUrl + "#schema",
                ["type"] = "JsonSchema",
                ["jsonSchema"] = JsonNode.Parse(schemaJson),
            })
            .Seal();
        var issued = await issuer.IssueAsync(wrapper,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
        return issued.Credential.ToBytes();
    }

    [Fact]
    public async Task JsonSchemaCredential_same_issuer_validates()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        byte[] wrapperBytes;
        using (var seed = BuildProvider(null))
        {
            wrapperBytes = await IssueSchemaCredentialAsync(seed.GetRequiredService<IIssuer>(), key, PersonSchema);
        }

        var resolver = Substitute.For<ICredentialSchemaResolver>();
        resolver.ResolveAsync(Arg.Any<SchemaReference>(), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.Found(new ResolvedSchema(SchemaUrl, SchemaDialect.JsonSchema2020_12, wrapperBytes)));
        using var provider = BuildProvider(resolver);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, name: "Ada", type: "JsonSchemaCredential");

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Schema)!.Status.Should().Be(CheckStatus.Passed, result.ToString());
    }

    [Fact]
    public async Task JsonSchemaCredential_from_a_different_issuer_is_indeterminate()
    {
        // Adversarial (mirrors the status-list issuer-binding test): a permissive schema VC self-signed by an
        // unrelated issuer must not be trusted, even though its own proof verifies.
        var credentialKey = TestKeys.New(KeyType.Ed25519);
        var attackerKey = TestKeys.New(KeyType.Ed25519);

        byte[] foreignWrapper;
        using (var seed = BuildProvider(null))
        {
            // A wrapper that accepts anything ("type: object"), signed by the attacker.
            foreignWrapper = await IssueSchemaCredentialAsync(seed.GetRequiredService<IIssuer>(), attackerKey,
                """{ "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object" }""");
        }

        var resolver = Substitute.For<ICredentialSchemaResolver>();
        resolver.ResolveAsync(Arg.Any<SchemaReference>(), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.Found(new ResolvedSchema(SchemaUrl, SchemaDialect.JsonSchema2020_12, foreignWrapper)));
        using var provider = BuildProvider(resolver);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), credentialKey, name: "Ada", type: "JsonSchemaCredential");

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var schema = result.Check(CheckKinds.Schema)!;
        schema.Status.Should().Be(CheckStatus.Indeterminate);
        schema.Diagnostics.Should().Contain(d => d.Code == "schema.wrapper_issuer_mismatch");
    }

    [Fact]
    public async Task JsonSchemaCredential_without_inner_schema_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        byte[] wrapperBytes;
        using (var seed = BuildProvider(null))
        {
            // A JsonSchemaCredential whose subject has no jsonSchema member.
            var wrapper = Credential.Build()
                .WithIssuer(key.Did)
                .AddType("JsonSchemaCredential")
                .AddSubject(new JsonObject { ["id"] = SchemaUrl + "#schema", ["type"] = "JsonSchema" })
                .Seal();
            var issued = await seed.GetRequiredService<IIssuer>().IssueAsync(wrapper,
                new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
            wrapperBytes = issued.Credential.ToBytes();
        }

        var resolver = Substitute.For<ICredentialSchemaResolver>();
        resolver.ResolveAsync(Arg.Any<SchemaReference>(), Arg.Any<CancellationToken>())
            .Returns(SchemaResolutionResult.Found(new ResolvedSchema(SchemaUrl, SchemaDialect.JsonSchema2020_12, wrapperBytes)));
        using var provider = BuildProvider(resolver);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, name: "Ada", type: "JsonSchemaCredential");

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var schema = result.Check(CheckKinds.Schema)!;
        schema.Status.Should().Be(CheckStatus.Indeterminate);
        schema.Diagnostics.Should().Contain(d => d.Code == "schema.wrapper_malformed");
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

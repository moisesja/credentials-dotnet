using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace Credentials.Rdfc.Tests;

/// <summary>
/// The opt-in RDFC-1.0 cryptosuites (<c>eddsa-rdfc-2022</c>, <c>ecdsa-rdfc-2019</c>) registered via
/// <c>UseRdfcSuites()</c>, exercised end-to-end. These live in their own package/test project because
/// RDFC pulls in dotNetRDF / Newtonsoft, which the default closure deliberately avoids (NFR-002).
/// </summary>
public sealed class RdfcIssueVerifyTests
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid().UseRdfcSuites()).BuildServiceProvider();

    [Theory]
    [InlineData("eddsa-rdfc-2022", KeyType.Ed25519)]
    [InlineData("ecdsa-rdfc-2019", KeyType.P256)]
    public async Task Rdfc_issue_then_verify_round_trips(string cryptosuite, KeyType keyType)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var keyPair = KeyGen.Generate(keyType);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        var verificationMethod = $"{did}#{keyPair.MultibasePublicKey}";

        var credential = Credential.Build()
            .WithIssuer(did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();

        var issued = await issuer.IssueAsync(
            credential,
            new DataIntegrityIssuanceRequest
            {
                Cryptosuite = cryptosuite,
                Signer = new KeyPairSigner(keyPair, Crypto),
                VerificationMethod = verificationMethod,
            });

        issued.Credential.HasEmbeddedProof.Should().BeTrue();
        var result = await verifier.VerifyCredentialAsync(issued.Credential);
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Fact]
    public void UseRdfcSuites_adds_the_rdfc_suites_to_capabilities()
    {
        using var provider = BuildProvider();
        var capabilities = provider.GetRequiredService<ISecuringCapabilities>();

        capabilities.AvailableDataIntegritySuites.Should().Contain(
            ["eddsa-jcs-2022", "ecdsa-jcs-2019", "eddsa-rdfc-2022", "ecdsa-rdfc-2019"]);
    }

    [Fact]
    public void UseRdfcSuites_is_idempotent()
    {
        using var provider = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseRdfcSuites().UseRdfcSuites())
            .BuildServiceProvider();

        var capabilities = provider.GetRequiredService<ISecuringCapabilities>();
        capabilities.AvailableDataIntegritySuites.Should().Contain("eddsa-rdfc-2022");
    }
}

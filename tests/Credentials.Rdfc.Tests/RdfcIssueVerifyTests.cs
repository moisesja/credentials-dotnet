using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.TestSupport;
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
    [FrTag("FR-011")]
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

    private const string UndefinedTermsContext = "https://www.w3.org/ns/credentials/undefined-terms/v2";

    private static Credential WithCustomClaim(string issuerDid, bool listUndefinedTermsContext)
    {
        var builder = Credential.Build().WithIssuer(issuerDid);
        if (listUndefinedTermsContext)
        {
            builder.AddContext(UndefinedTermsContext);
        }

        // "degree" is defined by no context: credentials/v2 has no @vocab.
        return builder.AddSubject(new JsonObject { ["id"] = "did:example:subject", ["degree"] = "BSc" }).Seal();
    }

    private static async Task<IssuedCredential> IssueRdfcAsync(IIssuer issuer, Credential credential, KeyPair keyPair) =>
        await issuer.IssueAsync(credential, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-rdfc-2022",
            Signer = new KeyPairSigner(keyPair, Crypto),
            VerificationMethod = $"did:key:{keyPair.MultibasePublicKey}#{keyPair.MultibasePublicKey}",
        });

    [Fact]
    [FrTag("FR-011")]
    public async Task An_undefined_term_cannot_be_secured_and_the_failure_keeps_the_issuer_contract()
    {
        // DataProofs >= 1.5.0 refuses to sign what RDFC would drop. The substrate's ProofGenerationException must
        // surface as the InvalidOperationException IIssuer documents, never as a DataProofs type (NFR-005).
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var keyPair = KeyGen.Generate(KeyType.Ed25519);

        var act = () => IssueRdfcAsync(issuer, WithCustomClaim($"did:key:{keyPair.MultibasePublicKey}", listUndefinedTermsContext: false), keyPair);

        (await act.Should().ThrowExactlyAsync<InvalidOperationException>())
            .WithMessage("*eddsa-rdfc-2022*")
            .WithInnerException<DataProofsDotnet.ProofGenerationException>();
    }

    [Fact]
    [FrTag("FR-011")]
    [FrTag("FR-040")]
    public async Task The_undefined_terms_context_makes_custom_claims_signed_and_tamper_evident()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var keyPair = KeyGen.Generate(KeyType.Ed25519);

        var issued = await IssueRdfcAsync(issuer, WithCustomClaim($"did:key:{keyPair.MultibasePublicKey}", listUndefinedTermsContext: true), keyPair);
        (await verifier.VerifyCredentialAsync(issued.Credential)).Decision.Should().Be(VerificationDecision.Accepted);

        // The custom claim is now inside the signature: changing it breaks the proof.
        var changed = JsonNode.Parse(issued.Credential.ToUtf8().Span)!.AsObject();
        changed["credentialSubject"]!["degree"] = "PhD";
        var changedResult = await verifier.VerifyCredentialAsync(System.Text.Encoding.UTF8.GetBytes(changed.ToJsonString()));
        changedResult.Decision.Should().Be(VerificationDecision.Rejected);
        changedResult.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);

        // A holder who strips the undefined-terms context to make the claim unsigned again (the pre-1.5.0
        // DataProofs hole) gets a definitive data-loss failure, not an Indeterminate.
        var stripped = JsonNode.Parse(issued.Credential.ToUtf8().Span)!.AsObject();
        var contexts = stripped["@context"]!.AsArray();
        contexts.RemoveAt(contexts.Count - 1);
        stripped["credentialSubject"]!["degree"] = "PhD";
        var strippedResult = await verifier.VerifyCredentialAsync(System.Text.Encoding.UTF8.GetBytes(stripped.ToJsonString()));
        strippedResult.Decision.Should().Be(VerificationDecision.Rejected);
        var proof = strippedResult.Check(CheckKinds.Proof)!;
        proof.Status.Should().Be(CheckStatus.Failed);
        proof.Diagnostics.Should().Contain(d => d.Code == "DATA_LOSS_DETECTION_ERROR");
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

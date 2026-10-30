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

    // The four positions the W3C VCDM 2.0 suite exercises for §11.1 language value objects (its
    // `*-language-direction-en-ok.json` fixtures): a JSON-pointer-like path into the credential object.
    public static TheoryData<string> LanguageValuePositions => new() { "name", "description", "issuer.name", "issuer.description" };

    private static Credential WithLanguageValue(string issuerDid, string position, bool withDirection)
    {
        var value = new JsonObject { ["@value"] = "Example Credential", ["@language"] = "en" };
        if (withDirection)
        {
            value["@direction"] = "ltr";
        }

        var document = JsonNode.Parse(Credential.Build()
            .WithIssuer(issuerDid)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal().ToUtf8().Span)!.AsObject();
        if (position.StartsWith("issuer.", StringComparison.Ordinal))
        {
            // The suite's issuer fixtures use the object form: {"id": did, "name": {...}}.
            document["issuer"] = new JsonObject { ["id"] = issuerDid, [position["issuer.".Length..]] = value };
        }
        else
        {
            document[position] = value;
        }

        return Credential.Parse(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
    }

    private static DataIntegrityIssuanceRequest Issuance(string cryptosuite, KeyPair keyPair) => new()
    {
        Cryptosuite = cryptosuite,
        Signer = new KeyPairSigner(keyPair, Crypto),
        VerificationMethod = $"did:key:{keyPair.MultibasePublicKey}#{keyPair.MultibasePublicKey}",
    };

    [Theory]
    [MemberData(nameof(LanguageValuePositions))]
    [FrTag("FR-011")]
    [FrTag("FR-040")]
    public async Task Rdfc_refuses_a_language_value_with_direction_in_every_suite_position_and_jcs_secures_it(string position)
    {
        // Scope decision (v1.2.0, docs/conformance.md): the RDFC suites cannot carry @direction losslessly
        // (DataProofs >= 1.5.0 fails closed), so issuance refuses it, naming the cause. The JCS suites sign the
        // JSON as written and are the supported path.
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        var withDirection = WithLanguageValue(did, position, withDirection: true);
        var rdfc = () => issuer.IssueAsync(withDirection, Issuance("eddsa-rdfc-2022", keyPair));
        (await rdfc.Should().ThrowExactlyAsync<InvalidOperationException>())
            .WithMessage("*eddsa-rdfc-2022*@direction*")
            .WithInnerException<DataProofsDotnet.ProofGenerationException>();

        var jcs = await issuer.IssueAsync(withDirection, Issuance("eddsa-jcs-2022", keyPair));
        (await verifier.VerifyCredentialAsync(jcs.Credential)).Decision.Should().Be(VerificationDecision.Accepted, position);

        // The limitation is the direction, not the language value object: language-only secures under RDFC.
        var languageOnly = await issuer.IssueAsync(WithLanguageValue(did, position, withDirection: false), Issuance("eddsa-rdfc-2022", keyPair));
        (await verifier.VerifyCredentialAsync(languageOnly.Credential)).Decision.Should().Be(VerificationDecision.Accepted, position);
    }

    [Theory]
    [MemberData(nameof(LanguageValuePositions))]
    [FrTag("FR-040")]
    public async Task Adding_a_direction_after_rdfc_signing_is_detected(string position)
    {
        // The security meaning of refusing @direction: under DataProofs <= 1.4 the signed bytes did not carry
        // the direction, so adding or flipping it after signing still verified. It is now a definitive failure.
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        var issued = await issuer.IssueAsync(WithLanguageValue(did, position, withDirection: false), Issuance("eddsa-rdfc-2022", keyPair));
        var tampered = JsonNode.Parse(issued.Credential.ToUtf8().Span)!.AsObject();
        var holder = position.StartsWith("issuer.", StringComparison.Ordinal) ? tampered["issuer"]!.AsObject() : tampered;
        holder[position.Split('.')[^1]]!.AsObject()["@direction"] = "rtl";

        var result = await verifier.VerifyCredentialAsync(System.Text.Encoding.UTF8.GetBytes(tampered.ToJsonString()));
        result.Decision.Should().Be(VerificationDecision.Rejected, position);
        var proof = result.Check(CheckKinds.Proof)!;
        proof.Status.Should().Be(CheckStatus.Failed);
        proof.Diagnostics.Should().Contain(d => d.Code == "DATA_LOSS_DETECTION_ERROR");
    }

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

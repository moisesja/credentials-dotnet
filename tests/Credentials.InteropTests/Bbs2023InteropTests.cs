using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Rdfc;
using Credentials.Roles;
using Credentials.Verification;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace Credentials.InteropTests;

/// <summary>
/// bbs-2023 (vc-di-bbs) interop (NFR-007), IsAvailable-gated. Derives a selective-disclosure proof with
/// the engine and pins the wire-format drift sentinels — the <c>bbs-2023</c> cryptosuite name and a
/// multibase-base64url (<c>u…</c>) derived <c>proofValue</c> — then confirms the derived proof verifies
/// and that tampering a revealed value breaks the cryptographically-enforced mandatory disclosure.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class Bbs2023InteropTests
{
    private static readonly DefaultKeyGenerator KeyGen = new();
    private static readonly bool Available = new Bbs2023Cryptosuite().IsAvailable;

    private static ServiceProvider Provider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid().UseBbs2023()).BuildServiceProvider();

    [SkippableFact]
    [TestSupport.FrTag("NFR-007")]
    public async Task Bbs_derived_proof_pins_the_vc_di_bbs_wire_format_and_verifies()
    {
        Skip.IfNot(Available, "the native BBS library is not available on this host.");
        using var provider = Provider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var baseCredential = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);
        var derived = await deriver.DeriveAsync(baseCredential, new BbsDisclosureRequest
        {
            RevealPointers = ["/credentialSubject/gpa"],
        });

        var proof = derived.AsElement().GetProperty("proof");
        proof.GetProperty("cryptosuite").GetString().Should().Be("bbs-2023", "the cryptosuite name is a drift sentinel");
        proof.GetProperty("proofValue").GetString().Should().StartWith("u",
            "a derived bbs-2023 proofValue is multibase-base64url (drift sentinel)");

        var result = await verifier.VerifyCredentialAsync(derived);
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [SkippableFact]
    [TestSupport.FrTag("NFR-007")]
    public async Task Bbs_tampered_revealed_mandatory_value_is_rejected()
    {
        Skip.IfNot(Available, "the native BBS library is not available on this host.");
        using var provider = Provider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var baseCredential = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);
        var derived = await deriver.DeriveAsync(baseCredential, new BbsDisclosureRequest
        {
            RevealPointers = ["/credentialSubject/gpa"],
        });

        // Tamper a revealed mandatory value (the issuer). The bbs header is recomputed from the revealed
        // mandatory messages, so it no longer matches the committed signature.
        var node = JsonNode.Parse(derived.ToBytes())!.AsObject();
        node["issuer"] = "did:example:not-the-real-issuer";
        var tampered = Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));

        var result = await verifier.VerifyCredentialAsync(tampered);
        result.Decision.Should().Be(VerificationDecision.Rejected, "a tampered mandatory value must not verify");
    }

    // Mirrors the M5 test / the Bbs2023 sample: signs a bbs-2023 base proof with a raw BLS key (the only
    // base-proof path the substrate exposes — engine issuance stays gated), so the holder can derive from it.
    private static async Task<Credential> CraftBaseAsync(string[] mandatoryPointers)
    {
        var bls = KeyGen.Generate(KeyType.Bls12381G2);
        var signerDid = $"did:key:{bls.MultibasePublicKey}";
        var vm = $"{signerDid}#{bls.MultibasePublicKey}";

        var credential = Credential.Build()
            .AddContext("https://www.w3.org/ns/credentials/examples/v2")
            .AddType("AlumniCredential")
            .WithIssuer(signerDid)
            .AddSubject(new JsonObject
            {
                ["id"] = "did:example:abcdefgh",
                ["alumniOf"] = "The School of Examples",
                ["gpa"] = "4.0",
                ["favoriteColor"] = "purple",
            })
            .Seal();

        var baseOptions = new DataIntegrityProof
        {
            Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
            VerificationMethod = vm,
            ProofPurpose = "assertionMethod",
            Created = "2026-01-02T00:00:00Z",
        };

        var hmacKey = new byte[32];
        for (var i = 0; i < hmacKey.Length; i++) hmacKey[i] = (byte)(i + 1);

        var baseProof = await new Bbs2023Cryptosuite().CreateBaseProofAsync(
            credential.AsElement(), baseOptions, bls.PrivateKey, hmacKey, mandatoryPointers);

        var node = JsonNode.Parse(credential.ToBytes())!.AsObject();
        node["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default);
        return Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));
    }
}

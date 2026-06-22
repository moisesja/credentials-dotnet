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

namespace Credentials.Rdfc.Tests;

/// <summary>
/// M5 end-to-end for the <c>bbs-2023</c> selective-disclosure cryptosuite: holder derivation (FR-031)
/// and verification of derived proofs (FR-042) through the real <c>AddCredentials().UseBbs2023()</c>
/// wiring. Issuance (FR-014) is gated — DataProofs exposes no key-store BBS create API — so base
/// credentials are crafted here directly via the substrate's raw-key API (test-only; the engine never
/// does raw-key issuance). Lives in the Rdfc test project so the dotNetRDF/Newtonsoft closure stays out
/// of the default test path (NFR-002).
/// </summary>
public sealed class Bbs2023SelectiveDisclosureTests
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    // The BBS native library ships with NetCrypto's closure; if a host lacks it, the lifecycle methods
    // throw and these tests are not meaningful. Gate on the capability so a binary-less host is a no-op.
    private static readonly bool BbsAvailable = new Bbs2023Cryptosuite().IsAvailable;

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid().UseBbs2023()).BuildServiceProvider();

    // ---- derive → verify ---------------------------------------------------------------------------

    [Fact]
    public async Task Bbs_derive_then_verify_round_trips()
    {
        if (!BbsAvailable) { return; } // BBS native lib ships with NetCrypto; guard a binary-less host
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);

        var derived = await deriver.DeriveAsync(
            baseCredential, new BbsDisclosureRequest { RevealPointers = ["/credentialSubject/gpa"] });

        derived.Securing.Should().Be(SecuringState.DataIntegrity);
        derived.HasEmbeddedProof.Should().BeTrue();

        // The reveal carries the mandatory group (issuer, subject id) + the selected gpa, and omits the
        // unselected claims (alumniOf, favoriteColor).
        var subject = derived.AsElement().GetProperty("credentialSubject");
        subject.TryGetProperty("id", out _).Should().BeTrue();          // mandatory
        subject.TryGetProperty("gpa", out _).Should().BeTrue();         // selected
        subject.TryGetProperty("favoriteColor", out _).Should().BeFalse(); // withheld
        subject.TryGetProperty("alumniOf", out _).Should().BeFalse();   // withheld

        var result = await verifier.VerifyCredentialAsync(derived);
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task Bbs_mandatory_group_is_always_revealed()
    {
        if (!BbsAvailable) { return; } // BBS native lib ships with NetCrypto; guard a binary-less host
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();

        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);

        // Reveal nothing extra: the mandatory group is still present.
        var derived = await deriver.DeriveAsync(baseCredential, new BbsDisclosureRequest());

        derived.Issuer.Should().NotBeNull();
        derived.AsElement().GetProperty("credentialSubject").TryGetProperty("id", out _).Should().BeTrue();
        derived.AsElement().GetProperty("credentialSubject").TryGetProperty("gpa", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Bbs_two_derivations_are_unlinkable_and_both_verify()
    {
        if (!BbsAvailable) { return; } // BBS native lib ships with NetCrypto; guard a binary-less host
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);
        var request = new BbsDisclosureRequest { RevealPointers = ["/credentialSubject/gpa"] };

        var first = await deriver.DeriveAsync(baseCredential, request);
        var second = await deriver.DeriveAsync(baseCredential, request);

        // Fresh random presentation headers ⇒ different derived proofValues (unlinkable, F9)...
        ProofValueOf(first).Should().NotBe(ProofValueOf(second));

        // ...and both still verify.
        (await verifier.VerifyCredentialAsync(first)).Decision.Should().Be(VerificationDecision.Accepted);
        (await verifier.VerifyCredentialAsync(second)).Decision.Should().Be(VerificationDecision.Accepted);
    }

    // ---- security ----------------------------------------------------------------------------------

    [Fact]
    public async Task Bbs_tampering_a_revealed_mandatory_value_is_rejected()
    {
        if (!BbsAvailable) { return; } // BBS native lib ships with NetCrypto; guard a binary-less host
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);
        var derived = await deriver.DeriveAsync(
            baseCredential, new BbsDisclosureRequest { RevealPointers = ["/credentialSubject/gpa"] });

        // Alter a revealed mandatory value (the issuer). The BBS header is recomputed from the revealed
        // mandatory messages, so a tampered mandatory statement no longer matches the committed header.
        var node = JsonNode.Parse(derived.ToBytes())!.AsObject();
        node["issuer"] = "did:example:attacker";
        var tampered = Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));

        var result = await verifier.VerifyCredentialAsync(tampered);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        // Either the BBS proof fails to verify (header mismatch) or the issuer binding fails — both Failed.
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Bbs_issuer_binding_rejects_a_mismatched_verification_method()
    {
        if (!BbsAvailable) { return; } // BBS native lib ships with NetCrypto; guard a binary-less host
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        // The base credential's issuer is a DID unrelated to the signing BLS key's DID: a valid BBS proof,
        // but the proof's verificationMethod base DID ≠ the credential issuer ⇒ issuer binding fails.
        var (baseCredential, _) = await CraftBaseAsync(
            ["/issuer", "/credentialSubject/id"], issuerDid: "did:example:not-the-signer");
        var derived = await deriver.DeriveAsync(baseCredential, new BbsDisclosureRequest());

        var result = await verifier.VerifyCredentialAsync(derived);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Diagnostics.Should().Contain(d => d.Code == "issuer_binding");
    }

    [Fact]
    public async Task Bbs_tampered_derived_proof_is_rejected_not_thrown()
    {
        if (!BbsAvailable) { return; } // BBS native lib ships with NetCrypto; guard a binary-less host
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);
        var derived = await deriver.DeriveAsync(
            baseCredential, new BbsDisclosureRequest { RevealPointers = ["/credentialSubject/gpa"] });

        // Corrupt a character of the derived proofValue.
        var node = JsonNode.Parse(derived.ToBytes())!.AsObject();
        var proof = node["proof"]!.AsObject();
        var pv = proof["proofValue"]!.GetValue<string>();
        proof["proofValue"] = pv[..^2] + (pv[^1] == 'A' ? "BB" : "AA");
        var tampered = Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));

        var result = await verifier.VerifyCredentialAsync(tampered);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    // ---- issuance gate (FR-014) --------------------------------------------------------------------

    [Fact]
    public async Task Bbs_issuance_is_gated()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var bls = KeyGen.Generate(KeyType.Bls12381G2);
        var did = $"did:key:{bls.MultibasePublicKey}";

        var credential = Credential.Build()
            .WithIssuer(did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();

        // bbs-2023 base proofs cannot be created through the single-message ISigner pipeline (no key-store
        // BBS create API exists; raw-key export would violate FR-015) — issuance fails fast.
        var act = () => issuer.IssueAsync(
            credential,
            new DataIntegrityIssuanceRequest
            {
                Cryptosuite = "bbs-2023",
                Signer = new KeyPairSigner(bls, Crypto),
                VerificationMethod = $"{did}#{bls.MultibasePublicKey}",
            });
        await act.Should().ThrowAsync<NotSupportedException>();
    }

    // ---- capabilities / DI -------------------------------------------------------------------------

    [Fact]
    public void UseBbs2023_adds_the_suite_to_capabilities_and_registers_the_deriver()
    {
        using var provider = BuildProvider();
        var capabilities = provider.GetRequiredService<ISecuringCapabilities>();

        capabilities.AvailableDataIntegritySuites.Should().Contain("bbs-2023");
        capabilities.IsSupported(SecuringSelector.DataIntegrity("bbs-2023")).Should().BeTrue();
        provider.GetService<IBbsDeriver>().Should().NotBeNull();
    }

    [Fact]
    public void UseBbs2023_is_idempotent()
    {
        using var provider = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseBbs2023().UseBbs2023())
            .BuildServiceProvider();

        provider.GetRequiredService<ISecuringCapabilities>().AvailableDataIntegritySuites.Should().Contain("bbs-2023");
    }

    // ---- helpers -----------------------------------------------------------------------------------

    /// <summary>
    /// Crafts a bbs-2023 base credential via the substrate's raw-key API (test-only — the engine gates
    /// issuance). The issuer is the BLS signing key's <c>did:key</c> unless <paramref name="issuerDid"/>
    /// overrides it (to exercise issuer-binding mismatch).
    /// </summary>
    private static async Task<(Credential Base, string Vm)> CraftBaseAsync(string[] mandatoryPointers, string? issuerDid = null)
    {
        var bls = KeyGen.Generate(KeyType.Bls12381G2);
        var signerDid = $"did:key:{bls.MultibasePublicKey}";
        var vm = $"{signerDid}#{bls.MultibasePublicKey}";

        var credential = Credential.Build()
            .AddContext("https://www.w3.org/ns/credentials/examples/v2")
            .AddType("AlumniCredential")
            .WithIssuer(issuerDid ?? signerDid)
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
        for (var i = 0; i < hmacKey.Length; i++)
        {
            hmacKey[i] = (byte)(i + 1);
        }

        var suite = new Bbs2023Cryptosuite();
        var baseProof = await suite.CreateBaseProofAsync(
            credential.AsElement(), baseOptions, bls.PrivateKey, hmacKey, mandatoryPointers);

        var node = JsonNode.Parse(credential.ToBytes())!.AsObject();
        node["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default);
        return (Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node)), vm);
    }

    private static string ProofValueOf(Credential credential) =>
        credential.AsElement().GetProperty("proof").GetProperty("proofValue").GetString()!;
}

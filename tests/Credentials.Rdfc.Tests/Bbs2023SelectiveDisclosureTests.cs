using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Rdfc;
using Credentials.Roles;
using Credentials.TestSupport;
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

    // The BBS native library ships in NetCrypto for every supported RID (osx-arm64/x64, linux-x64/arm64,
    // win-x64), so on a supported host BbsAvailable is true and the crypto tests below run for real.
    // COVERAGE NOTE: on a host that lacks the native library the `if (!BbsAvailable) { return; }` guards
    // make those tests a silent no-op — they report Passed without exercising any BBS path. A CI audit on
    // an unsupported RID must therefore read a green M5 crypto run as "not covered", not "verified".
    // (The non-crypto tests — issuance gate, capabilities, surface confinement — run unconditionally.)
    private static readonly bool BbsAvailable = new Bbs2023Cryptosuite().IsAvailable;

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid().UseBbs2023()).BuildServiceProvider();

    // ---- derive → verify ---------------------------------------------------------------------------

    [Fact]
    [FrTag("FR-031")]
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
    [FrTag("FR-042")]
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

    // ---- adversarial regressions (M5 adversarial pass, 2026-06-22) ---------------------------------

    [Theory]
    [InlineData("credentialSubject/gpa")] // missing leading '/'
    [InlineData("not-a-pointer")]
    [InlineData(" /credentialSubject")]   // leading whitespace
    [InlineData("\t")]
    public async Task Bbs_malformed_reveal_pointer_maps_to_credential_format_exception(string pointer)
    {
        if (!BbsAvailable) { return; }
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);

        // A malformed RFC 6901 pointer is malformed input → the documented CredentialFormatException,
        // never a raw substrate ArgumentException (which would leak the internal JsonPointer type).
        var act = () => deriver.DeriveAsync(baseCredential, new BbsDisclosureRequest { RevealPointers = [pointer] });
        await act.Should().ThrowAsync<CredentialFormatException>();
    }

    [Fact]
    public async Task Bbs_null_reveal_pointer_element_maps_to_credential_format_exception()
    {
        if (!BbsAvailable) { return; }
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);

        var act = () => deriver.DeriveAsync(baseCredential, new BbsDisclosureRequest { RevealPointers = [null!] });
        await act.Should().ThrowAsync<CredentialFormatException>();
    }

    [Fact]
    public async Task Bbs_nonexistent_reveal_pointer_reveals_nothing_extra_and_still_verifies()
    {
        if (!BbsAvailable) { return; }
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var (baseCredential, _) = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);

        // A well-formed pointer to an absent path is not an error — it just reveals nothing extra.
        var derived = await deriver.DeriveAsync(
            baseCredential, new BbsDisclosureRequest { RevealPointers = ["/credentialSubject/doesNotExist"] });
        (await verifier.VerifyCredentialAsync(derived)).Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task Bbs_withheld_validity_claim_not_in_mandatory_group_is_an_inherent_issuer_side_residual()
    {
        if (!BbsAvailable) { return; }
        using var provider = BuildProvider();
        var deriver = provider.GetRequiredService<IBbsDeriver>();
        var verifier = provider.GetRequiredService<IVerifier>();

        // Characterizes the inherent selective-disclosure residual (same class as the M4 SD-JWT residual):
        // an EXPIRED credential whose validUntil the issuer left OUT of the mandatory group. A holder
        // withholding it produces a genuinely valid proof over the reduced disclosure, and the verifier
        // cannot tell "no expiry" from "expiry hidden" — so it Accepts. The defence is issuer-side: validity
        // claims MUST be mandatory (documented on IBbsDeriver). This engine does not issue bbs-2023 bases.
        var notMandatory = await CraftExpiringBaseAsync(validUntilMandatory: false);
        var hidden = await deriver.DeriveAsync(notMandatory, new BbsDisclosureRequest()); // withhold validUntil
        (await verifier.VerifyCredentialAsync(hidden)).Decision.Should().Be(VerificationDecision.Accepted);

        // Mitigation: when the issuer puts validUntil in the MANDATORY group, the holder cannot hide it
        // (mandatory disclosure is cryptographically enforced) and the expired credential is correctly Rejected.
        var mandatory = await CraftExpiringBaseAsync(validUntilMandatory: true);
        var forced = await deriver.DeriveAsync(mandatory, new BbsDisclosureRequest());
        var result = await verifier.VerifyCredentialAsync(forced);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Failed);
    }

    // ---- issuance gate (FR-014) --------------------------------------------------------------------

    [Fact]
    [FrTag("FR-014")]
    [FrTag("FR-015")] // the gate exists because raw-key BBS issuance is refused — keys flow only via ISigner
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

        return (await EmbedBaseProofAsync(credential, vm, bls, mandatoryPointers), vm);
    }

    /// <summary>Crafts a base credential carrying an EXPIRED <c>validUntil</c>, optionally in the mandatory group.</summary>
    private static async Task<Credential> CraftExpiringBaseAsync(bool validUntilMandatory)
    {
        var bls = KeyGen.Generate(KeyType.Bls12381G2);
        var signerDid = $"did:key:{bls.MultibasePublicKey}";
        var vm = $"{signerDid}#{bls.MultibasePublicKey}";

        var credential = Credential.Build()
            .AddContext("https://www.w3.org/ns/credentials/examples/v2")
            .WithIssuer(signerDid)
            .AddSubject(new JsonObject { ["id"] = "did:example:abcdefgh", ["alumniOf"] = "The School of Examples" })
            .WithValidUntil(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .Seal();

        string[] mandatory = validUntilMandatory
            ? ["/issuer", "/credentialSubject/id", "/validUntil"]
            : ["/issuer", "/credentialSubject/id"];
        return await EmbedBaseProofAsync(credential, vm, bls, mandatory);
    }

    private static async Task<Credential> EmbedBaseProofAsync(Credential credential, string vm, KeyPair bls, string[] mandatoryPointers)
    {
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
        return Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));
    }

    private static string ProofValueOf(Credential credential) =>
        credential.AsElement().GetProperty("proof").GetProperty("proofValue").GetString()!;
}

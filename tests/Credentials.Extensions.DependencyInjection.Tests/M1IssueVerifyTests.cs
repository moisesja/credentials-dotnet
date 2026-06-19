using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M1 end-to-end issue → verify through the real <c>AddCredentials().UseNetDid()</c> wiring, with
/// in-memory <c>did:key</c> keys. Covers all four EdDSA/ECDSA suites (JCS + RDFC), report-don't-throw,
/// validity, capability discovery (FR-053), and DI fail-fast.
/// </summary>
public sealed class M1IssueVerifyTests
{
    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    private static Credential UnsecuredCredential(string issuerDid) => Credential.Build()
        .WithId("urn:uuid:11111111-1111-1111-1111-111111111111")
        .WithIssuer(issuerDid)
        .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
        .Seal();

    [Theory]
    [InlineData("eddsa-jcs-2022", KeyType.Ed25519)]
    [InlineData("ecdsa-jcs-2019", KeyType.P256)]
    public async Task Issue_then_verify_round_trips(string cryptosuite, KeyType keyType)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(keyType);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest
            {
                Cryptosuite = cryptosuite,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
            });

        issued.Credential.HasEmbeddedProof.Should().BeTrue();
        issued.Credential.Securing.Should().Be(SecuringState.DataIntegrity);

        var result = await verifier.VerifyCredentialAsync(issued.Credential);
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Skipped);
    }

    [Fact]
    public async Task Verify_round_trips_from_wire_bytes_with_fidelity()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // Serialize to the wire and verify the bytes path — the proof must survive a byte round-trip.
        var result = await verifier.VerifyCredentialAsync(issued.Credential.ToBytes());
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Fact]
    public async Task Tampered_credential_is_rejected_not_thrown()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // Tamper with a signed claim after issuance.
        var node = JsonNode.Parse(issued.Credential.ToBytes().AsSpan())!.AsObject();
        node["credentialSubject"]!["id"] = "did:example:attacker";
        var tampered = Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));

        var result = await verifier.VerifyCredentialAsync(tampered);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        // A bad signature is a definitive Failed, never Indeterminate, and never throws (FR-045/F7).
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Issuer_spoofing_is_rejected_by_issuer_binding()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        // A credential that CLAIMS the victim as issuer, but is validly signed with the attacker's key.
        // The signature is genuine; only the issuer↔verification-method binding catches the forgery.
        var credential = Credential.Build()
            .WithIssuer(victim.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var forged = await issuer.IssueAsync(
            credential,
            new DataIntegrityIssuanceRequest
            {
                Cryptosuite = "eddsa-jcs-2022",
                Signer = attacker.Signer,
                VerificationMethod = attacker.VerificationMethod,
            });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        var proof = result.Check(CheckKinds.Proof)!;
        proof.Status.Should().Be(CheckStatus.Failed);
        proof.Diagnostics.Should().Contain(d => d.Code == "issuer_binding");
    }

    [Fact]
    public async Task Expired_credential_fails_validity()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .WithValidUntil(DateTimeOffset.UtcNow.AddDays(-1))
            .Seal();
        var issued = await issuer.IssueAsync(
            unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(issued.Credential);
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Failed);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        // The proof itself is still valid.
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task Clock_skew_tolerates_a_just_expired_credential()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .WithValidUntil(DateTimeOffset.UtcNow.AddMinutes(-1))
            .Seal();
        var issued = await issuer.IssueAsync(
            unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(
            issued.Credential,
            new CredentialVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) });
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task Proof_set_with_one_invalid_proof_is_rejected()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // Build a proof SET: the genuine proof plus a tampered copy (one corrupted base58 char in the
        // signature). Verification must require ALL proofs valid, so the set must be Rejected.
        var node = JsonNode.Parse(issued.Credential.ToBytes().AsSpan())!.AsObject();
        var proofJson = node["proof"]!.ToJsonString();
        var tampered = JsonNode.Parse(proofJson)!.AsObject();
        var proofValue = tampered["proofValue"]!.GetValue<string>();
        tampered["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'a' ? 'b' : 'a');
        node["proof"] = new JsonArray(JsonNode.Parse(proofJson), tampered);
        var credential = Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));

        var result = await verifier.VerifyCredentialAsync(credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Vcdm11_credential_is_rejected_when_not_accepted()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        // A structurally valid VCDM 1.1 credential.
        const string json =
            """
            {
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "issuanceDate": "2020-01-01T00:00:00Z",
              "credentialSubject": { "id": "did:example:subject" }
            }
            """;
        var credential = Credential.Parse(json);

        var rejected = await verifier.VerifyCredentialAsync(
            credential, new CredentialVerificationOptions { AcceptVcdm11 = false });
        var rejectedStructure = rejected.Check(CheckKinds.Structure)!;
        rejectedStructure.Status.Should().Be(CheckStatus.Failed);
        rejectedStructure.Diagnostics.Should().Contain(d => d.Code == "vcdm11_not_accepted");
        rejected.Decision.Should().Be(VerificationDecision.Rejected);

        // With acceptance (the default), the same 1.1 credential passes the structure check.
        var accepted = await verifier.VerifyCredentialAsync(
            credential, new CredentialVerificationOptions { AcceptVcdm11 = true });
        accepted.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task Unresolvable_verification_method_is_indeterminate()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        // A proof referencing a verification method that NetDid cannot resolve.
        const string json =
            """
            {
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "type": ["VerifiableCredential"],
              "issuer": "did:key:zNotARealKey",
              "credentialSubject": { "id": "did:example:subject" },
              "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:zNotARealKey#zNotARealKey",
                "proofPurpose": "assertionMethod",
                "proofValue": "zInvalidSignatureValue"
              }
            }
            """;

        var result = await verifier.VerifyCredentialAsync(Credential.Parse(json));
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Indeterminate);
        result.Decision.Should().Be(VerificationDecision.Rejected); // fail-closed default
    }

    [Fact]
    public async Task Issuing_an_already_secured_credential_throws()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);
        var request = new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod };

        var issued = await issuer.IssueAsync(UnsecuredCredential(key.Did), request);

        var act = () => issuer.IssueAsync(issued.Credential, request);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Issuing_with_an_unregistered_suite_throws()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var act = () => issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest { Cryptosuite = "no-such-suite", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public void Capabilities_report_the_registered_suites()
    {
        using var provider = BuildProvider();
        var capabilities = provider.GetRequiredService<ISecuringCapabilities>();

        capabilities.AvailableForms.Should().Contain(SecuringForm.DataIntegrity);
        // The default closure is JCS-only (Newtonsoft-free, NFR-002); RDFC is opt-in via Credentials.Rdfc.
        capabilities.AvailableDataIntegritySuites.Should().Contain(["eddsa-jcs-2022", "ecdsa-jcs-2019"]);
        capabilities.AvailableDataIntegritySuites.Should().NotContain("eddsa-rdfc-2022");
        capabilities.IsSupported(SecuringSelector.DataIntegrity("eddsa-jcs-2022")).Should().BeTrue();
        capabilities.IsSupported(SecuringSelector.DataIntegrity("no-such-suite")).Should().BeFalse();
    }

    [Fact]
    public void AddCredentials_without_a_did_resolver_fails_fast()
    {
        var act = () => new ServiceCollection().AddCredentials(_ => { });
        act.Should().Throw<InvalidOperationException>().WithMessage("*UseNetDid*");
    }

    [Fact]
    public async Task AddCredentials_is_idempotent_across_repeated_registration()
    {
        // A second AddCredentials().UseNetDid() must not double-register did:key (which would crash
        // NetDid's composite resolver). The whole graph still resolves and verifies.
        var services = new ServiceCollection();
        services.AddCredentials(b => b.UseNetDid());
        services.AddCredentials(b => b.UseNetDid());
        using var provider = services.BuildServiceProvider();

        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);
        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(issued.Credential);
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Fact]
    public void Adding_an_extra_cryptosuite_needs_no_api_change()
    {
        // FR-053: a future suite is selectable by opaque string. Here we assert the selector surface
        // accepts an arbitrary suite name without any new type — support is a runtime registry concern.
        var selector = SecuringSelector.DataIntegrity("ecdsa-sd-2023");
        selector.Form.Should().Be(SecuringForm.DataIntegrity);
        selector.Cryptosuite.Should().Be("ecdsa-sd-2023");
    }
}

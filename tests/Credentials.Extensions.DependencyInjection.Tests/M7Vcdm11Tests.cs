using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Securing;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M7 — VCDM 1.1 verify (FR-044 / D8). The engine ISSUES 2.0 only but VERIFIES 1.1 on both the credential and
/// presentation paths, honoring <c>AcceptVcdm11</c>, projecting validity from <c>issuanceDate</c>/
/// <c>expirationDate</c>, and never upgrading a 1.1 document to 2.0. A secured 1.1 fixture is produced the way
/// a foreign 1.1 issuer would: a hand-built 1.1 document signed faithfully via the Data Integrity path (the
/// issuer signs the document's exact bytes; the 2.0 pin lives only in <c>CredentialBuilder</c>).
/// </summary>
public sealed class M7Vcdm11Tests
{
    private const string Challenge = "challenge-m7-001";
    private const string Domain = "https://verifier.example";

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    private static string V11CredentialJson(string issuerDid, string issuanceDate, string? expirationDate = null)
    {
        var obj = new JsonObject
        {
            ["@context"] = new JsonArray("https://www.w3.org/2018/credentials/v1"),
            ["type"] = new JsonArray("VerifiableCredential"),
            ["issuer"] = issuerDid,
            ["issuanceDate"] = issuanceDate,
            ["credentialSubject"] = new JsonObject { ["id"] = "did:example:subject", ["name"] = "Alice" },
        };
        if (expirationDate is not null)
        {
            obj["expirationDate"] = expirationDate;
        }

        return obj.ToJsonString();
    }

    /// <summary>
    /// Produces a Data-Integrity-secured VCDM 1.1 credential the way a foreign 1.1 issuer would — by signing a
    /// hand-built 1.1 document through the engine's INTERNAL Data Integrity mechanism, deliberately NOT the
    /// public <see cref="IIssuer"/>, which is VCDM 2.0 only by contract (D8) and rejects 1.1. The signed bytes
    /// are byte-identical to what the issuer would produce for the same document (sign-exact-bytes).
    /// </summary>
    private static async Task<Credential> SignV11CredentialAsync(
        ServiceProvider provider, string issuanceDate = "2020-01-01T00:00:00Z", string? expirationDate = null)
    {
        var issuerKey = TestKeys.New(KeyType.Ed25519);
        var unsecured = Credential.Parse(V11CredentialJson(issuerKey.Did, issuanceDate, expirationDate));

        var mechanism = provider.GetRequiredService<SecuringMechanismRegistry>()
            .ResolveForIssue(SecuringForm.DataIntegrity, "eddsa-jcs-2022");
        var outcome = await mechanism.SecureAsync(new SecureRequest
        {
            Document = unsecured.AsElement(),
            Cryptosuite = "eddsa-jcs-2022",
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
        }, CancellationToken.None);

        return Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(outcome.Document));
    }

    [Fact]
    public async Task V11_credential_di_secured_verifies_and_is_accepted()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        var secured = await SignV11CredentialAsync(provider);

        var result = await verifier.VerifyCredentialAsync(
            secured.ToBytes(), new CredentialVerificationOptions { AcceptVcdm11 = true });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Version.Should().Be(VcdmVersion.V1_1);
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task V11_credential_is_rejected_when_1_1_is_not_accepted()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        var secured = await SignV11CredentialAsync(provider);

        var result = await verifier.VerifyCredentialAsync(
            secured.ToBytes(), new CredentialVerificationOptions { AcceptVcdm11 = false });

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        result.Check(CheckKinds.Structure)!.Diagnostics.Should().Contain(d => d.Code == "vcdm11_not_accepted");
    }

    [Fact]
    public async Task V11_not_yet_valid_diagnostic_points_at_issuanceDate()
    {
        // G2: the validity window is projected from issuanceDate, and the diagnostic must name the member that
        // exists in the 1.1 document (/issuanceDate), not the 2.0 /validFrom.
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        var credential = Credential.Parse(V11CredentialJson("did:example:issuer", "2030-01-01T00:00:00Z"));
        var result = await verifier.VerifyCredentialAsync(credential, new CredentialVerificationOptions
        {
            AcceptVcdm11 = true,
            VerificationTime = DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
        });

        var validity = result.Check(CheckKinds.Validity)!;
        validity.Status.Should().Be(CheckStatus.Failed);
        validity.Diagnostics.Should().Contain(d => d.Code == "not_yet_valid" && d.JsonPointer == "/issuanceDate");
        validity.Diagnostics.Should().NotContain(d => d.JsonPointer == "/validFrom");
    }

    [Fact]
    public async Task V11_expired_diagnostic_points_at_expirationDate()
    {
        // G2: an expired 1.1 credential reports /expirationDate, not the 2.0 /validUntil.
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        var credential = Credential.Parse(
            V11CredentialJson("did:example:issuer", "2010-01-01T00:00:00Z", "2015-01-01T00:00:00Z"));
        var result = await verifier.VerifyCredentialAsync(credential, new CredentialVerificationOptions
        {
            AcceptVcdm11 = true,
            VerificationTime = DateTimeOffset.Parse("2020-01-01T00:00:00Z"),
        });

        var validity = result.Check(CheckKinds.Validity)!;
        validity.Status.Should().Be(CheckStatus.Failed);
        validity.Diagnostics.Should().Contain(d => d.Code == "expired" && d.JsonPointer == "/expirationDate");
        validity.Diagnostics.Should().NotContain(d => d.JsonPointer == "/validUntil");
    }

    [Fact]
    public async Task V11_presentation_di_bound_verifies_and_is_accepted()
    {
        using var provider = BuildProvider();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var secured = await SignV11CredentialAsync(provider);
        var holderKey = TestKeys.New(KeyType.Ed25519);

        // A hand-built 1.1 presentation embedding the secured 1.1 credential, then holder-bound (DI auth proof).
        var vpObject = new JsonObject
        {
            ["@context"] = new JsonArray("https://www.w3.org/2018/credentials/v1"),
            ["type"] = new JsonArray("VerifiablePresentation"),
            ["holder"] = holderKey.Did,
            ["verifiableCredential"] = new JsonArray(JsonNode.Parse(secured.ToBytes())!),
        };
        var vp = VerifiablePresentation.Parse(vpObject.ToJsonString());
        vp.Version.Should().Be(VcdmVersion.V1_1);

        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });
        bound.Version.Should().Be(VcdmVersion.V1_1); // no upgrade through binding

        var result = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Check(CheckKinds.HolderBinding)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
        result.Credentials.Should().HaveCount(1);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task V11_presentation_is_rejected_when_1_1_is_not_accepted()
    {
        // G1: the presentation envelope itself is 1.1 and must be gated by AcceptVcdm11 (the gap M7 closes).
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        var vpObject = new JsonObject
        {
            ["@context"] = new JsonArray("https://www.w3.org/2018/credentials/v1"),
            ["type"] = new JsonArray("VerifiablePresentation"),
            ["holder"] = "did:example:holder",
        };
        var vp = VerifiablePresentation.Parse(vpObject.ToJsonString());

        var options = new PresentationVerificationOptions
        {
            RequireHolderBinding = false,        // isolate the version gate
            RequireAtLeastOneCredential = false, // no children needed for this check
            CredentialOptions = new CredentialVerificationOptions { AcceptVcdm11 = false },
        };
        var rejected = await verifier.VerifyPresentationAsync(vp, options);

        rejected.Decision.Should().Be(VerificationDecision.Rejected, rejected.ToString());
        var structure = rejected.Check(CheckKinds.Structure)!;
        structure.Status.Should().Be(CheckStatus.Failed);
        structure.Diagnostics.Should().Contain(d => d.Code == "vcdm11_not_accepted");

        // ...and accepted (structure passes) when 1.1 is allowed.
        var allowed = await verifier.VerifyPresentationAsync(vp, options with
        {
            CredentialOptions = new CredentialVerificationOptions { AcceptVcdm11 = true },
        });
        allowed.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task V20_presentation_with_a_v11_child_rejects_the_child_when_not_accepted()
    {
        // G3: a 2.0 VP can legitimately carry a 1.1 credential; with AcceptVcdm11=false the CHILD is rejected
        // (inherited flag), while the 2.0 VP envelope's own structure still passes.
        using var provider = BuildProvider();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var secured = await SignV11CredentialAsync(provider);
        var holderKey = TestKeys.New(KeyType.Ed25519);

        var held = holder.Ingest(secured.ToBytes());
        var vp = holder.BuildPresentation(new VpAssemblyRequest // builder pins the VP envelope to 2.0
        {
            Holder = holderKey.Did,
            Credentials = [ContainedCredential.Embedded(held.Credential)],
        });
        vp.Version.Should().Be(VcdmVersion.V2_0);

        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var result = await verifier.VerifyPresentationAsync(bound, new PresentationVerificationOptions
        {
            ExpectedChallenge = Challenge,
            ExpectedDomain = Domain,
            CredentialOptions = new CredentialVerificationOptions { AcceptVcdm11 = false },
        });

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed); // the 2.0 VP itself is fine
        result.Credentials.Should().HaveCount(1);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Rejected);
        result.Credentials[0].Check(CheckKinds.Structure)!.Diagnostics
            .Should().Contain(d => d.Code == "vcdm11_not_accepted");
    }

    [Fact]
    public async Task IssueAsync_rejects_a_vcdm_1_1_credential()
    {
        // D8/FR-044: issuance is VCDM 2.0 only. The public issuer must REJECT a (parsed) 1.1 credential rather
        // than mint it — the contract is enforced at the role boundary, not merely assumed from the builder.
        // This is the guard that makes "we verify 1.1, we never issue it" true of the public API.
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var issuerKey = TestKeys.New(KeyType.Ed25519);
        var v11 = Credential.Parse(V11CredentialJson(issuerKey.Did, "2020-01-01T00:00:00Z"));

        var act = async () => await issuer.IssueAsync(v11, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-jcs-2022",
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
        });

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*VCDM 2.0 only*");
    }

    [Fact]
    public async Task Unknown_version_diagnostic_follows_parse_success_not_member_presence()
    {
        // Point 2 (review): the Unknown diagnostic pointer must follow PARSE SUCCESS (like ValidityProjection's
        // `validUntil ?? expirationDate`), not member presence. A present-but-MALFORMED validUntil must not
        // steal the pointer from the expirationDate whose value actually supplied the window.
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        const string json =
            """
            {
              "@context": ["https://example.com/not-a-vcdm-context"],
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "issuanceDate": "2010-01-01T00:00:00Z",
              "validUntil": "not-a-date",
              "expirationDate": "2015-01-01T00:00:00Z",
              "credentialSubject": { "id": "did:example:subject" }
            }
            """;
        var result = await verifier.VerifyCredentialAsync(Credential.Parse(json), new CredentialVerificationOptions
        {
            VerificationTime = DateTimeOffset.Parse("2020-01-01T00:00:00Z"),
        });

        var validity = result.Check(CheckKinds.Validity)!;
        validity.Diagnostics.Should().Contain(d => d.Code == "expired" && d.JsonPointer == "/expirationDate");
        validity.Diagnostics.Should().NotContain(d => d.JsonPointer == "/validUntil");
    }

    [Fact]
    public async Task Unknown_version_expired_diagnostic_names_the_member_that_exists()
    {
        // ATK5 (adversarial): an Unknown-version credential is rejected by structure regardless, but its
        // validity diagnostic must stay honest — it carries expirationDate (no validUntil), and the Unknown
        // branch mirrors ValidityProjection's fallback, so the pointer must name /expirationDate, not /validUntil.
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        const string json =
            """
            {
              "@context": ["https://example.com/not-a-vcdm-context"],
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "issuanceDate": "2010-01-01T00:00:00Z",
              "expirationDate": "2015-01-01T00:00:00Z",
              "credentialSubject": { "id": "did:example:subject" }
            }
            """;
        var result = await verifier.VerifyCredentialAsync(Credential.Parse(json), new CredentialVerificationOptions
        {
            VerificationTime = DateTimeOffset.Parse("2020-01-01T00:00:00Z"),
        });

        result.Decision.Should().Be(VerificationDecision.Rejected); // Unknown rejected by structure
        var validity = result.Check(CheckKinds.Validity)!;
        validity.Diagnostics.Should().Contain(d => d.Code == "expired" && d.JsonPointer == "/expirationDate");
        validity.Diagnostics.Should().NotContain(d => d.JsonPointer == "/validUntil");
    }

    [Fact]
    public async Task Unknown_context_credential_is_rejected()
    {
        // Positive version detection: a non-VCDM base context is Unknown and rejected (never guessed as 1.1/2.0).
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        const string json =
            """
            {
              "@context": ["https://example.com/not-a-vcdm-context"],
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "credentialSubject": { "id": "did:example:subject" }
            }
            """;
        var result = await verifier.VerifyCredentialAsync(Credential.Parse(json), new CredentialVerificationOptions());

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Failed);
    }
}

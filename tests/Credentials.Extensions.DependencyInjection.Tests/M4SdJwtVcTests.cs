using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Schema;
using Credentials.Securing;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NSubstitute;
using Xunit;
using Base64Url = System.Buffers.Text.Base64Url;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M4 end-to-end issue → verify for SD-JWT VC (FR-013) through the real <c>AddCredentials().UseNetDid()</c>
/// wiring with in-memory <c>did:key</c> keys. Covers the round trip + media/typ/vct profile, selective
/// disclosure, the reserved/structural disclosure guards, the optional <c>cnf</c>, issuer binding
/// (post-sign + self-consistent forgery + missing kid), F7 (bad-sig → Failed vs unresolvable → Indeterminate),
/// validity, fail-fast on unsupported keys, detection, and the Type Metadata hook.
/// </summary>
public sealed class M4SdJwtVcTests
{
    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    private static ServiceProvider BuildProvider(ICredentialTypeMetadataResolver metadata) =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid().UseTypeMetadataResolver(metadata)).BuildServiceProvider();

    private static Credential UnsecuredCredential(string issuerDid) => Credential.Build()
        .WithId("urn:uuid:44444444-4444-4444-4444-444444444444")
        .WithIssuer(issuerDid)
        .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["given_name"] = "Alice", ["age"] = 42 })
        .Seal();

    private const string Vct = "https://credentials.example/identity_credential";

    // ---- Round-trip ------------------------------------------------------------------------------

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task SdJwtVc_issue_then_verify_round_trips(KeyType keyType)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(keyType);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
                Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name")],
            });

        issued.Form.Should().Be(SecuringState.SdJwtVc);
        issued.MediaType.Should().Be("application/dc+sd-jwt");
        issued.CompactSdJwt.Should().NotBeNullOrEmpty();
        issued.CompactSdJwt!.Should().EndWith("~"); // SD-JWT portion ends in '~' (no KB-JWT)
        issued.Credential.Securing.Should().Be(SecuringState.SdJwtVc);
        issued.Credential.CompactEnvelope.Should().Be(issued.CompactSdJwt);

        // Verify the issued credential object directly...
        var direct = await verifier.VerifyCredentialAsync(issued.Credential);
        direct.Decision.Should().Be(VerificationDecision.Accepted, direct.ToString());
        direct.Mechanism.Should().Be(SecuringState.SdJwtVc);
        direct.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
        direct.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
        direct.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Passed);

        // ...and from the verbatim compact SD-JWT wire bytes (the bytes overload + envelope detection).
        var wire = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        wire.Decision.Should().Be(VerificationDecision.Accepted, wire.ToString());
        wire.Mechanism.Should().Be(SecuringState.SdJwtVc);
    }

    [Fact]
    public async Task SdJwtVc_pins_typ_media_and_vct_and_iss_in_the_clear()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var header = IssuerJwtHeader(issued.CompactSdJwt!);
        header["typ"]!.GetValue<string>().Should().Be("dc+sd-jwt");

        var payload = IssuerJwtPayload(issued.CompactSdJwt!);
        payload["vct"]!.GetValue<string>().Should().Be(Vct);                 // vct in the clear
        payload["iss"]!.GetValue<string>().Should().Be(key.Did);            // iss = issuer DID (binding anchor)
        payload["issuer"]!.GetValue<string>().Should().Be(key.Did);        // VCDM issuer preserved
    }

    [Fact]
    public async Task SdJwtVc_selective_disclosure_keeps_the_value_out_of_the_issuer_jwt()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
                Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name")],
            });

        // The issuer-JWT cleartext credentialSubject carries a `_sd` digest array, not the value.
        var subject = IssuerJwtPayload(issued.CompactSdJwt!)["credentialSubject"]!.AsObject();
        subject.ContainsKey("given_name").Should().BeFalse();
        subject.ContainsKey("_sd").Should().BeTrue();

        // The full SD-JWT carries at least one disclosure (the given_name), and it still verifies.
        issued.CompactSdJwt!.Split('~').Length.Should().BeGreaterThan(2); // issuerJwt ~ D1 ~ (trailing)
        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Fact]
    public async Task SdJwtVc_with_holder_binding_carries_a_cnf_key_and_still_verifies()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);
        var holder = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
                HolderBinding = HolderBindingKey.FromMultikey(holder.Signer.MultibasePublicKey),
            });

        IssuerJwtPayload(issued.CompactSdJwt!).ContainsKey("cnf").Should().BeTrue();

        // M4 verifies with RequireKeyBinding = false — a cnf-bearing SD-JWT without a KB-JWT still verifies.
        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    // ---- Disclosure guards (issue-side) -----------------------------------------------------------

    [Theory]
    [InlineData("issuer")]
    [InlineData("type")]
    [InlineData("@context")]
    [InlineData("id")]
    public async Task SdJwtVc_disclosing_a_structural_member_throws(string member)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var act = () => issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
                Disclosable = [DisclosureSelector.Claim(member)],
            });
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task SdJwtVc_disclosing_credentialSubject_as_a_whole_throws()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var act = () => issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
                Disclosable = [DisclosureSelector.Claim("credentialSubject")],
            });
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData("vct")]
    [InlineData("iss")]
    [InlineData("cnf")]
    [InlineData("status")]
    public async Task SdJwtVc_disclosing_a_reserved_claim_throws(string reserved)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var act = () => issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = key.Signer,
                VerificationMethod = key.VerificationMethod,
                Disclosable = [DisclosureSelector.Claim(reserved)],
            });
        await act.Should().ThrowAsync<ArgumentException>();
    }

    // ---- Issuer binding (the load-bearing security tests) -----------------------------------------

    [Fact]
    public async Task SdJwtVc_issuer_spoofing_is_rejected_by_issuer_binding()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        // iss = victim (via the VCDM issuer), but validly signed with the attacker's key under the attacker's kid.
        var forged = await issuer.IssueAsync(
            UnsecuredCredential(victim.Did),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = attacker.Signer, VerificationMethod = attacker.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        var proof = result.Check(CheckKinds.Proof)!;
        proof.Status.Should().Be(CheckStatus.Failed);
        proof.Diagnostics.Should().Contain(d => d.Code == "issuer_binding");
    }

    [Fact]
    public async Task SdJwtVc_self_consistent_forgery_under_victim_kid_fails_signature()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        // iss = victim AND kid = victim's VM, but signed with the ATTACKER's key. The binding would pass,
        // so only the signature check (against the victim's resolved key) catches the forgery.
        var forged = await issuer.IssueAsync(
            UnsecuredCredential(victim.Did),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = attacker.Signer, VerificationMethod = victim.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task SdJwtVc_missing_kid_is_rejected_fail_closed()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // A hand-crafted SD-JWT with the right typ but NO kid — there is no signer identity to bind the
        // issuer to, so it must be rejected (fail closed), not Indeterminate.
        var sdJwt = FabricateSdJwt(
            new JsonObject { ["alg"] = "EdDSA", ["typ"] = "dc+sd-jwt" },
            MinimalSdJwtPayload(key.Did));

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(sdJwt));
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task SdJwtVc_unresolvable_kid_is_indeterminate_not_failed()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // Valid structure + a kid that NetDid cannot resolve: key resolution fails BEFORE any signature
        // check, so the proof is Indeterminate (F7) — a DID/IO failure is not a crypto failure.
        var sdJwt = FabricateSdJwt(
            new JsonObject { ["alg"] = "EdDSA", ["typ"] = "dc+sd-jwt", ["kid"] = "did:key:zNotARealKey#zNotARealKey" },
            MinimalSdJwtPayload(key.Did));

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(sdJwt));
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Indeterminate);
        result.Decision.Should().Be(VerificationDecision.Rejected); // fail-closed default
    }

    [Fact]
    public async Task SdJwtVc_tampered_issuer_signature_is_rejected_not_thrown()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // Flip the last character of the issuer-JWT signature segment, leaving the SD-JWT structure intact.
        var segments = issued.CompactSdJwt!.Split('~');
        var jwtParts = segments[0].Split('.');
        var sig = jwtParts[2];
        jwtParts[2] = sig[..^1] + (sig[^1] == 'A' ? 'B' : 'A');
        segments[0] = string.Join('.', jwtParts);
        var tampered = string.Join('~', segments);

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(tampered));
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task SdJwtVc_expired_is_rejected_by_validity()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var credential = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .WithValidFrom(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .WithValidUntil(new DateTimeOffset(2020, 2, 1, 0, 0, 0, TimeSpan.Zero))
            .Seal();

        var issued = await issuer.IssueAsync(
            credential,
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);    // the signature is fine...
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Failed); // ...but it has expired
    }

    [Fact]
    public async Task SdJwtVc_unsupported_key_type_fails_fast_at_issue()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var signer = UnsupportedSigner();

        var act = () => issuer.IssueAsync(
            UnsecuredCredential("did:example:issuer"),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = signer, VerificationMethod = "did:example:issuer#k" });
        await act.Should().ThrowAsync<NotSupportedException>();
    }

    // ---- Type Metadata hook + capabilities --------------------------------------------------------

    [Fact]
    public async Task SdJwtVc_type_metadata_resolver_is_invoked_with_the_vct()
    {
        var metadata = Substitute.For<ICredentialTypeMetadataResolver>();
        metadata.ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new JsonObject { ["vct"] = Vct });

        using var provider = BuildProvider(metadata);
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        await metadata.Received().ResolveAsync(Vct, Arg.Any<CancellationToken>());
    }

    [Fact]
    public void Capabilities_report_the_sdjwtvc_form()
    {
        using var provider = BuildProvider();
        var capabilities = provider.GetRequiredService<ISecuringCapabilities>();

        capabilities.AvailableForms.Should().Contain(SecuringForm.SdJwtVc);
        capabilities.IsSupported(SecuringSelector.SdJwtVc()).Should().BeTrue();
    }

    // ---- helpers ----------------------------------------------------------------------------------

    private static JsonObject IssuerJwtHeader(string compactSdJwt) =>
        DecodeSegment(compactSdJwt.Split('~')[0].Split('.')[0]);

    private static JsonObject IssuerJwtPayload(string compactSdJwt) =>
        DecodeSegment(compactSdJwt.Split('~')[0].Split('.')[1]);

    private static JsonObject DecodeSegment(string segment) =>
        JsonNode.Parse(Base64Url.DecodeFromChars(segment))!.AsObject();

    private static JsonObject MinimalSdJwtPayload(string issuerDid) => new()
    {
        ["@context"] = new JsonArray("https://www.w3.org/ns/credentials/v2"),
        ["type"] = new JsonArray("VerifiableCredential"),
        ["issuer"] = issuerDid,
        ["iss"] = issuerDid,
        ["vct"] = Vct,
        ["credentialSubject"] = new JsonObject { ["id"] = "did:example:subject" },
    };

    /// <summary>Builds a compact SD-JWT (issuer-JWT with the given header/payload + a junk signature, then a trailing '~').</summary>
    private static string FabricateSdJwt(JsonObject header, JsonObject payload)
    {
        var h = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(payload));
        var s = Base64Url.EncodeToString(new byte[64]);
        return $"{h}.{p}.{s}~";
    }

    /// <summary>A signer that reports an out-of-scope key type, to exercise the fail-fast path.</summary>
    private static ISigner UnsupportedSigner()
    {
        var signer = Substitute.For<ISigner>();
        signer.KeyType.Returns(KeyType.P521);
        signer.PublicKey.Returns(new ReadOnlyMemory<byte>(new byte[32]));
        signer.MultibasePublicKey.Returns("zUnsupported");
        return signer;
    }
}

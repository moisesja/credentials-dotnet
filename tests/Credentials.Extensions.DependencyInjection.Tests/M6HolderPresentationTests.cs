using System.Text;
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
/// M6 SD-JWT VC holder presentation (FR-032): an issued cnf-bearing SD-JWT VC is held, presented with a
/// chosen disclosure subset + a Key Binding JWT (bound to the verifier's audience + nonce), and verified
/// with <c>RequireHolderBinding</c>. Negatives cover wrong audience / nonce / a missing KB-JWT / a KB-JWT
/// signed by the wrong key.
/// </summary>
public sealed class M6HolderPresentationTests
{
    private const string Vct = "https://credentials.example/identity_credential";
    private const string Audience = "https://verifier.example";
    private const string Nonce = "nonce-abc-123";

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    /// <summary>Issues a cnf-bound SD-JWT VC (holder key = the cnf) with one disclosable subject claim.</summary>
    private static async Task<(string Issued, TestKey Issuer, TestKey Holder)> IssueAsync(IIssuer issuer)
    {
        var issuerKey = TestKeys.New(KeyType.Ed25519);
        var holderKey = TestKeys.New(KeyType.Ed25519);

        var credential = Credential.Build()
            .WithIssuer(issuerKey.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["given_name"] = "Alice", ["age"] = 42 })
            .Seal();

        var issued = await issuer.IssueAsync(credential, new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
            Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name")],
            HolderBinding = HolderBindingKey.FromMultikey(holderKey.Signer.MultibasePublicKey),
        });

        return (issued.CompactSdJwt!, issuerKey, holderKey);
    }

    [Fact]
    public async Task Holder_ingest_inspect_present_then_verify_round_trips()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (issued, _, holderKey) = await IssueAsync(issuer);

        var held = holder.Ingest(Encoding.UTF8.GetBytes(issued));
        held.Securing.Should().Be(SecuringState.SdJwtVc);

        var inspection = holder.InspectSdJwt(held);
        inspection.Vct.Should().Be(Vct);
        inspection.SupportsHolderBinding.Should().BeTrue();
        inspection.DisclosableClaims.Should().Contain("given_name");

        var presentation = await holder.PresentSdJwtAsync(held, new SdJwtPresentationRequest
        {
            DiscloseClaims = ["given_name"],
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Audience = Audience,
            Nonce = Nonce,
        });

        var result = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(presentation),
            new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task Holder_can_withhold_a_disclosable_claim_and_it_still_verifies()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (issued, _, holderKey) = await IssueAsync(issuer);
        var held = holder.Ingest(Encoding.UTF8.GetBytes(issued));

        // Reveal nothing extra (withhold given_name) — still a valid presentation.
        var presentation = await holder.PresentSdJwtAsync(held, new SdJwtPresentationRequest
        {
            DiscloseClaims = [],
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Audience = Audience,
            Nonce = Nonce,
        });

        var result = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(presentation),
            new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce });
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Theory]
    [InlineData("https://attacker.example", Nonce)]   // wrong audience
    [InlineData(Audience, "wrong-nonce")]             // wrong nonce
    public async Task Presentation_with_wrong_audience_or_nonce_is_rejected(string expectedAudience, string expectedNonce)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (issued, _, holderKey) = await IssueAsync(issuer);
        var held = holder.Ingest(Encoding.UTF8.GetBytes(issued));
        var presentation = await holder.PresentSdJwtAsync(held, new SdJwtPresentationRequest
        {
            DiscloseClaims = ["given_name"],
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Audience = Audience,
            Nonce = Nonce,
        });

        var result = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(presentation),
            new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = expectedAudience, ExpectedNonce = expectedNonce });

        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Require_holder_binding_but_no_kb_jwt_is_rejected()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        // The issued SD-JWT (no holder presentation, so no KB-JWT) — but the verifier requires holder binding.
        var (issued, _, _) = await IssueAsync(issuer);

        var result = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(issued),
            new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce });

        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Kb_jwt_signed_by_a_non_cnf_key_is_rejected()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (issued, _, _) = await IssueAsync(issuer);
        var held = holder.Ingest(Encoding.UTF8.GetBytes(issued));

        // Present with a DIFFERENT holder key than the cnf — the KB-JWT signature won't verify against cnf.
        var imposter = TestKeys.New(KeyType.Ed25519);
        var presentation = await holder.PresentSdJwtAsync(held, new SdJwtPresentationRequest
        {
            DiscloseClaims = ["given_name"],
            HolderSigner = imposter.Signer,
            VerificationMethod = imposter.VerificationMethod,
            Audience = Audience,
            Nonce = Nonce,
        });

        var result = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(presentation),
            new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce });

        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }
}

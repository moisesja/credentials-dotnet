using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.TestSupport;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// SD-JWT VC behaviours that come from the DataProofs substrate and changed in DataProofs 2.1.0, pinned at
/// the credentials level so a later substrate move cannot change them unnoticed.
/// <list type="bullet">
/// <item>Issue #51 (dataproofs #48): the must-not-disclose rule now applies by position, so a
/// <c>credentialSubject</c> property that only shares a reserved claim's name issues, presents and
/// verifies.</item>
/// <item>dataproofs #45: the top-level JWT <c>nbf</c> / <c>exp</c> are now enforced at the verification
/// instant. The failure is reported by the proof check until issue #50 moves it to the Validity check.</item>
/// </list>
/// </summary>
public sealed class SdJwtVcSubstrateRegressionTests
{
    private const string Vct = "https://credentials.example/identity_credential";
    private const string Audience = "https://verifier.example";
    private const string Nonce = "nonce-regression-51";

    // exp = 2001-09-09T01:46:40Z and nbf = 2100-01-01T00:00:00Z, the values in issue #50's table.
    private const long PastExp = 1_000_000_000;
    private const long FutureNbf = 4_102_444_800;

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    // ---- #51: nested claims named like reserved SD-JWT VC claims ------------------------------------

    [Theory]
    [InlineData("status")]
    [InlineData("exp")]
    [InlineData("iss")]
    [InlineData("nbf")]
    [InlineData("cnf")]
    [InlineData("vct")]
    [InlineData("given_name")] // control: an ordinary name
    [FrTag("FR-013")]
    [FrTag("FR-032")]
    [FrTag("FR-042")]
    public async Task Nested_claim_named_like_a_reserved_claim_issues_presents_and_verifies(string name)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var issuerKey = TestKeys.New(KeyType.Ed25519);
        var holderKey = TestKeys.New(KeyType.Ed25519);

        var credential = Credential.Build()
            .WithIssuer(issuerKey.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject", [name] = "value" })
            .Seal();

        var issued = await issuer.IssueAsync(credential, new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
            Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", name)],
            HolderBinding = HolderBindingKey.FromMultikey(holderKey.Signer.MultibasePublicKey),
        });

        // The issued credential, with every Disclosure attached, verifies as issued.
        var direct = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        direct.Decision.Should().Be(VerificationDecision.Accepted, direct.ToString());

        // The holder sees the claim as disclosable, presents it with a Key Binding JWT, and it verifies.
        var held = holder.Ingest(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        holder.InspectSdJwt(held).DisclosableClaims.Should().Contain(name);

        var presentation = await holder.PresentSdJwtAsync(held, new SdJwtPresentationRequest
        {
            DiscloseClaims = [name],
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Audience = Audience,
            Nonce = Nonce,
        });

        var presented = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(presentation),
            new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce });
        presented.Decision.Should().Be(VerificationDecision.Accepted, presented.ToString());
        presented.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
    }

    // ---- dataproofs #45: the JWT nbf / exp window -----------------------------------------------------

    [Theory]
    [InlineData("exp", PastExp)]
    [InlineData("nbf", FutureNbf)]
    [FrTag("FR-040")]
    [FrTag("FR-042")]
    public async Task Sd_jwt_vc_outside_its_nbf_exp_window_is_rejected(string claim, long value)
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var compact = await IssueWithTimeClaimAsync(provider.GetRequiredService<IIssuer>(), claim, value);

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(compact));

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        // Today the substrate's window check surfaces as a proof failure; #50 moves it to the Validity check
        // (expired / not_yet_valid, with the configured clock skew). Update these two lines with #50.
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
        result.Check(CheckKinds.Validity)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Theory]
    [InlineData("exp", PastExp, "2001-09-09T00:00:00Z")]
    [InlineData("nbf", FutureNbf, "2100-01-02T00:00:00Z")]
    [FrTag("FR-040")]
    public async Task Sd_jwt_vc_nbf_exp_window_is_judged_at_the_verification_time(string claim, long value, string at)
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var compact = await IssueWithTimeClaimAsync(provider.GetRequiredService<IIssuer>(), claim, value);

        // The same credential is inside its window at this instant, so VerificationTime reaches the substrate.
        var result = await verifier.VerifyCredentialAsync(
            Encoding.UTF8.GetBytes(compact),
            new CredentialVerificationOptions { VerificationTime = DateTimeOffset.Parse(at, System.Globalization.CultureInfo.InvariantCulture) });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Theory]
    [InlineData("exp")]
    [InlineData("nbf")]
    [FrTag("FR-013")]
    public async Task Sd_jwt_vc_with_a_non_numeric_nbf_or_exp_is_not_issued(string claim)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var credential = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .SetMember(claim, "soon")
            .Seal();

        // The substrate refuses to sign an SD-JWT its own verifier would refuse (RFC 7519 NumericDate).
        var act = () => issuer.IssueAsync(credential, new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = key.Signer,
            VerificationMethod = key.VerificationMethod,
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    private static async Task<string> IssueWithTimeClaimAsync(IIssuer issuer, string claim, long value)
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var credential = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .SetMember(claim, value)
            .Seal();

        var issued = await issuer.IssueAsync(credential, new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = key.Signer,
            VerificationMethod = key.VerificationMethod,
        });

        return issued.CompactSdJwt!;
    }
}

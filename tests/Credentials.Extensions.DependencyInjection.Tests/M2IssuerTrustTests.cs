using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.TestSupport;
using Credentials.Trust;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NSubstitute;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M2 issuer-trust evaluation (FR-081/082, OQ-1). The policy is an explicit, optional step over the
/// proof-verified issuer; no trust lists ship in the library (the allowlist below is a test fixture).
/// </summary>
public sealed class M2IssuerTrustTests
{
    /// <summary>A minimal allowlist policy — the kind of sample that lives outside the library (FR-082).</summary>
    private sealed class AllowlistIssuerTrustPolicy(params string[] trusted) : IIssuerTrustPolicy
    {
        private readonly HashSet<string> _trusted = new(trusted, StringComparer.Ordinal);

        public Task<IssuerTrustResult> EvaluateAsync(IssuerTrustContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult(_trusted.Contains(context.IssuerId)
                ? IssuerTrustResult.Trusted()
                : IssuerTrustResult.Untrusted("issuer_not_allowlisted", "The issuer is not on the allowlist."));
    }

    private static ServiceProvider BuildProvider(IIssuerTrustPolicy? policy) =>
        new ServiceCollection()
            .AddCredentials(b =>
            {
                b.UseNetDid();
                if (policy is not null)
                {
                    b.UseIssuerTrustPolicy(policy);
                }
            })
            .BuildServiceProvider();

    private static async Task<Credential> IssueAsync(IIssuer issuer, TestKey key)
    {
        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var issued = await issuer.IssueAsync(unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
        return issued.Credential;
    }

    [Fact]
    [FrTag("FR-082")]
    public async Task Trusted_issuer_passes()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(new AllowlistIssuerTrustPolicy(key.Did));
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(credential);
        result.Check(CheckKinds.IssuerTrust)!.Status.Should().Be(CheckStatus.Passed);
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task Untrusted_issuer_fails_and_rejects()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(new AllowlistIssuerTrustPolicy("did:example:someone-else"));
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(credential);
        var trust = result.Check(CheckKinds.IssuerTrust)!;
        trust.Status.Should().Be(CheckStatus.Failed);
        trust.Diagnostics.Should().Contain(d => d.Code == "issuer_not_allowlisted");
        result.Decision.Should().Be(VerificationDecision.Rejected);
    }

    [Fact]
    public async Task Indeterminate_policy_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var policy = Substitute.For<IIssuerTrustPolicy>();
        policy.EvaluateAsync(Arg.Any<IssuerTrustContext>(), Arg.Any<CancellationToken>())
            .Returns(IssuerTrustResult.Indeterminate("registry_unreachable", "The trust registry could not be reached."));
        using var provider = BuildProvider(policy);
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(credential);
        result.Check(CheckKinds.IssuerTrust)!.Status.Should().Be(CheckStatus.Indeterminate);
    }

    [Fact]
    public async Task A_throwing_policy_is_indeterminate_not_a_crash()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var policy = Substitute.For<IIssuerTrustPolicy>();
        policy.EvaluateAsync(Arg.Any<IssuerTrustContext>(), Arg.Any<CancellationToken>())
            .Returns<Task<IssuerTrustResult>>(_ => throw new InvalidOperationException("boom"));
        using var provider = BuildProvider(policy);
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(credential);
        result.Check(CheckKinds.IssuerTrust)!.Status.Should().Be(CheckStatus.Indeterminate, "a throwing policy must never crash verification (FR-045)");
    }

    [Fact]
    [FrTag("FR-081")]
    public async Task Policy_receives_the_proof_verified_issuer_and_verification_method()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        IssuerTrustContext? captured = null;
        var policy = Substitute.For<IIssuerTrustPolicy>();
        policy.EvaluateAsync(Arg.Do<IssuerTrustContext>(c => captured = c), Arg.Any<CancellationToken>())
            .Returns(IssuerTrustResult.Trusted());
        using var provider = BuildProvider(policy);
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(credential);

        captured.Should().NotBeNull();
        captured!.IssuerId.Should().Be(key.Did, "trust must consume the proof-verified issuer, not a self-asserted one");
        captured.VerificationMethods.Should().Contain(key.VerificationMethod);
    }

    [Fact]
    public async Task No_policy_skips_trust()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(policy: null);
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(credential);
        result.Check(CheckKinds.IssuerTrust)!.Status.Should().Be(CheckStatus.Skipped);
    }

    [Fact]
    public async Task EvaluateIssuerTrust_false_skips_trust()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(new AllowlistIssuerTrustPolicy("did:example:someone-else"));
        var credential = await IssueAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>()
            .VerifyCredentialAsync(credential, new CredentialVerificationOptions { EvaluateIssuerTrust = false });
        result.Check(CheckKinds.IssuerTrust)!.Status.Should().Be(CheckStatus.Skipped);
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task Trust_is_skipped_when_the_proof_does_not_authenticate_the_issuer()
    {
        // A credential whose proof fails (issuer-spoofing): trust must not run on an unauthenticated issuer.
        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(new AllowlistIssuerTrustPolicy(victim.Did));

        var credential = Credential.Build()
            .WithIssuer(victim.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var forged = await provider.GetRequiredService<IIssuer>().IssueAsync(credential,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = attacker.Signer, VerificationMethod = attacker.VerificationMethod });

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(forged.Credential);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
        result.Check(CheckKinds.IssuerTrust)!.Status.Should().Be(CheckStatus.Skipped, "trust is never evaluated on a self-asserted issuer");
    }
}

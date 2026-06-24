using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.IssuerTrust;

/// <summary>
/// Issuer-trust evaluation (FR-081/FR-082): the same proof-valid credential is Accepted when its issuer
/// is on the verifier's allowlist and Rejected when it is not. The library ships no trust lists — the
/// <see cref="AllowlistIssuerTrustPolicy"/> is a sample-side policy supplied by the verifier (FR-082).
/// </summary>
public static class Program
{
    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; unused here because the sample wires
    /// two different trust policies, so it always builds its own providers.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        _ = services;
        var narrator = new SampleNarrator(output);
        narrator.Banner("Issuer trust (allowlist policy) — trusted Accepted vs untrusted Rejected", "FR-081", "FR-082");
        narrator.Step("FR-082: the library ships NO trust lists; this allowlist is a sample-side verifier policy");

        var issuerKey = SampleKeys.New();
        narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

        // Issue one proof-valid credential up front; both verifiers see the very same bytes.
        await using var issuerProvider = new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var issuer = issuerProvider.GetRequiredService<IIssuer>();
        var unsecured = Credential.Build()
            .WithId("urn:uuid:22222222-2222-2222-2222-222222222222")
            .WithIssuer(issuerKey.Did)
            .AddType("UniversityDegreeCredential")
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-jcs-2022",
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
        });
        narrator.Step($"issued a Data Integrity credential (issuer={issuerKey.Did[..16]}…)");

        // 1) Verifier that trusts this issuer → IssuerTrust Passed + Accepted.
        await using var trustedProvider = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseIssuerTrustPolicy(new AllowlistIssuerTrustPolicy(issuerKey.Did)))
            .BuildServiceProvider();
        var trusted = await trustedProvider.GetRequiredService<IVerifier>().VerifyCredentialAsync(issued.Credential);
        var trustedCheck = trusted.Check(CheckKinds.IssuerTrust)!;
        narrator.Result($"trusted verifier:   issuerTrust={trustedCheck.Status}, decision={trusted.Decision}");

        // 2) Verifier whose allowlist excludes this issuer → IssuerTrust Failed + Rejected.
        await using var untrustedProvider = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseIssuerTrustPolicy(new AllowlistIssuerTrustPolicy("did:example:someone-else")))
            .BuildServiceProvider();
        var untrusted = await untrustedProvider.GetRequiredService<IVerifier>().VerifyCredentialAsync(issued.Credential);
        var untrustedCheck = untrusted.Check(CheckKinds.IssuerTrust)!;
        narrator.Result($"untrusted verifier: issuerTrust={untrustedCheck.Status}, decision={untrusted.Decision}");

        if (trustedCheck.Status != CheckStatus.Passed || trusted.Decision != VerificationDecision.Accepted)
            throw new InvalidOperationException($"sample invariant failed: expected the allowlisted issuer to be Accepted, got {trusted.Decision} (issuerTrust={trustedCheck.Status})");
        if (untrustedCheck.Status != CheckStatus.Failed || untrusted.Decision != VerificationDecision.Rejected)
            throw new InvalidOperationException($"sample invariant failed: expected the non-allowlisted issuer to be Rejected, got {untrusted.Decision} (issuerTrust={untrustedCheck.Status})");
    }
}

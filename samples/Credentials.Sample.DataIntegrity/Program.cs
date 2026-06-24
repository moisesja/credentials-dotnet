using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.DataIntegrity;

/// <summary>Issues a credential with an embedded W3C Data Integrity proof (eddsa-jcs-2022) and verifies it.</summary>
public static class Program
{
    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("Embedded Data Integrity (eddsa-jcs-2022) — issue + verify", "FR-010", "FR-011", "FR-040", "FR-043");

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();

            // Discover which securing forms/suites are registered (runtime-discovered strings, FR-053).
            var capabilities = provider.GetRequiredService<ISecuringCapabilities>();
            narrator.Step($"securing forms available: {string.Join(", ", capabilities.AvailableForms)} "
                + $"(eddsa-jcs-2022 supported: {capabilities.IsSupported(SecuringSelector.DataIntegrity("eddsa-jcs-2022"))})");

            var issuerKey = SampleKeys.New();
            narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

            var unsecured = Credential.Build()
                .WithId("urn:uuid:11111111-1111-1111-1111-111111111111")
                .WithIssuer(issuerKey.Did)
                .AddType("UniversityDegreeCredential")
                .AddSubject(new JsonObject
                {
                    ["id"] = "did:example:subject",
                    ["degree"] = new JsonObject { ["type"] = "BachelorDegree", ["name"] = "B.Sc. Computer Science" },
                })
                .Seal();
            narrator.Step($"built + sealed an unsecured VCDM {unsecured.Version} credential");

            var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
            {
                Cryptosuite = "eddsa-jcs-2022",
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
            });
            narrator.Step($"secured it: {issued.Credential.Securing}, mediaType={issued.MediaType}, embedded proof={issued.Credential.HasEmbeddedProof}");

            var result = await verifier.VerifyCredentialAsync(issued.Credential);
            narrator.Result($"decision={result.Decision} (proof={result.Check(CheckKinds.Proof)!.Status}, structure={result.Check(CheckKinds.Structure)!.Status})");

            if (result.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted, got {result.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }
}

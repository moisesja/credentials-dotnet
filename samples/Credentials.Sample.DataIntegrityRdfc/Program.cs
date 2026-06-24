using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.DataIntegrityRdfc;

/// <summary>Issues a credential with an embedded W3C Data Integrity proof using the opt-in RDFC suite
/// (eddsa-rdfc-2022, registered via <c>UseRdfcSuites()</c>) and verifies it.</summary>
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
        narrator.Banner("Embedded Data Integrity (eddsa-rdfc-2022) — issue + verify", "FR-011", "FR-053");

        var provider = services ?? new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseRdfcSuites())
            .BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();
            var issuerKey = SampleKeys.New();
            narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

            var unsecured = Credential.Build()
                .WithId("urn:uuid:22222222-2222-2222-2222-222222222222")
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
                Cryptosuite = "eddsa-rdfc-2022",
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

using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.SdJwtVc;

/// <summary>
/// Issues an SD-JWT VC (FR-013) with two selectively-disclosable subject properties, shows the compact
/// wire form + its <c>application/dc+sd-jwt</c> media type, then verifies straight from the compact bytes.
/// </summary>
public static class Program
{
    private const string Vct = "https://credentials.example/identity";

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("SD-JWT VC (application/dc+sd-jwt) — issue with selective disclosure + verify", "FR-013");

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();
            var issuerKey = SampleKeys.New();
            narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

            var unsecured = Credential.Build()
                .WithId("urn:uuid:44444444-4444-4444-4444-444444444444")
                .WithIssuer(issuerKey.Did)
                .AddSubject(new JsonObject
                {
                    ["id"] = "did:example:subject",
                    ["given_name"] = "Alice",
                    ["age"] = 42,
                })
                .Seal();
            narrator.Step($"built + sealed an unsecured VCDM {unsecured.Version} credential");

            var issued = await issuer.IssueAsync(unsecured, new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
                Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name", "age")],
            });
            narrator.Step($"issued SD-JWT VC: mediaType={issued.MediaType}, disclosures={issued.CompactSdJwt!.Split('~').Length - 2}");
            narrator.Step($"compact wire form: {issued.CompactSdJwt![..Math.Min(48, issued.CompactSdJwt!.Length)]}… ({issued.CompactSdJwt!.Length} chars, ends in '~')");

            // Verify from the verbatim compact SD-JWT wire bytes (envelope detection picks SD-JWT VC).
            var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
            narrator.Result($"decision={result.Decision} (mechanism={result.Mechanism}, proof={result.Check(CheckKinds.Proof)!.Status})");

            if (issued.MediaType != "application/dc+sd-jwt")
                throw new InvalidOperationException($"sample invariant failed: expected mediaType application/dc+sd-jwt, got {issued.MediaType}");
            if (result.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted, got {result.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }
}

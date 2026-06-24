using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.PresentationDataIntegrity;

/// <summary>
/// Holder flow: a holder ingests an issued credential, assembles a Verifiable Presentation over it, binds
/// the VP to a holder key with an embedded Data Integrity authentication proof (challenge + domain), and a
/// verifier verifies the holder binding plus the contained credential.
/// </summary>
public static class Program
{
    private const string Challenge = "challenge-xyz-789";
    private const string Domain = "https://verifier.example";

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("Verifiable Presentation — Data Integrity holder binding (eddsa-jcs-2022)", "FR-030", "FR-033", "FR-034", "FR-041");

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var holder = provider.GetRequiredService<IHolder>();
            var verifier = provider.GetRequiredService<IVerifier>();

            var issuerKey = SampleKeys.New();
            var holderKey = SampleKeys.New();
            narrator.Step($"minted an issuer {issuerKey.Did[..28]}… and a holder {holderKey.Did[..28]}…");

            var unsecured = Credential.Build()
                .WithIssuer(issuerKey.Did)
                .AddSubject(new JsonObject { ["id"] = holderKey.Did, ["alumniOf"] = "Example University" })
                .Seal();
            var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
            {
                Cryptosuite = "eddsa-jcs-2022",
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
            });
            narrator.Step($"issuer secured the credential: {issued.Credential.Securing}");

            var held = holder.Ingest(issued.Credential.ToBytes());
            narrator.Step($"holder ingested it: {held.Securing}");

            var vp = holder.BuildPresentation(new VpAssemblyRequest
            {
                Holder = holderKey.Did,
                Credentials = [ContainedCredential.Embedded(held.Credential)],
            });
            narrator.Step("holder assembled a VP over the embedded credential");

            var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
            {
                HolderSigner = holderKey.Signer,
                VerificationMethod = holderKey.VerificationMethod,
                Challenge = Challenge,
                Domain = Domain,
            });
            narrator.Step($"holder bound the VP: {bound.Securing} (challenge + domain)");

            var result = await verifier.VerifyPresentationAsync(bound, new PresentationVerificationOptions
            {
                RequireHolderBinding = true,
                ExpectedChallenge = Challenge,
                ExpectedDomain = Domain,
            });
            narrator.Result($"decision={result.Decision} (holderBinding={result.Check(CheckKinds.HolderBinding)!.Status}, contained={result.Credentials[0].Decision})");

            if (result.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted, got {result.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }
}

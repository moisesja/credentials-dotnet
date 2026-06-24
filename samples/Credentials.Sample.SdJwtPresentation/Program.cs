using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.SdJwtPresentation;

/// <summary>
/// Holder-side SD-JWT VC presentation (FR-030/FR-032): an issuer mints a cnf-bound SD-JWT VC with a
/// disclosable claim, the holder ingests + inspects it, presents a chosen disclosure subset under a
/// Key Binding JWT bound to the verifier's audience + nonce, and the verifier accepts it.
/// </summary>
public static class Program
{
    private const string Vct = "https://credentials.example/identity_credential";
    private const string Audience = "https://verifier.example";
    private const string Nonce = "nonce-abc-123";

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("SD-JWT VC holder presentation — ingest, inspect, present (KB-JWT) + verify", "FR-030", "FR-032");

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var holder = provider.GetRequiredService<IHolder>();
            var verifier = provider.GetRequiredService<IVerifier>();

            var issuerKey = SampleKeys.New();
            var holderKey = SampleKeys.New();
            narrator.Step($"minted an issuer ({issuerKey.Did[..28]}…) and a holder confirmation key ({holderKey.Did[..28]}…)");

            var unsecured = Credential.Build()
                .WithId("urn:uuid:22222222-2222-2222-2222-222222222222")
                .WithIssuer(issuerKey.Did)
                .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["given_name"] = "Alice", ["age"] = 42 })
                .Seal();

            var issued = await issuer.IssueAsync(unsecured, new SdJwtVcIssuanceRequest
            {
                Vct = Vct,
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
                Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name")],
                HolderBinding = HolderBindingKey.FromMultikey(holderKey.Signer.MultibasePublicKey),
            });
            narrator.Step($"issued a cnf-bound SD-JWT VC: form={issued.Form}, mediaType={issued.MediaType}");

            var held = holder.Ingest(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
            narrator.Step($"holder ingested it: securing={held.Securing}");

            var inspection = holder.InspectSdJwt(held);
            narrator.Step($"inspected: vct={inspection.Vct}, holderBinding={inspection.SupportsHolderBinding}, disclosable=[{string.Join(", ", inspection.DisclosableClaims)}]");

            var presentation = await holder.PresentSdJwtAsync(held, new SdJwtPresentationRequest
            {
                DiscloseClaims = ["given_name"],
                HolderSigner = holderKey.Signer,
                VerificationMethod = holderKey.VerificationMethod,
                Audience = Audience,
                Nonce = Nonce,
            });
            narrator.Step($"presented with a KB-JWT bound to aud={Audience}, nonce={Nonce}");

            var result = await verifier.VerifyCredentialAsync(
                Encoding.UTF8.GetBytes(presentation),
                new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce });
            narrator.Result($"decision={result.Decision} (proof={result.Check(CheckKinds.Proof)!.Status})");

            if (result.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted, got {result.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }
}

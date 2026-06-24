using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.JoseEnvelope;

/// <summary>Issues a VC-JOSE enveloped credential (application/vc+jwt) and verifies it both as the issued
/// credential object and from the verbatim compact-JWS wire bytes.</summary>
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
        narrator.Banner("VC-JOSE enveloping (application/vc+jwt) — issue + verify (object & wire)", "FR-012");

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();
            var issuerKey = SampleKeys.New();
            narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

            var unsecured = Credential.Build()
                .WithId("urn:uuid:33333333-3333-3333-3333-333333333333")
                .WithIssuer(issuerKey.Did)
                .AddType("UniversityDegreeCredential")
                .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
                .Seal();
            narrator.Step($"built + sealed an unsecured VCDM {unsecured.Version} credential");

            var issued = await issuer.IssueAsync(unsecured, new JoseEnvelopeIssuanceRequest
            {
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
            });

            var segments = issued.CompactJws!.Split('.').Length;
            narrator.Step($"enveloped it: {issued.Form}, mediaType={issued.MediaType}, compact-JWS segments={segments}");
            if (segments != 3)
                throw new InvalidOperationException($"sample invariant failed: expected a 3-part compact JWS, got {segments} segments");

            var direct = await verifier.VerifyCredentialAsync(issued.Credential);
            narrator.Step($"verified the issued credential: decision={direct.Decision}, mechanism={direct.Mechanism}");

            var wire = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactJws));
            narrator.Result($"verified from verbatim compact-JWS bytes: decision={wire.Decision}, mechanism={wire.Mechanism}");

            if (direct.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted from the credential object, got {direct.Decision}");
            if (wire.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted from the wire bytes, got {wire.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }
}

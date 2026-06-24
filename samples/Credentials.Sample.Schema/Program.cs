using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Schema;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.Schema;

/// <summary>
/// Credential schema validation (FR-070): the credential declares a <c>credentialSchema</c> the verifier
/// fetches through a caller-supplied <see cref="ICredentialSchemaResolver"/>, then validates the credential
/// against that JSON Schema 2020-12. A conforming credential ⇒ schema Passed + Accepted.
/// </summary>
public static class Program
{
    private const string SchemaUrl = "https://schema.example/person";

    private const string PersonSchema =
        """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "properties": {
            "credentialSubject": {
              "type": "object",
              "properties": { "name": { "type": "string" } },
              "required": ["name"]
            }
          },
          "required": ["credentialSubject"]
        }
        """;

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("Credential Schema — JSON Schema 2020-12 validation", "FR-070");

        var resolver = new InMemorySchemaResolver(Encoding.UTF8.GetBytes(PersonSchema));

        var provider = services ?? new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseSchemaResolver(resolver))
            .BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();
            var issuerKey = SampleKeys.New();
            narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");
            narrator.Step($"serving a JSON Schema 2020-12 (requires credentialSubject.name) at {SchemaUrl}");

            // The credential declares the schema and carries the required 'name' member, so it conforms.
            var unsecured = Credential.Build()
                .WithId("urn:uuid:33333333-3333-3333-3333-333333333333")
                .WithIssuer(issuerKey.Did)
                .AddSchema(new JsonObject { ["id"] = SchemaUrl, ["type"] = "JsonSchema" })
                .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["name"] = "Ada" })
                .Seal();

            var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
            {
                Cryptosuite = "eddsa-jcs-2022",
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
            });
            narrator.Step("issued a credential with a credentialSchema and a conforming credentialSubject");

            var result = await verifier.VerifyCredentialAsync(issued.Credential);
            narrator.Result($"schema={result.Check(CheckKinds.Schema)!.Status}, decision={result.Decision}");

            if (result.Check(CheckKinds.Schema)!.Status != CheckStatus.Passed || result.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException(
                    $"sample invariant failed: expected schema Passed + Accepted, got {result.Check(CheckKinds.Schema)!.Status}/{result.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }

    /// <summary>An offline schema resolver that returns a fixed JSON Schema 2020-12 document.</summary>
    private sealed class InMemorySchemaResolver(byte[] schemaBytes) : ICredentialSchemaResolver
    {
        public Task<SchemaResolutionResult> ResolveAsync(SchemaReference reference, CancellationToken cancellationToken = default) =>
            Task.FromResult(SchemaResolutionResult.Found(new ResolvedSchema(SchemaUrl, SchemaDialect.JsonSchema2020_12, schemaBytes)));
    }
}

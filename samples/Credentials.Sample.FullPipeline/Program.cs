using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Schema;
using Credentials.Status;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.FullPipeline;

/// <summary>
/// The showcase: ONE credential carrying BOTH a <c>credentialSchema</c> and a <c>credentialStatus</c>,
/// verified through a provider wired with every M2 hook — an in-sample status-list fetcher (bit clear),
/// an in-sample schema resolver (matching schema), and an allowlist issuer-trust policy. Every gating
/// check (proof / structure / validity / status / schema / issuerTrust) must land on Passed and the
/// overall decision must be Accepted.
/// </summary>
public static class Program
{
    private const string SchemaUrl = "https://schema.example/person";
    private const string StatusListUrl = "https://issuer.example/status/1";
    private const long StatusIndex = 94_567;

    // A schema the issued credential satisfies (its subject carries a "name").
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

    public static Task Main() => RunAsync(Console.Out);

    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner(
            "Full pipeline — proof + structure + validity + status + schema + trust in one verification",
            "FR-040", "FR-070", "FR-022", "FR-081", "FR-082");

        var issuerKey = SampleKeys.New();
        narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

        // The status list is itself a signed VC. Sign an empty (all-clear) revocation list with the
        // SAME issuer so it is trusted (no issuer mismatch), then hand its secured bytes to the fetcher.
        var statusListBytes = await IssueClearStatusListAsync(issuerKey);
        narrator.Step($"issuer signed an all-clear status list (bit {StatusIndex} not set)");

        var schemaBytes = Encoding.UTF8.GetBytes(PersonSchema);

        var provider = services ?? new ServiceCollection()
            .AddCredentials(b => b
                .UseNetDid()
                .UseStatusListFetcher(new InMemoryStatusListFetcher(statusListBytes))
                .UseSchemaResolver(new InMemorySchemaResolver(schemaBytes))
                .UseIssuerTrustPolicy(new AllowlistIssuerTrustPolicy(issuerKey.Did)))
            .BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();

            // ONE credential that references BOTH the schema and the status list, and declares a
            // digestSRI over the schema bytes (the engine enforces it itself).
            var schemaDigest = "sha256-" + Convert.ToBase64String(SHA256.HashData(schemaBytes));
            var unsecured = Credential.Build()
                .WithId("urn:uuid:33333333-3333-3333-3333-333333333333")
                .WithIssuer(issuerKey.Did)
                .AddType("PersonCredential")
                .AddSchema(new JsonObject
                {
                    ["id"] = SchemaUrl,
                    ["type"] = "JsonSchema",
                    ["digestSRI"] = schemaDigest,
                })
                .AddStatus(BitstringStatusListEntry.Create(StatusPurpose.Revocation, StatusIndex, StatusListUrl))
                .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["name"] = "Ada Lovelace" })
                .Seal();
            narrator.Step("issued one credential carrying BOTH credentialSchema and credentialStatus");

            var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
            {
                Cryptosuite = "eddsa-jcs-2022",
                Signer = issuerKey.Signer,
                VerificationMethod = issuerKey.VerificationMethod,
            });

            var result = await verifier.VerifyCredentialAsync(issued.Credential);

            // Narrate every gating check, then prove they all Passed.
            string[] gating =
            [
                CheckKinds.Proof, CheckKinds.Structure, CheckKinds.Validity,
                CheckKinds.Status, CheckKinds.Schema, CheckKinds.IssuerTrust,
            ];
            foreach (var kind in gating)
            {
                var status = result.Check(kind)?.Status;
                narrator.Step($"check {kind,-11} = {status}");
                if (status != CheckStatus.Passed)
                {
                    throw new InvalidOperationException(
                        $"expected check '{kind}' to be Passed, got {status?.ToString() ?? "<absent>"}");
                }
            }

            narrator.Result($"decision={result.Decision} (all six gating checks Passed)");
            if (result.Decision != VerificationDecision.Accepted)
            {
                throw new InvalidOperationException($"expected Accepted, got {result.Decision}");
            }
        }
        finally
        {
            if (ownsProvider && provider is IDisposable d)
            {
                d.Dispose();
            }
        }
    }

    // Sign an empty (all-clear) revocation status list with the given issuer, returning its secured bytes.
    private static async Task<byte[]> IssueClearStatusListAsync(SampleKey issuerKey)
    {
        using var seed = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid())
            .BuildServiceProvider();

        var list = new StatusListManager().CreateList(new StatusListCreateOptions
        {
            Id = StatusListUrl,
            Issuer = issuerKey.Did,
            StatusPurpose = StatusPurpose.Revocation,
            ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
        });

        var issued = await seed.GetRequiredService<IIssuer>().IssueAsync(list, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-jcs-2022",
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
        });
        return issued.Credential.ToBytes();
    }

    /// <summary>An in-sample fetcher that always returns the one all-clear status list (offline).</summary>
    private sealed class InMemoryStatusListFetcher(byte[] securedListBytes) : IStatusListFetcher
    {
        public Task<StatusListFetchResult> FetchAsync(
            StatusListReference reference, CancellationToken cancellationToken = default) =>
            Task.FromResult(StatusListFetchResult.Found(securedListBytes));
    }

    /// <summary>An in-sample resolver that always returns the one matching JSON Schema (offline).</summary>
    private sealed class InMemorySchemaResolver(byte[] schemaBytes) : ICredentialSchemaResolver
    {
        public Task<SchemaResolutionResult> ResolveAsync(
            SchemaReference reference, CancellationToken cancellationToken = default) =>
            Task.FromResult(SchemaResolutionResult.Found(
                new ResolvedSchema(SchemaUrl, SchemaDialect.JsonSchema2020_12, schemaBytes)));
    }
}

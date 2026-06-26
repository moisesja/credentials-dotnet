using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Rdfc;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;

namespace Credentials.Samples.Bbs2023;

/// <summary>
/// Selective disclosure via the <c>bbs-2023</c> cryptosuite (FR-014 gated / FR-031 / FR-042): a holder
/// derives a minimal proof from a bbs-2023 base (mandatory group + a selected claim, the rest withheld),
/// and the verifier accepts the derived proof. The whole crypto path is gated on the native BBS library's
/// availability — on an unsupported host the sample narrates a clear skip and exits 0.
/// </summary>
/// <remarks>
/// The engine intentionally gates bbs-2023 issuance (no key-store BBS create API exists; raw-key export
/// would violate FR-015), so — exactly like the M5 test suite — the base credential here is crafted
/// directly through the substrate's raw-key API. This is sample/test-only; the engine never does raw-key
/// issuance.
/// </remarks>
public static class Program
{
    private static readonly DefaultKeyGenerator KeyGen = new();

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("BBS selective disclosure (bbs-2023) — derive + verify", "FR-014 (gated)", "FR-031", "FR-042");

        // Gate the whole crypto path on the native BBS library, exactly as the M5 test does.
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            narrator.Result("skipped: the native BBS library is unavailable on this host (no bbs-2023 path to exercise)");
            return;
        }

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid().UseBbs2023()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var deriver = provider.GetRequiredService<IBbsDeriver>();
            var verifier = provider.GetRequiredService<IVerifier>();

            // Craft a bbs-2023 base whose mandatory group is the issuer + the subject id.
            var baseCredential = await CraftBaseAsync(["/issuer", "/credentialSubject/id"]);
            narrator.Step("crafted a bbs-2023 base credential (substrate raw-key API; engine gates issuance)");

            // Derive: reveal the mandatory group + the selected gpa, withholding alumniOf + favoriteColor.
            var derived = await deriver.DeriveAsync(
                baseCredential, new BbsDisclosureRequest { RevealPointers = ["/credentialSubject/gpa"] });
            var subject = derived.ToElement().GetProperty("credentialSubject");
            narrator.Step(
                $"derived a minimal proof: securing={derived.Securing}, " +
                $"id={subject.TryGetProperty("id", out _)} (mandatory), gpa={subject.TryGetProperty("gpa", out _)} (selected), " +
                $"alumniOf={subject.TryGetProperty("alumniOf", out _)} / favoriteColor={subject.TryGetProperty("favoriteColor", out _)} (withheld)");

            var result = await verifier.VerifyCredentialAsync(derived);
            narrator.Result($"decision={result.Decision} (proof={result.Check(CheckKinds.Proof)!.Status}, structure={result.Check(CheckKinds.Structure)!.Status})");

            if (result.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: expected Accepted, got {result.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }

    /// <summary>
    /// Crafts a bbs-2023 base credential via the substrate's raw-key API (the engine gates issuance). The
    /// issuer is the BLS signing key's <c>did:key</c>. Mirrors the M5 test's CraftBaseAsync/EmbedBaseProofAsync.
    /// </summary>
    private static async Task<Credential> CraftBaseAsync(string[] mandatoryPointers)
    {
        var bls = KeyGen.Generate(KeyType.Bls12381G2);
        var signerDid = $"did:key:{bls.MultibasePublicKey}";
        var vm = $"{signerDid}#{bls.MultibasePublicKey}";

        var credential = Credential.Build()
            .AddContext("https://www.w3.org/ns/credentials/examples/v2")
            .AddType("AlumniCredential")
            .WithIssuer(signerDid)
            .AddSubject(new JsonObject
            {
                ["id"] = "did:example:abcdefgh",
                ["alumniOf"] = "The School of Examples",
                ["gpa"] = "4.0",
                ["favoriteColor"] = "purple",
            })
            .Seal();

        var baseOptions = new DataIntegrityProof
        {
            Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
            VerificationMethod = vm,
            ProofPurpose = "assertionMethod",
            Created = "2026-01-02T00:00:00Z",
        };

        var hmacKey = new byte[32];
        for (var i = 0; i < hmacKey.Length; i++)
        {
            hmacKey[i] = (byte)(i + 1);
        }

        var suite = new Bbs2023Cryptosuite();
        var baseProof = await suite.CreateBaseProofAsync(
            credential.ToElement(), baseOptions, bls.PrivateKey, hmacKey, mandatoryPointers);

        var node = JsonNode.Parse(credential.ToBytes())!.AsObject();
        node["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default);
        return Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(node));
    }
}

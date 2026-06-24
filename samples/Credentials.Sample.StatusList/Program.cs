using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Status;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.StatusList;

/// <summary>
/// Bitstring Status List (FR-016/020/022): a subject credential carries a <c>BitstringStatusListEntry</c>
/// pointing at an issuer-signed status-list credential. The verifier dereferences that list through a
/// caller-supplied <see cref="IStatusListFetcher"/>, verifies the list's own proof, then reads the bit:
/// CLEAR ⇒ Accepted, SET (revoked) ⇒ Rejected.
/// </summary>
public static class Program
{
    private const string ListUrl = "https://issuer.example/status/1";
    private const long Index = 94_567;

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("Bitstring Status List — revocation through a status-list credential", "FR-016", "FR-020", "FR-022");

        var manager = new StatusListManager();
        var issuerKey = SampleKeys.New();
        narrator.Step($"minted an issuer identity: {issuerKey.Did[..28]}…");

        // The fetcher the verifier will call to dereference the status-list credential. The issuer flips
        // the served list between the two verification passes (clear ⇒ revoked).
        var fetcher = new InMemoryStatusListFetcher();

        var provider = services ?? new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseStatusListFetcher(fetcher))
            .BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var issuer = provider.GetRequiredService<IIssuer>();
            var verifier = provider.GetRequiredService<IVerifier>();

            // The subject credential references index 94567 of the revocation list (FR-016).
            var subject = await IssueSubjectAsync(issuer, issuerKey);
            narrator.Step($"issued a subject credential referencing index {Index} of the status list");

            // Pass 1 — the list bit is CLEAR: the credential is not revoked ⇒ Accepted.
            fetcher.Serve(await IssueStatusListAsync(issuer, issuerKey, manager, revoked: false));
            var clear = await verifier.VerifyCredentialAsync(subject);
            narrator.Result($"bit CLEAR: status={clear.Check(CheckKinds.Status)!.Status}, decision={clear.Decision}");
            if (clear.Check(CheckKinds.Status)!.Status != CheckStatus.Passed || clear.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"sample invariant failed: clear list expected Passed/Accepted, got {clear.Check(CheckKinds.Status)!.Status}/{clear.Decision}");

            // Pass 2 — the issuer revokes index 94567 (sets the bit) and re-serves the signed list ⇒ Rejected.
            fetcher.Serve(await IssueStatusListAsync(issuer, issuerKey, manager, revoked: true));
            var revoked = await verifier.VerifyCredentialAsync(subject);
            narrator.Result($"bit SET (revoked): status={revoked.Check(CheckKinds.Status)!.Status}, decision={revoked.Decision}");
            if (revoked.Check(CheckKinds.Status)!.Status != CheckStatus.Failed || revoked.Decision != VerificationDecision.Rejected)
                throw new InvalidOperationException($"sample invariant failed: revoked list expected Failed/Rejected, got {revoked.Check(CheckKinds.Status)!.Status}/{revoked.Decision}");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }

    private static async Task<Credential> IssueSubjectAsync(IIssuer issuer, SampleKey key)
    {
        var unsecured = Credential.Build()
            .WithId("urn:uuid:22222222-2222-2222-2222-222222222222")
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .AddStatus(BitstringStatusListEntry.Create(StatusPurpose.Revocation, Index, ListUrl))
            .Seal();

        var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-jcs-2022",
            Signer = key.Signer,
            VerificationMethod = key.VerificationMethod,
        });
        return issued.Credential;
    }

    private static async Task<byte[]> IssueStatusListAsync(IIssuer issuer, SampleKey key, StatusListManager manager, bool revoked)
    {
        var list = manager.CreateList(new StatusListCreateOptions
        {
            Id = ListUrl,
            Issuer = key.Did,
            StatusPurpose = StatusPurpose.Revocation,
            ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
        });

        if (revoked)
        {
            list = manager.Revoke(list, Index);
        }

        var issued = await issuer.IssueAsync(list, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-jcs-2022",
            Signer = key.Signer,
            VerificationMethod = key.VerificationMethod,
        });
        return issued.Credential.ToBytes();
    }

    /// <summary>An offline status-list fetcher that returns the bytes the issuer last handed it.</summary>
    private sealed class InMemoryStatusListFetcher : IStatusListFetcher
    {
        private byte[]? _listBytes;

        public void Serve(byte[] listBytes) => _listBytes = listBytes;

        public Task<StatusListFetchResult> FetchAsync(StatusListReference reference, CancellationToken cancellationToken = default) =>
            Task.FromResult(_listBytes is null
                ? StatusListFetchResult.NotFound("not_served")
                : StatusListFetchResult.Found(_listBytes));
    }
}

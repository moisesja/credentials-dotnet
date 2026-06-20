namespace Credentials.Status;

/// <summary>
/// The caller-supplied hook (FR-081) the verifier uses to dereference a referenced status list. The
/// caller owns egress, caching, and privacy (the spec recommends proxies / Oblivious HTTP so the issuer
/// cannot observe which credential is being checked). The hook returns the <strong>secured</strong>
/// status-list credential; the verifier then verifies its proof recursively (FR-050) before trusting any
/// bit. When no fetcher is registered, the verifier reports the status check as <c>Skipped</c>.
/// </summary>
public interface IStatusListFetcher
{
    /// <summary>Resolves the status-list credential referenced by <paramref name="reference"/>.</summary>
    /// <param name="reference">The parsed status-list entry.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The fetch result — found (secured list bytes) or not found (a reason code).</returns>
    Task<StatusListFetchResult> FetchAsync(StatusListReference reference, CancellationToken cancellationToken = default);
}

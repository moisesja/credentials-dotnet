namespace Credentials.Trust;

/// <summary>
/// The caller-supplied issuer-trust policy (FR-082): an explicit, optional verifier step that decides
/// whether a credential's <em>proof-verified</em> issuer is trusted. It returns a structured decision plus
/// reason (never a bare bool). No trust lists ship in the library (D11) — provide an allowlist or registry
/// policy via DI. When no policy is registered (or the proof did not authenticate the issuer), the verifier
/// reports the issuer-trust check as <c>Skipped</c>; a throwing policy is reported as <c>Indeterminate</c>
/// (never crashes the verification).
/// </summary>
public interface IIssuerTrustPolicy
{
    /// <summary>Evaluates trust for the issuer described by <paramref name="context"/>.</summary>
    /// <param name="context">The proof-verified issuer context (identity only — never claims or keys).</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The structured trust decision and reason.</returns>
    Task<IssuerTrustResult> EvaluateAsync(IssuerTrustContext context, CancellationToken cancellationToken = default);
}

using Credentials.Trust;

namespace Credentials.Samples.Shared;

/// <summary>
/// A minimal allowlist issuer-trust policy (FR-082). The library ships <em>no</em> built-in trust lists;
/// trust is the verifier's policy to supply. This sample shows the shape: a structured
/// <see cref="IssuerTrustResult"/> (decision + reason code), never a bare boolean, evaluated over the
/// proof-verified issuer DID.
/// </summary>
/// <param name="trustedIssuerDids">The issuer DIDs this verifier trusts.</param>
public sealed class AllowlistIssuerTrustPolicy(params string[] trustedIssuerDids) : IIssuerTrustPolicy
{
    private readonly HashSet<string> _trusted = new(trustedIssuerDids, StringComparer.Ordinal);

    /// <summary>Trusts the issuer iff its DID is on the allowlist; otherwise returns a reasoned Untrusted.</summary>
    /// <param name="context">The proof-verified issuer context.</param>
    /// <param name="cancellationToken">Unused (the decision is synchronous).</param>
    public Task<IssuerTrustResult> EvaluateAsync(IssuerTrustContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(_trusted.Contains(context.IssuerId)
            ? IssuerTrustResult.Trusted()
            : IssuerTrustResult.Untrusted("issuer_not_allowlisted", "The issuer is not on the verifier's allowlist."));
}

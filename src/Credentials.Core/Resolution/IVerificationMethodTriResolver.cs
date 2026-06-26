using DataProofsDotnet.DataIntegrity;

namespace Credentials.Resolution;

/// <summary>
/// Resolves an embedded Data Integrity proof's <c>verificationMethod</c> DID URL to the issuer's
/// published verification method, as a tri-state so the Data Integrity path can honour F7 — symmetric
/// with <see cref="IEnvelopeKeyResolver"/> for the enveloping forms. A DID that genuinely cannot be
/// resolved (IO/network/unknown method) is <see cref="VerificationMethodResolutionStatus.DidUnresolvable"/>
/// (→ Indeterminate), while a DID that resolves but does not publish the referenced verification method
/// (e.g. an attacker-mangled <c>verificationMethod</c> fragment over a still-resolvable base DID) is
/// <see cref="VerificationMethodResolutionStatus.MethodNotFound"/> (→ Failed) — a tampered/forged
/// credential can never be downgraded to Indeterminate by choosing a bogus fragment.
/// </summary>
internal interface IVerificationMethodTriResolver
{
    /// <summary>Resolves a Data Integrity proof's <c>verificationMethod</c> to a tri-state outcome.</summary>
    Task<VerificationMethodResolution> ResolveAsync(string verificationMethodUrl, CancellationToken cancellationToken = default);
}

/// <summary>
/// The outcome class of an <see cref="IVerificationMethodTriResolver"/> resolution. The zero value is
/// deliberately a non-success (<see cref="DidUnresolvable"/>) so a <c>default</c>-constructed or otherwise
/// zero-initialized <see cref="VerificationMethodResolution"/> fails closed rather than masquerading as
/// <see cref="Resolved"/> with a null <see cref="VerificationMethodResolution.Method"/> a consumer would
/// dereference. Real outcomes are only ever produced via the factory members.
/// </summary>
internal enum VerificationMethodResolutionStatus
{
    /// <summary>The DID could not be resolved at all (IO/network/unknown method) — unknown validity (→ Indeterminate). The fail-closed zero value.</summary>
    DidUnresolvable,

    /// <summary>
    /// The DID resolved but its document does not contain the referenced verification method (or its key
    /// is unusable) — a definitive negative (→ Failed): the published key set does not authorize this method.
    /// </summary>
    MethodNotFound,

    /// <summary>The verification method was found and its public key extracted.</summary>
    Resolved,
}

/// <summary>
/// The tri-state result of resolving a Data Integrity proof's <c>verificationMethod</c>. The
/// <see cref="Method"/> is meaningful only when <see cref="Status"/> is
/// <see cref="VerificationMethodResolutionStatus.Resolved"/>.
/// </summary>
internal readonly record struct VerificationMethodResolution
{
    private VerificationMethodResolution(VerificationMethodResolutionStatus status, ResolvedVerificationMethod? method)
    {
        Status = status;
        Method = method;
    }

    /// <summary>The resolution outcome class.</summary>
    public VerificationMethodResolutionStatus Status { get; }

    /// <summary>The resolved verification method (only when <see cref="Status"/> is <see cref="VerificationMethodResolutionStatus.Resolved"/>).</summary>
    public ResolvedVerificationMethod? Method { get; }

    /// <summary>A successful resolution carrying the verification method.</summary>
    public static VerificationMethodResolution Resolved(ResolvedVerificationMethod method) =>
        new(VerificationMethodResolutionStatus.Resolved, method);

    /// <summary>The DID could not be resolved (→ Indeterminate).</summary>
    public static VerificationMethodResolution DidUnresolvable { get; } =
        new(VerificationMethodResolutionStatus.DidUnresolvable, null);

    /// <summary>The DID resolved but the referenced verification method / usable key is absent (→ Failed).</summary>
    public static VerificationMethodResolution MethodNotFound { get; } =
        new(VerificationMethodResolutionStatus.MethodNotFound, null);
}

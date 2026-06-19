namespace Credentials.Schema;

/// <summary>
/// The caller-supplied hook (FR-081) the verifier uses to fetch a credential's <c>credentialSchema</c>
/// document. The caller owns egress (and therefore SSRF posture) and caching; the engine enforces any
/// declared <c>digestSRI</c> over the returned bytes. When no resolver is registered, the verifier
/// reports the schema check as <c>Skipped</c>.
/// </summary>
public interface ICredentialSchemaResolver
{
    /// <summary>Resolves the schema referenced by <paramref name="reference"/>.</summary>
    /// <param name="reference">The parsed <c>credentialSchema</c> entry.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The resolution result — found (the schema bytes) or not found (a reason code).</returns>
    Task<SchemaResolutionResult> ResolveAsync(SchemaReference reference, CancellationToken cancellationToken = default);
}

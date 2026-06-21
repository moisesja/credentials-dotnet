using System.Text.Json.Nodes;

namespace Credentials.Schema;

/// <summary>
/// An optional verifier hook that resolves the SD-JWT VC Type Metadata document for a <c>vct</c>
/// (draft-ietf-oauth-sd-jwt-vc-16 §6). It is the credentials-dotnet-owned wrapper over the SD-JWT
/// substrate's draft resolver, so no draft-version type appears on the public API (FR-051/D12, fix F3):
/// the engine adapts this hook to the substrate internally. Implementations control egress — the default
/// posture is offline (a local cache); a network-fetching resolver is the consumer's explicit choice. The
/// hook is optional — when none is registered, Type Metadata retrieval is skipped (it is informational and
/// does not gate verification in this milestone).
/// </summary>
public interface ICredentialTypeMetadataResolver
{
    /// <summary>
    /// Resolves the Type Metadata document for the given <paramref name="vct"/>, or <see langword="null"/>
    /// when no metadata is available. Should return <see langword="null"/> for an unresolvable <c>vct</c>
    /// rather than throwing. Because Type Metadata is informational and non-gating, a fault is treated as
    /// "no metadata available" and never changes the verification verdict (a misbehaving resolver cannot
    /// downgrade an otherwise valid credential); only cancellation propagates.
    /// </summary>
    /// <param name="vct">The SD-JWT VC type claim value to resolve metadata for.</param>
    /// <param name="cancellationToken">Cancels the resolution.</param>
    Task<JsonObject?> ResolveAsync(string vct, CancellationToken cancellationToken = default);
}

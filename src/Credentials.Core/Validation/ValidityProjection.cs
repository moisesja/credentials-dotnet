using System.Text.Json.Nodes;
using Credentials.Json;

namespace Credentials.Validation;

/// <summary>
/// Reads a document's validity window, applying the VCDM 1.1 → 2.0 member fallback exactly once
/// (conformance fix D1): version 2.0 uses <c>validFrom</c> / <c>validUntil</c>; version 1.1 uses
/// <c>issuanceDate</c> / <c>expirationDate</c>. Shared by the typed layer and the verifier so the
/// fallback is applied in one place.
/// </summary>
public static class ValidityProjection
{
    /// <summary>The start of the validity window, or <see langword="null"/> if absent/unparseable.</summary>
    public static DateTimeOffset? GetValidFrom(JsonObject root, VcdmVersion version)
    {
        ArgumentNullException.ThrowIfNull(root);
        return version switch
        {
            VcdmVersion.V1_1 => Read(root, "issuanceDate"),
            VcdmVersion.V2_0 => Read(root, "validFrom"),
            // Unknown: best-effort — prefer the 2.0 member, fall back to the 1.1 member.
            _ => Read(root, "validFrom") ?? Read(root, "issuanceDate"),
        };
    }

    /// <summary>The end of the validity window, or <see langword="null"/> if absent/unparseable.</summary>
    public static DateTimeOffset? GetValidUntil(JsonObject root, VcdmVersion version)
    {
        ArgumentNullException.ThrowIfNull(root);
        return version switch
        {
            VcdmVersion.V1_1 => Read(root, "expirationDate"),
            VcdmVersion.V2_0 => Read(root, "validUntil"),
            _ => Read(root, "validUntil") ?? Read(root, "expirationDate"),
        };
    }

    private static DateTimeOffset? Read(JsonObject root, string member) =>
        Rfc3339.TryParse(JsonShape.AsString(root[member]), out var value) ? value : null;
}

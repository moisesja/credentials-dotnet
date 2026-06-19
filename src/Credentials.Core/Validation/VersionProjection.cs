using System.Text.Json.Nodes;
using Credentials.Json;

namespace Credentials.Validation;

/// <summary>
/// Detects the VCDM version of a document <em>positively</em> from the exact base URL at
/// <c>@context[0]</c> (conformance fix D1). There is no "v2 else v1.1" fallback: a first context
/// entry matching neither known base URL yields <see cref="VcdmVersion.Unknown"/>, which structural
/// validation rejects.
/// </summary>
public static class VersionProjection
{
    /// <summary>The VCDM 2.0 base context URL.</summary>
    public const string ContextV2 = "https://www.w3.org/ns/credentials/v2";

    /// <summary>The VCDM 1.1 base context URL.</summary>
    public const string ContextV1_1 = "https://www.w3.org/2018/credentials/v1";

    /// <summary>Returns the expected base context URL for a known version, or <see langword="null"/> for <see cref="VcdmVersion.Unknown"/>.</summary>
    public static string? BaseContextFor(VcdmVersion version) => version switch
    {
        VcdmVersion.V2_0 => ContextV2,
        VcdmVersion.V1_1 => ContextV1_1,
        _ => null,
    };

    /// <summary>
    /// Detects the version from the first <c>@context</c> entry (the only entry if <c>@context</c> is
    /// a bare string). Returns <see cref="VcdmVersion.Unknown"/> when absent or unrecognized.
    /// </summary>
    public static VcdmVersion Detect(JsonObject root)
    {
        ArgumentNullException.ThrowIfNull(root);

        var context = root["@context"];
        var first = context switch
        {
            JsonArray array when array.Count > 0 => JsonShape.AsString(array[0]),
            _ when JsonShape.IsString(context) => JsonShape.AsString(context),
            _ => null,
        };

        return first switch
        {
            ContextV2 => VcdmVersion.V2_0,
            ContextV1_1 => VcdmVersion.V1_1,
            _ => VcdmVersion.Unknown,
        };
    }
}

using System.Text.Json.Nodes;

namespace Credentials;

/// <summary>
/// A <c>credentialSchema</c> reference — a pointer to a schema (e.g. a JSON Schema) the credential's
/// claims are expected to conform to (VCDM 2.0 §4.11). Each reference requires both an <c>id</c> and
/// a <see cref="Type"/> (conformance fix H4). The full reference is preserved verbatim in
/// <see cref="Raw"/>.
/// </summary>
public sealed class CredentialSchemaRef
{
    private readonly JsonObject _raw;

    internal CredentialSchemaRef(string? id, string? type, JsonObject raw)
    {
        Id = id;
        Type = type;
        _raw = raw;
    }

    /// <summary>The schema identifier (<c>id</c>) — the URL the schema is fetched from, if present.</summary>
    public string? Id { get; }

    /// <summary>The schema type (e.g. <c>JsonSchema</c>), if present.</summary>
    public string? Type { get; }

    /// <summary>A deep clone of the full schema reference object.</summary>
    public JsonObject Raw => (JsonObject)_raw.DeepClone();
}

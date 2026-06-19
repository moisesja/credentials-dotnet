using System.Text.Json.Nodes;

namespace Credentials;

/// <summary>
/// The <c>issuer</c> of a credential — either a bare identifier string or an object whose
/// <c>id</c> is the issuer identifier (VCDM 2.0 §4.4). Object-form issuers require an <c>id</c>
/// (enforced by structural validation, conformance fix H3).
/// </summary>
public sealed class Issuer
{
    private readonly JsonObject? _object;

    internal Issuer(string id, JsonObject? objectForm)
    {
        Id = id;
        _object = objectForm;
    }

    /// <summary>The issuer identifier — the bare string, or the object's <c>id</c> member.</summary>
    public string Id { get; }

    /// <summary>True if the issuer was expressed as an object (with additional members beyond <c>id</c> possible).</summary>
    public bool IsObject => _object is not null;

    /// <summary>
    /// Returns a clone of an additional member of the object-form issuer (e.g. <c>name</c>), or
    /// <see langword="null"/> if the issuer is a bare string or the member is absent.
    /// </summary>
    public JsonNode? GetProperty(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _object? [name]?.DeepClone();
    }
}

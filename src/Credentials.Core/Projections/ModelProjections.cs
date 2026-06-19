using System.Text.Json.Nodes;
using Credentials.Json;

namespace Credentials.Projections;

/// <summary>
/// Internal read-only projections from the raw document node to the typed value model. Each helper
/// reads the live (frozen) root and deep-clones any node it stashes into a value type, so no live
/// node escapes by reference (NFR-003). These are pure functions of the immutable document, which is
/// what makes the typed accessors safe to memoize.
/// </summary>
internal static class ModelProjections
{
    public static IReadOnlyList<string> ReadContext(JsonObject root) =>
        JsonShape.ReadStringOrStringArray(root["@context"]);

    public static IReadOnlyList<string> ReadType(JsonObject root) =>
        JsonShape.ReadStringOrStringArray(root["type"]);

    public static string? ReadId(JsonObject root) => JsonShape.AsString(root["id"]);

    public static string? ReadHolder(JsonObject root)
    {
        var holder = root["holder"];
        return holder switch
        {
            JsonObject obj => JsonShape.AsString(obj["id"]),
            _ => JsonShape.AsString(holder),
        };
    }

    public static Issuer? ReadIssuer(JsonObject root)
    {
        var issuer = root["issuer"];
        switch (issuer)
        {
            case null:
                return null;
            case JsonObject obj:
            {
                var id = JsonShape.AsString(obj["id"]);
                return id is null ? null : new Issuer(id, (JsonObject)obj.DeepClone());
            }
            default:
            {
                var id = JsonShape.AsString(issuer);
                return id is null ? null : new Issuer(id, null);
            }
        }
    }

    public static IReadOnlyList<CredentialSubject> ReadSubjects(JsonObject root)
    {
        var subject = root["credentialSubject"];
        switch (subject)
        {
            case JsonObject obj:
                return [ToSubject(obj)];
            case JsonArray array:
            {
                var list = new List<CredentialSubject>(array.Count);
                foreach (var item in array)
                {
                    if (item is JsonObject obj)
                    {
                        list.Add(ToSubject(obj));
                    }
                }

                return list;
            }
            default:
                return [];
        }
    }

    public static IReadOnlyList<CredentialStatusEntry> ReadStatus(JsonObject root) =>
        ReadEntries(root["credentialStatus"], static (id, type, raw) => new CredentialStatusEntry(id, type, raw));

    public static IReadOnlyList<CredentialSchemaRef> ReadSchema(JsonObject root) =>
        ReadEntries(root["credentialSchema"], static (id, type, raw) => new CredentialSchemaRef(id, type, raw));

    private static CredentialSubject ToSubject(JsonObject obj) =>
        new(JsonShape.AsString(obj["id"]), (JsonObject)obj.DeepClone());

    private static IReadOnlyList<T> ReadEntries<T>(JsonNode? node, Func<string?, string?, JsonObject, T> factory)
    {
        switch (node)
        {
            case JsonObject obj:
                return [ToEntry(obj, factory)];
            case JsonArray array:
            {
                var list = new List<T>(array.Count);
                foreach (var item in array)
                {
                    if (item is JsonObject obj)
                    {
                        list.Add(ToEntry(obj, factory));
                    }
                }

                return list;
            }
            default:
                return [];
        }
    }

    private static T ToEntry<T>(JsonObject obj, Func<string?, string?, JsonObject, T> factory)
    {
        var id = JsonShape.AsString(obj["id"]);
        var type = JsonShape.AsString(obj["type"]) ?? FirstString(obj["type"]);
        return factory(id, type, (JsonObject)obj.DeepClone());
    }

    private static string? FirstString(JsonNode? node) =>
        node is JsonArray array && array.Count > 0 ? JsonShape.AsString(array[0]) : null;
}

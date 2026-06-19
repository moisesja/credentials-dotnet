using System.Text.Json;
using System.Text.Json.Nodes;

namespace Credentials.Json;

/// <summary>
/// Small internal helpers for classifying and reading <see cref="JsonNode"/> shapes without throwing.
/// Structural validation and the typed projections both operate on the raw node tree, so they need
/// to ask "is this a string / a non-empty array of strings / an object" without coercion.
/// </summary>
internal static class JsonShape
{
    /// <summary>The JSON value kind of a node; an absent (null) node is reported as <see cref="JsonValueKind.Undefined"/>.</summary>
    public static JsonValueKind Kind(JsonNode? node) =>
        node is null ? JsonValueKind.Undefined : node.GetValueKind();

    /// <summary>True if <paramref name="node"/> is a JSON string.</summary>
    public static bool IsString(JsonNode? node) => Kind(node) == JsonValueKind.String;

    /// <summary>True if <paramref name="node"/> is a JSON object.</summary>
    public static bool IsObject(JsonNode? node) => node is JsonObject;

    /// <summary>True if <paramref name="node"/> is a JSON array.</summary>
    public static bool IsArray(JsonNode? node) => node is JsonArray;

    /// <summary>Returns the string value if <paramref name="node"/> is a JSON string, otherwise <see langword="null"/>.</summary>
    public static string? AsString(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    /// <summary>
    /// Reads a member as a list of strings: a single JSON string becomes a one-element list; a JSON
    /// array contributes each of its string members (non-string members are skipped). Returns an
    /// empty list for any other shape. Order is preserved.
    /// </summary>
    public static IReadOnlyList<string> ReadStringOrStringArray(JsonNode? node)
    {
        switch (node)
        {
            case JsonValue when IsString(node):
                return [AsString(node)!];
            case JsonArray array:
            {
                var list = new List<string>(array.Count);
                foreach (var item in array)
                {
                    var s = AsString(item);
                    if (s is not null)
                    {
                        list.Add(s);
                    }
                }

                return list;
            }
            default:
                return [];
        }
    }

    /// <summary>True if every member of <paramref name="array"/> is a JSON string.</summary>
    public static bool AllStrings(JsonArray array)
    {
        foreach (var item in array)
        {
            if (!IsString(item))
            {
                return false;
            }
        }

        return true;
    }
}

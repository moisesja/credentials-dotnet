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

    /// <summary>True if <paramref name="node"/> is a JSON string that is neither empty nor whitespace-only.</summary>
    public static bool IsNonBlankString(JsonNode? node) => !string.IsNullOrWhiteSpace(AsString(node));

    /// <summary>
    /// True if <paramref name="node"/> is a single JSON string that is an absolute URI with a scheme
    /// (VCDM 2.0 identifier semantics — a URL). DIDs (<c>did:…</c>), URNs (<c>urn:…</c>) and HTTP(S) URLs
    /// pass; a scheme-less string, an embedded space, an integer, <see langword="null"/>, or an array of
    /// identifiers do not. It is intentionally not HTTP-only and does not require dereferenceability.
    /// </summary>
    public static bool IsAbsoluteUri(JsonNode? node)
    {
        var value = AsString(node);
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (char.IsWhiteSpace(c))
            {
                return false;
            }
        }

        // Uri.TryCreate with UriKind.Absolute already requires a scheme, so success alone is sufficient.
        return Uri.TryCreate(value, UriKind.Absolute, out _);
    }

    /// <summary>True if <paramref name="node"/> is a non-empty JSON array whose every member is a non-blank string.</summary>
    public static bool IsNonBlankStringArray(JsonNode? node)
    {
        if (node is not JsonArray array || array.Count == 0)
        {
            return false;
        }

        foreach (var item in array)
        {
            if (!IsNonBlankString(item))
            {
                return false;
            }
        }

        return true;
    }

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

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Credentials;

/// <summary>
/// The canonical store behind a <see cref="Credential"/> or <see cref="VerifiablePresentation"/> —
/// the single source of truth (D10 / OQ-3). It holds one <see cref="JsonObject"/> (mutable only while
/// a builder is assembling it, frozen thereafter) and, for documents parsed from the wire, the exact
/// original UTF-8 bytes. Proofs and canonicalization depend on byte/structure fidelity, so this type
/// guards three things: incoming bytes are copied defensively and bounded; nothing internal escapes by
/// reference (every projection returns a fresh copy/clone); and a built document is serialized exactly
/// once with <see cref="CredentialJson.Faithful"/> and pinned.
/// </summary>
public sealed class CredentialDocument
{
    /// <summary>
    /// The maximum accepted size, in bytes, of a credential document parsed from untrusted input.
    /// Caps worst-case parse/clone memory amplification (NFR-006); comfortably fits real credentials,
    /// status lists, and embedded presentations.
    /// </summary>
    public const int MaxInputBytes = 4 * 1024 * 1024;

    private static readonly JsonDocumentOptions ParseOptions = new()
    {
        MaxDepth = 256,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        // Reject duplicate object keys eagerly at parse: System.Text.Json otherwise admits them and
        // throws a non-JsonException lazily on first member access, which (a) breaks the parse/verify
        // "never throws anything but CredentialFormatException" contract and (b) lets the verbatim
        // wire bytes (which keep both keys) disagree with the parsed node tree (which keeps one).
        AllowDuplicateProperties = false,
    };

    private readonly JsonObject _root;
    private readonly ReadOnlyMemory<byte>? _originalUtf8;
    private readonly Lock _serializeGate = new();
    private byte[]? _serializedCache;
    private bool _frozen;

    private CredentialDocument(JsonObject root, DocumentOrigin origin, ReadOnlyMemory<byte>? originalUtf8, bool frozen)
    {
        _root = root;
        Origin = origin;
        _originalUtf8 = originalUtf8;
        _frozen = frozen;
    }

    /// <summary>Where this document's content came from — determines the fidelity strategy.</summary>
    public DocumentOrigin Origin { get; }

    /// <summary>True once the document is frozen (immutable). Documents cross public boundaries only when frozen.</summary>
    public bool IsFrozen => _frozen;

    /// <summary>
    /// Parses a document from exact UTF-8 wire bytes, copying them defensively and retaining them
    /// verbatim for byte-faithful verification. Input is bounded (depth, no comments, no trailing
    /// commas) to limit untrusted-input cost (NFR-006). The result is frozen.
    /// </summary>
    /// <exception cref="CredentialFormatException">The bytes are not valid JSON or the root is not an object.</exception>
    public static CredentialDocument Parse(ReadOnlyMemory<byte> utf8Json)
    {
        if (utf8Json.Length > MaxInputBytes)
        {
            throw new CredentialFormatException(
                $"The credential document is {utf8Json.Length} bytes, exceeding the maximum of {MaxInputBytes} bytes.");
        }

        var copy = utf8Json.ToArray();
        JsonObject root;
        try
        {
            var node = JsonNode.Parse(copy, nodeOptions: null, documentOptions: ParseOptions);
            root = node as JsonObject
                ?? throw new CredentialFormatException("The credential document root must be a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new CredentialFormatException("The credential document is not valid JSON.", ex);
        }

        return new CredentialDocument(root, DocumentOrigin.ReceivedBytes, copy, frozen: true);
    }

    /// <summary>Parses a document from a UTF-8 JSON string. See <see cref="Parse(ReadOnlyMemory{byte})"/>.</summary>
    public static CredentialDocument Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return Parse(Encoding.UTF8.GetBytes(json));
    }

    /// <summary>
    /// Creates a frozen document from a borrowed <see cref="JsonElement"/> by cloning it (the source
    /// element/document may be disposed afterward).
    /// </summary>
    /// <exception cref="CredentialFormatException"><paramref name="element"/> is not a JSON object.</exception>
    public static CredentialDocument FromElement(JsonElement element, DocumentOrigin origin = DocumentOrigin.ParsedElement)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new CredentialFormatException("The credential element must be a JSON object.");
        }

        var root = JsonObject.Create(element.Clone())
            ?? throw new CredentialFormatException("The credential element could not be read as an object.");
        return new CredentialDocument(root, origin, null, frozen: true);
    }

    internal static CredentialDocument CreateMutable() =>
        new(new JsonObject(), DocumentOrigin.Built, originalUtf8: null, frozen: false);

    /// <summary>
    /// The live root tree. Internal only, and a strict invariant: it is mutated solely by a builder
    /// while the document is unfrozen (via <see cref="Set"/>). Once frozen it is read-only — the typed
    /// projections and the serialize-once cache both read it and would desynchronize if it were mutated
    /// after freeze. The securing layer (M1) must produce a new document (re-ingested via
    /// <see cref="Parse(ReadOnlyMemory{byte})"/>), never mutate a frozen <see cref="Root"/>.
    /// </summary>
    internal JsonObject Root => _root;

    internal void Set(string member, JsonNode? value)
    {
        if (_frozen)
        {
            throw new InvalidOperationException("The credential document is frozen and cannot be modified.");
        }

        _root[member] = value;
    }

    internal CredentialDocument Freeze()
    {
        _frozen = true;
        return this;
    }

    /// <summary>Returns a deep clone of a top-level member, or <see langword="null"/> if absent. No live node escapes.</summary>
    public JsonNode? this[string member]
    {
        get
        {
            ArgumentNullException.ThrowIfNull(member);
            return _root[member]?.DeepClone();
        }
    }

    /// <summary>Returns a new frozen, built document with <paramref name="name"/> set to a clone of <paramref name="value"/>.</summary>
    public CredentialDocument WithMember(string name, JsonNode? value)
    {
        ArgumentNullException.ThrowIfNull(name);
        var clone = (JsonObject)_root.DeepClone();
        clone[name] = value?.DeepClone();
        return new CredentialDocument(clone, DocumentOrigin.Built, originalUtf8: null, frozen: true);
    }

    /// <summary>
    /// The document's UTF-8 bytes, as a fresh copy: the verbatim wire bytes for a received document,
    /// or the serialize-once-pinned faithful bytes for a built/parsed-element document.
    /// </summary>
    public ReadOnlyMemory<byte> ToUtf8()
    {
        if (Origin == DocumentOrigin.ReceivedBytes && _originalUtf8 is { } original)
        {
            return original.ToArray();
        }

        return SerializeOnce().AsSpan().ToArray();
    }

    /// <summary>The document's UTF-8 bytes as a fresh array. See <see cref="ToUtf8"/>.</summary>
    public byte[] ToBytes() => ToUtf8().ToArray();

    /// <summary>
    /// The whole document as a self-contained <see cref="JsonElement"/> (a 1:1 reparse of
    /// <see cref="ToUtf8"/>), suitable for handing to the Data Integrity pipeline.
    /// </summary>
    public JsonElement ToElement()
    {
        // Reuse ParseOptions so the reparse is governed by the same policy as the front door
        // (depth bound + no duplicate keys) and can never be more permissive than Parse.
        using var document = JsonDocument.Parse(ToUtf8(), ParseOptions);
        return document.RootElement.Clone();
    }

    /// <summary>A deep clone of the document as a <see cref="JsonObject"/> (used for SD-JWT claim selection).</summary>
    public JsonObject ToClaimsObject() => (JsonObject)_root.DeepClone();

    private byte[] SerializeOnce()
    {
        if (_serializedCache is { } cached)
        {
            return cached;
        }

        lock (_serializeGate)
        {
            // Deterministic output: a torn race recomputes identical bytes, so the double-check is safe.
            return _serializedCache ??= JsonSerializer.SerializeToUtf8Bytes(_root, CredentialJson.Faithful);
        }
    }
}

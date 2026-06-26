using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Json;
using Credentials.Projections;
using Credentials.Validation;

namespace Credentials;

/// <summary>
/// A W3C Verifiable Presentation (VCDM 2.0, or 1.1 on the verification path) — a holder-assembled
/// package of one or more credentials. Like <see cref="Credential"/>, it is backed by a frozen
/// <see cref="CredentialDocument"/> with lazy typed projections over it.
/// </summary>
public sealed class VerifiablePresentation
{
    private readonly CredentialDocument _document;
    private readonly Lazy<VcdmVersion> _version;
    private readonly Lazy<IReadOnlyList<string>> _context;
    private readonly Lazy<IReadOnlyList<string>> _type;
    private readonly Lazy<string?> _id;
    private readonly Lazy<string?> _holder;
    private readonly Lazy<IReadOnlyList<ContainedCredential>> _credentials;

    private VerifiablePresentation(CredentialDocument document, SecuringState securing)
    {
        _document = document;
        Securing = securing;

        const LazyThreadSafetyMode mode = LazyThreadSafetyMode.ExecutionAndPublication;
        _version = new Lazy<VcdmVersion>(() => VersionProjection.Detect(_document.Root), mode);
        _context = new Lazy<IReadOnlyList<string>>(() => ModelProjections.ReadContext(_document.Root), mode);
        _type = new Lazy<IReadOnlyList<string>>(() => ModelProjections.ReadType(_document.Root), mode);
        _id = new Lazy<string?>(() => ModelProjections.ReadId(_document.Root), mode);
        _holder = new Lazy<string?>(() => ModelProjections.ReadHolder(_document.Root), mode);
        _credentials = new Lazy<IReadOnlyList<ContainedCredential>>(ReadContainedCredentials, mode);
    }

    /// <summary>Starts building a new unsecured VCDM 2.0 presentation.</summary>
    public static VerifiablePresentationBuilder Build() => new();

    /// <summary>Parses a presentation from UTF-8 JSON wire bytes.</summary>
    /// <exception cref="CredentialFormatException">The bytes are not a valid JSON-object presentation.</exception>
    public static VerifiablePresentation Parse(ReadOnlyMemory<byte> utf8Json)
    {
        var document = CredentialDocument.Parse(utf8Json);
        return FromDocument(document, DetectSecuring(document));
    }

    /// <summary>Parses a presentation from a UTF-8 JSON string.</summary>
    public static VerifiablePresentation Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return Parse(Encoding.UTF8.GetBytes(json));
    }

    internal static VerifiablePresentation FromDocument(CredentialDocument document, SecuringState securing) =>
        new(document, securing);

    /// <summary>True — every presentation crossing a public boundary is frozen.</summary>
    public bool IsFrozen => _document.IsFrozen;

    /// <summary>How the presentation is secured.</summary>
    public SecuringState Securing { get; }

    /// <summary>Where the document's content came from.</summary>
    public DocumentOrigin Origin => _document.Origin;

    /// <summary>The detected VCDM version (positive detection — fix F8: presentations are version-detected, not hardcoded).</summary>
    public VcdmVersion Version => _version.Value;

    /// <summary>The <c>@context</c> entries, as strings.</summary>
    public IReadOnlyList<string> Context => _context.Value;

    /// <summary>The <c>type</c> values, always as a list.</summary>
    public IReadOnlyList<string> Type => _type.Value;

    /// <summary>The presentation <c>id</c>, or <see langword="null"/> if absent.</summary>
    public string? Id => _id.Value;

    /// <summary>The <c>holder</c> identifier, or <see langword="null"/> if absent.</summary>
    public string? Holder => _holder.Value;

    /// <summary>The contained credentials (embedded or enveloped), always as a list.</summary>
    public IReadOnlyList<ContainedCredential> VerifiableCredentials => _credentials.Value;

    /// <summary>Returns a deep clone of any top-level member by name.</summary>
    public JsonNode? GetMember(string name) => _document[name];

    /// <summary>The underlying document (the source of truth).</summary>
    public CredentialDocument Document => _document;

    /// <summary>The whole presentation as a self-contained <see cref="JsonElement"/>.</summary>
    public JsonElement ToElement() => _document.ToElement();

    /// <summary>The presentation's exact UTF-8 bytes.</summary>
    public ReadOnlyMemory<byte> ToUtf8() => _document.ToUtf8();

    /// <summary>The presentation's exact UTF-8 bytes as a fresh array.</summary>
    public byte[] ToBytes() => _document.ToBytes();

    /// <summary>Runs version-aware structural conformance validation over the presentation (FR-002, FR-005). Never throws.</summary>
    public StructuralValidationResult ValidateStructure() =>
        StructuralValidator.Validate(_document.Root, VcRole.Presentation, Version);

    private IReadOnlyList<ContainedCredential> ReadContainedCredentials()
    {
        var node = _document.Root["verifiableCredential"];
        return node switch
        {
            JsonArray array => array.Select(ToContained).Where(c => c is not null).Select(c => c!).ToArray(),
            null => [],
            _ => ToContained(node) is { } single ? [single] : [],
        };
    }

    private static ContainedCredential? ToContained(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
            {
                // Embedded JSON-object credential — wrap structure-faithfully.
                var document = CredentialDocument.FromElement(JsonSerializer.SerializeToElement(obj, CredentialJson.Faithful));
                var securing = obj["proof"] is not null ? SecuringState.DataIntegrity : SecuringState.Unsecured;
                return ContainedCredential.Embedded(Credential.FromDocument(document, securing));
            }
            case JsonValue when JsonShape.IsString(node):
                // Enveloped compact serialization (JOSE / SD-JWT) — kept verbatim.
                return ContainedCredential.Enveloped(JsonShape.AsString(node)!);
            default:
                return null;
        }
    }

    private static SecuringState DetectSecuring(CredentialDocument document) =>
        document.Root["proof"] is not null ? SecuringState.DataIntegrity : SecuringState.Unsecured;
}

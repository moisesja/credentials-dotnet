using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Projections;
using Credentials.Validation;

namespace Credentials;

/// <summary>
/// A W3C Verifiable Credential (VCDM 2.0, or 1.1 on the verification path). The credential is backed
/// by a <see cref="CredentialDocument"/> that is the single source of truth; the typed accessors here
/// are lazy projections over that frozen document, safe to memoize precisely because the document is
/// immutable. Unknown or non-standard members (e.g. <c>evidence</c>, vendor extensions) are never
/// lost — reach them with <see cref="GetMember"/> or the underlying <see cref="Document"/>.
/// </summary>
public sealed class Credential
{
    private readonly CredentialDocument _document;
    private readonly ReadOnlyMemory<byte> _envelope;
    private readonly Lazy<VcdmVersion> _version;
    private readonly Lazy<IReadOnlyList<string>> _context;
    private readonly Lazy<IReadOnlyList<string>> _type;
    private readonly Lazy<string?> _id;
    private readonly Lazy<Issuer?> _issuer;
    private readonly Lazy<IReadOnlyList<CredentialSubject>> _subjects;
    private readonly Lazy<DateTimeOffset?> _validFrom;
    private readonly Lazy<DateTimeOffset?> _validUntil;
    private readonly Lazy<IReadOnlyList<CredentialStatusEntry>> _status;
    private readonly Lazy<IReadOnlyList<CredentialSchemaRef>> _schema;

    private Credential(CredentialDocument document, SecuringState securing, ReadOnlyMemory<byte> envelope)
    {
        _document = document;
        _envelope = envelope;
        Securing = securing;

        const LazyThreadSafetyMode mode = LazyThreadSafetyMode.ExecutionAndPublication;
        _version = new Lazy<VcdmVersion>(() => VersionProjection.Detect(_document.Root), mode);
        _context = new Lazy<IReadOnlyList<string>>(() => ModelProjections.ReadContext(_document.Root), mode);
        _type = new Lazy<IReadOnlyList<string>>(() => ModelProjections.ReadType(_document.Root), mode);
        _id = new Lazy<string?>(() => ModelProjections.ReadId(_document.Root), mode);
        _issuer = new Lazy<Issuer?>(() => ModelProjections.ReadIssuer(_document.Root), mode);
        _subjects = new Lazy<IReadOnlyList<CredentialSubject>>(() => ModelProjections.ReadSubjects(_document.Root), mode);
        _validFrom = new Lazy<DateTimeOffset?>(() => ValidityProjection.GetValidFrom(_document.Root, Version), mode);
        _validUntil = new Lazy<DateTimeOffset?>(() => ValidityProjection.GetValidUntil(_document.Root, Version), mode);
        _status = new Lazy<IReadOnlyList<CredentialStatusEntry>>(() => ModelProjections.ReadStatus(_document.Root), mode);
        _schema = new Lazy<IReadOnlyList<CredentialSchemaRef>>(() => ModelProjections.ReadSchema(_document.Root), mode);
    }

    /// <summary>Starts building a new unsecured VCDM 2.0 credential.</summary>
    public static CredentialBuilder Build() => new();

    /// <summary>Parses a credential from UTF-8 JSON wire bytes (a JSON-object credential — embedded or unsecured).</summary>
    /// <exception cref="CredentialFormatException">The bytes are not a valid JSON-object credential.</exception>
    public static Credential Parse(ReadOnlyMemory<byte> utf8Json)
    {
        var document = CredentialDocument.Parse(utf8Json);
        return FromDocument(document, DetectSecuring(document));
    }

    /// <summary>Parses a credential from a UTF-8 JSON string. See <see cref="Parse(ReadOnlyMemory{byte})"/>.</summary>
    public static Credential Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return Parse(Encoding.UTF8.GetBytes(json));
    }

    internal static Credential FromDocument(CredentialDocument document, SecuringState securing) =>
        new(document, securing, default);

    /// <summary>
    /// Materializes an enveloped credential (JOSE/COSE): <paramref name="inner"/> is the decoded inner
    /// credential document (the bytes the signature covers), and <paramref name="envelope"/> is retained
    /// verbatim so the verifier can verify the original wire bytes (sign-exact-bytes).
    /// </summary>
    internal static Credential FromEnvelope(CredentialDocument inner, SecuringState securing, ReadOnlyMemory<byte> envelope) =>
        new(inner, securing, envelope);

    /// <summary>True — every credential crossing a public boundary is frozen.</summary>
    public bool IsFrozen => _document.IsFrozen;

    /// <summary>How the credential is secured (none / Data Integrity for a JSON-object credential).</summary>
    public SecuringState Securing { get; }

    /// <summary>Where the document's content came from.</summary>
    public DocumentOrigin Origin => _document.Origin;

    /// <summary>The detected VCDM version (positive detection; <see cref="VcdmVersion.Unknown"/> if unrecognized).</summary>
    public VcdmVersion Version => _version.Value;

    /// <summary>True if an embedded Data Integrity <c>proof</c> member is present.</summary>
    public bool HasEmbeddedProof => _document.Root["proof"] is not null;

    /// <summary>
    /// The verbatim compact serialization for a credential that has one — the compact JWS for a
    /// JOSE-enveloped credential (<see cref="SecuringState.Jose"/>) or the compact SD-JWT for an SD-JWT VC
    /// (<see cref="SecuringState.SdJwtVc"/>) — or <see langword="null"/> otherwise (Data Integrity / COSE
    /// have no compact string form). Kept byte-for-byte so it can be re-transmitted or embedded in a
    /// presentation without breaking the signature.
    /// </summary>
    public string? CompactEnvelope =>
        Securing is SecuringState.Jose or SecuringState.SdJwtVc ? Encoding.UTF8.GetString(_envelope.Span) : null;

    /// <summary>The verbatim secured wire bytes for an enveloped credential (compact JWS as UTF-8, or COSE_Sign1 bytes).</summary>
    internal ReadOnlyMemory<byte> EnvelopeBytes => _envelope;

    /// <summary>The <c>@context</c> entries, as strings (object-valued entries are available via <see cref="GetMember"/>).</summary>
    public IReadOnlyList<string> Context => _context.Value;

    /// <summary>The <c>type</c> values, always as a list.</summary>
    public IReadOnlyList<string> Type => _type.Value;

    /// <summary>The credential <c>id</c>, or <see langword="null"/> if absent.</summary>
    public string? Id => _id.Value;

    /// <summary>The <c>issuer</c>, or <see langword="null"/> if absent or malformed.</summary>
    public Issuer? Issuer => _issuer.Value;

    /// <summary>The credential subject(s), always as a list (FR-001 multiple subjects).</summary>
    public IReadOnlyList<CredentialSubject> CredentialSubjects => _subjects.Value;

    /// <summary>The validity-window start (<c>validFrom</c>, or 1.1 <c>issuanceDate</c>).</summary>
    public DateTimeOffset? ValidFrom => _validFrom.Value;

    /// <summary>The validity-window end (<c>validUntil</c>, or 1.1 <c>expirationDate</c>).</summary>
    public DateTimeOffset? ValidUntil => _validUntil.Value;

    /// <summary>The <c>credentialStatus</c> references, always as a list.</summary>
    public IReadOnlyList<CredentialStatusEntry> CredentialStatus => _status.Value;

    /// <summary>The <c>credentialSchema</c> references, always as a list.</summary>
    public IReadOnlyList<CredentialSchemaRef> CredentialSchema => _schema.Value;

    /// <summary>Returns a deep clone of any top-level member by name — the escape hatch for non-standard members.</summary>
    public JsonNode? GetMember(string name) => _document[name];

    /// <summary>The underlying document (the source of truth).</summary>
    public CredentialDocument Document => _document;

    /// <summary>The whole credential as a self-contained <see cref="JsonElement"/> (for the Data Integrity pipeline).</summary>
    public JsonElement AsElement() => _document.ToElement();

    /// <summary>
    /// The credential's exact UTF-8 bytes (for enveloping JOSE/COSE signing over the exact payload).
    /// Byte-stable across calls — the backing document returns its verbatim wire bytes (received) or
    /// serialize-once-pinned bytes (built), never a re-serialization — which the verifier's
    /// <c>envelope_payload_mismatch</c> guard relies on when binding the verified payload to this credential.
    /// </summary>
    public ReadOnlyMemory<byte> AsUtf8() => _document.ToUtf8();

    /// <summary>A deep clone of the credential as a <see cref="JsonObject"/> (for SD-JWT VC claim selection).</summary>
    public JsonObject AsClaimsObject() => _document.ToClaimsObject();

    /// <summary>The credential's exact UTF-8 bytes as a fresh array.</summary>
    public byte[] ToBytes() => _document.ToBytes();

    /// <summary>Runs version-aware structural conformance validation over the document (FR-005). Never throws.</summary>
    public StructuralValidationResult ValidateStructure() =>
        StructuralValidator.Validate(_document.Root, VcRole.Credential, Version);

    private static SecuringState DetectSecuring(CredentialDocument document) =>
        document.Root["proof"] is not null ? SecuringState.DataIntegrity : SecuringState.Unsecured;
}

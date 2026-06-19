using System.Text.Json.Nodes;
using Credentials.Verification;

namespace Credentials.Schema;

/// <summary>The schema language a <see cref="ResolvedSchema"/> is expressed in. JSON Schema 2020-12 ships
/// in v1; the abstraction keeps the validation seam open to SHACL later without an API break (D9).</summary>
public enum SchemaDialect
{
    /// <summary>JSON Schema, 2020-12 dialect.</summary>
    JsonSchema2020_12,
}

/// <summary>
/// A parsed <c>credentialSchema</c> reference handed to the <see cref="ICredentialSchemaResolver"/>. The
/// caller fetches the schema (controlling its own egress) and returns the bytes; the engine enforces any
/// <see cref="ExpectedDigestSri"/> itself. The verbatim entry is in <see cref="Raw"/>.
/// </summary>
public sealed record SchemaReference
{
    /// <summary>The schema <c>id</c> (the URL it is fetched from).</summary>
    public required string Id { get; init; }

    /// <summary>The <c>credentialSchema.type</c> (e.g. <c>JsonSchema</c> / <c>JsonSchemaCredential</c>).</summary>
    public required string Type { get; init; }

    /// <summary>
    /// The Subresource Integrity digest (<c>digestSRI</c>) declared on the entry, if any. When present,
    /// the engine recomputes the digest over the fetched bytes and rejects a mismatch before parsing.
    /// </summary>
    public string? ExpectedDigestSri { get; init; }

    /// <summary>A deep clone of the full <c>credentialSchema</c> entry.</summary>
    public required JsonObject Raw { get; init; }
}

/// <summary>The dialect-abstracted result of fetching a schema document.</summary>
public sealed class SchemaResolutionResult
{
    private SchemaResolutionResult(bool isFound, ResolvedSchema? schema, string? reasonCode)
    {
        IsFound = isFound;
        Schema = schema;
        ReasonCode = reasonCode;
    }

    /// <summary>Whether the schema was resolved.</summary>
    public bool IsFound { get; }

    /// <summary>The resolved schema (only when <see cref="IsFound"/>).</summary>
    public ResolvedSchema? Schema { get; }

    /// <summary>A short, secret-free reason code when the schema was not resolved.</summary>
    public string? ReasonCode { get; }

    /// <summary>The schema was resolved.</summary>
    public static SchemaResolutionResult Found(ResolvedSchema schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        return new SchemaResolutionResult(true, schema, null);
    }

    /// <summary>The schema could not be resolved (⇒ the schema check is <c>Indeterminate</c>).</summary>
    public static SchemaResolutionResult NotFound(string reasonCode = "unresolvable") =>
        new(false, null, reasonCode);
}

/// <summary>
/// A fetched schema document: its <see cref="Dialect"/> and the verbatim fetched <see cref="Content"/>
/// bytes (so the engine computes <c>digestSRI</c> itself — NFR-006 — before parsing).
/// </summary>
public sealed class ResolvedSchema
{
    /// <summary>Creates a resolved schema.</summary>
    public ResolvedSchema(string id, SchemaDialect dialect, ReadOnlyMemory<byte> content)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        Id = id;
        Dialect = dialect;
        Content = content;
    }

    /// <summary>The schema identifier.</summary>
    public string Id { get; }

    /// <summary>The schema language.</summary>
    public SchemaDialect Dialect { get; }

    /// <summary>The verbatim fetched schema bytes.</summary>
    public ReadOnlyMemory<byte> Content { get; }
}

/// <summary>The tri-state outcome of validating a credential against a schema.</summary>
public sealed record SchemaCheckResult
{
    private SchemaCheckResult(SchemaCheckOutcome outcome, IReadOnlyList<CheckDiagnostic> diagnostics)
    {
        Outcome = outcome;
        Diagnostics = diagnostics;
    }

    /// <summary>The outcome.</summary>
    public SchemaCheckOutcome Outcome { get; }

    /// <summary>Validation diagnostics (secret-free), typically present on failure.</summary>
    public IReadOnlyList<CheckDiagnostic> Diagnostics { get; }

    /// <summary>The credential conforms to the schema.</summary>
    public static SchemaCheckResult Success() => new(SchemaCheckOutcome.Success, []);

    /// <summary>The credential does not conform.</summary>
    public static SchemaCheckResult Failure(IReadOnlyList<CheckDiagnostic> diagnostics) =>
        new(SchemaCheckOutcome.Failure, diagnostics);

    /// <summary>Validation could not be performed (unknown dialect, unparseable schema, evaluation fault).</summary>
    public static SchemaCheckResult Indeterminate(string code, string message) =>
        new(SchemaCheckOutcome.Indeterminate, [new CheckDiagnostic(code, message, DiagnosticSeverity.Error)]);
}

/// <summary>The tri-state schema validation outcome.</summary>
public enum SchemaCheckOutcome
{
    /// <summary>The credential conforms to the schema.</summary>
    Success,

    /// <summary>The credential violates the schema.</summary>
    Failure,

    /// <summary>Validation could not be completed.</summary>
    Indeterminate,
}

using System.Text.Json;

namespace Credentials.Schema;

/// <summary>
/// Validates a credential against a resolved schema of a given <c>credentialSchema.type</c>. This is the
/// SHACL-ready seam (D9): the v1 implementation handles JSON Schema 2020-12; a SHACL validator can be added
/// later purely by DI registration, with no API break. Implementations are collected into the immutable
/// <c>SchemaValidatorRegistry</c>, keyed by <see cref="SchemaType"/>.
/// </summary>
public interface ICredentialSchemaValidator
{
    /// <summary>The <c>credentialSchema.type</c> this validator handles (e.g. <c>JsonSchema</c>).</summary>
    string SchemaType { get; }

    /// <summary>The schema dialect this validator produces/consumes.</summary>
    SchemaDialect Dialect { get; }

    /// <summary>
    /// Validates <paramref name="credential"/> against <paramref name="schema"/>. Never throws — returns a
    /// tri-state <see cref="SchemaCheckResult"/> (an unparseable schema or evaluation fault is
    /// <see cref="SchemaCheckOutcome.Indeterminate"/>).
    /// </summary>
    SchemaCheckResult Validate(ResolvedSchema schema, JsonElement credential);
}

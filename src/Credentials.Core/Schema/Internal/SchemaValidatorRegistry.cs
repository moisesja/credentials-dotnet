using System.Collections.Frozen;

namespace Credentials.Schema;

/// <summary>
/// Resolves a <c>credentialSchema.type</c> to its <see cref="ICredentialSchemaValidator"/>. Built once from
/// the DI-registered validators and <strong>immutable thereafter</strong> — there is no public
/// <c>Register</c> (conformance/hardening fix F6); a new dialect (e.g. SHACL) is added by registering
/// another <see cref="ICredentialSchemaValidator"/> before the registry is constructed.
/// </summary>
internal sealed class SchemaValidatorRegistry
{
    private readonly FrozenDictionary<string, ICredentialSchemaValidator> _byType;

    public SchemaValidatorRegistry(IEnumerable<ICredentialSchemaValidator> validators)
    {
        ArgumentNullException.ThrowIfNull(validators);

        var byType = new Dictionary<string, ICredentialSchemaValidator>(StringComparer.Ordinal);
        foreach (var validator in validators)
        {
            // Last registration wins, mirroring the securing-mechanism registry's semantics.
            byType[validator.SchemaType] = validator;
        }

        _byType = byType.ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <summary>The schema types this registry can validate.</summary>
    public IReadOnlyCollection<string> SupportedTypes => _byType.Keys;

    /// <summary>The validator for a schema type, or <see langword="null"/> if none is registered.</summary>
    public ICredentialSchemaValidator? Get(string schemaType) => _byType.GetValueOrDefault(schemaType);
}

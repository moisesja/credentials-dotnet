using System.Text.Json.Nodes;
using Credentials.Validation;

namespace Credentials;

/// <summary>
/// Builds an unsecured VCDM 2.0 <see cref="VerifiablePresentation"/> by writing through to the
/// underlying document. The base context and base type (<c>VerifiablePresentation</c>) are seeded at
/// index 0 and cannot be displaced. Embedded credentials are added as JSON objects; enveloped
/// credentials are added as verbatim compact serializations. Single-use; call <see cref="Seal"/> once.
/// </summary>
public sealed class VerifiablePresentationBuilder
{
    private readonly CredentialDocument _document;
    private bool _sealed;

    internal VerifiablePresentationBuilder()
    {
        _document = CredentialDocument.CreateMutable();
        _document.Set("@context", new JsonArray(VersionProjection.ContextV2));
        _document.Set("type", new JsonArray("VerifiablePresentation"));
    }

    /// <summary>Sets the presentation <c>id</c>.</summary>
    public VerifiablePresentationBuilder WithId(string id)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        EnsureMutable();
        _document.Set("id", id);
        return this;
    }

    /// <summary>Sets the <c>holder</c> identifier.</summary>
    public VerifiablePresentationBuilder WithHolder(string holderId)
    {
        ArgumentException.ThrowIfNullOrEmpty(holderId);
        EnsureMutable();
        _document.Set("holder", holderId);
        return this;
    }

    /// <summary>Appends an additional <c>type</c> value (after the base <c>VerifiablePresentation</c>).</summary>
    public VerifiablePresentationBuilder AddType(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);
        EnsureMutable();
        ((JsonArray)_document.Root["type"]!).Add(type);
        return this;
    }

    /// <summary>Appends an additional <c>@context</c> URL at index ≥ 1; never displaces the base context.</summary>
    public VerifiablePresentationBuilder AddContext(string contextUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(contextUrl);
        EnsureMutable();
        ((JsonArray)_document.Root["@context"]!).Add(contextUrl);
        return this;
    }

    /// <summary>Adds an embedded JSON-object credential to <c>verifiableCredential</c>.</summary>
    public VerifiablePresentationBuilder AddCredential(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        EnsureMutable();
        Append(credential.ToClaimsObject());
        return this;
    }

    /// <summary>Adds an enveloped credential (a verbatim compact serialization) to <c>verifiableCredential</c>.</summary>
    public VerifiablePresentationBuilder AddEnvelopedCredential(string compactSerialization)
    {
        ArgumentException.ThrowIfNullOrEmpty(compactSerialization);
        EnsureMutable();
        Append(compactSerialization);
        return this;
    }

    /// <summary>
    /// Validates the assembled presentation against VCDM 2.0, freezes it, and returns the unsecured
    /// <see cref="VerifiablePresentation"/>. The builder cannot be reused.
    /// </summary>
    /// <exception cref="CredentialStructureException">The assembled presentation is not structurally valid.</exception>
    public VerifiablePresentation Seal()
    {
        EnsureMutable();
        var result = StructuralValidator.Validate(_document.Root, VcRole.Presentation, VcdmVersion.V2_0);
        if (!result.IsValid)
        {
            throw new CredentialStructureException(result.Problems);
        }

        _sealed = true;
        _document.Freeze();
        return VerifiablePresentation.FromDocument(_document, SecuringState.Unsecured);
    }

    private void Append(JsonNode child)
    {
        switch (_document.Root["verifiableCredential"])
        {
            case null:
                _document.Set("verifiableCredential", new JsonArray(child));
                break;
            case JsonArray array:
                array.Add(child);
                break;
            case { } existing:
                _document.Set("verifiableCredential", new JsonArray(existing.DeepClone(), child));
                break;
        }
    }

    private void EnsureMutable()
    {
        if (_sealed)
        {
            throw new InvalidOperationException("The presentation builder has already been sealed and cannot be reused.");
        }
    }
}

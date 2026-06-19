using System.Text.Json.Nodes;
using Credentials.Validation;

namespace Credentials;

/// <summary>
/// Builds an unsecured VCDM 2.0 <see cref="Credential"/> by writing through to the underlying
/// document from the first call, so the sealed document is exactly what the issuer assembled —
/// member order preserved and unknown members carried verbatim. The base context and base type are
/// seeded at index 0 and cannot be displaced (conformance fix A2). The builder is single-use; call
/// <see cref="Seal"/> exactly once.
/// </summary>
public sealed class CredentialBuilder
{
    private readonly CredentialDocument _document;
    private bool _sealed;

    internal CredentialBuilder()
    {
        _document = CredentialDocument.CreateMutable();
        _document.Set("@context", new JsonArray(VersionProjection.ContextV2));
        _document.Set("type", new JsonArray("VerifiableCredential"));
    }

    /// <summary>Sets the credential <c>id</c>.</summary>
    public CredentialBuilder WithId(string id)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        EnsureMutable();
        _document.Set("id", id);
        return this;
    }

    /// <summary>Sets a bare-string <c>issuer</c> identifier.</summary>
    public CredentialBuilder WithIssuer(string issuerId)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuerId);
        EnsureMutable();
        _document.Set("issuer", issuerId);
        return this;
    }

    /// <summary>Sets an object-form <c>issuer</c> (which must contain a string <c>id</c>; checked at <see cref="Seal"/>).</summary>
    public CredentialBuilder WithIssuer(JsonObject issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        EnsureMutable();
        _document.Set("issuer", issuer.DeepClone());
        return this;
    }

    /// <summary>Appends an additional <c>type</c> value (after the base <c>VerifiableCredential</c>).</summary>
    public CredentialBuilder AddType(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);
        EnsureMutable();
        ((JsonArray)_document.Root["type"]!).Add(type);
        return this;
    }

    /// <summary>Appends an additional <c>@context</c> URL at index ≥ 1; never displaces the base context at index 0.</summary>
    public CredentialBuilder AddContext(string contextUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(contextUrl);
        EnsureMutable();
        ((JsonArray)_document.Root["@context"]!).Add(contextUrl);
        return this;
    }

    /// <summary>Adds a <c>credentialSubject</c>; a second subject promotes the member to an array (FR-001).</summary>
    public CredentialBuilder AddSubject(JsonObject subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        EnsureMutable();
        AddOrPromote("credentialSubject", subject);
        return this;
    }

    /// <summary>Adds a <c>credentialStatus</c> reference; a second reference promotes the member to an array (FR-016).</summary>
    public CredentialBuilder AddStatus(JsonObject status)
    {
        ArgumentNullException.ThrowIfNull(status);
        EnsureMutable();
        AddOrPromote("credentialStatus", status);
        return this;
    }

    /// <summary>Adds a <c>credentialSchema</c> reference; a second reference promotes the member to an array.</summary>
    public CredentialBuilder AddSchema(JsonObject schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        EnsureMutable();
        AddOrPromote("credentialSchema", schema);
        return this;
    }

    /// <summary>Sets <c>validFrom</c> (emitted as an RFC 3339 / xsd:dateTimeStamp with offset).</summary>
    public CredentialBuilder WithValidFrom(DateTimeOffset validFrom)
    {
        EnsureMutable();
        _document.Set("validFrom", Rfc3339.Format(validFrom));
        return this;
    }

    /// <summary>Sets <c>validUntil</c> (emitted as an RFC 3339 / xsd:dateTimeStamp with offset).</summary>
    public CredentialBuilder WithValidUntil(DateTimeOffset validUntil)
    {
        EnsureMutable();
        _document.Set("validUntil", Rfc3339.Format(validUntil));
        return this;
    }

    /// <summary>
    /// Sets an arbitrary top-level member (e.g. <c>termsOfUse</c>, <c>evidence</c>, a vendor extension).
    /// <c>@context</c> and <c>type</c> are protected: use <see cref="AddContext"/> / <see cref="AddType"/>
    /// (conformance fix A2).
    /// </summary>
    public CredentialBuilder SetMember(string name, JsonNode? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        EnsureMutable();
        if (name is "@context" or "type")
        {
            throw new ArgumentException(
                $"'{name}' is protected; use Add{(name == "@context" ? "Context" : "Type")} instead.", nameof(name));
        }

        _document.Set(name, value?.DeepClone());
        return this;
    }

    /// <summary>
    /// Validates the assembled credential against VCDM 2.0 (issuance is 2.0 only — D8), freezes it, and
    /// returns the unsecured <see cref="Credential"/>. The builder cannot be reused.
    /// </summary>
    /// <exception cref="CredentialStructureException">The assembled credential is not structurally valid.</exception>
    public Credential Seal()
    {
        EnsureMutable();
        var result = StructuralValidator.Validate(_document.Root, VcRole.Credential, VcdmVersion.V2_0);
        if (!result.IsValid)
        {
            throw new CredentialStructureException(result.Problems);
        }

        _sealed = true;
        _document.Freeze();
        return Credential.FromDocument(_document, SecuringState.Unsecured);
    }

    private void AddOrPromote(string member, JsonObject value)
    {
        var clone = value.DeepClone();
        switch (_document.Root[member])
        {
            case null:
                _document.Set(member, clone);
                break;
            case JsonArray array:
                array.Add(clone);
                break;
            case { } existing:
                _document.Set(member, new JsonArray(existing.DeepClone(), clone));
                break;
        }
    }

    private void EnsureMutable()
    {
        if (_sealed)
        {
            throw new InvalidOperationException("The credential builder has already been sealed and cannot be reused.");
        }
    }
}

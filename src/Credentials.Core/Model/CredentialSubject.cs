using System.Text.Json.Nodes;

namespace Credentials;

/// <summary>
/// A single <c>credentialSubject</c> entry — the claims about one subject. A credential may carry
/// one subject or many (VCDM 2.0 §4.5); <see cref="Credential.CredentialSubjects"/> always exposes
/// them as a list. The optional <see cref="Id"/> identifies the subject when present.
/// </summary>
public sealed class CredentialSubject
{
    private readonly JsonObject _claims;

    internal CredentialSubject(string? id, JsonObject claims)
    {
        Id = id;
        _claims = claims;
    }

    /// <summary>The subject identifier (<c>id</c>), or <see langword="null"/> for a subject without one.</summary>
    public string? Id { get; }

    /// <summary>A deep clone of the full subject object (including <c>id</c> and every claim).</summary>
    public JsonObject Claims => (JsonObject)_claims.DeepClone();

    /// <summary>Returns a clone of a single claim by name, or <see langword="null"/> if absent.</summary>
    public JsonNode? this[string claim]
    {
        get
        {
            ArgumentNullException.ThrowIfNull(claim);
            return _claims[claim]?.DeepClone();
        }
    }
}

using System.Text.Json.Nodes;

namespace Credentials;

/// <summary>
/// A <c>credentialStatus</c> reference — a pointer to a mechanism (e.g. a Bitstring Status List
/// entry) by which a verifier can check whether the credential has been revoked or suspended
/// (VCDM 2.0 §4.9). Each entry requires a <see cref="Type"/> (conformance fix H4). The full entry is
/// preserved verbatim in <see cref="Raw"/> because mechanism-specific members (such as
/// <c>statusListIndex</c>) are read by the status subsystem in a later milestone.
/// </summary>
public sealed class CredentialStatusEntry
{
    private readonly JsonObject _raw;

    internal CredentialStatusEntry(string? id, string? type, JsonObject raw)
    {
        Id = id;
        Type = type;
        _raw = raw;
    }

    /// <summary>The status entry identifier (<c>id</c>), if present.</summary>
    public string? Id { get; }

    /// <summary>The status mechanism type (e.g. <c>BitstringStatusListEntry</c>), if present.</summary>
    public string? Type { get; }

    /// <summary>A deep clone of the full status entry object.</summary>
    public JsonObject Raw => (JsonObject)_raw.DeepClone();
}

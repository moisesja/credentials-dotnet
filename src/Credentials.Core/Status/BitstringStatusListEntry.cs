using System.Text.Json.Nodes;

namespace Credentials.Status;

/// <summary>
/// A typed builder for a <c>credentialStatus</c> entry of type <c>BitstringStatusListEntry</c>
/// (Bitstring Status List v1.0) — the issuer-side helper for FR-016. Produce the wire object with
/// <see cref="ToJsonObject"/> and attach it via <c>CredentialBuilder.AddStatus(...)</c>.
/// </summary>
public sealed record BitstringStatusListEntry
{
    /// <summary>The <c>BitstringStatusListEntry</c> type token.</summary>
    public const string TypeName = "BitstringStatusListEntry";

    /// <summary>The status entry <c>id</c> (optional).</summary>
    public string? Id { get; init; }

    /// <summary>
    /// The status purpose this entry checks (e.g. <see cref="StatusPurpose.Revocation"/> /
    /// <see cref="StatusPurpose.Suspension"/>). Required.
    /// </summary>
    public required string StatusPurpose { get; init; }

    /// <summary>
    /// The index into the status list bitstring, expressed (per spec) as a base-10 string. Required.
    /// </summary>
    public required string StatusListIndex { get; init; }

    /// <summary>The URL of the <c>BitstringStatusListCredential</c> to dereference. Required.</summary>
    public required string StatusListCredential { get; init; }

    /// <summary>The number of bits per entry (optional; defaults to 1 when absent).</summary>
    public int? StatusSize { get; init; }

    /// <summary>Creates an entry from an integer index (formatted to the spec's base-10 string form).</summary>
    public static BitstringStatusListEntry Create(
        string statusPurpose, long statusListIndex, string statusListCredential, string? id = null, int? statusSize = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(statusListIndex);
        return new BitstringStatusListEntry
        {
            Id = id,
            StatusPurpose = statusPurpose,
            StatusListIndex = statusListIndex.ToString(System.Globalization.CultureInfo.InvariantCulture),
            StatusListCredential = statusListCredential,
            StatusSize = statusSize,
        };
    }

    /// <summary>Renders this entry as the <c>credentialStatus</c> wire object.</summary>
    public JsonObject ToJsonObject()
    {
        ArgumentException.ThrowIfNullOrEmpty(StatusPurpose);
        ArgumentException.ThrowIfNullOrEmpty(StatusListIndex);
        ArgumentException.ThrowIfNullOrEmpty(StatusListCredential);

        var obj = new JsonObject
        {
            ["type"] = TypeName,
            ["statusPurpose"] = StatusPurpose,
            ["statusListIndex"] = StatusListIndex,
            ["statusListCredential"] = StatusListCredential,
        };

        if (Id is not null)
        {
            obj["id"] = Id;
        }

        if (StatusSize is { } size)
        {
            obj["statusSize"] = size;
        }

        return obj;
    }
}

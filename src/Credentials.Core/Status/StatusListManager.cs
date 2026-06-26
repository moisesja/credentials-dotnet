using System.Text.Json.Nodes;
using Credentials.Json;

namespace Credentials.Status;

/// <summary>
/// Issuer-side production and maintenance of Bitstring Status List v1.0 status-list credentials
/// (FR-020/021). It assembles and updates the <strong>unsecured</strong>
/// <c>BitstringStatusListCredential</c> (one bitstring per purpose) for the issuer to sign through
/// <see cref="Roles.IIssuer"/>; it performs no signing and holds no keys. The status-list credential is
/// the single source of truth — every method takes one in and returns a fresh, unsecured credential out
/// (a frozen credential is never mutated).
/// </summary>
public sealed class StatusListManager
{
    /// <summary>The <c>credentialSubject.type</c> token for a status list.</summary>
    public const string SubjectType = "BitstringStatusList";

    /// <summary>The credential <c>type</c> token for a status-list credential.</summary>
    public const string CredentialType = "BitstringStatusListCredential";

    /// <summary>Creates an empty (all-valid) status-list credential for a single purpose.</summary>
    /// <param name="options">The list metadata (id, issuer, purpose, optional length and subject id).</param>
    /// <returns>An unsecured <see cref="Credential"/> ready for the issuer to sign.</returns>
    public Credential CreateList(StatusListCreateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(options.Id);
        ArgumentException.ThrowIfNullOrEmpty(options.Issuer);
        ArgumentException.ThrowIfNullOrEmpty(options.StatusPurpose);

        var bitstring = StatusBitstring.CreateEmpty(options.LengthBits);
        var subject = new JsonObject
        {
            ["id"] = options.SubjectId ?? (options.Id + "#list"),
            ["type"] = SubjectType,
            ["statusPurpose"] = options.StatusPurpose,
            ["encodedList"] = StatusBitstring.Encode(bitstring),
        };

        var builder = Credential.Build()
            .WithId(options.Id)
            .WithIssuer(options.Issuer)
            .AddType(CredentialType)
            .AddSubject(subject);

        if (options.ValidFrom is { } from)
        {
            builder.WithValidFrom(from);
        }

        if (options.ValidUntil is { } until)
        {
            builder.WithValidUntil(until);
        }

        return builder.Seal();
    }

    /// <summary>
    /// Reads the single-bit status for entry <paramref name="entryIndex"/> from a status-list credential.
    /// For multi-bit lists use <see cref="GetStatusValue"/>.
    /// </summary>
    public bool GetStatus(Credential statusListCredential, long entryIndex)
    {
        ArgumentNullException.ThrowIfNull(statusListCredential);
        ArgumentOutOfRangeException.ThrowIfNegative(entryIndex);

        var (_, encoded) = ReadSubject(statusListCredential.ToClaimsObject());
        var bitstring = StatusBitstring.Decode(encoded);
        return StatusBitstring.GetBit(bitstring, entryIndex);
    }

    /// <summary>Reads the multi-bit status value for entry <paramref name="entryIndex"/> (bit position
    /// <c>entryIndex * statusSize</c>, MSB-first).</summary>
    public long GetStatusValue(Credential statusListCredential, long entryIndex, int statusSize)
    {
        ArgumentNullException.ThrowIfNull(statusListCredential);
        ArgumentOutOfRangeException.ThrowIfNegative(entryIndex);
        ArgumentOutOfRangeException.ThrowIfLessThan(statusSize, 1);

        var (_, encoded) = ReadSubject(statusListCredential.ToClaimsObject());
        var bitstring = StatusBitstring.Decode(encoded);
        return StatusBitstring.GetValue(bitstring, checked(entryIndex * statusSize), statusSize);
    }

    /// <summary>
    /// Returns a fresh, unsecured copy of the status-list credential with the single-bit status for entry
    /// <paramref name="entryIndex"/> set or cleared, and any existing <c>proof</c> dropped (editing a signed
    /// document invalidates its proof, so it must be re-signed).
    /// </summary>
    public Credential WithStatus(Credential statusListCredential, long entryIndex, bool isSet)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(entryIndex);
        return Update(statusListCredential, bits => StatusBitstring.SetBit(bits, entryIndex, isSet));
    }

    /// <summary>
    /// Returns a fresh, unsecured copy with the multi-bit status <paramref name="value"/> written for entry
    /// <paramref name="entryIndex"/> (at bit position <c>entryIndex * statusSize</c>, MSB-first).
    /// </summary>
    public Credential WithStatusValue(Credential statusListCredential, long entryIndex, long value, int statusSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(entryIndex);
        ArgumentOutOfRangeException.ThrowIfLessThan(statusSize, 1);
        return Update(statusListCredential, bits => StatusBitstring.SetValue(bits, checked(entryIndex * statusSize), value, statusSize));
    }

    /// <summary>Marks entry <paramref name="entryIndex"/> revoked (sets the bit).</summary>
    public Credential Revoke(Credential statusListCredential, long entryIndex) =>
        WithStatus(statusListCredential, entryIndex, isSet: true);

    /// <summary>Marks entry <paramref name="entryIndex"/> suspended (sets the bit). Reversible.</summary>
    public Credential Suspend(Credential statusListCredential, long entryIndex) =>
        WithStatus(statusListCredential, entryIndex, isSet: true);

    /// <summary>Reinstates entry <paramref name="entryIndex"/> (clears the bit).</summary>
    public Credential Reinstate(Credential statusListCredential, long entryIndex) =>
        WithStatus(statusListCredential, entryIndex, isSet: false);

    private static Credential Update(Credential statusListCredential, Action<byte[]> mutate)
    {
        ArgumentNullException.ThrowIfNull(statusListCredential);

        var root = statusListCredential.ToClaimsObject();
        root.Remove("proof");

        var (subject, encoded) = ReadSubject(root);
        var bitstring = StatusBitstring.Decode(encoded);
        mutate(bitstring);
        subject["encodedList"] = StatusBitstring.Encode(bitstring);

        var document = CredentialDocument.FromElement(root.ToJsonElement(), DocumentOrigin.Built);
        return Credential.FromDocument(document, SecuringState.Unsecured);
    }

    private static (JsonObject Subject, string EncodedList) ReadSubject(JsonObject root)
    {
        var subjectNode = root["credentialSubject"];
        var subject = subjectNode switch
        {
            JsonObject obj => obj,
            JsonArray array => FirstStatusListSubject(array),
            _ => null,
        };

        if (subject is null)
        {
            throw new FormatException("The status-list credential has no BitstringStatusList credentialSubject.");
        }

        if (JsonShape.AsString(subject["encodedList"]) is not { Length: > 0 } encoded)
        {
            throw new FormatException("The status-list credentialSubject has no encodedList.");
        }

        return (subject, encoded);
    }

    private static JsonObject? FirstStatusListSubject(JsonArray array)
    {
        // Return the BitstringStatusList subject specifically — never a fallback to an arbitrary first
        // subject, which would silently operate on the wrong object. No match ⇒ null ⇒ a clean "no
        // BitstringStatusList subject" failure in ReadSubject.
        foreach (var item in array)
        {
            if (item is JsonObject obj
                && string.Equals(JsonShape.AsString(obj["type"]), SubjectType, StringComparison.Ordinal))
            {
                return obj;
            }
        }

        return null;
    }
}

/// <summary>Options for creating a Bitstring Status List credential.</summary>
public sealed record StatusListCreateOptions
{
    /// <summary>The status-list credential <c>id</c> (the URL it is published at). Required.</summary>
    public required string Id { get; init; }

    /// <summary>The issuer identifier. Required.</summary>
    public required string Issuer { get; init; }

    /// <summary>The status purpose (e.g. <see cref="StatusPurpose.Revocation"/>). Required.</summary>
    public required string StatusPurpose { get; init; }

    /// <summary>The <c>credentialSubject.id</c>; defaults to <c><see cref="Id"/>#list</c>.</summary>
    public string? SubjectId { get; init; }

    /// <summary>The bitstring length in bits; clamped up to the 131,072-bit spec minimum.</summary>
    public int LengthBits { get; init; } = StatusBitstring.MinimumBits;

    /// <summary>The list's <c>validFrom</c> (optional).</summary>
    public DateTimeOffset? ValidFrom { get; init; }

    /// <summary>The list's <c>validUntil</c> (optional). A status list past its window is not trusted by verifiers.</summary>
    public DateTimeOffset? ValidUntil { get; init; }
}

internal static class JsonNodeExtensions
{
    public static System.Text.Json.JsonElement ToJsonElement(this JsonObject obj) =>
        System.Text.Json.JsonSerializer.SerializeToElement(obj, CredentialJson.Faithful);
}

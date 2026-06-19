using System.Globalization;
using System.Text.Json.Nodes;

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

    /// <summary>Reads the status bit for <paramref name="index"/> from a status-list credential.</summary>
    public bool GetStatus(Credential statusListCredential, long index)
    {
        ArgumentNullException.ThrowIfNull(statusListCredential);
        ArgumentOutOfRangeException.ThrowIfNegative(index);

        var (subject, encoded) = ReadSubject(statusListCredential.AsClaimsObject());
        _ = subject;
        var bitstring = StatusBitstring.Decode(encoded);
        return StatusBitstring.GetBit(bitstring, index);
    }

    /// <summary>
    /// Returns a fresh, unsecured copy of the status-list credential with the bit at
    /// <paramref name="index"/> set or cleared, and any existing <c>proof</c> dropped (editing a signed
    /// document invalidates its proof, so it must be re-signed).
    /// </summary>
    public Credential WithStatus(Credential statusListCredential, long index, bool isSet)
    {
        ArgumentNullException.ThrowIfNull(statusListCredential);
        ArgumentOutOfRangeException.ThrowIfNegative(index);

        var root = statusListCredential.AsClaimsObject();
        root.Remove("proof");

        var (subject, encoded) = ReadSubject(root);
        var bitstring = StatusBitstring.Decode(encoded);
        StatusBitstring.SetBit(bitstring, index, isSet);
        subject["encodedList"] = StatusBitstring.Encode(bitstring);

        var document = CredentialDocument.FromElement(root.ToJsonElement(), DocumentOrigin.Built);
        return Credential.FromDocument(document, SecuringState.Unsecured);
    }

    /// <summary>Marks the credential at <paramref name="index"/> revoked/suspended (sets the bit).</summary>
    public Credential Revoke(Credential statusListCredential, long index) =>
        WithStatus(statusListCredential, index, isSet: true);

    /// <summary>Marks the credential at <paramref name="index"/> suspended (sets the bit). Reversible.</summary>
    public Credential Suspend(Credential statusListCredential, long index) =>
        WithStatus(statusListCredential, index, isSet: true);

    /// <summary>Reinstates the credential at <paramref name="index"/> (clears the bit).</summary>
    public Credential Reinstate(Credential statusListCredential, long index) =>
        WithStatus(statusListCredential, index, isSet: false);

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

        if (subject["encodedList"]?.GetValue<string>() is not { Length: > 0 } encoded)
        {
            throw new FormatException("The status-list credentialSubject has no encodedList.");
        }

        return (subject, encoded);
    }

    private static JsonObject? FirstStatusListSubject(JsonArray array)
    {
        foreach (var item in array)
        {
            if (item is JsonObject obj
                && string.Equals(obj["type"]?.GetValue<string>(), SubjectType, StringComparison.Ordinal))
            {
                return obj;
            }
        }

        return array.FirstOrDefault() as JsonObject;
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

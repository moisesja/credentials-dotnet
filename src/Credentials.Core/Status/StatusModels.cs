using System.Text.Json.Nodes;

namespace Credentials.Status;

/// <summary>
/// A parsed reference to a status-list entry, handed to the <see cref="IStatusListFetcher"/> so the
/// caller can dereference the list (controlling its own egress and caching). Carries the verbatim entry
/// in <see cref="Raw"/> for any mechanism-specific members.
/// </summary>
public sealed record StatusListReference
{
    /// <summary>The URL of the <c>BitstringStatusListCredential</c> to fetch.</summary>
    public required string StatusListCredential { get; init; }

    /// <summary>The status purpose the entry declares.</summary>
    public required string StatusPurpose { get; init; }

    /// <summary>The status list index, as the spec's base-10 string.</summary>
    public required string StatusListIndex { get; init; }

    /// <summary>The number of bits per entry (1 when the entry omitted <c>statusSize</c>).</summary>
    public int StatusSize { get; init; } = 1;

    /// <summary>A deep clone of the full <c>credentialStatus</c> entry.</summary>
    public required JsonObject Raw { get; init; }
}

/// <summary>
/// The result of a status-list fetch. On success it carries the <strong>secured</strong> status-list
/// credential bytes so the verifier can verify the list's own proof (Bitstring Status List Validate step
/// 4); on a miss it carries a reason code and the check is reported as <c>Indeterminate</c> (never thrown).
/// </summary>
public sealed class StatusListFetchResult
{
    private StatusListFetchResult(bool isFound, ReadOnlyMemory<byte> credential, string? reasonCode)
    {
        IsFound = isFound;
        Credential = credential;
        ReasonCode = reasonCode;
    }

    /// <summary>Whether the status-list credential was found.</summary>
    public bool IsFound { get; }

    /// <summary>The secured status-list credential's UTF-8 wire bytes (only when <see cref="IsFound"/>).</summary>
    public ReadOnlyMemory<byte> Credential { get; }

    /// <summary>A short, secret-free reason code when the list was not found.</summary>
    public string? ReasonCode { get; }

    /// <summary>The list was found: <paramref name="securedCredentialBytes"/> is the secured list VC.</summary>
    public static StatusListFetchResult Found(ReadOnlyMemory<byte> securedCredentialBytes) =>
        new(true, securedCredentialBytes, null);

    /// <summary>The list could not be retrieved (⇒ the status check is <c>Indeterminate</c>).</summary>
    public static StatusListFetchResult NotFound(string reasonCode = "list_unreachable") =>
        new(false, default, reasonCode);
}

/// <summary>
/// The structured, secret-free outcome of evaluating a credential's status entries (NFR-008). One
/// <see cref="StatusCheckDetail"/> per evaluated entry.
/// </summary>
public sealed record StatusCheckResult
{
    /// <summary>The per-entry details, in evaluation order.</summary>
    public required IReadOnlyList<StatusCheckDetail> Details { get; init; }
}

/// <summary>One entry's status outcome — logging-safe (carries no credential claims or keys).</summary>
public sealed record StatusCheckDetail
{
    /// <summary>The status purpose evaluated.</summary>
    public required string StatusPurpose { get; init; }

    /// <summary>Whether the status bit was set (revoked / suspended for the 1-bit purposes).</summary>
    public required bool IsSet { get; init; }

    /// <summary>The raw multi-bit value, when <c>statusSize &gt; 1</c>.</summary>
    public long? Value { get; init; }

    /// <summary>The resolved <c>statusMessage</c> text, when present (purpose <c>message</c>).</summary>
    public string? StatusMessage { get; init; }
}

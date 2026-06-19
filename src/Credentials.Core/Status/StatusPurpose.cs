namespace Credentials.Status;

/// <summary>
/// The well-known Bitstring Status List v1.0 status purposes. Strings (not an enum) because the spec
/// treats <c>statusPurpose</c> as an open set — a future purpose is usable without an API change.
/// </summary>
public static class StatusPurpose
{
    /// <summary>Cancels the validity of a credential. Irreversible.</summary>
    public const string Revocation = "revocation";

    /// <summary>Temporarily suspends a credential. Reversible (reinstatable).</summary>
    public const string Suspension = "suspension";

    /// <summary>A multi-bit named status (requires <c>statusSize &gt; 1</c> and a <c>statusMessage</c> table).</summary>
    public const string Message = "message";

    /// <summary>Signals that an updated credential is available.</summary>
    public const string Refresh = "refresh";
}

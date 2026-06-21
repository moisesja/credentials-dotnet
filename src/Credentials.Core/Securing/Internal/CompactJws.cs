using System.Buffers.Text;
using System.Text.Json;

namespace Credentials.Securing;

/// <summary>
/// Minimal, substrate-free reader for a compact JWS (<c>header.payload.signature</c>). Used by the
/// JOSE enveloping path to (a) read the protected-header <c>kid</c> so the key can be resolved
/// asynchronously before the synchronous substrate verify, and (b) recover the inner credential bytes
/// at ingest. It only base64url-decodes and reads JSON — it never verifies a signature (that is the
/// substrate's job) and pulls in no DataProofs type.
/// </summary>
internal static class CompactJws
{
    /// <summary>Reads the protected-header <c>kid</c> of a compact JWS, or <see langword="null"/> if absent/malformed.</summary>
    public static string? ReadKid(string compact)
    {
        if (!TrySplit(compact, out var header, out _, out _))
        {
            return null;
        }

        try
        {
            var headerBytes = Base64Url.DecodeFromChars(header);
            using var document = JsonDocument.Parse(headerBytes);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("kid", out var kid)
                && kid.ValueKind == JsonValueKind.String)
            {
                return kid.GetString();
            }
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return null;
        }

        return null;
    }

    /// <summary>Decodes the payload (second segment) of a compact JWS to its exact bytes.</summary>
    /// <exception cref="CredentialFormatException">The string is not a compact JWS or the payload is not valid base64url.</exception>
    public static byte[] DecodePayload(string compact)
    {
        if (!TrySplit(compact, out _, out var payload, out _))
        {
            throw new CredentialFormatException("The value is not a compact JWS (expected three '.'-separated segments).");
        }

        try
        {
            return Base64Url.DecodeFromChars(payload);
        }
        catch (FormatException ex)
        {
            throw new CredentialFormatException("The compact JWS payload is not valid base64url.", ex);
        }
    }

    private static bool TrySplit(
        string compact,
        out ReadOnlySpan<char> header,
        out ReadOnlySpan<char> payload,
        out ReadOnlySpan<char> signature)
    {
        header = default;
        payload = default;
        signature = default;
        if (string.IsNullOrEmpty(compact))
        {
            return false;
        }

        var first = compact.IndexOf('.');
        if (first <= 0)
        {
            return false;
        }

        var second = compact.IndexOf('.', first + 1);
        if (second <= first + 1 || second == compact.Length - 1)
        {
            return false;
        }

        // A compact JWS has exactly two '.' separators; a third makes it a JWE or malformed.
        if (compact.IndexOf('.', second + 1) >= 0)
        {
            return false;
        }

        header = compact.AsSpan(0, first);
        payload = compact.AsSpan(first + 1, second - first - 1);
        signature = compact.AsSpan(second + 1);
        return true;
    }
}

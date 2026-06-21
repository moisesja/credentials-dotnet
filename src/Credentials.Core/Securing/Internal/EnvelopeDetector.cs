namespace Credentials.Securing;

/// <summary>
/// Classifies untrusted verifier input by its securing form purely from its bytes — before any parse
/// or decode — so the verifier can route a compact JWS or a COSE_Sign1 message to the right enveloping
/// mechanism instead of blindly handing it to <see cref="CredentialDocument.Parse(ReadOnlyMemory{byte})"/>
/// (which requires a JSON object and would throw). Detection is a routing hint only; the authoritative
/// check is the subsequent decode/verify, which fails closed on anything that does not actually decode.
/// </summary>
internal static class EnvelopeDetector
{
    /// <summary>
    /// Returns the detected enveloping form, or <see langword="null"/> for a JSON-object credential (or
    /// anything unrecognized — the caller then attempts <see cref="CredentialDocument.Parse(ReadOnlyMemory{byte})"/>,
    /// which throws <see cref="CredentialFormatException"/> on malformed input).
    /// </summary>
    public static SecuringForm? Detect(ReadOnlySpan<byte> bytes)
    {
        var start = 0;
        while (start < bytes.Length && IsJsonWhitespace(bytes[start]))
        {
            start++;
        }

        if (start >= bytes.Length)
        {
            return null;
        }

        var first = bytes[start];

        // A JSON-object credential (embedded Data Integrity or unsecured) starts with '{'.
        if (first == (byte)'{')
        {
            return null;
        }

        // COSE_Sign1: the tagged form (CBOR tag 18 = 0xD2, or 0xD8 0x12), or an untagged 4-element
        // array (0x84). None of these collide with JSON ('{') or base64url (the JWS alphabet).
        if (first == 0xD2
            || (first == 0xD8 && start + 1 < bytes.Length && bytes[start + 1] == 0x12)
            || first == 0x84)
        {
            return SecuringForm.Cose;
        }

        // A compact JWS: ASCII base64url with exactly two '.' separators (header.payload.signature).
        if (IsBase64UrlChar(first) && LooksLikeCompactJws(bytes[start..]))
        {
            return SecuringForm.Jose;
        }

        return null;
    }

    private static bool LooksLikeCompactJws(ReadOnlySpan<byte> bytes)
    {
        // Trim trailing JSON whitespace (a wire token may carry a trailing newline).
        var end = bytes.Length;
        while (end > 0 && IsJsonWhitespace(bytes[end - 1]))
        {
            end--;
        }

        var dots = 0;
        for (var i = 0; i < end; i++)
        {
            var b = bytes[i];
            if (b == (byte)'.')
            {
                dots++;
                if (dots > 2)
                {
                    return false;
                }
            }
            else if (!IsBase64UrlChar(b))
            {
                return false;
            }
        }

        return dots == 2;
    }

    private static bool IsBase64UrlChar(byte b) =>
        b is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or >= (byte)'0' and <= (byte)'9'
            or (byte)'-' or (byte)'_';

    private static bool IsJsonWhitespace(byte b) =>
        b is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r';
}

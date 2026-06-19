using System.Globalization;
using System.Text.RegularExpressions;

namespace Credentials.Validation;

/// <summary>
/// Strict <c>xsd:dateTimeStamp</c> parsing for VCDM validity timestamps (conformance fix C1). The
/// data model requires a mandatory timezone offset (<c>Z</c> or <c>±hh:mm</c>); an offset-less string
/// is rejected rather than silently localized.
/// </summary>
internal static partial class Rfc3339
{
    // Date + 'T' + time, optional fractional seconds, MANDATORY offset (Z or ±hh:mm).
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex DateTimeStampPattern();

    /// <summary>
    /// Parses a strict <c>xsd:dateTimeStamp</c>. Returns <see langword="false"/> for a null value, a
    /// value lacking a timezone offset, or any otherwise unparseable value.
    /// </summary>
    public static bool TryParse(string? value, out DateTimeOffset result)
    {
        result = default;
        if (value is null || !DateTimeStampPattern().IsMatch(value))
        {
            return false;
        }

        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out result);
    }

    /// <summary>Formats a <see cref="DateTimeOffset"/> as an RFC 3339 / <c>xsd:dateTimeStamp</c> with offset (<c>Z</c> for UTC).</summary>
    public static string Format(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero
            ? value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
            : value.ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);
}

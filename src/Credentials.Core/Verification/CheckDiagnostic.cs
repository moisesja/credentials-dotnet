namespace Credentials.Verification;

/// <summary>The severity of a <see cref="CheckDiagnostic"/>.</summary>
public enum DiagnosticSeverity
{
    /// <summary>Informational; does not by itself indicate a problem.</summary>
    Info,

    /// <summary>A non-fatal concern worth surfacing.</summary>
    Warning,

    /// <summary>An error explaining why a check failed or could not complete.</summary>
    Error,
}

/// <summary>
/// One diagnostic attached to a verification check: a stable machine-readable <see cref="Code"/>, a
/// secret-free human-readable <see cref="Message"/>, a <see cref="Severity"/>, and an optional
/// <see cref="JsonPointer"/> locating the offending member. Messages are mapped from upstream codes
/// to vetted credentials-dotnet text — never an upstream free-text message verbatim — so they are
/// safe to log (NFR-008).
/// </summary>
/// <param name="Code">A stable, machine-readable diagnostic code.</param>
/// <param name="Message">A short, secret-free, human-readable description.</param>
/// <param name="Severity">The diagnostic severity.</param>
/// <param name="JsonPointer">An optional RFC 6901 JSON Pointer to the offending member.</param>
public sealed record CheckDiagnostic(
    string Code,
    string Message,
    DiagnosticSeverity Severity = DiagnosticSeverity.Error,
    string? JsonPointer = null);

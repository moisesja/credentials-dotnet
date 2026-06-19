namespace Credentials.Verification;

/// <summary>
/// The result of one verification check: its <see cref="Kind"/>, its <see cref="Status"/>, and any
/// <see cref="Diagnostics"/>. Effectively immutable and safe to share across threads (NFR-003).
/// </summary>
public sealed class CheckResult
{
    private CheckResult(string kind, CheckStatus status, IReadOnlyList<CheckDiagnostic> diagnostics, object? detail = null)
    {
        Kind = kind;
        Status = status;
        Diagnostics = diagnostics;
        Detail = detail;
    }

    /// <summary>The check identifier (see <see cref="CheckKinds"/>).</summary>
    public string Kind { get; }

    /// <summary>The outcome.</summary>
    public CheckStatus Status { get; }

    /// <summary>Any diagnostics — typically present for <see cref="CheckStatus.Failed"/> / <see cref="CheckStatus.Indeterminate"/>.</summary>
    public IReadOnlyList<CheckDiagnostic> Diagnostics { get; }

    /// <summary>
    /// An optional structured, secret-free payload specific to the check (e.g. a
    /// <see cref="Status.StatusCheckResult"/> for the status check), for callers that want detail beyond
    /// the diagnostics. <see langword="null"/> for checks that carry none.
    /// </summary>
    public object? Detail { get; }

    /// <summary>Returns a copy of this result carrying the given structured <paramref name="detail"/>.</summary>
    internal CheckResult WithDetail(object? detail) => new(Kind, Status, Diagnostics, detail);

    /// <summary>A passed check.</summary>
    public static CheckResult Passed(string kind) => new(kind, CheckStatus.Passed, []);

    /// <summary>A failed check (a definitive negative) with one diagnostic.</summary>
    public static CheckResult Failed(string kind, string code, string message, string? jsonPointer = null) =>
        new(kind, CheckStatus.Failed, [new CheckDiagnostic(code, message, DiagnosticSeverity.Error, jsonPointer)]);

    /// <summary>A failed check carrying several diagnostics.</summary>
    public static CheckResult Failed(string kind, IReadOnlyList<CheckDiagnostic> diagnostics) =>
        new(kind, CheckStatus.Failed, diagnostics);

    /// <summary>An indeterminate check (could not complete) with one diagnostic.</summary>
    public static CheckResult Indeterminate(string kind, string code, string message) =>
        new(kind, CheckStatus.Indeterminate, [new CheckDiagnostic(code, message, DiagnosticSeverity.Error)]);

    /// <summary>An indeterminate check carrying several diagnostics.</summary>
    public static CheckResult Indeterminate(string kind, IReadOnlyList<CheckDiagnostic> diagnostics) =>
        new(kind, CheckStatus.Indeterminate, diagnostics);

    /// <summary>A skipped check (not run) with an explanatory diagnostic.</summary>
    public static CheckResult Skipped(string kind, string message) =>
        new(kind, CheckStatus.Skipped, [new CheckDiagnostic("skipped", message, DiagnosticSeverity.Info)]);
}

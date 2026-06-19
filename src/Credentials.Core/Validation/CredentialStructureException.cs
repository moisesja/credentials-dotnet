namespace Credentials.Validation;

/// <summary>
/// Thrown when a credential or presentation is structurally malformed at a point where the engine
/// cannot proceed — specifically at issuance (<see cref="CredentialBuilder.Seal"/>), where producing
/// a non-conformant credential would be a programming error. On the verification path, structural
/// problems are reported through the verification result rather than thrown (FR-045).
/// </summary>
public sealed class CredentialStructureException : Exception
{
    /// <summary>Creates the exception from the structural problems that caused it.</summary>
    public CredentialStructureException(IReadOnlyList<StructuralProblem> problems)
        : base(BuildMessage(problems)) => Problems = problems;

    /// <summary>The structural problems that caused the failure.</summary>
    public IReadOnlyList<StructuralProblem> Problems { get; }

    private static string BuildMessage(IReadOnlyList<StructuralProblem> problems)
    {
        ArgumentNullException.ThrowIfNull(problems);
        if (problems.Count == 0)
        {
            return "The credential is structurally invalid.";
        }

        var details = string.Join("; ", problems.Select(p => $"{p.Code} at {p.JsonPointer}: {p.Message}"));
        return $"The credential is structurally invalid ({problems.Count} problem(s)): {details}";
    }
}

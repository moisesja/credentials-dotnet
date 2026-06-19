namespace Credentials.Validation;

/// <summary>
/// The outcome of a <see cref="StructuralValidator"/> run: <see cref="IsValid"/> plus the list of
/// <see cref="StructuralProblem"/>s found (empty when valid). Effectively immutable and safe to share
/// across threads (NFR-003).
/// </summary>
public sealed class StructuralValidationResult
{
    /// <summary>A reusable valid result with no problems.</summary>
    public static StructuralValidationResult Valid { get; } = new([]);

    internal StructuralValidationResult(IReadOnlyList<StructuralProblem> problems) => Problems = problems;

    /// <summary>True when no structural problems were found.</summary>
    public bool IsValid => Problems.Count == 0;

    /// <summary>The structural problems found, in document order. Empty when <see cref="IsValid"/>.</summary>
    public IReadOnlyList<StructuralProblem> Problems { get; }
}

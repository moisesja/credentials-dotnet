namespace Credentials.Verification;

/// <summary>
/// Policy governing how individual check outcomes compose into the overall
/// <see cref="VerificationDecision"/>.
/// </summary>
public sealed record VerificationPolicy
{
    /// <summary>
    /// When <see langword="true"/> (the default, fail-closed), a check that could not be completed
    /// (<see cref="CheckStatus.Indeterminate"/>) rejects the credential. When <see langword="false"/>,
    /// an indeterminate check yields an overall <see cref="VerificationDecision.Indeterminate"/>
    /// instead of <see cref="VerificationDecision.Rejected"/>.
    /// </summary>
    public bool TreatIndeterminateAsFailure { get; init; } = true;
}

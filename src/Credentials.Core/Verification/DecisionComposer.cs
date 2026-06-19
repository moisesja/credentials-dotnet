namespace Credentials.Verification;

/// <summary>
/// Composes per-check outcomes into the overall <see cref="VerificationDecision"/>. The single home of
/// the decision rule: skipped checks are ignored; any failed check rejects; otherwise any indeterminate
/// check yields <see cref="VerificationDecision.Indeterminate"/> (or rejects under a fail-closed policy);
/// otherwise the credential is accepted.
/// </summary>
internal static class DecisionComposer
{
    public static VerificationDecision Compose(IReadOnlyList<CheckResult> checks, VerificationPolicy policy)
    {
        var failed = false;
        var indeterminate = false;

        foreach (var check in checks)
        {
            switch (check.Status)
            {
                case CheckStatus.Failed:
                    failed = true;
                    break;
                case CheckStatus.Indeterminate:
                    indeterminate = true;
                    break;
            }
        }

        if (failed)
        {
            return VerificationDecision.Rejected;
        }

        if (indeterminate)
        {
            return policy.TreatIndeterminateAsFailure
                ? VerificationDecision.Rejected
                : VerificationDecision.Indeterminate;
        }

        return VerificationDecision.Accepted;
    }
}

namespace Credentials.Verification;

/// <summary>The overall decision of a verification, composed from the individual check outcomes.</summary>
public enum VerificationDecision
{
    /// <summary>Every check that ran passed (or was skipped); the credential is accepted.</summary>
    Accepted,

    /// <summary>At least one check definitively failed; the credential is rejected.</summary>
    Rejected,

    /// <summary>No check failed, but at least one could not be completed, so acceptance cannot be asserted.</summary>
    Indeterminate,
}

namespace Credentials.Verification;

/// <summary>The outcome of a single verification check.</summary>
public enum CheckStatus
{
    /// <summary>The check ran and the credential satisfied it.</summary>
    Passed,

    /// <summary>The check ran and the credential failed it (a definitive negative — e.g. a bad signature).</summary>
    Failed,

    /// <summary>The check could not be completed (e.g. a verification method could not be resolved); the result is unknown.</summary>
    Indeterminate,

    /// <summary>The check was not run (not requested, or its substrate is not configured).</summary>
    Skipped,
}

namespace Credentials;

/// <summary>
/// Names a securing mechanism and, where relevant, its cryptosuite — by opaque string, so a future
/// suite (e.g. <c>ecdsa-sd-2023</c>) is selectable the day it ships with no public-API change
/// (FR-053). No draft-version type appears here.
/// </summary>
/// <param name="Form">The securing family.</param>
/// <param name="Cryptosuite">The Data Integrity cryptosuite name, when <paramref name="Form"/> is <see cref="SecuringForm.DataIntegrity"/>.</param>
public readonly record struct SecuringSelector(SecuringForm Form, string? Cryptosuite = null)
{
    /// <summary>Selects an embedded Data Integrity proof with the given cryptosuite (e.g. <c>eddsa-jcs-2022</c>).</summary>
    public static SecuringSelector DataIntegrity(string cryptosuite)
    {
        ArgumentException.ThrowIfNullOrEmpty(cryptosuite);
        return new SecuringSelector(SecuringForm.DataIntegrity, cryptosuite);
    }
}

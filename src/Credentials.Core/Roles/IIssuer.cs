namespace Credentials.Roles;

/// <summary>
/// The Issuer role: secures an unsecured credential in a requested form. The credential itself is
/// assembled with <see cref="Credential.Build"/> (FR-010); this secures it (FR-011) by delegating to
/// the proofs layer and signing through the <c>NetCrypto.ISigner</c> resolved by the caller (FR-015).
/// </summary>
public interface IIssuer
{
    /// <summary>
    /// Secures <paramref name="credential"/> (which must be unsecured) according to
    /// <paramref name="request"/>, returning the secured credential.
    /// </summary>
    /// <exception cref="System.NotSupportedException">The requested form/cryptosuite is not available.</exception>
    /// <exception cref="System.InvalidOperationException">The credential is already secured.</exception>
    Task<IssuedCredential> IssueAsync(Credential credential, IssuanceRequest request, CancellationToken cancellationToken = default);
}

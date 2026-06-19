using Credentials.Verification;

namespace Credentials.Roles;

/// <summary>
/// The Verifier role: checks a credential end-to-end and returns a structured result (FR-040/043).
/// Verification is side-effect free and reports failed checks through the result rather than throwing;
/// exceptions are reserved for malformed input and programming errors (FR-045).
/// </summary>
public interface IVerifier
{
    /// <summary>Verifies a parsed credential.</summary>
    ValueTask<CredentialVerificationResult> VerifyCredentialAsync(
        Credential credential,
        CredentialVerificationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Parses and verifies a credential from UTF-8 JSON wire bytes.</summary>
    /// <exception cref="CredentialFormatException">The bytes are not a parseable credential.</exception>
    ValueTask<CredentialVerificationResult> VerifyCredentialAsync(
        ReadOnlyMemory<byte> credential,
        CredentialVerificationOptions? options = null,
        CancellationToken cancellationToken = default);
}

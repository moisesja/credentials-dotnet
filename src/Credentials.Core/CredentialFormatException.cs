namespace Credentials;

/// <summary>
/// Thrown when input handed to the engine cannot be parsed as a credential or presentation at all —
/// malformed JSON, a non-object root, or an undecodable envelope. This is distinct from a structural
/// conformance failure (which is reported, not thrown, on the verification path): a
/// <see cref="CredentialFormatException"/> means the bytes are not a document the engine can reason
/// about.
/// </summary>
public sealed class CredentialFormatException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public CredentialFormatException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception with a message and the underlying parse error.</summary>
    public CredentialFormatException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

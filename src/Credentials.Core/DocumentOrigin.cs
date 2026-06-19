namespace Credentials;

/// <summary>
/// Records where a <see cref="CredentialDocument"/>'s content came from, so the securing layer can
/// choose the correct fidelity strategy: a document parsed from received wire bytes must verify
/// against those exact bytes, whereas a document we built ourselves is serialized once and pinned.
/// </summary>
public enum DocumentOrigin
{
    /// <summary>Parsed from exact UTF-8 wire bytes that are retained verbatim for byte-faithful verification.</summary>
    ReceivedBytes,

    /// <summary>Assembled by a builder in this process; serialized once (with the faithful options) and pinned.</summary>
    Built,

    /// <summary>Cloned from a borrowed <see cref="System.Text.Json.JsonElement"/>; serialized once and pinned.</summary>
    ParsedElement,
}

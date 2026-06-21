namespace Credentials.Roles;

/// <summary>
/// The hash algorithm used for SD-JWT VC disclosure digests (the <c>_sd_alg</c> claim). A draft-free
/// name — the wire value (<c>sha-256</c>/<c>sha-384</c>/<c>sha-512</c>) is owned by the SD-JWT
/// substrate and mapped internally, so no draft-version type appears on the public API (FR-051/D12).
/// </summary>
public enum SdHashName
{
    /// <summary>SHA-256 (the SD-JWT default, <c>sha-256</c>).</summary>
    Sha256,

    /// <summary>SHA-384 (<c>sha-384</c>).</summary>
    Sha384,

    /// <summary>SHA-512 (<c>sha-512</c>).</summary>
    Sha512,
}

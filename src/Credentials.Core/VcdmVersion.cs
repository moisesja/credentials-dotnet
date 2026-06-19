namespace Credentials;

/// <summary>
/// The Verifiable Credentials Data Model version a document declares, detected positively from the
/// exact base URL at <c>@context[0]</c>. Detection is positive (never a "v2 else v1.1" fallback): a
/// document whose first context entry matches neither known base URL is <see cref="Unknown"/> and is
/// rejected by structural validation (conformance fix D1).
/// </summary>
public enum VcdmVersion
{
    /// <summary>The base context did not match a known VCDM version; the document is rejected.</summary>
    Unknown,

    /// <summary>VCDM 1.1 — base context <c>https://www.w3.org/2018/credentials/v1</c>. Accepted on verification only (D8).</summary>
    V1_1,

    /// <summary>VCDM 2.0 — base context <c>https://www.w3.org/ns/credentials/v2</c>. The only version this library issues.</summary>
    V2_0,
}

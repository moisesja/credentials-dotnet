using System.Text.Json.Nodes;

namespace Credentials.Tests;

/// <summary>Shared JSON fixtures for the M0 test-suite.</summary>
internal static class TestVectors
{
    /// <summary>A minimal, structurally valid VCDM 2.0 credential as a fresh mutable <see cref="JsonObject"/>.</summary>
    public static JsonObject ValidV2Credential() => (JsonObject)JsonNode.Parse(
        """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiableCredential"],
          "issuer": "did:example:issuer",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": { "id": "did:example:subject", "name": "Alice" }
        }
        """)!;

    /// <summary>A minimal, structurally valid VCDM 1.1 credential as a fresh mutable <see cref="JsonObject"/>.</summary>
    public static JsonObject ValidV1Credential() => (JsonObject)JsonNode.Parse(
        """
        {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          "type": ["VerifiableCredential"],
          "issuer": "did:example:issuer",
          "issuanceDate": "2020-01-01T00:00:00Z",
          "credentialSubject": { "id": "did:example:subject", "name": "Alice" }
        }
        """)!;

    /// <summary>A structurally valid VCDM 2.0 presentation as a fresh mutable <see cref="JsonObject"/>.</summary>
    public static JsonObject ValidV2Presentation() => (JsonObject)JsonNode.Parse(
        """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiablePresentation"],
          "holder": "did:example:holder"
        }
        """)!;
}

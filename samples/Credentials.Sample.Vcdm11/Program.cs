using Credentials;
using Credentials.Roles;
using Credentials.Samples.Shared;
using Credentials.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace Credentials.Samples.Vcdm11;

/// <summary>
/// Verifies a VCDM 1.1 credential (FR-044 / D8). The engine ISSUES 2.0 only, so this credential is a
/// fixture the way a foreign 1.1 issuer would emit it — a Data-Integrity-secured 1.1 document whose
/// <c>did:key</c> issuer is self-contained, so verification is fully offline. The sample shows that 1.1
/// verifies by default (<c>AcceptVcdm11 = true</c>), is never upgraded to 2.0, and is rejected when the
/// verifier opts out of 1.1.
/// </summary>
public static class Program
{
    // A genuine eddsa-jcs-2022-secured VCDM 1.1 credential (issuer is a did:key, so the public key is in
    // the DID — no network needed to verify). Generated once via the engine's internal mechanism (the
    // public issuer is 2.0-only by contract and rejects 1.1).
    private const string Vcdm11Credential = """
        {
          "@context": [ "https://www.w3.org/2018/credentials/v1" ],
          "type": [ "VerifiableCredential" ],
          "id": "urn:uuid:1111aaaa-1111-1111-1111-111111111111",
          "issuer": "did:key:z6MkgzE8Ku9GCWPkR7snn3mQNpUvfYZAFofcCoJ6X7mbqaV8",
          "issuanceDate": "2020-01-01T00:00:00Z",
          "credentialSubject": { "id": "did:example:subject", "name": "Alice" },
          "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z6MkgzE8Ku9GCWPkR7snn3mQNpUvfYZAFofcCoJ6X7mbqaV8#z6MkgzE8Ku9GCWPkR7snn3mQNpUvfYZAFofcCoJ6X7mbqaV8",
            "proofPurpose": "assertionMethod",
            "@context": [ "https://www.w3.org/2018/credentials/v1" ],
            "proofValue": "z5Y6ZWrWtX7ALfFaQGN3uZW2shDC7aUFE1BwRM4tVF5oUfetiVKng4fR866EqhGFq9hkkeKEJv83WwjYYDBZgY6M8"
          }
        }
        """;

    /// <summary>Console entry point.</summary>
    public static Task Main() => RunAsync(Console.Out);

    /// <summary>Runs the sample, writing narration to <paramref name="output"/>.</summary>
    /// <param name="output">Where to write the FR-tagged narration.</param>
    /// <param name="services">An optional pre-configured provider; when null the sample builds its own.</param>
    public static async Task RunAsync(TextWriter output, IServiceProvider? services = null)
    {
        var narrator = new SampleNarrator(output);
        narrator.Banner("VCDM 1.1 verify — accept 1.1, never upgrade, opt-out gate", "FR-044");

        var provider = services ?? new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        var ownsProvider = services is null;
        try
        {
            var verifier = provider.GetRequiredService<IVerifier>();

            var credential = Credential.Parse(Vcdm11Credential);
            narrator.Step($"parsed a {credential.Version} credential (issuance is 2.0-only; this is a foreign-issued 1.1 VC)");

            // Default options accept 1.1 (AcceptVcdm11 = true).
            var accepted = await verifier.VerifyCredentialAsync(credential);
            narrator.Result($"default (AcceptVcdm11=true): {accepted.Decision} (proof={accepted.Check(CheckKinds.Proof)!.Status}, validity={accepted.Check(CheckKinds.Validity)!.Status})");

            // Opt out of 1.1 — the same credential is now rejected before its proof is even trusted.
            var rejected = await verifier.VerifyCredentialAsync(credential, new CredentialVerificationOptions { AcceptVcdm11 = false });
            narrator.Result($"opt-out (AcceptVcdm11=false): {rejected.Decision}");

            if (accepted.Decision != VerificationDecision.Accepted)
                throw new InvalidOperationException($"expected the 1.1 credential to be Accepted by default, got {accepted.Decision}");
            if (rejected.Decision != VerificationDecision.Rejected)
                throw new InvalidOperationException($"expected the 1.1 credential to be Rejected when AcceptVcdm11=false, got {rejected.Decision}");
            if (credential.Version != VcdmVersion.V1_1)
                throw new InvalidOperationException("the 1.1 credential must not be upgraded to 2.0");
        }
        finally
        {
            if (ownsProvider && provider is IDisposable disposable) disposable.Dispose();
        }
    }
}

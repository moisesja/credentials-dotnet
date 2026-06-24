using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.TestSupport;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;
using Base64Url = System.Buffers.Text.Base64Url;

namespace Credentials.InteropTests;

/// <summary>
/// SD-JWT VC interop (NFR-007): the disclosures our engine emits must be recognizable to any conformant
/// SD-JWT verifier, i.e. each disclosure's digest must be exactly <c>base64url(SHA-256(ascii(disclosure)))</c>
/// (RFC 9901 §4.2.4.1). Independently recomputing the digests here and matching them against the issued
/// <c>_sd</c> array proves cross-implementation agreement on the disclosure-digest algorithm — the core of
/// SD-JWT interop — without needing a foreign verifier. Plus the negative cases and the media-type sentinel.
/// </summary>
public sealed class SdJwtVcInteropTests
{
    private const string Vct = "https://credentials.example/identity_credential";

    private static (IIssuer Issuer, IVerifier Verifier) Roles()
    {
        var provider = new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();
        return (provider.GetRequiredService<IIssuer>(), provider.GetRequiredService<IVerifier>());
    }

    private static (ISigner Signer, string Did, string Vm) Key()
    {
        var kp = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        var did = $"did:key:{kp.MultibasePublicKey}";
        return (new KeyPairSigner(kp, new DefaultCryptoProvider()), did, $"{did}#{kp.MultibasePublicKey}");
    }

    private static async Task<string> IssueDisclosableAsync(IIssuer issuer)
    {
        var key = Key();
        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["given_name"] = "Alice", ["family_name"] = "Smith" })
            .Seal();
        var issued = await issuer.IssueAsync(unsecured, new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = key.Signer,
            VerificationMethod = key.Vm,
            Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name", "family_name")],
        });
        issued.MediaType.Should().Be("application/dc+sd-jwt", "the SD-JWT VC media type is a drift sentinel");
        return issued.CompactSdJwt!;
    }

    [Fact]
    [FrTag("NFR-007")]
    public async Task SdJwt_disclosure_digests_equal_independent_sha256_base64url()
    {
        var (issuer, _) = Roles();
        var compact = await IssueDisclosableAsync(issuer);

        var parts = compact.Split('~');
        var issuerJwt = parts[0];
        var disclosures = parts[1..].Where(p => p.Length > 0).ToArray();
        disclosures.Should().HaveCountGreaterThanOrEqualTo(2, "both disclosable claims must be present as disclosures");

        var payloadJson = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(issuerJwt.Split('.')[1]));
        var header = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(issuerJwt.Split('.')[0]));
        header.Should().Contain("dc+sd-jwt", "typ must be dc+sd-jwt (drift sentinel)");

        foreach (var disclosure in disclosures)
        {
            // RFC 9901: digest = base64url-no-pad( SHA-256( ASCII(<the base64url disclosure string>) ) ).
            var digest = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));
            payloadJson.Should().Contain($"\"{digest}\"",
                "each disclosure's spec-computed digest must appear in an _sd array — interop on the digest algorithm");
        }
    }

    [Fact]
    [FrTag("NFR-007")]
    public async Task SdJwt_tampered_disclosure_is_rejected()
    {
        var (issuer, verifier) = Roles();
        var compact = await IssueDisclosableAsync(issuer);

        var parts = compact.Split('~');
        // Re-encode the first disclosure with a changed value: still a well-formed disclosure, but its
        // SHA-256 digest no longer matches the signed _sd entry, so the verifier must reject it.
        var disclosed = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1])))!.AsArray();
        disclosed[^1] = "tampered-value";
        parts[1] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(disclosed.ToJsonString()));
        var tampered = string.Join('~', parts);

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(tampered));
        result.Decision.Should().Be(VerificationDecision.Rejected, "a tampered disclosure must not verify");
    }

    [Fact]
    [FrTag("NFR-007")]
    public async Task SdJwt_unmatched_disclosure_is_rejected()
    {
        var (issuer, verifier) = Roles();
        var compact = await IssueDisclosableAsync(issuer);

        // Append a well-formed but never-issued disclosure (its digest is in no _sd array) — RFC 9901
        // requires the verifier to reject an unmatched disclosure.
        var salt = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        var rogue = Base64Url.EncodeToString(Encoding.UTF8.GetBytes($"[\"{salt}\",\"role\",\"admin\"]"));
        var parts = compact.TrimEnd('~').Split('~').ToList();
        parts.Add(rogue);
        var withRogue = string.Join('~', parts) + "~";

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(withRogue));
        result.Decision.Should().Be(VerificationDecision.Rejected, "an unmatched disclosure must not verify");
    }
}

using System.Text;
using System.Text.Json;
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

namespace Credentials.RoundTripTests;

/// <summary>
/// FR-003 byte-fidelity Definition of Done: for every securing family this engine issues end-to-end
/// (unsecured, embedded Data Integrity in JCS and RDFC, VC-JOSE, VC-COSE, SD-JWT VC), the secured
/// artifact survives serialize → parse → verify with byte-perfect fidelity, the issuer's member order
/// is preserved, the core never strips or re-adds <c>proof</c>, enveloping uses verbatim wire bytes,
/// and the signed bytes equal the wire bytes. Selective-disclosure derivation (bbs-2023) byte-fidelity
/// is covered by the M5 suite; bbs-2023 base <em>issuance</em> stays gated (R-1), so it has no
/// issue→round-trip path here.
/// </summary>
public sealed class RoundTripFidelityTests
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid().UseRdfcSuites()).BuildServiceProvider();

    private static (ISigner Signer, string Did, string Vm) NewKey(KeyType keyType = KeyType.Ed25519)
    {
        var keyPair = KeyGen.Generate(keyType);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        return (new KeyPairSigner(keyPair, Crypto), did, $"{did}#{keyPair.MultibasePublicKey}");
    }

    private static Credential UnsecuredCredential(string issuerDid, JsonObject? subject = null) => Credential.Build()
        .WithId("urn:uuid:abcdabcd-0000-0000-0000-abcdabcdabcd")
        .WithIssuer(issuerDid)
        .AddSubject(subject ?? new JsonObject { ["id"] = "did:example:subject" })
        .Seal();

    // ---- Unsecured received-bytes fidelity --------------------------------------------------------

    [Fact]
    [FrTag("FR-003")]
    public void Parsed_received_bytes_are_preserved_verbatim_with_unknown_members()
    {
        // Deliberate member order + an unknown top-level member (evidence) the typed layer doesn't model.
        const string json = """
            {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"id":"urn:uuid:1","issuer":"did:example:issuer","credentialSubject":{"id":"did:example:subject"},"evidence":[{"type":["DocumentVerification"],"verifier":"did:example:gov"}]}
            """;
        var original = Encoding.UTF8.GetBytes(json);

        var credential = Credential.Parse(original);

        credential.ToBytes().Should().Equal(original, "received bytes must be retained verbatim (FR-003)");
        credential.AsUtf8().ToArray().Should().Equal(original);
        credential.GetMember("evidence").Should().NotBeNull("unknown members must round-trip (FR-001/003)");

        // Member order is preserved on re-serialization (parse → reparse is byte-stable).
        Credential.Parse(credential.ToBytes()).ToBytes().Should().Equal(original);
    }

    // ---- Embedded Data Integrity ------------------------------------------------------------------

    [Theory]
    [FrTag("FR-003")]
    [InlineData("eddsa-jcs-2022", KeyType.Ed25519)]
    [InlineData("ecdsa-jcs-2019", KeyType.P256)]
    [InlineData("eddsa-rdfc-2022", KeyType.Ed25519)]
    [InlineData("ecdsa-rdfc-2019", KeyType.P256)]
    public async Task Embedded_di_issue_serialize_parse_verify_is_byte_stable(string cryptosuite, KeyType keyType)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = NewKey(keyType);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new DataIntegrityIssuanceRequest { Cryptosuite = cryptosuite, Signer = key.Signer, VerificationMethod = key.Vm });

        issued.Credential.HasEmbeddedProof.Should().BeTrue();

        // Stored bytes == wire bytes == re-serialized bytes: the secured artifact is re-ingested as the
        // source of truth, so serializing it again is byte-identical (no proof re-strip/re-add, no drift).
        var stored = issued.Credential.AsUtf8().ToArray();
        var reparsed = Credential.Parse(stored);
        reparsed.AsUtf8().ToArray().Should().Equal(stored);
        reparsed.ToBytes().Should().Equal(stored);
        reparsed.HasEmbeddedProof.Should().BeTrue();

        // Exactly one proof member, present in both representations (the core neither strips nor adds it).
        ProofCount(stored).Should().Be(1);

        // The re-parsed secured credential still verifies end-to-end.
        var result = await verifier.VerifyCredentialAsync(reparsed);
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    // ---- VC-JOSE: verbatim compact + exact signed payload (golden bytes) ---------------------------

    [Fact]
    [FrTag("FR-003")]
    public async Task Jose_compact_is_verbatim_and_signs_the_exact_source_bytes()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = NewKey();

        var unsecured = UnsecuredCredential(key.Did);
        var issued = await issuer.IssueAsync(
            unsecured, new JoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.Vm });

        // The credential's verbatim compact serialization is exactly the issued token.
        issued.Credential.CompactEnvelope.Should().Be(issued.CompactJws);

        // Golden bytes: the JWS payload segment is the credential's exact bytes (no re-serialization).
        var payload = Base64Url.DecodeFromChars(issued.CompactJws!.Split('.')[1]);
        payload.Should().Equal(unsecured.AsUtf8().ToArray());

        // Re-ingesting the verbatim wire bytes preserves the token character-for-character and verifies.
        var holder = provider.GetRequiredService<IHolder>();
        var reingested = holder.Ingest(Encoding.UTF8.GetBytes(issued.CompactJws!));
        reingested.Compact.Should().Be(issued.CompactJws);
        reingested.Credential.CompactEnvelope.Should().Be(issued.CompactJws);
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactJws!)))
            .Decision.Should().Be(VerificationDecision.Accepted);
    }

    // ---- VC-COSE: verbatim bytes -------------------------------------------------------------------

    [Fact]
    [FrTag("FR-003")]
    public async Task Cose_wire_bytes_are_verbatim_and_verify()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = NewKey();

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new CoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.Vm });

        issued.CoseBytes.Should().NotBeNull();
        issued.Credential.CompactEnvelope.Should().BeNull("COSE has no compact string form");

        // The verbatim COSE_Sign1 bytes verify; copying them does not alter them.
        var wire = issued.CoseBytes!.Value.ToArray();
        (await verifier.VerifyCredentialAsync(wire)).Decision.Should().Be(VerificationDecision.Accepted);
        wire.Should().Equal(issued.CoseBytes!.Value.ToArray(), "the wire bytes are immutable / not re-encoded");
    }

    // ---- SD-JWT VC: verbatim compact ---------------------------------------------------------------

    [Fact]
    [FrTag("FR-003")]
    public async Task SdJwt_compact_is_verbatim_and_verifies()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = NewKey();

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new SdJwtVcIssuanceRequest { Vct = "https://credentials.example/identity", Signer = key.Signer, VerificationMethod = key.Vm });

        issued.CompactSdJwt.Should().NotBeNullOrEmpty();
        issued.Credential.CompactEnvelope.Should().Be(issued.CompactSdJwt);

        var holder = provider.GetRequiredService<IHolder>();
        var reingested = holder.Ingest(Encoding.UTF8.GetBytes(issued.CompactSdJwt!));
        reingested.Compact.Should().Be(issued.CompactSdJwt);
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactSdJwt!)))
            .Decision.Should().Be(VerificationDecision.Accepted);
    }

    // ---- H1: relaxed-escaping value fidelity through the embedded path -----------------------------

    [Fact]
    [FrTag("FR-003")]
    public async Task Built_credential_with_special_characters_round_trips_and_preserves_values()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = NewKey();

        const string tricky = "a<b>c&d \"q\" 😀 — ümlaut";
        var unsecured = UnsecuredCredential(key.Did, new JsonObject { ["id"] = "did:example:subject", ["note"] = tricky });

        var issued = await issuer.IssueAsync(
            unsecured, new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.Vm });

        var reparsed = Credential.Parse(issued.Credential.AsUtf8());
        var note = reparsed.AsElement().GetProperty("credentialSubject").GetProperty("note").GetString();
        note.Should().Be(tricky, "<>& and non-BMP characters must survive build → sign → parse byte-for-byte (H1)");

        (await verifier.VerifyCredentialAsync(reparsed)).Decision.Should().Be(VerificationDecision.Accepted);
    }

    // Counts proofs honestly: a single proof object is 1, an array of N proofs is N (a Data Integrity
    // document may carry a `proof` array), absent is 0 — so the "exactly one proof" assertion catches an
    // accidental multi-proof emission, not just presence.
    private static int ProofCount(byte[] securedJson)
    {
        var root = JsonNode.Parse(securedJson)!.AsObject();
        if (!root.TryGetPropertyValue("proof", out var proof) || proof is null) return 0;
        return proof is JsonArray array ? array.Count : 1;
    }
}

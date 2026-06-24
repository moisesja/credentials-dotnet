using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Securing;
using Credentials.TestSupport;
using Credentials.Verification;
using DataProofsDotnet.Cose;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NSubstitute;
using Xunit;
using Base64Url = System.Buffers.Text.Base64Url;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M3 end-to-end issue → verify for the enveloping forms (VC-JOSE-COSE, FR-012) through the real
/// <c>AddCredentials().UseNetDid()</c> wiring with in-memory <c>did:key</c> keys. Covers both
/// serializations, sign-exact-bytes round-trip, the G1 typ/cty pinning (negatives), F7 bad-signature →
/// Failed vs resolver-failure → Indeterminate, issuer binding (post-sign + self-consistent forgery),
/// fail-fast on unsupported keys, and envelope detection.
/// </summary>
public sealed class M3EnvelopingTests
{
    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    private static Credential UnsecuredCredential(string issuerDid) => Credential.Build()
        .WithId("urn:uuid:33333333-3333-3333-3333-333333333333")
        .WithIssuer(issuerDid)
        .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
        .Seal();

    // ---- JOSE -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [FrTag("FR-012")]
    public async Task Jose_issue_then_verify_round_trips(KeyType keyType)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(keyType);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new JoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        issued.Form.Should().Be(SecuringState.Jose);
        issued.MediaType.Should().Be("application/vc+jwt");
        issued.CompactJws.Should().NotBeNullOrEmpty();
        issued.CompactJws!.Split('.').Should().HaveCount(3);
        issued.Credential.Securing.Should().Be(SecuringState.Jose);
        issued.Credential.CompactEnvelope.Should().Be(issued.CompactJws);

        // Verify the issued credential object directly...
        var direct = await verifier.VerifyCredentialAsync(issued.Credential);
        direct.Decision.Should().Be(VerificationDecision.Accepted, direct.ToString());
        direct.Mechanism.Should().Be(SecuringState.Jose);
        direct.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
        direct.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);

        // ...and from the verbatim compact-JWS wire bytes (the bytes overload + envelope detection).
        var wire = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactJws));
        wire.Decision.Should().Be(VerificationDecision.Accepted, wire.ToString());
        wire.Mechanism.Should().Be(SecuringState.Jose);
    }

    [Fact]
    public async Task Jose_signs_the_exact_credential_bytes()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var unsecured = UnsecuredCredential(key.Did);
        var issued = await issuer.IssueAsync(
            unsecured, new JoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // The JWS payload segment must be the credential's exact bytes (no re-serialization).
        var payloadSegment = issued.CompactJws!.Split('.')[1];
        var decoded = Base64Url.DecodeFromChars(payloadSegment);
        decoded.Should().Equal(unsecured.AsUtf8().ToArray());
    }

    [Fact]
    public async Task Jose_relaxed_escaping_credential_round_trips()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["note"] = "a<b>c&d 😀" })
            .Seal();
        var issued = await issuer.IssueAsync(
            unsecured, new JoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(issued.CompactJws!));
        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
    }

    [Fact]
    public async Task Jose_tampered_signature_is_rejected_not_thrown()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new JoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // Flip the last character of the signature segment.
        var parts = issued.CompactJws!.Split('.');
        var sig = parts[2];
        parts[2] = sig[..^1] + (sig[^1] == 'A' ? 'B' : 'A');
        var tampered = string.Join('.', parts);

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(tampered));
        result.Decision.Should().Be(VerificationDecision.Rejected);
        // A bad signature is a definitive Failed, never Indeterminate, and never throws (FR-045/F7).
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Jose_issuer_spoofing_is_rejected_by_issuer_binding()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        // Claims the victim as issuer; validly signed with the attacker's key under the attacker's kid.
        var credential = Credential.Build()
            .WithIssuer(victim.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var forged = await issuer.IssueAsync(
            credential,
            new JoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = attacker.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        var proof = result.Check(CheckKinds.Proof)!;
        proof.Status.Should().Be(CheckStatus.Failed);
        proof.Diagnostics.Should().Contain(d => d.Code == "issuer_binding");
    }

    [Fact]
    public async Task Jose_self_consistent_forgery_under_victim_kid_fails_signature()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        // issuer = victim AND kid = victim's verification method, but signed with the ATTACKER's key.
        // The kid base DID matches the issuer (binding would pass), so only the signature check —
        // against the victim's resolved public key — catches the forgery.
        var credential = Credential.Build()
            .WithIssuer(victim.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var forged = await issuer.IssueAsync(
            credential,
            new JoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = victim.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Jose_missing_kid_is_rejected_fail_closed()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // A hand-crafted compact JWS with valid typ/cty but NO kid — there is no signer identity to bind
        // the issuer to, so it must be rejected (fail closed), not Indeterminate.
        var compact = FabricateJws(
            new JsonObject { ["alg"] = "EdDSA", ["typ"] = "vc+jwt", ["cty"] = "vc" },
            UnsecuredCredential(key.Did).AsUtf8().ToArray());

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(compact));
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Jose_unresolvable_kid_is_indeterminate_not_failed()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // Valid structure + a kid that NetDid cannot resolve: the key resolution fails BEFORE any
        // signature check, so the proof is Indeterminate (F7) — a DID/IO failure is not a crypto failure.
        var compact = FabricateJws(
            new JsonObject
            {
                ["alg"] = "EdDSA",
                ["typ"] = "vc+jwt",
                ["cty"] = "vc",
                ["kid"] = "did:key:zNotARealKey#zNotARealKey",
            },
            UnsecuredCredential(key.Did).AsUtf8().ToArray());

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(compact));
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Indeterminate);
        result.Decision.Should().Be(VerificationDecision.Rejected); // fail-closed default
    }

    [Fact]
    public async Task Jose_wrong_typ_is_rejected()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // typ != vc+jwt — the substrate's pinned-header assertion (G1) rejects it as malformed.
        var compact = FabricateJws(
            new JsonObject { ["alg"] = "EdDSA", ["typ"] = "JWT", ["cty"] = "vc", ["kid"] = key.VerificationMethod },
            UnsecuredCredential(key.Did).AsUtf8().ToArray());

        var result = await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(compact));
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    // ---- COSE -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task Cose_issue_then_verify_round_trips(KeyType keyType)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(keyType);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new CoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        issued.Form.Should().Be(SecuringState.Cose);
        issued.MediaType.Should().Be("application/vc+cose");
        issued.CoseBytes.Should().NotBeNull();
        issued.CoseBytes!.Value.Length.Should().BeGreaterThan(0);
        issued.Credential.Securing.Should().Be(SecuringState.Cose);
        issued.Credential.CompactEnvelope.Should().BeNull(); // COSE has no compact string form

        var direct = await verifier.VerifyCredentialAsync(issued.Credential);
        direct.Decision.Should().Be(VerificationDecision.Accepted, direct.ToString());
        direct.Mechanism.Should().Be(SecuringState.Cose);
        direct.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);

        var wire = await verifier.VerifyCredentialAsync(issued.CoseBytes!.Value);
        wire.Decision.Should().Be(VerificationDecision.Accepted, wire.ToString());
        wire.Mechanism.Should().Be(SecuringState.Cose);
    }

    [Fact]
    public async Task Cose_tampered_signature_is_rejected_not_thrown()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new CoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        // Corrupt a byte near the end (within the signature) of the COSE_Sign1 message.
        var bytes = issued.CoseBytes!.Value.ToArray();
        bytes[^1] ^= 0xFF;

        var result = await verifier.VerifyCredentialAsync(bytes);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Cose_issuer_spoofing_is_rejected_by_issuer_binding()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        var credential = Credential.Build()
            .WithIssuer(victim.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var forged = await issuer.IssueAsync(
            credential,
            new CoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = attacker.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        var proof = result.Check(CheckKinds.Proof)!;
        proof.Status.Should().Be(CheckStatus.Failed);
        proof.Diagnostics.Should().Contain(d => d.Code == "issuer_binding");
    }

    [Fact]
    public async Task Cose_self_consistent_forgery_under_victim_kid_fails_signature()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var attacker = TestKeys.New(KeyType.Ed25519);
        var victim = TestKeys.New(KeyType.Ed25519);

        // issuer = victim AND kid = victim's verification method, but signed with the ATTACKER's key. The
        // kid base DID matches the issuer (binding would pass), so only the signature check — against the
        // victim's resolved key — catches the forgery.
        var credential = Credential.Build()
            .WithIssuer(victim.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .Seal();
        var forged = await issuer.IssueAsync(
            credential,
            new CoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = victim.VerificationMethod });

        var result = await verifier.VerifyCredentialAsync(forged.Credential);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Cose_missing_kid_is_rejected_fail_closed()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // A validly-signed COSE_Sign1 with the correct pinned headers but NO kid — there is no signer
        // identity to bind the issuer to, so it must be rejected (fail closed), not Indeterminate.
        var envelope = await FabricateCose(
            UnsecuredCredential(key.Did).AsUtf8().ToArray(), key.Signer, CoseAlgorithm.EdDsa,
            keyId: null, contentType: VcCose.CredentialContentType, type: VcCose.EnvelopeType);

        var result = await verifier.VerifyCredentialAsync(envelope);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Cose_wrong_typ_is_rejected()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // Correct content-type, valid signature, resolvable kid — but typ != application/vc+cose. The
        // substrate's pinned-header assertion (G1) rejects it as malformed before the signature matters.
        var envelope = await FabricateCose(
            UnsecuredCredential(key.Did).AsUtf8().ToArray(), key.Signer, CoseAlgorithm.EdDsa,
            keyId: Encoding.UTF8.GetBytes(key.VerificationMethod), contentType: VcCose.CredentialContentType,
            type: "application/example+cose");

        var result = await verifier.VerifyCredentialAsync(envelope);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Cose_wrong_content_type_is_rejected()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();
        var key = TestKeys.New(KeyType.Ed25519);

        // Correct typ, valid signature, resolvable kid — but content-type != application/vc (G1).
        var envelope = await FabricateCose(
            UnsecuredCredential(key.Did).AsUtf8().ToArray(), key.Signer, CoseAlgorithm.EdDsa,
            keyId: Encoding.UTF8.GetBytes(key.VerificationMethod), contentType: "application/example",
            type: VcCose.EnvelopeType);

        var result = await verifier.VerifyCredentialAsync(envelope);
        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
    }

    // ---- Payload-integrity guard (sign-exact-bytes defence in depth) ------------------------------

    [Fact]
    public async Task Jose_verified_payload_must_match_the_inner_document()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new JoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var mechanism = provider.GetServices<ISecuringMechanism>().First(m => m.Form == SecuringForm.Jose);

        // A genuine, signature-valid envelope, but the stages would validate a DIFFERENT inner document:
        // the integrity guard must reject it even though the signature verifies (decoder-divergence defence).
        var request = new VerifyRequest
        {
            Document = issued.Credential.AsElement(),
            Envelope = Encoding.UTF8.GetBytes(issued.CompactJws!),
            ExpectedPayload = Encoding.UTF8.GetBytes(
                "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"]}"),
        };

        var result = await mechanism.VerifyAsync(request, default);
        result.Status.Should().Be(SecuringVerificationStatus.Invalid);
        result.Problems.Should().Contain(p => p.Code == "envelope_payload_mismatch");
    }

    [Fact]
    public async Task Cose_verified_payload_must_match_the_inner_document()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var key = TestKeys.New(KeyType.Ed25519);

        var issued = await issuer.IssueAsync(
            UnsecuredCredential(key.Did),
            new CoseEnvelopeIssuanceRequest { Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var mechanism = provider.GetServices<ISecuringMechanism>().First(m => m.Form == SecuringForm.Cose);

        var request = new VerifyRequest
        {
            Document = issued.Credential.AsElement(),
            Envelope = issued.CoseBytes!.Value,
            ExpectedPayload = Encoding.UTF8.GetBytes(
                "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"]}"),
        };

        var result = await mechanism.VerifyAsync(request, default);
        result.Status.Should().Be(SecuringVerificationStatus.Invalid);
        result.Problems.Should().Contain(p => p.Code == "envelope_payload_mismatch");
    }

    // ---- Fail-fast / detection / capabilities -----------------------------------------------------

    [Fact]
    public async Task Jose_unsupported_key_type_fails_fast_at_issue()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var signer = UnsupportedSigner();

        var act = () => issuer.IssueAsync(
            UnsecuredCredential("did:example:issuer"),
            new JoseEnvelopeIssuanceRequest { Signer = signer, VerificationMethod = "did:example:issuer#k" });
        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task Cose_unsupported_key_type_fails_fast_at_issue()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var signer = UnsupportedSigner();

        var act = () => issuer.IssueAsync(
            UnsecuredCredential("did:example:issuer"),
            new CoseEnvelopeIssuanceRequest { Signer = signer, VerificationMethod = "did:example:issuer#k" });
        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task Garbage_bytes_throw_credential_format_exception()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        var act = () => verifier.VerifyCredentialAsync(new byte[] { 0x00, 0x01, 0x02, 0x03 }).AsTask();
        await act.Should().ThrowAsync<CredentialFormatException>();
    }

    [Fact]
    public async Task Truncated_jose_envelope_throws_credential_format_exception()
    {
        using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IVerifier>();

        // Detected as a compact JWS, but the payload segment is not valid base64url JSON → undecodable.
        var act = () => verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes("aaaa.@@@@.cccc")).AsTask();
        await act.Should().ThrowAsync<CredentialFormatException>();
    }

    [Fact]
    public void Capabilities_report_the_enveloping_forms()
    {
        using var provider = BuildProvider();
        var capabilities = provider.GetRequiredService<ISecuringCapabilities>();

        capabilities.AvailableForms.Should().Contain([SecuringForm.Jose, SecuringForm.Cose]);
        capabilities.IsSupported(SecuringSelector.Jose()).Should().BeTrue();
        capabilities.IsSupported(SecuringSelector.Cose()).Should().BeTrue();
    }

    // ---- helpers ----------------------------------------------------------------------------------

    /// <summary>Builds a compact JWS string with the given header and payload and a junk signature.</summary>
    private static string FabricateJws(JsonObject header, byte[] payload)
    {
        var h = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = Base64Url.EncodeToString(payload);
        var s = Base64Url.EncodeToString(new byte[64]);
        return $"{h}.{p}.{s}";
    }

    /// <summary>Builds a raw COSE_Sign1 envelope with caller-controlled (possibly wrong/absent) headers.</summary>
    private static async Task<byte[]> FabricateCose(
        byte[] payload, ISigner signer, CoseAlgorithm algorithm, ReadOnlyMemory<byte>? keyId, string? contentType, string? type)
    {
        return await CoseSign1.SignAsync(payload, signer, new CoseSign1SignOptions
        {
            Algorithm = algorithm,
            KeyId = keyId,
            ContentType = contentType,
            Type = type,
        });
    }

    /// <summary>A signer that reports an out-of-scope key type, to exercise the fail-fast path.</summary>
    private static ISigner UnsupportedSigner()
    {
        var signer = Substitute.For<ISigner>();
        signer.KeyType.Returns(KeyType.P521);
        signer.PublicKey.Returns(new ReadOnlyMemory<byte>(new byte[32]));
        signer.MultibasePublicKey.Returns("zUnsupported");
        return signer;
    }
}

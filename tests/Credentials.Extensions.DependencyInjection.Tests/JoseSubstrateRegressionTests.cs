using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.TestSupport;
using Credentials.Verification;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;
using Xunit;
using Base64Url = System.Buffers.Text.Base64Url;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// Regression guards for the JOSE substrate behaviors Credentials relies on, added with the DataProofs
/// 1.1.0 → 1.3.0 rebuild (issue #20). DataProofs 1.2–1.3 changed <c>kid</c> handling: <c>JwsKidPlacement</c>,
/// reading an <i>unprotected</i> (unsigned) <c>kid</c> from JSON-serialized JWS, and header disjointness.
/// These tests pin the properties that make those changes unreachable from Credentials: JSON-serialized JWS
/// never reaches the JOSE path, only the <b>signed</b> <c>kid</c> is bound, every token Credentials emits
/// carries its <c>kid</c> in the protected header, and hostile headers fail without escaping exceptions.
/// It also pins NetCrypto ≥ 1.5.0's ES256K high-S acceptance and the freshness invariants that keep it harmless.
/// Each DID publishes one key under an <c>authentication</c> VM and an <c>assertionMethod</c> VM (the
/// shape DataProofs' 1.3.0 security note uses), and every fixture signs under the VM the role requires.
/// </summary>
public sealed class JoseSubstrateRegressionTests
{
    private const string Challenge = "regression-challenge";
    private const string Domain = "https://verifier.example";
    private const string Vct = "https://credentials.example/regression";

    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    private sealed record TestDid(string Did, KeyPair Pair, ISigner Signer, string AuthVm, string AssertVm);

    private sealed class MapDidResolver : IDidResolver
    {
        private readonly Dictionary<string, DidDocument> _docs = new(StringComparer.Ordinal);

        public bool CanResolve(string did) => true;

        public Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default) =>
            Task.FromResult(_docs.TryGetValue(did, out var doc)
                ? new DidResolutionResult { DidDocument = doc, ResolutionMetadata = new DidResolutionMetadata() }
                : new DidResolutionResult { DidDocument = null, ResolutionMetadata = new DidResolutionMetadata { Error = "notFound" } });

        public TestDid Add(string did, KeyType keyType = KeyType.Ed25519)
        {
            var pair = KeyGen.Generate(keyType);
            var authVm = did + "#auth";
            var assertVm = did + "#assert";
            _docs[did] = new DidDocument
            {
                Id = did,
                VerificationMethod = [Vm(authVm, did, pair), Vm(assertVm, did, pair)],
                Authentication = [VerificationRelationshipEntry.FromReference(authVm)],
                AssertionMethod = [VerificationRelationshipEntry.FromReference(assertVm)],
            };
            return new TestDid(did, pair, new KeyPairSigner(pair, Crypto), authVm, assertVm);
        }

        private static VerificationMethod Vm(string id, string controller, KeyPair pair) => new()
        {
            Id = id,
            Type = "Multikey",
            Controller = controller,
            PublicKeyMultibase = pair.MultibasePublicKey,
        };
    }

    private static ServiceProvider BuildProvider(MapDidResolver resolver)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IDidResolver>(resolver);
        services.AddCredentials(_ => { });
        return services.BuildServiceProvider();
    }

    private static Credential Unsecured(string issuerDid) => Credential.Build()
        .WithId("urn:uuid:20202020-2020-2020-2020-202020202020")
        .WithIssuer(issuerDid)
        .AddSubject(new JsonObject { ["id"] = "did:example:subject", ["given_name"] = "Alice" })
        .Seal();

    private static JsonObject ProtectedHeader(string compactJws) =>
        JsonNode.Parse(Base64Url.DecodeFromChars(compactJws.Split('.')[0]))!.AsObject();

    private static readonly BigInteger Secp256k1Order = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", NumberStyles.HexNumber);

    // The ECDSA signature twin: replace S with n − S in the R‖S signature segment of a compact JWS.
    private static string MalleateEs256k(string compactJws)
    {
        var parts = compactJws.Split('.');
        var signature = Base64Url.DecodeFromChars(parts[2]);
        var half = signature.Length / 2;
        var s = new BigInteger(signature.AsSpan(half), isUnsigned: true, isBigEndian: true);
        var negated = (Secp256k1Order - s).ToByteArray(isUnsigned: true, isBigEndian: true);
        Array.Clear(signature, half, half);
        negated.CopyTo(signature, signature.Length - negated.Length);
        parts[2] = Base64Url.EncodeToString(signature);
        return string.Join('.', parts);
    }

    private static async Task<string> SignCompactAsync(byte[] header, ReadOnlyMemory<byte> payload, ISigner signer)
    {
        var signingInput = Base64Url.EncodeToString(header) + "." + Base64Url.EncodeToString(payload.Span);
        var signature = await signer.SignAsync(Encoding.ASCII.GetBytes(signingInput));
        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    [Fact]
    [FrTag("FR-040")]
    [FrTag("FR-041")]
    public async Task Json_serialized_jws_with_an_unsigned_kid_is_never_accepted_through_any_entry_point()
    {
        var resolver = new MapDidResolver();
        var issuer = resolver.Add("did:example:issuer");
        var holder = resolver.Add("did:example:holder");
        using var provider = BuildProvider(resolver);
        var holderRole = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        // Genuinely signed by the issuer, but the protected header carries no kid: the kid travels only in
        // the unprotected header, so it is NOT covered by the signature.
        var protectedB64 = Base64Url.EncodeToString(
            JsonSerializer.SerializeToUtf8Bytes(new JsonObject { ["alg"] = "EdDSA", ["typ"] = "vc+jwt", ["cty"] = "vc" }));
        var payloadB64 = Base64Url.EncodeToString(Unsecured(issuer.Did).ToUtf8().Span);
        var signatureB64 = Base64Url.EncodeToString(
            await issuer.Signer.SignAsync(Encoding.ASCII.GetBytes(protectedB64 + "." + payloadB64)));
        var flattened = new JsonObject
        {
            ["payload"] = payloadB64,
            ["protected"] = protectedB64,
            ["header"] = new JsonObject { ["kid"] = issuer.AssertVm },
            ["signature"] = signatureB64,
        }.ToJsonString();
        var general = new JsonObject
        {
            ["payload"] = payloadB64,
            ["signatures"] = new JsonArray(new JsonObject
            {
                ["protected"] = protectedB64,
                ["header"] = new JsonObject { ["kid"] = issuer.AssertVm },
                ["signature"] = signatureB64,
            }),
        }.ToJsonString();

        // Premise: the substrate itself accepts this shape and reports the unsigned kid. The test is only
        // meaningful while that holds.
        var jwk = JwkConversion.FromMultikey(issuer.Pair.MultibasePublicKey, issuer.AssertVm);
        var substrate = JwsParser.Parse(flattened, _ => jwk, new JoseCryptoProvider());
        substrate.SignerKid.Should().Be(issuer.AssertVm);
        substrate.SignerKidIsProtected.Should().BeFalse();

        foreach (var json in new[] { flattened, general, "  \n" + flattened })
        {
            var bytes = Encoding.UTF8.GetBytes(json);

            var credentialResult = await TryVerifyAsync(() => verifier.VerifyCredentialAsync(bytes));
            credentialResult?.Decision.Should().NotBe(VerificationDecision.Accepted);

            var presentationResult = await TryVerifyAsync(() => verifier.VerifyPresentationAsync(
                bytes, new PresentationVerificationOptions { ExpectedChallenge = Challenge }));
            presentationResult?.Decision.Should().NotBe(VerificationDecision.Accepted);

            try
            {
                holderRole.Ingest(bytes).Securing.Should().NotBe(SecuringState.Jose);
            }
            catch (CredentialFormatException)
            {
                // Refusing to ingest is also acceptable.
            }
        }

        // Smuggled as enveloped children of a validly bound vp+jwt: the presentation must not accept them.
        var vpJwt = await holderRole.BindWithJoseEnvelopeAsync(
            holderRole.BuildPresentation(new VpAssemblyRequest
            {
                Holder = holder.Did,
                Credentials = [ContainedCredential.Enveloped(flattened), ContainedCredential.Enveloped(general)],
            }),
            new VpBindingRequest { HolderSigner = holder.Signer, VerificationMethod = holder.AuthVm, Challenge = Challenge, Domain = Domain });
        var vpResult = await verifier.VerifyPresentationAsync(
            Encoding.UTF8.GetBytes(vpJwt), new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });

        vpResult.Decision.Should().NotBe(VerificationDecision.Accepted);
        vpResult.Credentials.Should().OnlyContain(c => c.Decision != VerificationDecision.Accepted);
    }

    [Fact]
    [FrTag("FR-040")]
    [FrTag("FR-041")]
    public async Task Compact_forgeries_whose_signed_kid_disagrees_with_the_issuer_or_holder_are_rejected()
    {
        var resolver = new MapDidResolver();
        var victim = resolver.Add("did:example:victim");
        var attacker = resolver.Add("did:example:attacker");
        using var provider = BuildProvider(resolver);
        var issuerRole = provider.GetRequiredService<IIssuer>();
        var holderRole = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();
        var vpOptions = new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain };

        // vc+jwt claiming issuer = victim, self-consistently signed by the attacker under the attacker's kid.
        var attackerKid = await issuerRole.IssueAsync(Unsecured(victim.Did),
            new JoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = attacker.AssertVm });
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(attackerKid.CompactJws!)))
            .Decision.Should().Be(VerificationDecision.Rejected);

        // vc+jwt claiming issuer = victim whose signed kid names the victim's VM, but signed with the attacker's key.
        var lyingKid = await issuerRole.IssueAsync(Unsecured(victim.Did),
            new JoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = victim.AssertVm });
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(lyingKid.CompactJws!)))
            .Decision.Should().Be(VerificationDecision.Rejected);

        // Post-sign tampering: an honest attacker-issued vc+jwt whose protected kid is rewritten to the victim's VM.
        var honest = await issuerRole.IssueAsync(Unsecured(attacker.Did),
            new JoseEnvelopeIssuanceRequest { Signer = attacker.Signer, VerificationMethod = attacker.AssertVm });
        var parts = honest.CompactJws!.Split('.');
        var header = ProtectedHeader(honest.CompactJws!);
        header["kid"] = victim.AssertVm;
        parts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(string.Join('.', parts))))
            .Decision.Should().Be(VerificationDecision.Rejected);

        // SD-JWT VC with issuer = iss = victim, signed by the attacker under the attacker's kid.
        var sdJwt = await issuerRole.IssueAsync(Unsecured(victim.Did),
            new SdJwtVcIssuanceRequest { Vct = Vct, Signer = attacker.Signer, VerificationMethod = attacker.AssertVm });
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(sdJwt.CompactSdJwt!)))
            .Decision.Should().Be(VerificationDecision.Rejected);

        // vp+jwt with holder = victim, bound by the attacker under the attacker's kid, then under the victim's kid.
        var vp = holderRole.BuildPresentation(new VpAssemblyRequest
        {
            Holder = victim.Did,
            Credentials = [ContainedCredential.Enveloped(honest.CompactJws!)],
        });
        foreach (var kid in new[] { attacker.AuthVm, victim.AuthVm })
        {
            var forged = await holderRole.BindWithJoseEnvelopeAsync(vp, new VpBindingRequest
            {
                HolderSigner = attacker.Signer,
                VerificationMethod = kid,
                Challenge = Challenge,
                Domain = Domain,
            });
            (await verifier.VerifyPresentationAsync(Encoding.UTF8.GetBytes(forged), vpOptions))
                .Decision.Should().Be(VerificationDecision.Rejected, "holder bound under {0}", kid);
        }
    }

    [Fact]
    [FrTag("FR-012")]
    [FrTag("FR-013")]
    [FrTag("FR-032")]
    [FrTag("FR-034")]
    public async Task Every_emitted_jose_token_carries_its_kid_in_the_protected_header()
    {
        // DataProofs 1.3.0's JwsKidPlacement.Auto may move the kid to the unprotected header for some media
        // types. Every compact token Credentials emits must keep it inside the signature.
        var resolver = new MapDidResolver();
        var issuer = resolver.Add("did:example:issuer");
        var holder = resolver.Add("did:example:holder");
        using var provider = BuildProvider(resolver);
        var issuerRole = provider.GetRequiredService<IIssuer>();
        var holderRole = provider.GetRequiredService<IHolder>();

        var jose = await issuerRole.IssueAsync(Unsecured(issuer.Did),
            new JoseEnvelopeIssuanceRequest { Signer = issuer.Signer, VerificationMethod = issuer.AssertVm });
        var sdJwt = await issuerRole.IssueAsync(Unsecured(issuer.Did), new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = issuer.Signer,
            VerificationMethod = issuer.AssertVm,
            Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name")],
            HolderBinding = HolderBindingKey.FromMultikey(holder.Pair.MultibasePublicKey),
        });
        var kbPresentation = await holderRole.PresentSdJwtAsync(
            holderRole.Ingest(Encoding.UTF8.GetBytes(sdJwt.CompactSdJwt!)),
            new SdJwtPresentationRequest
            {
                DiscloseClaims = ["given_name"],
                HolderSigner = holder.Signer,
                VerificationMethod = holder.AuthVm,
                Audience = Domain,
                Nonce = Challenge,
            });
        var vpJwt = await holderRole.BindWithJoseEnvelopeAsync(
            holderRole.BuildPresentation(new VpAssemblyRequest { Holder = holder.Did, Credentials = [ContainedCredential.Enveloped(jose.CompactJws!)] }),
            new VpBindingRequest { HolderSigner = holder.Signer, VerificationMethod = holder.AuthVm, Challenge = Challenge, Domain = Domain });

        var tokens = new (string Label, string Compact, string ExpectedKid)[]
        {
            ("vc+jwt", jose.CompactJws!, issuer.AssertVm),
            ("dc+sd-jwt issuer JWT", sdJwt.CompactSdJwt!.Split('~')[0], issuer.AssertVm),
            ("kb+jwt", kbPresentation.Split('~')[^1], holder.AuthVm),
            ("vp+jwt", vpJwt, holder.AuthVm),
        };
        foreach (var (label, compact, expectedKid) in tokens)
        {
            compact.Split('.').Should().HaveCount(3, label);
            ProtectedHeader(compact)["kid"]?.GetValue<string>().Should().Be(expectedKid, label);
        }
    }

    [Fact]
    [FrTag("FR-040")]
    [FrTag("FR-041")]
    public async Task Hostile_protected_headers_signed_with_the_real_key_fail_without_escaping()
    {
        var resolver = new MapDidResolver();
        var issuer = resolver.Add("did:example:issuer");
        using var provider = BuildProvider(resolver);
        var verifier = provider.GetRequiredService<IVerifier>();
        var vc = Unsecured(issuer.Did).ToUtf8();
        var vp = Encoding.UTF8.GetBytes(new JsonObject
        {
            ["@context"] = new JsonArray("https://www.w3.org/ns/credentials/v2"),
            ["type"] = new JsonArray("VerifiablePresentation"),
            ["holder"] = issuer.Did,
            ["nonce"] = Challenge,
        }.ToJsonString());
        var assertKid = issuer.AssertVm;
        var authKid = issuer.AuthVm;

        var credentialHeaders = new[]
        {
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":null}",
            "{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":123}",
            "[1]",
            $"{{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\",\"kid\":\"{assertKid}\"}}",
            $"{{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\",\"typ\":\"vp+jwt\"}}",
            $"{{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\",\"crit\":[\"x\"],\"x\":1}}",
            $"{{\"alg\":1,\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\"}}",
            $"{{\"alg\":\"none\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\"}}",
            $"{{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\",\"z\":{new string('[', 200)}{new string(']', 200)}}}",
        };
        var presentationHeaders = new[]
        {
            "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\",\"kid\":null}",
            $"{{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\",\"kid\":\"{authKid}\",\"kid\":\"{authKid}\"}}",
        };

        foreach (var header in credentialHeaders)
        {
            var compact = await SignCompactAsync(Encoding.UTF8.GetBytes(header), vc, issuer.Signer);
            var result = await TryVerifyAsync(() => verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(compact)));
            result?.Decision.Should().NotBe(VerificationDecision.Accepted, header);
        }

        foreach (var header in presentationHeaders)
        {
            var compact = await SignCompactAsync(Encoding.UTF8.GetBytes(header), vp, issuer.Signer);
            var result = await TryVerifyAsync(() => verifier.VerifyPresentationAsync(
                Encoding.UTF8.GetBytes(compact),
                new PresentationVerificationOptions { ExpectedChallenge = Challenge, RequireAtLeastOneCredential = false }));
            result?.Decision.Should().NotBe(VerificationDecision.Accepted, header);
        }

        // A malformed signature over a well-formed header is a definitive failure (Failed), never Indeterminate.
        var goodHeader = Encoding.UTF8.GetBytes($"{{\"alg\":\"EdDSA\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"{assertKid}\"}}");
        var honest = await SignCompactAsync(goodHeader, vc, issuer.Signer);
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(honest))).Decision.Should().Be(VerificationDecision.Accepted);

        var signingInput = honest[..honest.LastIndexOf('.')];
        foreach (var badSignature in new[] { new byte[10], new byte[65], new byte[64] })
        {
            var result = await verifier.VerifyCredentialAsync(
                Encoding.UTF8.GetBytes(signingInput + "." + Base64Url.EncodeToString(badSignature)));
            result.Decision.Should().Be(VerificationDecision.Rejected);
            result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Failed);
        }
    }

    [Fact]
    [FrTag("FR-040")]
    [FrTag("FR-041")]
    [FrTag("FR-042")]
    public async Task Es256k_signature_twins_verify_but_never_defeat_freshness_or_disclosure_binding()
    {
        // NetCrypto >= 1.5.0 accepts high-S secp256k1 signatures, so (R, S) and (R, n − S) both verify for
        // ES256K, as they always have for the NIST curves. A twin must never yield an outcome the original
        // could not: freshness is keyed on signed content (nonce / aud / challenge), and sd_hash covers the
        // issuer JWT including its signature.
        var resolver = new MapDidResolver();
        var issuer = resolver.Add("did:example:issuer", KeyType.Secp256k1);
        var holder = resolver.Add("did:example:holder", KeyType.Secp256k1);
        using var provider = BuildProvider(resolver);
        var issuerRole = provider.GetRequiredService<IIssuer>();
        var holderRole = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        // Pinned behavior: a vc+jwt twin is a second valid encoding of the same credential.
        var jose = await issuerRole.IssueAsync(Unsecured(issuer.Did),
            new JoseEnvelopeIssuanceRequest { Signer = issuer.Signer, VerificationMethod = issuer.AssertVm });
        var joseTwin = MalleateEs256k(jose.CompactJws!);
        joseTwin.Should().NotBe(jose.CompactJws);
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(joseTwin)))
            .Decision.Should().Be(VerificationDecision.Accepted);

        // SD-JWT VC + KB-JWT: a twin of the issuer JWT breaks sd_hash; a twin of the KB-JWT is still bound to
        // the nonce it signed.
        var sdJwt = await issuerRole.IssueAsync(Unsecured(issuer.Did), new SdJwtVcIssuanceRequest
        {
            Vct = Vct,
            Signer = issuer.Signer,
            VerificationMethod = issuer.AssertVm,
            Disclosable = [DisclosureSelector.ObjectProperties("credentialSubject", "given_name")],
            HolderBinding = HolderBindingKey.FromMultikey(holder.Pair.MultibasePublicKey),
        });
        var presentation = await holderRole.PresentSdJwtAsync(
            holderRole.Ingest(Encoding.UTF8.GetBytes(sdJwt.CompactSdJwt!)),
            new SdJwtPresentationRequest
            {
                DiscloseClaims = ["given_name"],
                HolderSigner = holder.Signer,
                VerificationMethod = holder.AuthVm,
                Audience = Domain,
                Nonce = Challenge,
            });
        var kbOptions = new CredentialVerificationOptions { RequireHolderBinding = true, ExpectedAudience = Domain, ExpectedNonce = Challenge };
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(presentation), kbOptions))
            .Decision.Should().Be(VerificationDecision.Accepted);

        var parts = presentation.Split('~');
        var issuerTwin = (string[])parts.Clone();
        issuerTwin[0] = MalleateEs256k(parts[0]);
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(string.Join('~', issuerTwin)), kbOptions))
            .Decision.Should().Be(VerificationDecision.Rejected, "sd_hash covers the issuer JWT, signature included");

        var kbTwin = (string[])parts.Clone();
        kbTwin[^1] = MalleateEs256k(parts[^1]);
        (await verifier.VerifyCredentialAsync(Encoding.UTF8.GetBytes(string.Join('~', kbTwin)), kbOptions with { ExpectedNonce = "a-fresh-nonce" }))
            .Decision.Should().Be(VerificationDecision.Rejected, "the KB-JWT twin still carries the old nonce");

        // vp+jwt: a twin still carries the challenge it was bound to.
        var vpJwt = await holderRole.BindWithJoseEnvelopeAsync(
            holderRole.BuildPresentation(new VpAssemblyRequest { Holder = holder.Did, Credentials = [ContainedCredential.Enveloped(jose.CompactJws!)] }),
            new VpBindingRequest { HolderSigner = holder.Signer, VerificationMethod = holder.AuthVm, Challenge = Challenge, Domain = Domain });
        (await verifier.VerifyPresentationAsync(Encoding.UTF8.GetBytes(MalleateEs256k(vpJwt)),
                new PresentationVerificationOptions { ExpectedChallenge = "a-fresh-challenge", ExpectedDomain = Domain }))
            .Decision.Should().Be(VerificationDecision.Rejected, "the vp+jwt twin still carries the old challenge");
    }

    // A CredentialFormatException (refusing to parse) is an acceptable outcome; any other exception escaping
    // the verifier is a contract violation and fails the test by propagating.
    private static async Task<T?> TryVerifyAsync<T>(Func<ValueTask<T>> verify)
        where T : class
    {
        try
        {
            return await verify();
        }
        catch (CredentialFormatException)
        {
            return null;
        }
    }
}

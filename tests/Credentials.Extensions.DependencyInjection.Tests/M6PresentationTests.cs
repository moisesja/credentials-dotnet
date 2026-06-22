using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M6 Verifiable Presentation assembly, holder binding (Data Integrity authentication + JOSE vp+jwt), and
/// verification (FR-002/030/033/034/041): a holder ingests a credential, builds a VP, binds it to a holder
/// key, and a verifier verifies the holder binding + each contained credential. Negatives cover challenge/
/// domain mismatch, holder-binding forgery, an unbound presentation, and a failing contained credential.
/// </summary>
public sealed class M6PresentationTests
{
    private const string Challenge = "challenge-xyz-789";
    private const string Domain = "https://verifier.example";

    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

    /// <summary>Issues an embedded Data Integrity credential and returns a holder-held copy + the holder key.</summary>
    private static async Task<(HeldCredential Held, TestKey Holder)> HoldACredentialAsync(IIssuer issuer, IHolder holder)
    {
        var issuerKey = TestKeys.New(KeyType.Ed25519);
        var holderKey = TestKeys.New(KeyType.Ed25519);

        var credential = Credential.Build()
            .WithIssuer(issuerKey.Did)
            .AddSubject(new JsonObject { ["id"] = holderKey.Did, ["alumniOf"] = "Example University" })
            .Seal();

        var issued = await issuer.IssueAsync(credential, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-jcs-2022",
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
        });

        return (holder.Ingest(issued.Credential.ToBytes()), holderKey);
    }

    private static VerifiablePresentation BuildVp(IHolder holder, HeldCredential held, string holderDid) =>
        holder.BuildPresentation(new VpAssemblyRequest
        {
            Holder = holderDid,
            Credentials = [ContainedCredential.Embedded(held.Credential)],
        });

    [Fact]
    public async Task Data_integrity_bound_presentation_round_trips()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);

        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        bound.Securing.Should().Be(SecuringState.DataIntegrity);

        var result = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Check(CheckKinds.HolderBinding)!.Status.Should().Be(CheckStatus.Passed);
        result.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
        result.Credentials.Should().HaveCount(1);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Accepted);

        // ...and from the wire bytes.
        var fromBytes = await verifier.VerifyPresentationAsync(
            bound.ToBytes(), new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });
        fromBytes.Decision.Should().Be(VerificationDecision.Accepted, fromBytes.ToString());
    }

    [Fact]
    public async Task Jose_vp_jwt_bound_presentation_round_trips()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);

        var vpJwt = await holder.BindWithJoseEnvelopeAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });
        vpJwt.Split('.').Should().HaveCount(3); // compact JWS

        var result = await verifier.VerifyPresentationAsync(
            Encoding.UTF8.GetBytes(vpJwt),
            new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Mechanism.Should().Be(SecuringState.Jose);
        result.Check(CheckKinds.HolderBinding)!.Status.Should().Be(CheckStatus.Passed);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task Jose_vp_jwt_replay_against_a_fresh_challenge_is_rejected()
    {
        // F1 (adversarial): a vp+jwt is captured and replayed to a verifier that demands a DIFFERENT
        // challenge. The holder signed nonce/aud into the VP, so the verifier rejects the stale binding.
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);

        var vpJwt = await holder.BindWithJoseEnvelopeAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var result = await verifier.VerifyPresentationAsync(
            Encoding.UTF8.GetBytes(vpJwt),
            new PresentationVerificationOptions { ExpectedChallenge = "a-fresh-challenge", ExpectedDomain = Domain });

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        var binding = result.Check(CheckKinds.HolderBinding)!;
        binding.Status.Should().Be(CheckStatus.Failed);
        binding.Diagnostics.Should().Contain(d => d.Code == "holder_binding_replay");
    }

    [Fact]
    public async Task Required_holder_binding_without_an_expected_challenge_is_rejected()
    {
        // F2 (adversarial): RequireHolderBinding must fail CLOSED — a verifier that demands a binding but
        // supplies no challenge to bind against would otherwise accept any captured presentation.
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var result = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions()); // RequireHolderBinding defaults true, no ExpectedChallenge

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        var binding = result.Check(CheckKinds.HolderBinding)!;
        binding.Status.Should().Be(CheckStatus.Failed);
        binding.Diagnostics.Should().Contain(d => d.Code == "holder_binding_challenge_required");
    }

    [Fact]
    public async Task Presentation_with_a_malformed_contained_credential_is_rejected_not_thrown()
    {
        // F4 (adversarial): a structurally broken contained credential must be REPORTED as a rejected
        // child, never throw out of the verifier.
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        // Replace the embedded child with a non-object junk node.
        var node = JsonNode.Parse(bound.ToBytes())!.AsObject();
        node["verifiableCredential"]!.AsArray()[0] = "not-a-credential";
        var brokenBytes = Encoding.UTF8.GetBytes(node.ToJsonString());

        var result = await verifier.VerifyPresentationAsync(
            brokenBytes,
            new PresentationVerificationOptions
            {
                RequireHolderBinding = false, // isolate the contained-credential path
                ExpectedChallenge = Challenge,
                ExpectedDomain = Domain,
            });

        result.Decision.Should().Be(VerificationDecision.Rejected, result.ToString());
        result.Credentials.Should().HaveCount(1);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Rejected);
    }

    [Fact]
    public async Task Empty_presentation_is_rejected_when_at_least_one_credential_required()
    {
        // F6 (adversarial): a VP with no credentials proves only holder-key possession; it must not compose
        // to Accepted by default. RequireAtLeastOneCredential (default true) makes it a structure failure.
        using var provider = BuildProvider();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var holderKey = TestKeys.New(KeyType.Ed25519);
        var vp = holder.BuildPresentation(new VpAssemblyRequest { Holder = holderKey.Did, Credentials = [] });
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var rejected = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });
        rejected.Decision.Should().Be(VerificationDecision.Rejected, rejected.ToString());
        rejected.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Failed);
        rejected.Check(CheckKinds.Structure)!.Diagnostics.Should().Contain(d => d.Code == "presentation_no_credentials");

        // ...but accepted when the caller opts out (e.g. a key-possession-only presentation).
        var allowed = await verifier.VerifyPresentationAsync(
            bound,
            new PresentationVerificationOptions
            {
                ExpectedChallenge = Challenge,
                ExpectedDomain = Domain,
                RequireAtLeastOneCredential = false,
            });
        allowed.Check(CheckKinds.Structure)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Theory]
    [InlineData("wrong-challenge", Domain)]
    [InlineData(Challenge, "https://attacker.example")]
    public async Task Di_binding_with_wrong_challenge_or_domain_is_rejected(string expectedChallenge, string expectedDomain)
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var result = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions { ExpectedChallenge = expectedChallenge, ExpectedDomain = expectedDomain });

        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Check(CheckKinds.HolderBinding)!.Status.Should().Be(CheckStatus.Failed);
    }

    [Fact]
    public async Task Holder_binding_forgery_is_rejected()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);

        // The VP claims holderKey as holder, but the binding is signed with the ATTACKER's key.
        var attacker = TestKeys.New(KeyType.Ed25519);
        var vp = BuildVp(holder, held, holderKey.Did);
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = attacker.Signer,
            VerificationMethod = attacker.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var result = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });

        result.Decision.Should().Be(VerificationDecision.Rejected);
        var binding = result.Check(CheckKinds.HolderBinding)!;
        binding.Status.Should().Be(CheckStatus.Failed);
        binding.Diagnostics.Should().Contain(d => d.Code == "holder_binding");
    }

    [Fact]
    public async Task Unbound_presentation_is_rejected_when_holder_binding_required()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did); // not bound

        var required = await verifier.VerifyPresentationAsync(vp, new PresentationVerificationOptions { RequireHolderBinding = true });
        required.Decision.Should().Be(VerificationDecision.Rejected);
        required.Check(CheckKinds.HolderBinding)!.Status.Should().Be(CheckStatus.Failed);

        // ...but accepted (binding Skipped) when not required and the contained credential is valid.
        var notRequired = await verifier.VerifyPresentationAsync(vp, new PresentationVerificationOptions { RequireHolderBinding = false });
        notRequired.Check(CheckKinds.HolderBinding)!.Status.Should().Be(CheckStatus.Skipped);
        notRequired.Decision.Should().Be(VerificationDecision.Accepted, notRequired.ToString());
    }

    [Fact]
    public async Task Presentation_with_a_tampered_contained_credential_is_rejected()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        var (held, holderKey) = await HoldACredentialAsync(issuer, holder);
        var vp = BuildVp(holder, held, holderKey.Did);
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        // Tamper a claim of the embedded contained credential (after the holder bound the VP). The holder
        // binding still verifies over the tampered VP only if re-signed — but the CONTAINED credential's own
        // issuer proof no longer verifies, so the presentation is Rejected.
        var node = JsonNode.Parse(bound.ToBytes())!.AsObject();
        node["verifiableCredential"]!.AsArray()[0]!.AsObject()["credentialSubject"]!.AsObject()["alumniOf"] = "Forged University";
        var tamperedBytes = Encoding.UTF8.GetBytes(node.ToJsonString());

        // Re-bind would be needed for the holder proof; here we just confirm the contained-credential failure
        // dominates regardless of the holder binding (the per-credential proof is independent).
        var result = await verifier.VerifyPresentationAsync(
            tamperedBytes,
            new PresentationVerificationOptions
            {
                RequireHolderBinding = false, // isolate the contained-credential check
                ExpectedChallenge = Challenge,
                ExpectedDomain = Domain,
            });

        result.Decision.Should().Be(VerificationDecision.Rejected);
        result.Credentials.Should().HaveCount(1);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Rejected);
    }

    [Fact]
    public async Task Presentation_with_an_enveloped_jose_child_round_trips()
    {
        using var provider = BuildProvider();
        var issuer = provider.GetRequiredService<IIssuer>();
        var holder = provider.GetRequiredService<IHolder>();
        var verifier = provider.GetRequiredService<IVerifier>();

        // Issue a JOSE vc+jwt credential, hold it, and present it as an ENVELOPED (verbatim compact) child.
        var issuerKey = TestKeys.New(KeyType.Ed25519);
        var holderKey = TestKeys.New(KeyType.Ed25519);
        var credential = Credential.Build()
            .WithIssuer(issuerKey.Did)
            .AddSubject(new JsonObject { ["id"] = holderKey.Did })
            .Seal();
        var issued = await issuer.IssueAsync(credential, new JoseEnvelopeIssuanceRequest
        {
            Signer = issuerKey.Signer,
            VerificationMethod = issuerKey.VerificationMethod,
        });

        var held = holder.Ingest(Encoding.UTF8.GetBytes(issued.CompactJws!));
        held.Securing.Should().Be(SecuringState.Jose);

        var vp = holder.BuildPresentation(new VpAssemblyRequest
        {
            Holder = holderKey.Did,
            Credentials = [ContainedCredential.Enveloped(held.Compact!)],
        });
        var bound = await holder.BindWithDataIntegrityAsync(vp, new VpBindingRequest
        {
            HolderSigner = holderKey.Signer,
            VerificationMethod = holderKey.VerificationMethod,
            Challenge = Challenge,
            Domain = Domain,
        });

        var result = await verifier.VerifyPresentationAsync(
            bound, new PresentationVerificationOptions { ExpectedChallenge = Challenge, ExpectedDomain = Domain });

        result.Decision.Should().Be(VerificationDecision.Accepted, result.ToString());
        result.Credentials.Should().HaveCount(1);
        result.Credentials[0].Mechanism.Should().Be(SecuringState.Jose);
        result.Credentials[0].Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public void Holder_and_verifier_are_registered()
    {
        using var provider = BuildProvider();
        provider.GetService<IHolder>().Should().NotBeNull();
        provider.GetService<IVerifier>().Should().NotBeNull();
    }
}

using Credentials.Resolution;
using Credentials.TestSupport;
using FluentAssertions;
using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// Unit tests for the NetDid → proofs verification-method resolver and its tri-state (F7): a DID that
/// resolves but does not publish the referenced method (no key, or an unknown fragment) is a definitive
/// <see cref="VerificationMethodResolutionStatus.MethodNotFound"/> (→ Failed), while a DID that cannot be
/// resolved at all is <see cref="VerificationMethodResolutionStatus.DidUnresolvable"/> (→ Indeterminate).
/// </summary>
public sealed class NetDidVerificationMethodResolverTests
{
    [Fact]
    public async Task MethodNotFound_when_the_verification_method_has_no_public_key()
    {
        // A resolvable DID document whose verification method carries neither publicKeyMultibase nor
        // publicKeyJwk — the published key set does not authorize the method, so this is a definitive
        // failure (→ Failed), not an unknown resolution (→ Indeterminate).
        const string vm = "did:example:subject#key-1";
        var document = new DidDocument
        {
            Id = "did:example:subject",
            VerificationMethod =
            [
                new VerificationMethod { Id = vm, Type = "Multikey", Controller = "did:example:subject" },
            ],
            AssertionMethod = [VerificationRelationshipEntry.FromReference(vm)],
        };
        var resolver = new NetDidVerificationMethodResolver(FakeDidResolver.Returning(document));

        var resolved = await resolver.ResolveAsync(vm);

        resolved.Status.Should().Be(VerificationMethodResolutionStatus.MethodNotFound);
    }

    [Fact]
    public async Task MethodNotFound_when_the_fragment_matches_no_method()
    {
        // The base DID resolves, but the requested fragment matches no published method — the exact
        // attacker move (mangle the fragment) that must NOT be downgraded to Indeterminate.
        var document = new DidDocument
        {
            Id = "did:example:subject",
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "did:example:subject#key-1",
                    Type = "Multikey",
                    Controller = "did:example:subject",
                    PublicKeyMultibase = NewMultibaseKey(),
                },
            ],
        };
        var resolver = new NetDidVerificationMethodResolver(FakeDidResolver.Returning(document));

        var resolved = await resolver.ResolveAsync("did:example:subject#does-not-exist");

        resolved.Status.Should().Be(VerificationMethodResolutionStatus.MethodNotFound);
    }

    [Fact]
    public async Task DidUnresolvable_when_resolution_reports_an_error()
    {
        var resolver = new NetDidVerificationMethodResolver(FakeDidResolver.Error("notFound"));

        var resolved = await resolver.ResolveAsync("did:example:missing#key-1");

        resolved.Status.Should().Be(VerificationMethodResolutionStatus.DidUnresolvable);
    }

    [Fact]
    [FrTag("FR-080")]
    public async Task Resolves_a_keyed_method_with_its_relationship()
    {
        const string vm = "did:example:subject#key-1";
        var document = new DidDocument
        {
            Id = "did:example:subject",
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = vm,
                    Type = "Multikey",
                    Controller = "did:example:subject",
                    PublicKeyMultibase = NewMultibaseKey(),
                },
            ],
            AssertionMethod = [VerificationRelationshipEntry.FromReference(vm)],
        };
        var resolver = new NetDidVerificationMethodResolver(FakeDidResolver.Returning(document));

        var resolved = await resolver.ResolveAsync(vm);

        resolved.Status.Should().Be(VerificationMethodResolutionStatus.Resolved);
        resolved.Method.Should().NotBeNull();
        resolved.Method!.Id.Should().Be(vm);
        resolved.Method.Controller.Should().Be("did:example:subject");
        resolved.Method.Relationships.Should().Contain(ProofPurpose.AssertionMethod);
    }

    private static string NewMultibaseKey() => new DefaultKeyGenerator().Generate(KeyType.Ed25519).MultibasePublicKey;

    private sealed class FakeDidResolver : IDidResolver
    {
        private readonly DidResolutionResult _result;

        private FakeDidResolver(DidResolutionResult result) => _result = result;

        public static FakeDidResolver Returning(DidDocument document) => new(new DidResolutionResult
        {
            DidDocument = document,
            ResolutionMetadata = new DidResolutionMetadata(),
        });

        public static FakeDidResolver Error(string error) => new(new DidResolutionResult
        {
            DidDocument = null,
            ResolutionMetadata = new DidResolutionMetadata { Error = error },
        });

        public bool CanResolve(string did) => true;

        public Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default) =>
            Task.FromResult(_result);
    }
}

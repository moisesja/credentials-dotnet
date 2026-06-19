using Credentials.Resolution;
using FluentAssertions;
using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// Unit tests for the NetDid → proofs verification-method resolver, including the defensive paths the
/// reviewer flagged: a verification method with no public key, and a fragment that matches no method.
/// </summary>
public sealed class NetDidVerificationMethodResolverTests
{
    [Fact]
    public async Task Returns_null_when_the_verification_method_has_no_public_key()
    {
        // A resolvable DID document whose verification method carries neither publicKeyMultibase nor
        // publicKeyJwk — the resolver must fail to resolve (→ Unresolvable → Indeterminate), not throw.
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

        resolved.Should().BeNull();
    }

    [Fact]
    public async Task Returns_null_when_the_fragment_matches_no_method()
    {
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

        resolved.Should().BeNull();
    }

    [Fact]
    public async Task Returns_null_when_resolution_reports_an_error()
    {
        var resolver = new NetDidVerificationMethodResolver(FakeDidResolver.Error("notFound"));

        var resolved = await resolver.ResolveAsync("did:example:missing#key-1");

        resolved.Should().BeNull();
    }

    [Fact]
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

        resolved.Should().NotBeNull();
        resolved!.Id.Should().Be(vm);
        resolved.Controller.Should().Be("did:example:subject");
        resolved.Relationships.Should().Contain(ProofPurpose.AssertionMethod);
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

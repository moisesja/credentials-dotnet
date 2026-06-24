using System.Text.Json.Nodes;
using Credentials;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// FR-004: the typed accessors on <see cref="Credential"/> are lazy projections computed over the
/// frozen <c>CredentialDocument</c> and memoized — safe precisely because the backing document is
/// immutable. Reading a projection twice must return the very same materialized instance (no recompute),
/// and the projected value must faithfully reflect the underlying document.
/// </summary>
public sealed class LazyProjectionTests
{
    private const string Json =
        """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
          "type": ["VerifiableCredential", "UniversityDegreeCredential"],
          "issuer": "did:example:issuer",
          "credentialSubject": [
            { "id": "did:example:a", "name": "Alice" },
            { "id": "did:example:b", "name": "Bob" }
          ]
        }
        """;

    [Fact]
    [FrTag("FR-004")]
    public void Typed_projections_are_memoized_and_reflect_the_frozen_document()
    {
        var credential = Credential.Parse(Json);
        credential.IsFrozen.Should().BeTrue();

        // Each read of a typed projection returns the SAME materialized instance — the Lazy<T> computes
        // once over the frozen document and caches; a second read must not recompute a fresh list/object.
        ReferenceEquals(credential.CredentialSubjects, credential.CredentialSubjects)
            .Should().BeTrue("the subjects projection is memoized, not recomputed per access");
        ReferenceEquals(credential.Context, credential.Context)
            .Should().BeTrue("the @context projection is memoized");
        ReferenceEquals(credential.Type, credential.Type)
            .Should().BeTrue("the type projection is memoized");
        ReferenceEquals(credential.Issuer, credential.Issuer)
            .Should().BeTrue("the issuer projection is memoized");

        // ...and the memoized values faithfully project the underlying document.
        credential.Context.Should().ContainInOrder(
            "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2");
        credential.Type.Should().ContainInOrder("VerifiableCredential", "UniversityDegreeCredential");
        credential.Issuer!.Id.Should().Be("did:example:issuer");
        credential.CredentialSubjects.Select(s => s.Id).Should().ContainInOrder("did:example:a", "did:example:b");

        // The projection is over the document, which is the source of truth: a GetMember clone of the
        // subject array carries the same ids the typed projection surfaced.
        var rawSubjects = credential.GetMember("credentialSubject")!.AsArray();
        rawSubjects.Select(n => n!["id"]!.GetValue<string>())
            .Should().ContainInOrder(credential.CredentialSubjects.Select(s => s.Id!));
    }
}

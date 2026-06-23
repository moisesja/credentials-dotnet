using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// FR-003 round-trip fidelity (the document-centric core preserves byte/structure for proof
/// verification) and NFR-003 effective immutability / thread-safety.
/// </summary>
public sealed class CredentialFidelityTests
{
    private const string ReceivedJson =
        """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:issuer","credentialSubject":{"id":"did:example:subject","x":"<a>&b'c"},"vendorExtension":{"keep":"me"}}""";

    [Fact]
    public void Received_bytes_are_preserved_verbatim()
    {
        var bytes = Encoding.UTF8.GetBytes(ReceivedJson);
        var credential = Credential.Parse(bytes);

        credential.Origin.Should().Be(DocumentOrigin.ReceivedBytes);
        credential.AsUtf8().ToArray().Should().Equal(bytes, "received documents must verify against their exact bytes");
    }

    [Fact]
    [FrTag("FR-001")]
    public void Unknown_members_survive_round_trip()
    {
        var credential = Credential.Parse(ReceivedJson);
        credential.GetMember("vendorExtension").Should().NotBeNull();

        var reparsed = Credential.Parse(credential.ToBytes());
        reparsed.GetMember("vendorExtension").Should().NotBeNull();
    }

    [Fact]
    public void Built_credential_serialize_is_stable_and_reparses()
    {
        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddSubject(new JsonObject { ["id"] = "did:example:s" })
            .Seal();

        var first = credential.ToBytes();
        var second = credential.ToBytes();
        first.Should().Equal(second, "a built document serializes once and pins the bytes");

        Credential.Parse(first).Issuer!.Id.Should().Be("did:example:issuer");
    }

    [Fact]
    public void Indexer_returns_a_clone_that_cannot_mutate_the_document()
    {
        var credential = Credential.Parse(ReceivedJson);

        var member = credential.Document["credentialSubject"] as JsonObject;
        member!["x"] = "tampered";

        // The credential's own view is unchanged.
        (credential.Document["credentialSubject"] as JsonObject)!["x"]!.GetValue<string>()
            .Should().Be("<a>&b'c");
    }

    [Fact]
    public void AsClaimsObject_returns_an_independent_clone()
    {
        var credential = Credential.Parse(ReceivedJson);
        var claims = credential.AsClaimsObject();
        claims["injected"] = "value";

        credential.GetMember("injected").Should().BeNull();
    }

    [Fact]
    [FrTag("NFR-003")]
    public void Concurrent_serialization_is_thread_safe_and_deterministic()
    {
        var credential = Credential.Build()
            .WithIssuer("did:example:issuer")
            .AddSubject(new JsonObject { ["id"] = "did:example:s", ["n"] = 1 })
            .Seal();

        var results = new ConcurrentBag<string>();
        Parallel.For(0, 64, _ => results.Add(Convert.ToBase64String(credential.ToBytes())));

        results.Distinct().Should().HaveCount(1, "serialize-once must yield identical bytes under concurrency");
    }
}

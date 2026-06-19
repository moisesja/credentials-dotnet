using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using DataProofsDotnet;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// Conformance fix F1: <see cref="CredentialJson.Faithful"/> must byte-mirror
/// <see cref="DataProofsJsonOptions.Default"/>, because for a credential we build, the bytes we
/// serialize are the bytes the securing layer signs and emits. The mirror is enforced here so a
/// dependency bump that changes the default can never silently desynchronize signed-vs-wire bytes.
/// </summary>
public sealed class CredentialJsonFaithfulTests
{
    public static TheoryData<string> Fixtures() => new()
    {
        """{"a":1,"b":"two","c":[1,2,3]}""",
        // Special characters that the default encoder over-escapes but UnsafeRelaxedJsonEscaping does not.
        """{"html":"<a href='x'>&amp;</a>","plus":"a+b","amp":"x&y"}""",
        // Null members (exercise DefaultIgnoreCondition = WhenWritingNull).
        """{"present":"v","absent":null,"nested":{"x":null,"y":1}}""",
        // Non-BMP emoji + accents (escaping/encoding parity).
        """{"emoji":"😀","accents":"café","cjk":"日本語"}""",
        // Member ordering is preserved faithfully (not sorted).
        """{"z":1,"a":2,"m":3,"@context":["https://www.w3.org/ns/credentials/v2"]}""",
    };

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Faithful_byte_mirrors_dataproofs_default(string json)
    {
        var node = JsonNode.Parse(json);

        var faithful = JsonSerializer.SerializeToUtf8Bytes(node, CredentialJson.Faithful);
        var dependency = JsonSerializer.SerializeToUtf8Bytes(node, DataProofsJsonOptions.Default);

        faithful.Should().Equal(dependency, "CredentialJson.Faithful must inherit DataProofsJsonOptions.Default exactly (F1)");
    }

    [Fact]
    public void Faithful_uses_relaxed_escaping_for_credential_safe_characters()
    {
        var node = JsonNode.Parse("""{"v":"<x>&'+"}""");
        var text = Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(node, CredentialJson.Faithful));
        text.Should().Contain("<x>&'+", "relaxed escaping must not escape these characters (fix H1)");
    }

    [Fact]
    public void Faithful_inherits_the_dependency_serialization_settings()
    {
        // Inherited, not hand-copied (F1): the load-bearing settings match the dependency exactly.
        CredentialJson.Faithful.DefaultIgnoreCondition.Should().Be(DataProofsJsonOptions.Default.DefaultIgnoreCondition);
        CredentialJson.Faithful.PropertyNamingPolicy.Should().BeSameAs(DataProofsJsonOptions.Default.PropertyNamingPolicy);
        CredentialJson.Faithful.Encoder.Should().BeSameAs(DataProofsJsonOptions.Default.Encoder);
        CredentialJson.Faithful.WriteIndented.Should().Be(DataProofsJsonOptions.Default.WriteIndented);
        CredentialJson.Faithful.IsReadOnly.Should().BeTrue();
    }
}

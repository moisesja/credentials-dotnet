using System.Text.Json.Nodes;
using Credentials;
using Credentials.Validation;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// Regression tests for the M0 adversarial review (2026-06-18): each test pins an exploit the
/// adversarial agents confirmed by running code, so it can never silently regress.
/// </summary>
public sealed class AdversarialHardeningTests
{
    private static IReadOnlyList<string> CredentialCodes(JsonObject root) =>
        StructuralValidator.Validate(root, VcRole.Credential, VcdmVersion.V2_0).Problems.Select(p => p.Code).ToList();

    // --- Duplicate JSON keys: rejected eagerly as CredentialFormatException, never a leaked
    //     ArgumentException, never a signed-vs-parsed split (all 3 agents). ---

    [Fact]
    public void Duplicate_top_level_key_is_rejected_at_parse()
    {
        const string json = """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"type":["x"]}""";
        var act = () => Credential.Parse(json);
        act.Should().Throw<CredentialFormatException>();
    }

    [Fact]
    public void Duplicate_nested_key_is_rejected_at_parse()
    {
        const string json =
            """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"credentialSubject":{"id":"a","id":"b"}}""";
        var act = () => Credential.Parse(json);
        act.Should().Throw<CredentialFormatException>();
    }

    // --- Input-size bound (NFR-006): oversized input is rejected before parse/clone. ---

    [Fact]
    public void Oversized_input_is_rejected()
    {
        var oversized = new byte[CredentialDocument.MaxInputBytes + 1];
        var act = () => Credential.Parse(oversized);
        act.Should().Throw<CredentialFormatException>();
    }

    // --- A1: @context entries after index 0 must be string IRIs or context objects. ---

    [Fact]
    public void Context_non_string_non_object_entry_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = new JsonArray("https://www.w3.org/ns/credentials/v2", 42);
        CredentialCodes(c).Should().Contain("context.invalid_entry");
    }

    [Fact]
    public void Context_object_entry_after_index0_is_allowed()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = new JsonArray(
            "https://www.w3.org/ns/credentials/v2",
            new JsonObject { ["@vocab"] = "https://example.com/" });
        StructuralValidator.Validate(c, VcRole.Credential, VcdmVersion.V2_0).IsValid.Should().BeTrue();
    }

    // --- B1: an array of credentialSubjects must not contain empty objects. ---

    [Fact]
    public void CredentialSubject_array_with_empty_object_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSubject"] = new JsonArray(new JsonObject());
        CredentialCodes(c).Should().Contain("subject.empty");
    }

    // --- H2/H3/H4: empty/blank identity and type strings are rejected. ---

    [Fact]
    public void Blank_top_level_id_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["id"] = "";
        CredentialCodes(c).Should().Contain("id.invalid");
    }

    [Fact]
    public void Empty_bare_issuer_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["issuer"] = "";
        CredentialCodes(c).Should().Contain("issuer.invalid_shape");
    }

    [Fact]
    public void Object_issuer_with_blank_id_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["issuer"] = new JsonObject { ["id"] = "   " };
        CredentialCodes(c).Should().Contain("issuer.object_missing_id");
    }

    [Fact]
    public void CredentialStatus_with_empty_type_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialStatus"] = new JsonObject { ["id"] = "https://example.com/s#1", ["type"] = "" };
        CredentialCodes(c).Should().Contain("credentialStatus.missing_type");
    }

    [Fact]
    public void CredentialSchema_with_empty_id_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSchema"] = new JsonObject { ["type"] = "JsonSchema", ["id"] = "" };
        CredentialCodes(c).Should().Contain("credentialSchema.missing_id");
    }
}

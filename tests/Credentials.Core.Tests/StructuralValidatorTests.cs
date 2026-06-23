using System.Text.Json.Nodes;
using Credentials.Validation;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// FR-005 structural conformance, with the conformance fixes (A1–A3, B1, C1–C2, D1, F8, H2–H4)
/// exercised as negative cases — the bulk of the W3C VCDM 2.0 test corpus is negative, and the
/// design must fail closed on each.
/// </summary>
public sealed class StructuralValidatorTests
{
    private static IReadOnlyList<string> CodesFor(JsonObject root, VcRole role, VcdmVersion version) =>
        StructuralValidator.Validate(root, role, version).Problems.Select(p => p.Code).ToList();

    private static IReadOnlyList<string> CredentialCodes(JsonObject root) =>
        CodesFor(root, VcRole.Credential, VcdmVersion.V2_0);

    [Fact]
    public void Valid_v2_credential_passes()
    {
        StructuralValidator.Validate(TestVectors.ValidV2Credential(), VcRole.Credential, VcdmVersion.V2_0)
            .IsValid.Should().BeTrue();
    }

    [Fact]
    public void Valid_v1_credential_passes_as_v1()
    {
        StructuralValidator.Validate(TestVectors.ValidV1Credential(), VcRole.Credential, VcdmVersion.V1_1)
            .IsValid.Should().BeTrue();
    }

    // --- A1: @context base ---

    [Fact]
    public void Context_wrong_base_url_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = new JsonArray("https://example.com/not-vcdm");
        CredentialCodes(c).Should().Contain("context.index0_mismatch");
    }

    [Fact]
    public void Context_object_at_index0_is_a_distinct_failure()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = new JsonArray(new JsonObject { ["@vocab"] = "https://example.com/" });
        CredentialCodes(c).Should().Contain("context.index0_not_string");
    }

    [Fact]
    public void Context_empty_array_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = new JsonArray();
        CredentialCodes(c).Should().Contain("context.empty");
    }

    [Fact]
    public void Context_missing_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c.Remove("@context");
        CredentialCodes(c).Should().Contain("context.missing");
    }

    [Fact]
    public void Context_not_array_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = "https://www.w3.org/ns/credentials/v2";
        CredentialCodes(c).Should().Contain("context.not_array");
    }

    // --- D1: positive version detection + version/date consistency ---

    [Fact]
    public void Unknown_version_is_reported()
    {
        var c = TestVectors.ValidV2Credential();
        c["@context"] = new JsonArray("https://example.com/unknown");
        CodesFor(c, VcRole.Credential, VcdmVersion.Unknown).Should().Contain("version.unknown");
    }

    [Fact]
    public void V2_with_issuanceDate_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["issuanceDate"] = "2020-01-01T00:00:00Z";
        CredentialCodes(c).Should().Contain("version.mismatch_dates_v2");
    }

    [Fact]
    public void V1_missing_issuanceDate_is_rejected()
    {
        var c = TestVectors.ValidV1Credential();
        c.Remove("issuanceDate");
        CodesFor(c, VcRole.Credential, VcdmVersion.V1_1).Should().Contain("version.missing_issuanceDate_v11");
    }

    [Fact]
    public void V1_with_validFrom_is_rejected()
    {
        var c = TestVectors.ValidV1Credential();
        c["validFrom"] = "2020-01-01T00:00:00Z";
        CodesFor(c, VcRole.Credential, VcdmVersion.V1_1).Should().Contain("version.mismatch_dates_v11");
    }

    // --- A3: type shape + base type ---

    [Fact]
    public void Type_missing_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c.Remove("type");
        CredentialCodes(c).Should().Contain("type.missing");
    }

    [Theory]
    [InlineData("42")]
    [InlineData("[]")]
    [InlineData("[\"VerifiableCredential\", 7]")]
    public void Type_invalid_shape_is_rejected(string typeJson)
    {
        var c = TestVectors.ValidV2Credential();
        c["type"] = JsonNode.Parse(typeJson);
        CredentialCodes(c).Should().Contain("type.invalid_shape");
    }

    [Fact]
    public void Type_without_base_type_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["type"] = new JsonArray("UniversityDegreeCredential");
        CredentialCodes(c).Should().Contain("type.missing_base");
    }

    // --- B1: credentialSubject shape ---

    [Fact]
    public void Subject_missing_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c.Remove("credentialSubject");
        CredentialCodes(c).Should().Contain("subject.missing");
    }

    [Fact]
    public void Subject_empty_object_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSubject"] = new JsonObject();
        CredentialCodes(c).Should().Contain("subject.empty");
    }

    [Fact]
    public void Subject_empty_array_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSubject"] = new JsonArray();
        CredentialCodes(c).Should().Contain("subject.empty");
    }

    [Fact]
    public void Subject_array_with_non_object_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSubject"] = new JsonArray("not-an-object");
        CredentialCodes(c).Should().Contain("subject.invalid_shape");
    }

    [Fact]
    public void Multiple_object_subjects_are_valid()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSubject"] = new JsonArray(
            new JsonObject { ["id"] = "did:example:a" },
            new JsonObject { ["id"] = "did:example:b" });
        StructuralValidator.Validate(c, VcRole.Credential, VcdmVersion.V2_0).IsValid.Should().BeTrue();
    }

    // --- C1/C2: strict dateTimeStamp + window ordering ---

    [Fact]
    public void ValidFrom_without_offset_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["validFrom"] = "2026-01-01T00:00:00"; // no timezone offset
        CredentialCodes(c).Should().Contain("validity.validFrom_invalid");
    }

    [Fact]
    public void Inverted_validity_window_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["validFrom"] = "2026-06-01T00:00:00Z";
        c["validUntil"] = "2026-01-01T00:00:00Z";
        CredentialCodes(c).Should().Contain("validity.window_inverted");
    }

    [Fact]
    public void V1_inverted_validity_window_is_rejected()
    {
        // The 1.1 window is issuanceDate→expirationDate; an inverted one is rejected just like 2.0's.
        var c = TestVectors.ValidV1Credential();
        c["issuanceDate"] = "2026-06-01T00:00:00Z";
        c["expirationDate"] = "2026-01-01T00:00:00Z";
        CodesFor(c, VcRole.Credential, VcdmVersion.V1_1).Should().Contain("validity.window_inverted");
    }

    // --- H2/H3/H4: typed-member requirements ---

    [Fact]
    public void Non_string_id_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["id"] = 42;
        CredentialCodes(c).Should().Contain("id.invalid");
    }

    [Fact]
    public void Issuer_missing_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c.Remove("issuer");
        CredentialCodes(c).Should().Contain("issuer.missing");
    }

    [Fact]
    public void Object_issuer_without_id_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["issuer"] = new JsonObject { ["name"] = "Example University" };
        CredentialCodes(c).Should().Contain("issuer.object_missing_id");
    }

    [Fact]
    public void Object_issuer_with_id_is_valid()
    {
        var c = TestVectors.ValidV2Credential();
        c["issuer"] = new JsonObject { ["id"] = "did:example:issuer", ["name"] = "Example University" };
        StructuralValidator.Validate(c, VcRole.Credential, VcdmVersion.V2_0).IsValid.Should().BeTrue();
    }

    [Fact]
    public void CredentialStatus_without_type_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialStatus"] = new JsonObject { ["id"] = "https://example.com/status/1#4" };
        CredentialCodes(c).Should().Contain("credentialStatus.missing_type");
    }

    [Fact]
    public void CredentialSchema_without_id_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["credentialSchema"] = new JsonObject { ["type"] = "JsonSchema" };
        CredentialCodes(c).Should().Contain("credentialSchema.missing_id");
    }

    [Fact]
    public void Evidence_without_type_is_rejected()
    {
        var c = TestVectors.ValidV2Credential();
        c["evidence"] = new JsonObject { ["verifier"] = "did:example:v" };
        CredentialCodes(c).Should().Contain("evidence.missing_type");
    }

    // --- F8: presentations are version-detected, not hardcoded ---

    [Fact]
    public void Valid_v2_presentation_passes()
    {
        StructuralValidator.Validate(TestVectors.ValidV2Presentation(), VcRole.Presentation, VcdmVersion.V2_0)
            .IsValid.Should().BeTrue();
    }

    [Fact]
    public void Presentation_without_base_type_is_rejected()
    {
        var p = TestVectors.ValidV2Presentation();
        p["type"] = new JsonArray("SomethingElse");
        CodesFor(p, VcRole.Presentation, VcdmVersion.V2_0).Should().Contain("type.missing_base");
    }

    [Fact]
    public void V1_presentation_is_accepted_when_detected_as_v1()
    {
        var p = TestVectors.ValidV2Presentation();
        p["@context"] = new JsonArray("https://www.w3.org/2018/credentials/v1");
        StructuralValidator.Validate(p, VcRole.Presentation, VcdmVersion.V1_1).IsValid.Should().BeTrue();
    }
}

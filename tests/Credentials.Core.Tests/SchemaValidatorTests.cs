using System.Text;
using System.Text.Json;
using Credentials.Schema;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>JSON Schema 2020-12 credential-schema validation (FR-070) and the immutable validator registry (F6).</summary>
public sealed class SchemaValidatorTests
{
    private static readonly JsonSchema2020Validator Validator = new();

    private static ResolvedSchema Schema(string json) =>
        new("https://schema.example/1", SchemaDialect.JsonSchema2020_12, Encoding.UTF8.GetBytes(json));

    private static JsonElement Credential(string json) => JsonDocument.Parse(json).RootElement;

    private const string PersonSchema =
        """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "properties": {
            "credentialSubject": {
              "type": "object",
              "properties": { "name": { "type": "string" }, "age": { "type": "integer", "minimum": 0 } },
              "required": ["name"]
            }
          },
          "required": ["credentialSubject"]
        }
        """;

    [Fact]
    public void Validates_a_conforming_credential()
    {
        var result = Validator.Validate(
            Schema(PersonSchema),
            Credential("""{ "credentialSubject": { "name": "Ada", "age": 36 } }"""));

        result.Outcome.Should().Be(SchemaCheckOutcome.Success);
    }

    [Fact]
    public void Rejects_a_non_conforming_credential_with_diagnostics()
    {
        var result = Validator.Validate(
            Schema(PersonSchema),
            Credential("""{ "credentialSubject": { "age": -5 } }""")); // missing name, age < minimum

        result.Outcome.Should().Be(SchemaCheckOutcome.Failure);
        result.Diagnostics.Should().NotBeEmpty();
    }

    [Fact]
    public void Asserts_format_keywords()
    {
        const string emailSchema =
            """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "object",
              "properties": { "email": { "type": "string", "format": "email" } }
            }
            """;

        var bad = Validator.Validate(Schema(emailSchema), Credential("""{ "email": "not-an-email" }"""));
        bad.Outcome.Should().Be(SchemaCheckOutcome.Failure, "format validation is enabled (RequireFormatValidation)");

        var good = Validator.Validate(Schema(emailSchema), Credential("""{ "email": "ada@example.com" }"""));
        good.Outcome.Should().Be(SchemaCheckOutcome.Success);
    }

    [Fact]
    public void Unparseable_schema_is_indeterminate()
    {
        var result = Validator.Validate(Schema("{ this is not json"), Credential("""{ "a": 1 }"""));
        result.Outcome.Should().Be(SchemaCheckOutcome.Indeterminate);
    }

    [Theory]
    [InlineData("""{ "type": 5 }""")]
    [InlineData("""{ "$ref": 1 }""")]
    [InlineData("""{ "minimum": "x" }""")]
    [InlineData("""{ "required": "a" }""")]
    [InlineData("""{ "properties": [] }""")]
    [InlineData("""{ "$schema": "https://unknown.example/dialect" }""")]
    [InlineData("[1]")]
    [InlineData("5")]
    public void Structurally_invalid_schema_is_indeterminate_and_never_throws(string schemaJson)
    {
        // JsonSchema.Net 9 reports these as JsonSchemaException, which must not escape the validator.
        var result = Validator.Validate(Schema(schemaJson), Credential("""{ "a": 1 }"""));
        result.Outcome.Should().Be(SchemaCheckOutcome.Indeterminate);
    }

    [Fact]
    public void A_schema_id_from_one_validation_never_resolves_another_validations_ref()
    {
        // JsonSchema.Net 9 registers built schemas process-wide unless given a local registry. Without isolation,
        // the first (attacker-suppliable) schema would answer the second schema's $ref.
        const string id = "https://isolation.example/a";
        Validator.Validate(Schema($$"""{ "$id": "{{id}}", "type": "string" }"""), Credential("\"s\""))
            .Outcome.Should().Be(SchemaCheckOutcome.Success);

        var result = Validator.Validate(Schema($$"""{ "$ref": "{{id}}" }"""), Credential("123"));
        result.Outcome.Should().Be(SchemaCheckOutcome.Indeterminate, "the $ref must stay unresolved, not borrow another validation's schema");
    }

    [Fact]
    public void The_same_schema_id_can_be_validated_repeatedly_with_different_content()
    {
        const string id = "https://isolation.example/reused";
        Validator.Validate(Schema($$"""{ "$id": "{{id}}", "type": "string" }"""), Credential("\"s\""))
            .Outcome.Should().Be(SchemaCheckOutcome.Success);
        Validator.Validate(Schema($$"""{ "$id": "{{id}}", "type": "integer" }"""), Credential("123"))
            .Outcome.Should().Be(SchemaCheckOutcome.Success);
        Validator.Validate(Schema($$"""{ "$id": "{{id}}", "type": "integer" }"""), Credential("\"s\""))
            .Outcome.Should().Be(SchemaCheckOutcome.Failure);
    }

    [Fact]
    public void An_external_ref_is_unresolved_not_fetched()
    {
        // No fetcher is wired (SSRF): an external $ref fails resolution instead of reaching the network.
        var result = Validator.Validate(Schema("""{ "$ref": "https://schema.invalid/remote.json" }"""), Credential("""{ "a": 1 }"""));
        result.Outcome.Should().Be(SchemaCheckOutcome.Indeterminate);
    }

    [Fact]
    public void A_catastrophic_backtracking_pattern_is_cut_off_as_indeterminate()
    {
        // ReDoS: the regex match timeout bounds a pathological pattern instead of hanging verification.
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = Validator.Validate(
            Schema("""{ "type": "string", "pattern": "^(a+)+$" }"""),
            Credential("\"" + new string('a', 30) + "!\""));

        result.Outcome.Should().Be(SchemaCheckOutcome.Indeterminate);
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void Registry_dispatches_by_type_and_is_immutable()
    {
        var registry = new SchemaValidatorRegistry([Validator]);

        registry.Get(JsonSchema2020Validator.JsonSchemaType).Should().BeSameAs(Validator);
        registry.Get("ShaclValidator2025").Should().BeNull();
        registry.SupportedTypes.Should().Contain(JsonSchema2020Validator.JsonSchemaType);

        // There is no public Register: the surface is constructor-only (F6).
        typeof(SchemaValidatorRegistry).GetMethod("Register").Should().BeNull();
    }
}

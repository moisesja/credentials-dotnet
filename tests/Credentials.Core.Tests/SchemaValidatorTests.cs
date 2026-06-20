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

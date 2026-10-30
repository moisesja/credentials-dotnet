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
    [InlineData("""{ "$schema": 5 }""")]
    [InlineData("""{ "properties": { "a": { "$schema": 5 } } }""")]
    [InlineData("""{ "pattern": "\ud800" }""")]
    [InlineData("""{ "$ref": "\ud800" }""")]
    [InlineData("""{ "required": ["\ud800"] }""")]
    public void Structurally_invalid_schema_is_indeterminate_and_never_throws(string schemaJson)
    {
        // JsonSchema.Net 9 reports these as JsonSchemaException or InvalidOperationException, which must not
        // escape the validator.
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

    // A `$defs` entry that defines a meta-schema at `uri` with the given vocabularies.
    private static string MetaSchemaDefinition(string uri, string vocabularies) =>
        $$""" "m": { "$defs": { "meta": { "$id": "{{uri}}", "$vocabulary": {{vocabularies}} } } } """;

    // Defines a core-only dialect at `uri` and uses it in a $defs subschema, so the dialect is actually resolved.
    private static string DialectPoisoningSchema(string uri) =>
        $$"""{ "$defs": { {{MetaSchemaDefinition(uri, CoreVocabularyOnly)}}, "x": { "$schema": "{{uri}}" } } }""";

    private const string CoreVocabularyOnly = """{ "https://json-schema.org/draft/2020-12/vocab/core": true }""";

    private const string FullVocabularies =
        """{ "https://json-schema.org/draft/2020-12/vocab/core": true, "https://json-schema.org/draft/2020-12/vocab/applicator": true, "https://json-schema.org/draft/2020-12/vocab/validation": true }""";

    [Fact]
    public void A_dialect_defined_by_one_schema_never_redefines_that_dialect_for_another()
    {
        // JsonSchema.Net 9 otherwise records a document-defined dialect process-wide, first writer wins. A core-only
        // vocabulary makes validation keywords annotations, so an attacker's schema could make a later victim
        // schema that declares the same $schema pass anything.
        var uri = $"https://dialect.example/meta-{Guid.NewGuid():N}";
        var victim = Schema($$"""{ "$schema": "{{uri}}", "type": "string" }""");
        Validator.Validate(victim, Credential("123")).Outcome.Should().Be(SchemaCheckOutcome.Indeterminate);

        Validator.Validate(Schema(DialectPoisoningSchema(uri)), Credential("{}")).Outcome.Should().Be(SchemaCheckOutcome.Success);

        Validator.Validate(victim, Credential("123")).Outcome.Should().Be(SchemaCheckOutcome.Indeterminate,
            "another validation's dialect definition must not leak into this one");
    }

    [Fact]
    public void A_self_contained_dialect_keeps_its_own_vocabularies_after_another_schema_defined_the_same_uri()
    {
        var uri = $"https://dialect.example/meta-{Guid.NewGuid():N}";
        Validator.Validate(Schema(DialectPoisoningSchema(uri)), Credential("{}")).Outcome.Should().Be(SchemaCheckOutcome.Success);

        var legit = Schema($$"""
            { "$defs": { {{MetaSchemaDefinition(uri, FullVocabularies)}} },
              "properties": { "credentialSubject": { "$schema": "{{uri}}", "type": "object",
                "properties": { "age": { "type": "integer", "minimum": 18 } }, "required": ["age"] } } }
            """);
        Validator.Validate(legit, Credential("""{ "credentialSubject": { "age": 5 } }""")).Outcome.Should().Be(SchemaCheckOutcome.Failure);
        Validator.Validate(legit, Credential("""{ "credentialSubject": { "age": 30 } }""")).Outcome.Should().Be(SchemaCheckOutcome.Success);
    }

    [Fact]
    public void A_fetcher_installed_on_the_global_registry_is_never_used()
    {
        // JsonSchema.Net falls back to SchemaRegistry.Global.Fetch, which any code in the host process may set.
        var calls = new List<Uri>();
        var original = global::Json.Schema.SchemaRegistry.Global.Fetch;
        global::Json.Schema.SchemaRegistry.Global.Fetch = (uri, _) =>
        {
            lock (calls)
            {
                calls.Add(uri);
            }

            return null;
        };
        try
        {
            foreach (var schemaJson in new[]
            {
                """{ "$ref": "https://fetch.invalid/ref.json" }""",
                """{ "$schema": "https://fetch.invalid/meta.json" }""",
                """{ "$dynamicRef": "https://fetch.invalid/dyn.json#x" }""",
            })
            {
                Validator.Validate(Schema(schemaJson), Credential("1")).Outcome.Should().Be(SchemaCheckOutcome.Indeterminate, schemaJson);
            }
        }
        finally
        {
            global::Json.Schema.SchemaRegistry.Global.Fetch = original;
        }

        calls.Should().BeEmpty();
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

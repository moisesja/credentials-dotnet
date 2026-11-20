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

    // JsonSchema.Net 9.7.0 (issue #52) split the `hostname` format by dialect, following the JSON Schema
    // Test Suite: draft 7 through 2020-12 apply the IDNA A-label rules (RFC 5891), draft 6 does not (RFC 1123
    // only). Up to 9.6.0 every dialect applied them. The format registry comes from the build dialect, not
    // from the `$schema` a document declares, and the validator always builds with 2020-12. So a schema that
    // declares draft 6 still gets the IDNA rules, on 9.6.0 and 9.7.0 alike, and the upstream change does not
    // reach credential verification. The draft 6 rows pin that: they fail if the validator's build dialect
    // changes or if JsonSchema.Net starts taking formats from the declared dialect.
    private static string HostnameSchema(string? dialect) =>
        $$"""
        {
          {{(dialect is null ? string.Empty : $"\"$schema\": \"{dialect}\",")}}
          "type": "object",
          "properties": { "host": { "type": "string", "format": "hostname" } }
        }
        """;

    [Theory]
    [InlineData("xn--X")]             // invalid Punycode
    [InlineData("XN--aa---o47jg78q")] // "--" in the third and fourth positions of the decoded label
    public void Hostname_format_applies_the_IDNA_rules_whatever_dialect_the_schema_declares(string hostname)
    {
        var instance = Credential($$"""{ "host": "{{hostname}}" }""");

        foreach (var dialect in new string?[]
                 {
                     null, // no $schema: the validator's default, 2020-12
                     "https://json-schema.org/draft/2020-12/schema",
                     "https://json-schema.org/draft/2019-09/schema",
                     "http://json-schema.org/draft-07/schema#",
                     "http://json-schema.org/draft-06/schema#", // draft 6's own hostname would accept both values
                 })
        {
            Validator.Validate(Schema(HostnameSchema(dialect)), instance).Outcome
                .Should().Be(SchemaCheckOutcome.Failure, "the 2020-12 format registry applies under {0}", dialect ?? "the default dialect");
        }
    }

    [Fact]
    public void Hostname_format_accepts_a_valid_A_label_in_2020_12()
    {
        // Positive control: the 2020-12 rejections above are the IDNA rules, not a refusal of every A-label.
        Validator.Validate(Schema(HostnameSchema(null)), Credential("""{ "host": "xn--9n2bp8q.xn--9t4b11yi5a" }""")).Outcome
            .Should().Be(SchemaCheckOutcome.Success);
    }

    // JsonSchema.Net 9.7.0 (issue #52) changed `$dynamicRef` in the v1 dialect, following the current JSON Schema
    // Test Suite: v1 now takes a bare anchor name ("node") and refuses "#node", the reverse of 9.6.0. A schema
    // reaches v1 by declaring it, at the root or in any subschema. 2020-12 keeps the URI-reference form. Every
    // change is between Indeterminate and an evaluated result, never between Success and Failure, so it cannot
    // admit a non-conforming credential. The rows pin both dialects, so the next change surfaces here.
    private static string DynamicRefSchema(string? dialect, string reference) =>
        $$"""
        {
          {{(dialect is null ? string.Empty : $"\"$schema\": \"{dialect}\",")}}
          "$dynamicAnchor": "node",
          "type": "object",
          "properties": { "credentialSubject": { "$dynamicRef": "{{reference}}" }, "n": { "type": "integer" } }
        }
        """;

    [Theory]
    [InlineData("https://json-schema.org/v1", "node", SchemaCheckOutcome.Failure)]            // 9.6.0: Indeterminate
    [InlineData("https://json-schema.org/v1/2026", "node", SchemaCheckOutcome.Failure)]       // 9.6.0: Indeterminate
    [InlineData("https://json-schema.org/v1", "#node", SchemaCheckOutcome.Indeterminate)]     // 9.6.0: Failure
    [InlineData(null, "#node", SchemaCheckOutcome.Failure)]
    [InlineData("https://json-schema.org/draft/2020-12/schema", "#node", SchemaCheckOutcome.Failure)]
    // In 2020-12 a bare name is a relative URI, which would need a fetch: unresolved, never fetched.
    [InlineData("https://json-schema.org/draft/2020-12/schema", "node", SchemaCheckOutcome.Indeterminate)]
    public void DynamicRef_anchor_syntax_follows_the_declared_dialect(string? dialect, string reference, SchemaCheckOutcome expected)
    {
        // credentialSubject re-enters the root through $dynamicRef, so its `n` must be an integer too.
        Validator.Validate(Schema(DynamicRefSchema(dialect, reference)), Credential("""{ "credentialSubject": { "n": "x" } }"""))
            .Outcome.Should().Be(expected);
    }

    [Theory]
    [InlineData("https://json-schema.org/v1", "node")]
    [InlineData(null, "#node")]
    public void DynamicRef_resolves_and_accepts_a_conforming_credential(string? dialect, string reference)
    {
        // Positive control: the Failure rows above are the recursive constraint, not an unresolvable reference.
        Validator.Validate(Schema(DynamicRefSchema(dialect, reference)), Credential("""{ "credentialSubject": { "n": 1 } }"""))
            .Outcome.Should().Be(SchemaCheckOutcome.Success);
    }

    [Fact]
    public void A_v1_subschema_inside_a_2020_12_schema_uses_the_v1_dynamicRef_syntax()
    {
        // A root-level $schema check would not see v1 here.
        const string schema =
            """
            {
              "properties": { "credentialSubject": { "$ref": "https://schema.example/v1" } },
              "$defs": {
                "v1": {
                  "$schema": "https://json-schema.org/v1", "$id": "https://schema.example/v1", "$dynamicAnchor": "n",
                  "properties": { "c": { "$dynamicRef": "n" }, "k": { "type": "integer" } }
                }
              }
            }
            """;

        Validator.Validate(Schema(schema), Credential("""{ "credentialSubject": { "c": { "k": "x" } } }""")).Outcome
            .Should().Be(SchemaCheckOutcome.Failure);
        Validator.Validate(Schema(schema), Credential("""{ "credentialSubject": { "c": { "k": 1 } } }""")).Outcome
            .Should().Be(SchemaCheckOutcome.Success);
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

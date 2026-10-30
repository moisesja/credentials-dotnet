using System.Text;
using System.Text.Json;
using Credentials.Verification;
using Json.Schema;

namespace Credentials.Schema;

/// <summary>
/// Validates a credential against a JSON Schema 2020-12 document (FR-070) using JsonSchema.Net (System.Text.Json
/// native — no Newtonsoft, NFR-002). Handles <c>credentialSchema.type == "JsonSchema"</c>. Format keywords are
/// asserted (<c>RequireFormatValidation</c>). Never throws: an unparseable schema or an evaluation fault is
/// reported as <see cref="SchemaCheckOutcome.Indeterminate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>SSRF:</strong> no external reference is ever fetched. Each validation's local registry has a
/// <see cref="SchemaRegistry.Fetch"/> that refuses. That matters because JsonSchema.Net falls back to the
/// process-wide <see cref="SchemaRegistry.Global"/>'s fetcher, which any other code in the host process may
/// set. An unresolved external <c>$ref</c>, <c>$dynamicRef</c> or meta-schema therefore yields
/// <see cref="SchemaCheckOutcome.Indeterminate"/> with no egress. The caller's resolver controls all schema
/// fetching, and a declared <c>digestSRI</c> pins the bytes.
/// </para>
/// <para>
/// <strong>Registry isolation:</strong> each validation builds into a fresh local <see cref="SchemaRegistry"/>
/// <em>and</em> a fresh local <see cref="DialectRegistry"/>. JsonSchema.Net 9 otherwise records schemas and
/// custom dialects in process-wide registries, which leads to three problems:
/// <list type="bullet">
/// <item>A schema supplied with one credential could answer another credential's <c>$ref</c>.</item>
/// <item>A schema could redefine a custom <c>$schema</c> dialect for every later validation, the first
/// writer winning. For example, a core-only vocabulary turns validation keywords into annotations, so a
/// non-conforming credential would pass.</item>
/// <item>The process-wide dialect dictionary grows without bound and is not thread-safe.</item>
/// </list>
/// </para>
/// <para>
/// <strong>Dialect:</strong> a schema without <c>$schema</c> is evaluated as 2020-12. A <c>$schema</c> the
/// document declares, at the root or in any subschema, selects that dialect if JsonSchema.Net knows it, or if
/// the same document defines it. Otherwise the result is <see cref="SchemaCheckOutcome.Indeterminate"/>.
/// </para>
/// <para>
/// <strong>ReDoS:</strong> a malicious <c>pattern</c>/<c>format</c> regex cannot hang the validator
/// indefinitely — the BCL regex engine's match timeout fires and the evaluation is reported as
/// <see cref="SchemaCheckOutcome.Indeterminate"/>. A pathological schema can still cost up to that timeout
/// per regex, so schemas must come from a trusted resolver and (ideally) be pinned with <c>digestSRI</c>;
/// the same trust boundary that gates SSRF gates this amplification.
/// </para>
/// </remarks>
internal sealed class JsonSchema2020Validator : ICredentialSchemaValidator
{
    /// <summary>The <c>credentialSchema.type</c> for a plain JSON Schema document.</summary>
    public const string JsonSchemaType = "JsonSchema";

    private static readonly EvaluationOptions Options = new()
    {
        RequireFormatValidation = true,
        OutputFormat = OutputFormat.List,
    };

    // Throwing, rather than returning null, keeps JsonSchema.Net from falling back to SchemaRegistry.Global.Fetch.
    private static IBaseDocument? RefuseFetch(Uri uri, SchemaRegistry registry) =>
        throw new InvalidOperationException("Credential schemas never fetch external references.");

    public string SchemaType => JsonSchemaType;

    public SchemaDialect Dialect => SchemaDialect.JsonSchema2020_12;

    public SchemaCheckResult Validate(ResolvedSchema schema, JsonElement credential)
    {
        ArgumentNullException.ThrowIfNull(schema);

        JsonSchema parsed;
        try
        {
            // Fresh local registries per validation keep this schema's $ids and dialects out of the process-wide
            // registries and stop any fetch (see the remarks). 2020-12 is the default dialect.
            parsed = JsonSchema.FromText(
                Encoding.UTF8.GetString(schema.Content.Span),
                new BuildOptions
                {
                    Dialect = global::Json.Schema.Dialect.Draft202012,
                    SchemaRegistry = new SchemaRegistry { Fetch = RefuseFetch },
                    DialectRegistry = new DialectRegistry(),
                });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // JsonSchema.Net 9 reports a malformed schema in several ways: JsonException,
            // JsonSchemaException ({"type":5}, {"$ref":1}, an unknown $schema), and InvalidOperationException
            // (a non-string $schema, a lone surrogate in a keyword value). All of them mean the same thing here.
            return SchemaCheckResult.Indeterminate("schema.unparseable", "The schema document is not valid JSON Schema.");
        }

        EvaluationResults results;
        try
        {
            results = parsed.Evaluate(credential, Options);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A pathological schema (e.g. unresolvable $ref) surfaces as an evaluation fault → Indeterminate.
            return SchemaCheckResult.Indeterminate("schema.evaluation_error", "The schema could not be evaluated against the credential.");
        }

        if (results.IsValid)
        {
            return SchemaCheckResult.Success();
        }

        var diagnostics = new List<CheckDiagnostic>();
        CollectErrors(results, diagnostics);
        if (diagnostics.Count == 0)
        {
            diagnostics.Add(new CheckDiagnostic("schema.violation", "The credential does not conform to its schema.", DiagnosticSeverity.Error));
        }

        return SchemaCheckResult.Failure(diagnostics);
    }

    private static void CollectErrors(EvaluationResults results, List<CheckDiagnostic> diagnostics)
    {
        // With OutputFormat.List, Details is the flattened set of nodes; surface each node that has errors.
        if (results.Errors is { Count: > 0 } errors)
        {
            AddErrors(results.InstanceLocation.ToString(), errors, diagnostics);
        }

        foreach (var detail in results.Details ?? [])
        {
            if (detail.Errors is { Count: > 0 } detailErrors)
            {
                AddErrors(detail.InstanceLocation.ToString(), detailErrors, diagnostics);
            }
        }
    }

    private static void AddErrors(string instanceLocation, IReadOnlyDictionary<string, string> errors, List<CheckDiagnostic> diagnostics)
    {
        foreach (var (keyword, message) in errors)
        {
            // Schema-validation messages are JsonSchema.Net's own (keyword + reason), not credential
            // claim values, so they are safe to surface (NFR-008). Cap defensively.
            var safe = message.Length > 500 ? message[..500] : message;
            diagnostics.Add(new CheckDiagnostic(
                $"schema.{keyword}",
                safe,
                DiagnosticSeverity.Error,
                string.IsNullOrEmpty(instanceLocation) ? "/" : instanceLocation));
        }
    }
}

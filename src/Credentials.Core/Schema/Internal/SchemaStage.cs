using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Cryptography;
using Credentials.Json;
using Credentials.Roles;
using Credentials.Verification;

namespace Credentials.Schema;

/// <summary>
/// The verifier's credential-schema stage (FR-070). For each <c>credentialSchema</c> entry it resolves the
/// schema via the injected <see cref="ICredentialSchemaResolver"/>, enforces any declared <c>digestSRI</c>
/// over the fetched bytes via the <see cref="IDigestService"/> seam (NetCrypto.Hash) before parsing, and
/// validates the credential through the type-keyed <see cref="SchemaValidatorRegistry"/>.
///
/// <para>
/// <c>JsonSchemaCredential</c> entries (the schema wrapped in its own verifiable credential) have the
/// wrapper's proof verified recursively through the same <see cref="IVerifier"/> (with the validity window
/// enabled) before the inner JSON Schema is extracted and applied — reusing the status stage's recursion.
/// </para>
///
/// <para>
/// Never throws (FR-045): a schema violation is <see cref="CheckStatus.Failed"/>; an unresolvable schema,
/// an unknown type, or an evaluation fault is <see cref="CheckStatus.Indeterminate"/>; a digest mismatch is
/// <see cref="CheckStatus.Failed"/>. Reports <see cref="CheckStatus.Skipped"/> when schema checking is
/// disabled, the credential declares no schema, or no resolver is configured.
/// </para>
/// </summary>
internal sealed class SchemaStage
{
    /// <summary>The <c>credentialSchema.type</c> for a schema wrapped in a verifiable credential.</summary>
    public const string JsonSchemaCredentialType = "JsonSchemaCredential";

    private readonly ICredentialSchemaResolver? _resolver;
    private readonly SchemaValidatorRegistry _validators;
    private readonly IDigestService _digests;

    public SchemaStage(ICredentialSchemaResolver? resolver, SchemaValidatorRegistry validators, IDigestService digests)
    {
        _resolver = resolver;
        _validators = validators ?? throw new ArgumentNullException(nameof(validators));
        _digests = digests ?? throw new ArgumentNullException(nameof(digests));
    }

    public async Task<CheckResult> EvaluateAsync(
        Credential credential,
        CredentialVerificationOptions options,
        IVerifier verifier,
        CancellationToken cancellationToken)
    {
        if (!options.CheckSchema)
        {
            return CheckResult.Skipped(CheckKinds.Schema, "Schema checking is disabled for this verification.");
        }

        var entries = credential.CredentialSchema;
        if (entries.Count == 0)
        {
            return CheckResult.Skipped(CheckKinds.Schema, "The credential declares no credentialSchema.");
        }

        if (_resolver is null)
        {
            return CheckResult.Skipped(CheckKinds.Schema, "No credential-schema resolver is configured.");
        }

        var credentialElement = credential.AsElement();
        var diagnostics = new List<CheckDiagnostic>();
        var worst = CheckStatus.Passed;

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var outcome = await EvaluateEntryAsync(entry.Raw, credentialElement, options, verifier, cancellationToken).ConfigureAwait(false);
            worst = Worse(worst, outcome.Status);
            diagnostics.AddRange(outcome.Diagnostics);
        }

        return worst switch
        {
            CheckStatus.Failed => CheckResult.Failed(CheckKinds.Schema, diagnostics),
            CheckStatus.Indeterminate => CheckResult.Indeterminate(CheckKinds.Schema, diagnostics),
            _ => CheckResult.Passed(CheckKinds.Schema),
        };
    }

    private async Task<StageOutcome> EvaluateEntryAsync(
        JsonObject entry,
        JsonElement credential,
        CredentialVerificationOptions options,
        IVerifier verifier,
        CancellationToken cancellationToken)
    {
        var type = JsonShape.AsString(entry["type"]);
        if (string.IsNullOrEmpty(type))
        {
            return StageOutcome.Indeterminate("schema.entry_invalid", "The credentialSchema entry has no type.");
        }

        var id = JsonShape.AsString(entry["id"]);
        if (string.IsNullOrEmpty(id))
        {
            return StageOutcome.Indeterminate("schema.entry_invalid", "The credentialSchema entry has no id.");
        }

        var reference = new SchemaReference
        {
            Id = id,
            Type = type,
            ExpectedDigestSri = JsonShape.AsString(entry["digestSRI"]),
            Raw = (JsonObject)entry.DeepClone(),
        };

        SchemaResolutionResult resolution;
        try
        {
            resolution = await _resolver!.ResolveAsync(reference, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return StageOutcome.Indeterminate("schema.unresolvable", "The schema could not be resolved.");
        }

        if (resolution is null || !resolution.IsFound || resolution.Schema is null)
        {
            return StageOutcome.Indeterminate("schema.unresolvable", "The schema could not be resolved.");
        }

        var resolved = resolution.Schema;

        // Enforce digestSRI over the fetched bytes BEFORE parsing them (NFR-006).
        if (reference.ExpectedDigestSri is { Length: > 0 } sri)
        {
            var digestOutcome = VerifyDigest(sri, resolved.Content.Span);
            if (digestOutcome is not null)
            {
                return digestOutcome.Value;
            }
        }

        // JsonSchemaCredential: unwrap the schema VC (verify its proof first), then validate as JsonSchema.
        if (string.Equals(type, JsonSchemaCredentialType, StringComparison.Ordinal))
        {
            return await ValidateWrappedSchemaAsync(resolved, credential, options, verifier, cancellationToken).ConfigureAwait(false);
        }

        var validator = _validators.Get(type);
        if (validator is null)
        {
            return StageOutcome.Indeterminate("schema.unknown_type", $"No validator is registered for credentialSchema type '{type}'.");
        }

        return Map(validator.Validate(resolved, credential));
    }

    private async Task<StageOutcome> ValidateWrappedSchemaAsync(
        ResolvedSchema wrapper,
        JsonElement credential,
        CredentialVerificationOptions options,
        IVerifier verifier,
        CancellationToken cancellationToken)
    {
        Credential schemaCredential;
        try
        {
            schemaCredential = Credential.Parse(wrapper.Content);
        }
        catch (CredentialFormatException)
        {
            return StageOutcome.Indeterminate("schema.wrapper_malformed", "The JsonSchemaCredential is not a valid credential.");
        }

        var innerOptions = new CredentialVerificationOptions
        {
            VerificationTime = options.VerificationTime,
            ClockSkew = options.ClockSkew,
            AcceptVcdm11 = options.AcceptVcdm11,
            Policy = options.Policy,
            CheckStatus = false,
            CheckSchema = false,
            EvaluateIssuerTrust = false,
        };

        var wrapperResult = await verifier.VerifyCredentialAsync(schemaCredential, innerOptions, cancellationToken).ConfigureAwait(false);
        if (wrapperResult.Decision != VerificationDecision.Accepted)
        {
            return StageOutcome.Indeterminate("schema.wrapper_unverified",
                "The JsonSchemaCredential's own proof did not verify (or it is outside its validity window).");
        }

        // The inner JSON Schema lives at credentialSubject.jsonSchema.
        var subject = schemaCredential.CredentialSubjects.FirstOrDefault();
        if (subject?["jsonSchema"] is not JsonObject innerSchema)
        {
            return StageOutcome.Indeterminate("schema.wrapper_malformed", "The JsonSchemaCredential has no credentialSubject.jsonSchema.");
        }

        var validator = _validators.Get(JsonSchema2020Validator.JsonSchemaType);
        if (validator is null)
        {
            return StageOutcome.Indeterminate("schema.unknown_type", "No JSON Schema validator is registered.");
        }

        var innerBytes = JsonSerializer.SerializeToUtf8Bytes(innerSchema, CredentialJson.Faithful);
        var innerResolved = new ResolvedSchema(wrapper.Id, SchemaDialect.JsonSchema2020_12, innerBytes);
        return Map(validator.Validate(innerResolved, credential));
    }

    private StageOutcome? VerifyDigest(string sri, ReadOnlySpan<byte> content)
    {
        // SRI form: "<alg>-<base64>" (e.g. sha256-…). The digest goes through the NetCrypto.Hash seam.
        var dash = sri.IndexOf('-');
        if (dash <= 0 || dash == sri.Length - 1)
        {
            return StageOutcome.Indeterminate("schema.digest_unsupported", "The digestSRI is not a recognised <alg>-<base64> value.");
        }

        var alg = sri[..dash];
        var expected = sri[(dash + 1)..];
        byte[] actual;
        switch (alg)
        {
            case "sha256":
                actual = _digests.Sha256(content);
                break;
            case "sha384":
                actual = _digests.Sha384(content);
                break;
            case "sha512":
                actual = _digests.Sha512(content);
                break;
            default:
                return StageOutcome.Indeterminate("schema.digest_unsupported", $"Unsupported digestSRI algorithm '{alg}'.");
        }

        var actualBase64 = Convert.ToBase64String(actual);
        if (!FixedTimeEquals(actualBase64, expected))
        {
            return StageOutcome.Failed("schema.digest_mismatch", "The fetched schema does not match its declared digestSRI.");
        }

        return null;
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        // Compare the base64 strings byte-wise in constant time over the max length (integrity, not secrecy,
        // but cheap and avoids early-exit signal).
        var ba = System.Text.Encoding.ASCII.GetBytes(a);
        var bb = System.Text.Encoding.ASCII.GetBytes(b);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    private static StageOutcome Map(SchemaCheckResult result) => result.Outcome switch
    {
        SchemaCheckOutcome.Success => StageOutcome.Passed(),
        SchemaCheckOutcome.Failure => new StageOutcome(CheckStatus.Failed, result.Diagnostics),
        _ => new StageOutcome(CheckStatus.Indeterminate, result.Diagnostics),
    };

    private static CheckStatus Worse(CheckStatus a, CheckStatus b)
    {
        if (a == CheckStatus.Failed || b == CheckStatus.Failed)
        {
            return CheckStatus.Failed;
        }

        if (a == CheckStatus.Indeterminate || b == CheckStatus.Indeterminate)
        {
            return CheckStatus.Indeterminate;
        }

        return CheckStatus.Passed;
    }

    private readonly record struct StageOutcome(CheckStatus Status, IReadOnlyList<CheckDiagnostic> Diagnostics)
    {
        public static StageOutcome Passed() => new(CheckStatus.Passed, []);

        public static StageOutcome Failed(string code, string message) =>
            new(CheckStatus.Failed, [new CheckDiagnostic(code, message, DiagnosticSeverity.Error)]);

        public static StageOutcome Indeterminate(string code, string message) =>
            new(CheckStatus.Indeterminate, [new CheckDiagnostic(code, message, DiagnosticSeverity.Error)]);
    }
}
